'use strict';
// The capture engine: index, rows, packet details, filter, statistics, follow stream and export.
// It runs in a worker thread (src/core/worker.js) so a 1 GB capture never blocks the extension host;
// tests call it directly. All work is local; nothing here opens a socket or resolves a name on the network.
const fs = require('fs');
const { FileSource, gunzipToSource, indexCapture, buildExport } = require('./capture');
const { dissect, dnsNames, LINKTYPES } = require('./dissect');
const { compile } = require('./filter');

const tick = () => new Promise(r => setImmediate(r));

/** Cheap check for DNS before running the full dissector while indexing. */
function maybeDns(b, at, len, lt) {
  let o = at, end = at + len, et = -1;
  if (lt === 1) { if (len < 14) return false; et = (b[o + 12] << 8) | b[o + 13]; o += 14; if (et === 0x8100 && o + 4 <= end) { et = (b[o + 2] << 8) | b[o + 3]; o += 4; } }
  else if (lt === 113) { if (len < 16) return false; et = (b[o + 14] << 8) | b[o + 15]; o += 16; }
  else if (lt === 276) { if (len < 20) return false; et = (b[o] << 8) | b[o + 1]; o += 20; }
  else if (lt === 0 || lt === 108) { o += 4; et = o < end ? ((b[o] >> 4) === 6 ? 0x86dd : 0x0800) : -1; }
  else if (lt === 101 || lt === 12 || lt === 14 || lt === 228 || lt === 229) { et = o < end ? ((b[o] >> 4) === 6 ? 0x86dd : 0x0800) : -1; }
  else return false;
  let proto, p;
  if (et === 0x0800) { if (o + 20 > end) return false; proto = b[o + 9]; p = o + (b[o] & 15) * 4; }
  else if (et === 0x86dd) { if (o + 40 > end) return false; proto = b[o + 6]; p = o + 40; }
  else return false;
  if ((proto !== 17 && proto !== 6) || p + 4 > end) return false;
  const sp = (b[p] << 8) | b[p + 1], dp = (b[p + 2] << 8) | b[p + 3];
  return sp === 53 || dp === 53 || sp === 5353 || dp === 5353 || sp === 5355 || dp === 5355;
}

function pad(n, w = 2) { return String(n).padStart(w, '0'); }

class Engine {
  constructor(post) {
    this.post = post || (() => {});
    this.src = null; this.idx = null; this.ifs = []; this.names = new Map(); this.view = null; this.info = null;
    this.analysis = null; this.analysisPromise = null; this.jobs = new Map(); this.nsRes = false;
  }

  /** opts: { gz: boolean, maxGzipMB: number, name: string } */
  async open(path, opts = {}) {
    const t0 = Date.now();
    let src, capped = false, gzInfo = null;
    try {
      if (opts.gz) {
        const cap = Math.max(1, opts.maxGzipMB || 512) * 1048576;
        const r = await gunzipToSource(path, cap, (out, inp, total) => this.post({ type: 'progress', phase: 'unzip', done: inp, total, out }));
        src = r.source; capped = r.capped; gzInfo = r;
      } else src = new FileSource(path);
    } catch (e) {
      return { error: gzErr(e), size: 0 };
    }
    this.src = src;
    const size = src.size;
    let lastPost = 0;
    const res = await indexCapture(src, {
      yieldEvery: 20000,
      onProgress: (pos, total) => { const now = Date.now(); if (now - lastPost > 150) { lastPost = now; this.post({ type: 'progress', phase: 'index', done: pos, total, packets: this.idxRef ? this.idxRef.n : 0 }); } },
      onPacket: (i, b, at, len, lt) => {
        if (maybeDns(b, at, len, lt)) {
          const pairs = dnsNames(b.subarray(at, at + len), lt);
          if (pairs) for (const [addr, name] of pairs) if (!this.names.has(addr) && this.names.size < 200000) this.names.set(addr, { name, from: `DNS answer in packet ${i + 1}` });
        }
      },
    });
    this.idxRef = res.index;
    this.idx = res.index; this.ifs = res.interfaces;
    for (const [addr, name, from] of res.names) if (!this.names.has(addr)) this.names.set(addr, { name, from: 'Name resolution block in the file' });
    const warnings = res.warnings.slice();
    if (capped && gzInfo.bomb) warnings.unshift(`This .gz file unpacks at about ${gzInfo.bomb} times its packed size, which is what a gzip bomb does. Unpacking stopped at ${Math.round(size / 1048576)} MB; the packets in that part are shown.`);
    else if (capped) warnings.unshift(`This .gz file expands to more than ${opts.maxGzipMB || 512} MB (it may be a gzip bomb, or a very large capture). Only the first ${opts.maxGzipMB || 512} MB were unpacked; the packets in that part are shown. Unzip it yourself to see the rest, or raise the setting pcapViewer.maxGzipMB.`);
    if (gzInfo && gzInfo.gzError) warnings.unshift(`The .gz data is damaged after ${(size / 1048576).toFixed(1)} MB (${gzInfo.gzError}). The packets before that point are shown.`);
    const n = this.idx.n;
    if (src.trim) { const end = n ? this.idx.off[n - 1] + this.idx.len[n - 1] : 0; const unpacked = src.size; src.trim(end); if (src.size < unpacked) this.trimmedFrom = unpacked; }
    this.nsRes = this.ifs.some(f => f.res && ((f.res.dec !== undefined && f.res.dec > 6) || f.res.bin > 20));
    let t1 = -1;
    for (let i = 0; i < n; i++) if (!this.idx.noTs.has(i)) { t1 = i; break; }
    this.first = t1 >= 0 ? [this.idx.sec[t1], this.idx.ns[t1]] : [0, 0];
    this.info = {
      error: res.error, format: res.format, count: n, size, compressed: gzInfo ? gzInfo.compressed : 0, capped, warnings,
      interfaces: this.ifs.map(f => ({ linktype: f.linktype, linkName: LINKTYPES[f.linktype] || `link type ${f.linktype}`, name: f.name || '', snaplen: f.snaplen })),
      section: res.section, names: this.names.size, ms: Date.now() - t0,
      firstTime: t1 >= 0 ? this.absTime(t1, 'utc') : '', duration: this.lastTimed(),
    };
    return this.info;
  }

  lastTimed() { for (let i = this.idx.n - 1; i >= 0; i--) if (!this.idx.noTs.has(i)) return this.relSec(i); return 0; }

  close() { if (this.src) this.src.close(); this.src = null; this.idx = null; }

  relSec(i) { return (this.idx.sec[i] - this.first[0]) + (this.idx.ns[i] - this.first[1]) / 1e9; }

  absTime(i, mode) {
    const s = this.idx.sec[i], ns = this.idx.ns[i];
    const d = new Date(s * 1000);
    const frac = this.nsRes ? pad(ns, 9) : pad(Math.floor(ns / 1000), 6);
    if (mode === 'utc') return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${frac}`;
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${frac}`;
  }

  timeText(i, mode, prev) {
    if (this.idx.noTs.size && this.idx.noTs.has(i)) return 'no time (simple block)';
    if (mode === 'utc' || mode === 'local') return this.absTime(i, mode);
    if (mode === 'delta') { const p = prev >= 0 ? prev : i; const v = (this.idx.sec[i] - this.idx.sec[p]) + (this.idx.ns[i] - this.idx.ns[p]) / 1e9; return v.toFixed(this.nsRes ? 9 : 6); }
    return this.relSec(i).toFixed(this.nsRes ? 9 : 6);
  }

  bytes(i) { return this.src.read(this.idx.off[i], this.idx.len[i]); }

  lt(i) { return this.ifs[this.idx.ifc[i]].linktype; }

  dissectAt(i, tree) {
    const opts = { tree, orig: this.idx.orig[i], number: i + 1 };
    if (tree) { opts.time = this.idx.noTs.has(i) ? 'none (simple packet block)' : this.absTime(i, 'utc') + ' UTC'; opts.comment = this.idx.comments.get(i); }
    const r = dissect(this.bytes(i), this.lt(i), opts);
    if (this.ifs.length > 1) r.f['frame.interface_id'] = this.idx.ifc[i];
    r.f['frame.time_relative'] = this.relSec(i);
    if (this.analysis && this.analysis.stream[i] >= 0 && r.l4) r.f[r.l4.proto + '.stream'] = this.analysis.stream[i];
    if (r.malformed) r.f['_ws.malformed'] = 1;
    return r;
  }

  name(addr) { const e = this.names.get(addr); return e ? e.name : ''; }

  viewCount() { return this.view ? this.view.length : (this.idx ? this.idx.n : 0); }

  rows(start, count, opts = {}) {
    const out = [], n = this.viewCount();
    const end = Math.min(n, start + Math.min(count, 2000));
    for (let k = Math.max(0, start); k < end; k++) {
      const i = this.view ? this.view[k] : k;
      const prev = k > 0 ? (this.view ? this.view[k - 1] : k - 1) : -1;
      let r;
      try { r = this.dissectAt(i, false); } catch (e) { r = { proto: '?', src: '', dst: '', info: 'Could not decode: ' + e.message, protos: [], malformed: true }; }
      const src = opts.names ? (this.name(r.src) || r.src) : r.src, dst = opts.names ? (this.name(r.dst) || r.dst) : r.dst;
      out.push({ k, no: i + 1, time: this.timeText(i, opts.time || 'relative', prev), src, dst, srcAddr: r.src, dstAddr: r.dst, proto: r.proto, len: this.idx.orig[i], info: r.info.slice(0, 400), cls: rowClass(r) });
    }
    return { start, rows: out, total: n };
  }

  packet(no) {
    const i = no - 1;
    if (!this.idx || i < 0 || i >= this.idx.n) return { error: `There is no packet ${no}.` };
    const b = this.bytes(i);
    const r = this.dissectAt(i, true);
    const names = [];
    for (const a of [r.src, r.dst]) { const e = this.names.get(a); if (e) names.push({ addr: a, name: e.name, from: e.from }); }
    return { no, bytes: new Uint8Array(b), tree: r.tree, proto: r.proto, info: r.info, l4: r.l4 ? { proto: r.l4.proto } : null, names, orig: this.idx.orig[i] };
  }

  /** Run a display filter over every packet. Cancels an older filter job. */
  async filter(expr, jobId) {
    const c = compile(expr);
    if (!c.ok) return { ok: false, error: c.error, at: c.at };
    this.filterJob = jobId;
    if (/\.stream\b/.test(expr)) await this.analyze();
    if (this.filterJob !== jobId) return { ok: false, cancelled: true };
    if (c.empty) { this.view = null; return { ok: true, count: this.idx.n, total: this.idx.n }; }
    const n = this.idx.n, hits = [];
    const t0 = Date.now(); let last = 0;
    for (let i = 0; i < n; i++) {
      let r;
      try { r = this.dissectAt(i, false); } catch { continue; }
      if (c.test(r.f)) hits.push(i);
      if ((i & 4095) === 4095) {
        const now = Date.now();
        if (now - last > 200) { last = now; this.post({ type: 'progress', phase: 'filter', done: i, total: n, matches: hits.length }); }
        await tick();
        if (this.filterJob !== jobId) return { ok: false, cancelled: true };
      }
    }
    this.view = Uint32Array.from(hits);
    return { ok: true, count: hits.length, total: n, ms: Date.now() - t0 };
  }

  /** Position of packet `no` in the current view, or -1. */
  find(no) {
    if (!this.view) return no - 1 < this.viewCount() ? no - 1 : -1;
    let lo = 0, hi = this.view.length - 1; const i = no - 1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (this.view[m] === i) return m; if (this.view[m] < i) lo = m + 1; else hi = m - 1; }
    return -1;
  }

  /** One pass over all packets: protocol hierarchy, conversations, endpoints and stream numbers. */
  analyze() {
    if (this.analysis) return Promise.resolve(this.analysis);
    if (!this.analysisPromise) this.analysisPromise = this._analyze().then(a => { this.analysis = a; return a; });
    return this.analysisPromise;
  }

  async _analyze() {
    const n = this.idx.n;
    const stream = new Int32Array(n).fill(-1);
    const streams = new Map(), convs = new Map(), eps = new Map(), hier = new Map();
    let nextStream = { tcp: 0, udp: 0 };
    const ep = (k, kind, bytes, tx) => {
      let e = eps.get(kind + ' ' + k);
      if (!e) { if (eps.size > 300000) return; e = { kind, addr: k, packets: 0, bytes: 0, txp: 0, txb: 0, rxp: 0, rxb: 0 }; eps.set(kind + ' ' + k, e); }
      e.packets++; e.bytes += bytes; if (tx) { e.txp++; e.txb += bytes; } else { e.rxp++; e.rxb += bytes; }
    };
    const conv = (kind, a, b, bytes, t, extra) => {
      const fwd = a <= b, key = kind + ' ' + (fwd ? a + ' ' + b : b + ' ' + a);
      let c = convs.get(key);
      if (!c) { if (convs.size > 300000) return null; c = { kind, a: fwd ? a : b, b: fwd ? b : a, packets: 0, bytes: 0, abp: 0, abb: 0, bap: 0, bab: 0, start: t, end: t, ...extra }; convs.set(key, c); }
      c.packets++; c.bytes += bytes; c.end = t; if (fwd) { c.abp++; c.abb += bytes; } else { c.bap++; c.bab += bytes; }
      return c;
    };
    let last = 0;
    for (let i = 0; i < n; i++) {
      let r;
      try { r = dissect(this.bytes(i), this.lt(i), { tree: false, orig: this.idx.orig[i] }); } catch { continue; }
      const len = this.idx.orig[i], t = this.relSec(i);
      const path = r.protos.filter(p => p !== 'frame' && p !== 'raw' && p !== 'null').join('/');
      const h = hier.get(path) || { packets: 0, bytes: 0 }; h.packets++; h.bytes += len; hier.set(path, h);
      const f = r.f;
      if (f['eth.src'] !== undefined) { const s = [].concat(f['eth.src'])[0], d = [].concat(f['eth.dst'])[0]; conv('Ethernet', s, d, len, t); ep(s, 'Ethernet', len, true); ep(d, 'Ethernet', len, false); }
      const v4 = f['ip.src'] !== undefined, v6 = f['ipv6.src'] !== undefined;
      if (v4 || v6) {
        const s = [].concat(v4 ? f['ip.src'] : f['ipv6.src'])[0], d = [].concat(v4 ? f['ip.dst'] : f['ipv6.dst'])[0];
        const kind = v4 ? 'IPv4' : 'IPv6';
        conv(kind, s, d, len, t); ep(s, kind, len, true); ep(d, kind, len, false);
      }
      if (r.l4) {
        const L = r.l4, a = `${bracket(L.src)}:${L.sp}`, b = `${bracket(L.dst)}:${L.dp}`;
        const key = L.proto + ' ' + (a <= b ? a + ' ' + b : b + ' ' + a);
        let sid = streams.get(key);
        if (sid === undefined) { sid = nextStream[L.proto]++; streams.set(key, sid); }
        stream[i] = sid;
        const c = conv(L.proto.toUpperCase(), a, b, len, t, { stream: sid, first: i + 1 });
        if (c && c.stream === undefined) c.stream = sid;
        ep(a, L.proto.toUpperCase(), len, true); ep(b, L.proto.toUpperCase(), len, false);
      }
      if ((i & 4095) === 4095) {
        const now = Date.now(); if (now - last > 250) { last = now; this.post({ type: 'progress', phase: 'stats', done: i, total: n }); }
        await tick();
      }
    }
    return { stream, streams: nextStream, convs, eps, hier };
  }

  async stats() {
    const a = await this.analyze();
    const top = (m, k) => [...m.values()].sort((x, y) => y.bytes - x.bytes).slice(0, k);
    const conv = top(a.convs, 20000), eps = top(a.eps, 20000);
    for (const e of eps) { const ad = e.kind === 'TCP' || e.kind === 'UDP' ? e.addr.replace(/^\[|\]:\d+$|:\d+$/g, '') : e.addr; e.name = e.kind === 'Ethernet' ? '' : this.name(ad) || ''; }
    const hier = [...a.hier.entries()].map(([path, v]) => ({ path, ...v }));
    return { conversations: conv, endpoints: eps, hierarchy: hier, total: this.idx.n, convCount: a.convs.size, epCount: a.eps.size, names: [...this.names.entries()].slice(0, 5000).map(([addr, v]) => ({ addr, ...v })) };
  }

  /** Follow the TCP or UDP stream of packet `no`: the payloads in capture order, by direction. */
  async follow(no, maxBytes = 16 * 1048576) {
    const i0 = no - 1;
    const r0 = this.dissectAt(i0, false);
    if (!r0.l4) return { error: `Packet ${no} is not TCP or UDP, so it has no stream to follow.` };
    const a = await this.analyze();
    const sid = a.stream[i0];
    const L = r0.l4, proto = L.proto;
    const key = proto + ' ' + (() => { const x = `${bracket(L.src)}:${L.sp}`, y = `${bracket(L.dst)}:${L.dp}`; return x <= y ? x + ' ' + y : y + ' ' + x; })();
    const segs = [];
    let total = [0, 0], client = null, truncated = false;
    const nextSeq = [null, null], seen = [0, 0];
    for (let i = 0; i < this.idx.n; i++) {
      if (a.stream[i] !== sid) continue;
      const r = this.dissectAt(i, false);
      if (!r.l4 || r.l4.proto !== proto) continue;
      const l = r.l4, x = `${bracket(l.src)}:${l.sp}`, y = `${bracket(l.dst)}:${l.dp}`;
      if (proto + ' ' + (x <= y ? x + ' ' + y : y + ' ' + x) !== key) continue;
      if (client === null) client = x;
      // The side that sent the first SYN (or the first packet) is the client.
      if (proto === 'tcp' && (l.flags & 0x12) === 0x02) client = x;
      const dir = x === client ? 0 : 1;
      if (l.len <= 0) { if (proto === 'tcp' && (l.flags & 3)) nextSeq[dir] = (l.seq + 1) >>> 0; continue; }
      let off = l.off, len = l.len;
      if (proto === 'tcp' && nextSeq[dir] !== null) {
        const diff = ((nextSeq[dir] - l.seq) | 0);
        if (diff >= len) continue;               // a retransmission of data we already have
        if (diff > 0) { off += diff; len -= diff; } // partly new
      }
      if (proto === 'tcp') nextSeq[dir] = (l.seq + l.len) >>> 0;
      seen[dir]++;
      if (total[0] + total[1] + len > maxBytes) { truncated = true; break; }
      const b = this.bytes(i);
      const prev = segs[segs.length - 1];
      const chunk = new Uint8Array(b.subarray(off, off + len));
      if (prev && prev.dir === dir && prev.nos.length < 1000) { prev.parts.push(chunk); prev.nos.push(i + 1); }
      else segs.push({ dir, parts: [chunk], nos: [i + 1] });
      total[dir] += len;
    }
    const out = segs.map(s => { const n = s.parts.reduce((t, p) => t + p.length, 0); const u = new Uint8Array(n); let o = 0; for (const p of s.parts) { u.set(p, o); o += p.length; } return { dir: s.dir, bytes: u, first: s.nos[0], last: s.nos[s.nos.length - 1] }; });
    const filter = proto === 'tcp' || proto === 'udp' ? `${proto}.stream == ${sid}` : '';
    const other = client === `${bracket(L.src)}:${L.sp}` ? `${bracket(L.dst)}:${L.dp}` : `${bracket(L.src)}:${L.sp}`;
    return { proto, stream: sid, client: client || '', server: other, segments: out, bytes: total, truncated, filter };
  }

  exportTo(path, which) {
    let list;
    if (which === 'view') list = this.view ? Array.from(this.view) : Array.from({ length: this.idx.n }, (_, i) => i);
    else list = which.map(no => no - 1).filter(i => i >= 0 && i < this.idx.n).sort((a, b) => a - b);
    const fd = fs.openSync(path, 'w');
    let bytes = 0;
    try {
      const r = buildExport(this.src, this.idx, this.ifs, list, b => { fs.writeSync(fd, b); bytes += b.length; });
      return { ok: true, count: list.length, bytes, format: r.format };
    } finally { fs.closeSync(fd); }
  }
}

function bracket(a) { return a && a.includes(':') ? `[${a}]` : a; }

function rowClass(r) {
  if (r.malformed) return 'bad';
  const p = r.protos;
  if (p.includes('tcp') && (r.f['tcp.flags.reset'] === 1)) return 'rst';
  if (p.includes('tcp') && (r.f['tcp.flags.syn'] === 1 || r.f['tcp.flags.fin'] === 1)) return 'syn';
  if (p.includes('http')) return 'http';
  if (p.includes('tls') || p.includes('quic')) return 'tls';
  if (p.includes('dns') || p.includes('mdns')) return 'dns';
  if (p.includes('dhcp')) return 'dhcp';
  if (p.includes('arp')) return 'arp';
  if (p.includes('icmp') || p.includes('icmpv6')) return 'icmp';
  if (p.includes('udp')) return 'udp';
  if (p.includes('tcp')) return 'tcp';
  return '';
}

function gzErr(e) {
  const m = (e && e.message) || String(e);
  if (/incorrect header check|unknown compression/i.test(m)) return `The file ends in .gz but is not gzip data (${m}).`;
  if (/unexpected end/i.test(m)) return `The .gz file is cut off before any packet could be read (${m}).`;
  if (e && e.code === 'EACCES') return 'You do not have permission to read this file. (EACCES)';
  return m;
}

module.exports = { Engine, maybeDns, rowClass };
