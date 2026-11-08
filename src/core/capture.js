'use strict';
// Reads pcap and pcapng captures (also gzip-compressed) and builds a packet index: where each packet's bytes
// are, their lengths, the time and the interface. Pure Node; no native code and no network.
// Every length in the file is checked against the file size and a per-packet limit, so a damaged or hostile
// file ends with a clear warning instead of a loop, a hang or a huge allocation.
const fs = require('fs');
const zlib = require('zlib');

const MAX_CAPLEN = 262144;          // the largest packet libpcap and Wireshark write (256 KB)
const MAX_BLOCK = 16 * 1048576;     // the largest pcapng block we accept (16 MB)
const CHUNK = 4 * 1048576;          // read size for local files
const ZERO_RUN = 64;                // this many all-zero pcap records in a row = the rest is padding, not packets
const BOMB_MIN_OUT = 64 * 1048576;  // past this much unpacked data ...
const BOMB_RATIO = 200;             // ... a .gz that unpacks at more than 200 times its packed size is a gzip bomb

/** Random access to the capture bytes: a local file (read in ranges) or chunks in memory (gzip). */
class FileSource {
  constructor(path) { this.fd = fs.openSync(path, 'r'); this.size = fs.fstatSync(this.fd).size; }
  read(off, len) {
    len = Math.max(0, Math.min(len, this.size - off));
    const b = Buffer.allocUnsafe(len);
    let got = 0;
    while (got < len) { const n = fs.readSync(this.fd, b, got, len - got, off + got); if (n <= 0) break; got += n; }
    return got < len ? b.subarray(0, got) : b;
  }
  close() { try { fs.closeSync(this.fd); } catch {} }
}

class ChunkSource {
  constructor(chunks) {
    this.chunks = chunks; this.starts = []; let s = 0;
    for (const c of chunks) { this.starts.push(s); s += c.length; }
    this.size = s;
  }
  read(off, len) {
    len = Math.max(0, Math.min(len, this.size - off));
    if (len === 0) return Buffer.alloc(0);
    let lo = 0, hi = this.chunks.length - 1;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (this.starts[m] <= off) lo = m; else hi = m - 1; }
    const c = this.chunks[lo], at = off - this.starts[lo];
    if (at + len <= c.length) return c.subarray(at, at + len);
    const out = Buffer.allocUnsafe(len); let got = 0, i = lo, p = at;
    while (got < len && i < this.chunks.length) {
      const n = Math.min(len - got, this.chunks[i].length - p);
      this.chunks[i].copy(out, got, p, p + n); got += n; i++; p = 0;
    }
    return out;
  }
  /** Drop the bytes after `end` (after the last packet), so a gzip bomb or trailing junk does not stay in memory. */
  trim(end) {
    if (end >= this.size) return;
    const keep = []; let s = 0;
    for (const c of this.chunks) { if (s >= end) break; keep.push(s + c.length > end ? Buffer.from(c.subarray(0, end - s)) : c); s += c.length; }
    this.chunks = keep; this.starts = []; let t = 0; for (const c of keep) { this.starts.push(t); t += c.length; }
    this.size = t;
  }
  close() { this.chunks = []; }
}

/** Decompress a .gz file in a stream, stopping at capBytes. Resolves { source, capped, compressed }. */
function gunzipToSource(path, capBytes, onProgress) {
  return new Promise((resolve, reject) => {
    const chunks = []; let total = 0, capped = false, done = false, readBytes = 0, bomb = 0;
    const compressed = fs.statSync(path).size;
    const input = fs.createReadStream(path, { highWaterMark: 1048576 });
    const gz = zlib.createGunzip({ chunkSize: 1048576 });
    input.on('data', d => { readBytes += d.length; });
    const finish = err => {
      if (done) return; done = true;
      input.destroy(); gz.destroy();
      if (err && !total) { reject(err); return; }
      resolve({ source: new ChunkSource(chunks), capped, bomb, compressed, gzError: err ? String(err.message || err) : '' });
    };
    gz.on('data', d => {
      if (done) return;
      if (total + d.length > capBytes) { chunks.push(Buffer.from(d.subarray(0, capBytes - total))); total = capBytes; capped = true; finish(); return; }
      chunks.push(Buffer.from(d)); total += d.length;
      // Real captures unpack at a few times their size; 200 times and more is a gzip bomb, so stop early.
      if (total > BOMB_MIN_OUT && gz.bytesWritten > 0 && total / gz.bytesWritten > BOMB_RATIO) { capped = true; bomb = Math.round(total / gz.bytesWritten); finish(); return; }
      if (onProgress) onProgress(total, readBytes, compressed);
    });
    gz.on('end', () => finish());
    gz.on('error', e => finish(e));
    input.on('error', e => finish(e));
    input.pipe(gz);
  });
}

function isGzip(head) { return head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b; }

/** Growable typed arrays for the packet index. */
class Index {
  constructor() { this.n = 0; this.cap = 0; this.grow(1024); this.comments = new Map(); this.noTs = new Set(); }
  grow(c) {
    const cp = (T, old) => { const a = new T(c); if (old) a.set(old.subarray(0, this.n)); return a; };
    this.off = cp(Float64Array, this.off); this.len = cp(Uint32Array, this.len); this.orig = cp(Uint32Array, this.orig);
    this.sec = cp(Float64Array, this.sec); this.ns = cp(Uint32Array, this.ns); this.ifc = cp(Uint16Array, this.ifc);
    this.cap = c;
  }
  push(off, len, orig, sec, ns, ifc) {
    if (this.n === this.cap) this.grow(this.cap * 2);
    const i = this.n++;
    this.off[i] = off; this.len[i] = len; this.orig[i] = orig; this.sec[i] = sec; this.ns[i] = ns; this.ifc[i] = ifc;
    return i;
  }
  trim() { if (this.cap > this.n + 1024) this.grow(this.n + 1); }
}

/** A sliding read window over a source so a 1 GB file is never in memory at once. */
class Window {
  constructor(src) { this.src = src; this.buf = Buffer.alloc(0); this.base = 0; }
  /** Returns the buffer and the position of `pos` in it, with at least `len` bytes (or fewer at the end of file). */
  get(pos, len) {
    if (pos < this.base || pos + len > this.base + this.buf.length) {
      this.buf = this.src.read(pos, Math.max(CHUNK, len)); this.base = pos;
    }
    return pos - this.base;
  }
}

function hex(n) { return '0x' + n.toString(16).toUpperCase(); }
function fmt(n) { return n.toLocaleString('en-US'); }
function pk(n) { return `${fmt(n)} packet${n === 1 ? '' : 's'}`; }

/** Split a 64-bit timestamp (hi, lo) in units of 1/10^d or 1/2^b seconds into seconds and nanoseconds. */
function splitTs(hi, lo, res) {
  if (res.dec !== undefined && res.dec <= 6) {
    const v = hi * 4294967296 + lo, div = 10 ** res.dec;
    const sec = Math.floor(v / div);
    return [sec, Math.round((v - sec * div) * (10 ** (9 - res.dec)))];
  }
  const v = (BigInt(hi) << 32n) | BigInt(lo);
  if (res.dec !== undefined) {
    const div = 10n ** BigInt(res.dec);
    const sec = v / div, frac = v % div;
    const ns = res.dec >= 9 ? frac / (10n ** BigInt(res.dec - 9)) : frac * (10n ** BigInt(9 - res.dec));
    return [Number(sec), Number(ns)];
  }
  const b = BigInt(res.bin), sec = v >> b, frac = v & ((1n << b) - 1n);
  return [Number(sec), Number((frac * 1000000000n) >> b)];
}

function tsResol(byte) { return (byte & 0x80) ? { bin: byte & 0x7f } : { dec: byte }; }

/**
 * Build the packet index. Calls onPacket(i, buf, at, len, linktype) for every packet (for name harvesting)
 * and onProgress(pos, size) now and then. Returns { format, index, interfaces, names, warnings, error }.
 */
async function indexCapture(src, opts = {}) {
  const onPacket = opts.onPacket || null, onProgress = opts.onProgress || null, yieldEvery = opts.yieldEvery || 0;
  const res = { format: '', index: new Index(), interfaces: [], names: [], warnings: [], error: '', section: {} };
  const size = src.size;
  if (size === 0) { res.error = 'The file is empty (0 bytes), so there are no packets to show.'; return res; }
  const head = src.read(0, Math.min(size, 64));
  if (head.length < 4) { res.error = `The file has only ${head.length} bytes. A capture file starts with a header of at least 24 bytes.`; return res; }
  const m = head.readUInt32LE(0);
  const PCAP = { 0xa1b2c3d4: [true, false], 0xd4c3b2a1: [false, false], 0xa1b23c4d: [true, true], 0x4d3cb2a1: [false, true] };
  if (m === 0x0a0d0d0a) return indexPcapng(src, res, onPacket, onProgress, yieldEvery);
  if (PCAP[m]) return indexPcap(src, res, PCAP[m][0], PCAP[m][1], onPacket, onProgress, yieldEvery);
  if (isGzip(head)) { res.error = 'This file is gzip-compressed. Rename it to end in .gz (for example capture.pcap.gz) to open it.'; return res; }
  res.error = `This is not a pcap or pcapng capture: the first 4 bytes are ${[...head.subarray(0, 4)].map(b => b.toString(16).padStart(2, '0')).join(' ')}. `
    + 'A pcap file starts with d4 c3 b2 a1 (or a1 b2 c3 d4, 4d 3c b2 a1, a1 b2 3c 4d) and a pcapng file with 0a 0d 0d 0a.';
  return res;
}

async function maybeYield(count, every, onProgress, pos, size) {
  if (every && count % every === 0) {
    if (onProgress) onProgress(pos, size);
    await new Promise(r => setImmediate(r));
  }
}

async function indexPcap(src, res, le, nano, onPacket, onProgress, yieldEvery) {
  const size = src.size;
  res.format = nano ? 'pcap (nanosecond)' : 'pcap';
  if (size < 24) { res.error = `The pcap header is cut off: the file has ${size} bytes and the header needs 24.`; return res; }
  const h = src.read(0, 24);
  const u16 = (b, o) => le ? b.readUInt16LE(o) : b.readUInt16BE(o);
  const u32 = (b, o) => le ? b.readUInt32LE(o) : b.readUInt32BE(o);
  const linkRaw = u32(h, 20), snap = u32(h, 16);
  const linktype = linkRaw & 0x0fffffff;
  res.section = { version: `${u16(h, 4)}.${u16(h, 6)}`, byteOrder: le ? 'little-endian' : 'big-endian', snaplen: snap, resolution: nano ? 'nanoseconds' : 'microseconds' };
  res.interfaces.push({ linktype, name: '', snaplen: snap, res: nano ? { dec: 9 } : { dec: 6 } });
  const limit = Math.max(MAX_CAPLEN, Math.min(snap, 16 * 1048576));
  const win = new Window(src);
  let pos = 24, zeros = 0, count = 0;
  const idx = res.index;
  while (pos < size) {
    if (pos + 16 > size) { res.warnings.push(`The file ends inside the header of packet ${fmt(idx.n + 1)} (${size - pos} of 16 bytes at offset ${hex(pos)}). The capture was probably cut off while it was written.`); break; }
    let at = win.get(pos, 16);
    const b = win.buf;
    const sec = u32(b, at), frac = u32(b, at + 4), caplen = u32(b, at + 8), orig = u32(b, at + 12);
    if (sec === 0 && frac === 0 && caplen === 0 && orig === 0) {
      if (++zeros >= ZERO_RUN) {
        // Drop the zero records we already counted; they were padding.
        idx.n = Math.max(0, idx.n - (ZERO_RUN - 1));
        res.warnings.push(`From offset ${hex(pos - (ZERO_RUN - 1) * 16)} on, the file holds only zero bytes, not packets. Reading stopped there.`);
        break;
      }
    } else zeros = 0;
    if (caplen > limit) {
      res.warnings.push(`Packet ${fmt(idx.n + 1)} at offset ${hex(pos)} says it has ${fmt(caplen)} bytes, more than the ${fmt(limit)}-byte limit for one packet. The file is damaged from here, so reading stopped. ${pk(idx.n)} before it ${idx.n === 1 ? 'is' : 'are'} shown.`);
      break;
    }
    if (pos + 16 + caplen > size) {
      res.warnings.push(`Packet ${fmt(idx.n + 1)} says it has ${fmt(caplen)} bytes, but the file ends ${fmt(size - pos - 16)} bytes after its header. The capture was cut off; the packets before it are shown.`);
      break;
    }
    const ns = nano ? frac : frac * 1000;
    const i = idx.push(pos + 16, caplen, orig, sec + Math.floor(ns / 1e9), ns % 1e9, 0);
    if (onPacket && caplen) { at = win.get(pos + 16, caplen); onPacket(i, win.buf, at, caplen, linktype); }
    pos += 16 + caplen; count++;
    if (yieldEvery) await maybeYield(count, yieldEvery, onProgress, pos, size);
  }
  idx.trim();
  return res;
}

function readOptions(b, at, end, le) {
  const out = [];
  while (at + 4 <= end) {
    const code = le ? b.readUInt16LE(at) : b.readUInt16BE(at), len = le ? b.readUInt16LE(at + 2) : b.readUInt16BE(at + 2);
    if (code === 0) break;
    if (at + 4 + len > end) break;
    out.push([code, b.subarray(at + 4, at + 4 + len)]);
    at += 4 + ((len + 3) & ~3);
  }
  return out;
}

function optString(v) { return Buffer.from(v).toString('utf8').replace(/\0+$/, ''); }

async function indexPcapng(src, res, onPacket, onProgress, yieldEvery) {
  const size = src.size;
  res.format = 'pcapng';
  const win = new Window(src);
  const idx = res.index;
  let pos = 0, le = true, sectionIfs = [], count = 0, sections = 0;
  while (pos < size) {
    if (pos + 12 > size) { res.warnings.push(`The file ends inside a block header at offset ${hex(pos)} (${size - pos} bytes left). The capture was probably cut off.`); break; }
    let at = win.get(pos, 12);
    let b = win.buf;
    const typeLE = b.readUInt32LE(at);
    if (typeLE === 0x0a0d0d0a) {
      const bom = b.readUInt32LE(at + 8);
      if (bom === 0x1a2b3c4d) le = true; else if (bom === 0x4d3c2b1a) le = false;
      else { res.warnings.push(`Section header at offset ${hex(pos)} has an unknown byte-order mark ${hex(bom)}. Reading stopped.`); break; }
    } else if (pos === 0) { res.error = 'This pcapng file does not start with a section header block.'; return res; }
    const type = le ? b.readUInt32LE(at) : b.readUInt32BE(at);
    const blen = le ? b.readUInt32LE(at + 4) : b.readUInt32BE(at + 4);
    if (blen < 12 || blen % 4 !== 0) {
      res.warnings.push(`The block at offset ${hex(pos)} has a length of ${fmt(blen)} bytes, which is not possible (at least 12 and a multiple of 4). The file is damaged here, so reading stopped. ${pk(idx.n)} before it ${idx.n === 1 ? 'is' : 'are'} shown.`);
      break;
    }
    if (blen > MAX_BLOCK) {
      res.warnings.push(`The block at offset ${hex(pos)} says it is ${fmt(blen)} bytes, more than the 16 MB limit for one block. The file is damaged here, so reading stopped. ${pk(idx.n)} before it ${idx.n === 1 ? 'is' : 'are'} shown.`);
      break;
    }
    if (pos + blen > size) {
      res.warnings.push(`The block at offset ${hex(pos)} says it is ${fmt(blen)} bytes, but only ${fmt(size - pos)} bytes are left in the file. The capture was cut off or damaged; ${pk(idx.n)} before it ${idx.n === 1 ? 'is' : 'are'} shown.`);
      break;
    }
    at = win.get(pos, blen); b = win.buf;
    const u16 = o => le ? b.readUInt16LE(at + o) : b.readUInt16BE(at + o);
    const u32 = o => le ? b.readUInt32LE(at + o) : b.readUInt32BE(at + o);
    const tail = u32(blen - 4);
    if (tail !== blen) res.warnings.length < 20 && res.warnings.push(`The block at offset ${hex(pos)} has different lengths at its start (${fmt(blen)}) and end (${fmt(tail)}). It was read with the first one.`);
    if (type === 0x0a0d0d0a) {
      sections++; sectionIfs = [];
      if (sections === 1 && blen >= 28) {
        const o = readOptions(b, at + 24, at + blen - 4, le), sec = { version: `${u16(12)}.${u16(14)}`, byteOrder: le ? 'little-endian' : 'big-endian' };
        for (const [c, v] of o) { if (c === 2) sec.hardware = optString(v); if (c === 3) sec.os = optString(v); if (c === 4) sec.application = optString(v); if (c === 1) sec.comment = optString(v); }
        res.section = sec;
      }
    } else if (type === 1) {
      if (blen < 20) { res.warnings.push(`Interface block at offset ${hex(pos)} is too short.`); }
      else {
        const iface = { linktype: u16(8), snaplen: u32(12), name: '', res: { dec: 6 }, tsoffset: 0, description: '' };
        for (const [c, v] of readOptions(b, at + 16, at + blen - 4, le)) {
          if (c === 2) iface.name = optString(v);
          if (c === 3) iface.description = optString(v);
          if (c === 9 && v.length >= 1) iface.res = tsResol(v[0]);
          if (c === 14 && v.length >= 8) iface.tsoffset = Number(le ? v.readBigInt64LE(0) : v.readBigInt64BE(0));
        }
        if (res.interfaces.length >= 65535) { res.warnings.push('The file has more than 65,535 interfaces. Reading stopped.'); break; }
        res.interfaces.push(iface); sectionIfs.push(res.interfaces.length - 1);
      }
    } else if (type === 6 || type === 2) {
      // Enhanced packet block (6) and the old packet block (2).
      const ifId = type === 6 ? u32(8) : u16(8);
      const caplen = u32(20), orig = u32(24);
      const g = sectionIfs[ifId];
      if (g === undefined) {
        if (res.warnings.length < 20) res.warnings.push(`Packet block at offset ${hex(pos)} names interface ${ifId}, which the file does not describe. The packet was skipped.`);
      } else if (28 + caplen > blen - 4) {
        if (res.warnings.length < 20) res.warnings.push(`Packet block at offset ${hex(pos)} says its packet has ${fmt(caplen)} bytes, more than the block holds. The packet was skipped.`);
      } else {
        const iface = res.interfaces[g];
        const [sec, ns] = splitTs(u32(12), u32(16), iface.res);
        const i = idx.push(pos + 28, caplen, orig, sec + iface.tsoffset, ns, g);
        const optAt = at + 28 + ((caplen + 3) & ~3);
        if (optAt + 4 <= at + blen - 4) for (const [c, v] of readOptions(b, optAt, at + blen - 4, le)) if (c === 1) idx.comments.set(i, optString(v).slice(0, 4000));
        if (onPacket && caplen) onPacket(i, b, at + 28, caplen, iface.linktype);
        count++;
      }
    } else if (type === 3) {
      // Simple packet block: interface 0, no time stamp.
      const g = sectionIfs[0];
      if (g !== undefined) {
        const orig = u32(8), snap = res.interfaces[g].snaplen || 0;
        const caplen = Math.min(orig, blen - 16, snap > 0 ? snap : orig);
        const i = idx.push(pos + 12, caplen, orig, 0, 0, g);
        idx.noTs.add(i);
        if (onPacket && caplen) onPacket(i, b, at + 12, caplen, res.interfaces[g].linktype);
        count++;
      }
    } else if (type === 4) {
      // Name resolution block: IPv4 and IPv6 names the capture tool resolved when it ran.
      let o = at + 8; const end = at + blen - 4;
      while (o + 4 <= end) {
        const rt = le ? b.readUInt16LE(o) : b.readUInt16BE(o), rl = le ? b.readUInt16LE(o + 2) : b.readUInt16BE(o + 2);
        if (rt === 0 || o + 4 + rl > end) break;
        const v = b.subarray(o + 4, o + 4 + rl);
        if (rt === 1 && rl > 4) { const addr = [...v.subarray(0, 4)].join('.'); for (const n of optString(v.subarray(4)).split('\0').filter(Boolean)) res.names.push([addr, n, 'NRB']); }
        if (rt === 2 && rl > 16) { const addr = ipv6Str(v, 0); for (const n of optString(v.subarray(16)).split('\0').filter(Boolean)) res.names.push([addr, n, 'NRB']); }
        o += 4 + ((rl + 3) & ~3);
      }
    }
    // Other blocks (statistics, decryption secrets, custom, unknown) are skipped by their length.
    pos += blen;
    if (yieldEvery) await maybeYield(++count, yieldEvery, onProgress, pos, size);
  }
  idx.trim();
  return res;
}

function ipv6Str(b, o) {
  const w = []; for (let i = 0; i < 8; i++) w.push(((b[o + 2 * i] << 8) | b[o + 2 * i + 1]).toString(16));
  // collapse the longest run of zero words
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) { if (w[i] === '0') { let j = i; while (j < 8 && w[j] === '0') j++; if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; } i = j; } else i++; }
  if (best < 0) return w.join(':');
  return w.slice(0, best).join(':') + '::' + w.slice(best + bestLen).join(':');
}

/** Write packets as a classic pcap file (one link type) or pcapng (several). */
function buildExport(src, idx, interfaces, list, write) {
  const lts = new Set(); for (const i of list) lts.add(interfaces[idx.ifc[i]].linktype);
  const parts = { push(...b) { for (const x of b) write(x); } };
  if (lts.size <= 1) {
    const lt = lts.size ? [...lts][0] : 1;
    const h = Buffer.alloc(24);
    h.writeUInt32LE(0xa1b23c4d, 0); h.writeUInt16LE(2, 4); h.writeUInt16LE(4, 6); h.writeUInt32LE(MAX_CAPLEN, 16); h.writeUInt32LE(lt, 20);
    parts.push(h);
    for (const i of list) {
      const r = Buffer.alloc(16);
      r.writeUInt32LE(idx.sec[i] >>> 0, 0); r.writeUInt32LE(idx.ns[i], 4); r.writeUInt32LE(idx.len[i], 8); r.writeUInt32LE(idx.orig[i], 12);
      parts.push(r, Buffer.from(src.read(idx.off[i], idx.len[i])));
    }
    return { format: 'pcap', linktypes: [...lts] };
  }
  const shb = Buffer.alloc(28);
  shb.writeUInt32LE(0x0a0d0d0a, 0); shb.writeUInt32LE(28, 4); shb.writeUInt32LE(0x1a2b3c4d, 8); shb.writeUInt16LE(1, 12); shb.writeUInt16LE(0, 14);
  shb.writeInt32LE(-1, 16); shb.writeInt32LE(-1, 20); shb.writeUInt32LE(28, 24);
  parts.push(shb);
  const map = new Map();
  for (const lt of lts) {
    const idb = Buffer.alloc(32);
    idb.writeUInt32LE(1, 0); idb.writeUInt32LE(32, 4); idb.writeUInt16LE(lt, 8); idb.writeUInt32LE(MAX_CAPLEN, 12);
    idb.writeUInt16LE(9, 16); idb.writeUInt16LE(1, 18); idb.writeUInt8(9, 20); idb.writeUInt32LE(32, 28);
    map.set(lt, map.size); parts.push(idb);
  }
  for (const i of list) {
    const len = idx.len[i], pad = (4 - (len % 4)) % 4, blen = 32 + len + pad;
    const h = Buffer.alloc(28);
    const t = BigInt(Math.floor(idx.sec[i])) * 1000000000n + BigInt(idx.ns[i]);
    h.writeUInt32LE(6, 0); h.writeUInt32LE(blen, 4); h.writeUInt32LE(map.get(interfaces[idx.ifc[i]].linktype), 8);
    h.writeUInt32LE(Number(t >> 32n), 12); h.writeUInt32LE(Number(t & 0xffffffffn), 16); h.writeUInt32LE(len, 20); h.writeUInt32LE(idx.orig[i], 24);
    const tail = Buffer.alloc(pad + 4); tail.writeUInt32LE(blen, pad);
    parts.push(h, Buffer.from(src.read(idx.off[i], len)), tail);
  }
  return { format: 'pcapng', linktypes: [...lts] };
}

module.exports = { FileSource, ChunkSource, gunzipToSource, isGzip, indexCapture, splitTs, ipv6Str, buildExport, MAX_CAPLEN, Index };
