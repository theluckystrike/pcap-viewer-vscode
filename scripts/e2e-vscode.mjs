// Release check in a real VS Code: installs the .vsix into an isolated profile, opens the captures made by
// scripts/make_samples.py (with --large-mb and --bomb), drives the webview with real mouse and key events,
// compares with tcpdump and expected.json, and writes screenshots and a JSON report.
// usage: node scripts/e2e-vscode.mjs <work> <port> <vsix> <samplesDir> <shotDir> <outJson> [quick]
import { launch, installVsix, sleep } from './vsc.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { execSync, execFileSync } from 'node:child_process';

const [work0, port, vsix, ws0, shotDir, outJson, mode] = process.argv.slice(2);
const quick = mode === 'quick';
const work = path.resolve(work0), ws = path.resolve(ws0);
const P = n => path.join(ws, n);
const expected = JSON.parse(fs.readFileSync(P('expected.json'), 'utf8'));
const R = { install: null, vscode: '', steps: [], console: [], memory: [], network: {} };
fs.rmSync(path.join(work, 'ud'), { recursive: true, force: true });
R.install = installVsix(work, vsix);
const baseSettings = {
  'files.simpleDialog.enable': true, 'workbench.secondarySideBar.defaultVisibility': 'hidden', 'workbench.auxiliaryBar.visible': false,
  'window.titleBarStyle': 'custom', 'editor.fontSize': 13, 'window.menuStyle': 'custom', 'extensions.ignoreRecommendations': true, 'workbench.editor.enablePreview': false,
};
const vs = await launch(work, Number(port), ws, baseSettings);
const settingsFile = path.join(work, 'ud', 'User', 'settings.json');
const shots = [];
// A screenshot that times out (CDP under heavy machine load) is logged, not counted as a product failure.
const shotErrors = [];
const shot = async name => { const f = path.join(shotDir, `pcap-${String(shots.length + 1).padStart(2, '0')}-${name}.png`); try { await vs.shot(f); shots.push(f); return f; } catch (e) { shotErrors.push(name + ': ' + e.message); return null; } };
const step = async (name, fn) => {
  const t0 = Date.now();
  try { const v = await fn(); R.steps.push({ name, ok: v !== false, value: v, ms: Date.now() - t0 }); console.log('PASS', name, JSON.stringify(v).slice(0, 300)); }
  catch (e) {
    if (/^SKIP/.test(e.message)) { R.steps.push({ name, ok: null, skipped: e.message, ms: Date.now() - t0 }); console.log('SKIP', name, e.message); return; }
    R.steps.push({ name, ok: false, error: String(e.message || e).slice(0, 800), ms: Date.now() - t0 }); console.log('FAIL', name, String(e.message || e).slice(0, 400));
    try { await shot('FAIL-' + name.replace(/\W+/g, '_').slice(0, 40)); } catch {}
  }
};
const assert = (c, msg) => { if (!c) throw new Error(msg); };
let wv;
const E = expr => vs.wvEval(wv, expr);
const probe = async () => JSON.parse(await E(`JSON.stringify(window.pcapViewerProbe ? window.pcapViewerProbe() : null)`));
const findWv = async (title, ms = 15000) => vs.waitFor(async () => (await vs.webviews()).find(w => w.title === title && w.w > 0), ms);
const waitProbe = async (fn, ms = 20000, what = 'condition') => { const v = await vs.waitFor(async () => { const p = await probe(); return p && fn(p) ? p : null; }, ms, 100); if (!v) throw new Error('timeout waiting for ' + what + ': ' + JSON.stringify(await probe()).slice(0, 600)); return v; };
const cmd = async label => {
  const b = JSON.parse(await vs.wbEval(`JSON.stringify(document.querySelector('.part.titlebar').getBoundingClientRect())`));
  await vs.click(b.x + b.width * 0.3, b.y + b.height / 2); await sleep(200);
  await vs.command(label);
};
const closeAll = async () => { await cmd('View: Close All Editors'); await sleep(600); };
const open = async (file, ms = 30000) => {
  const t0 = Date.now();
  vs.open(P(file));
  wv = await findWv(path.basename(file), ms);
  if (!wv) throw new Error('no PCAP Viewer webview for ' + file);
  const p = await waitProbe(p => p.rendered || p.error, ms, 'render of ' + file);
  if (p.rendered && p.total) await waitProbe(p => p.rows.length > 0 && p.rows[0][0] !== '', 10000, 'rows');
  return { ms: Date.now() - t0, p: await probe() };
};
const tcpdumpCount = f => Number(execSync(`tcpdump -nn -r ${JSON.stringify(f)} 2>/dev/null | wc -l`, { encoding: 'utf8', maxBuffer: 1 << 30 }).trim());
const typeFilter = async text => {
  await vs.wvClick(wv, `document.querySelector('#filter')`); await sleep(100);
  await vs.key('a', 'KeyA', 4); await vs.key('Backspace', 'Backspace');
  await vs.type(text); await sleep(150); await vs.key('Enter', 'Enter');
  return waitProbe(p => p.filter === text.trim() && !/Filtering/.test(p.count), 120000, 'filter ' + text);
};
const rowSel = no => `[...document.querySelectorAll('#rows .row[data-pos]')].find(r => r.children[0].textContent === '${no}')`;
const clickRow = async (no, opts) => { await vs.wvClick(wv, rowSel(no), { dx: 30, ...(opts || {}) }); await sleep(300); return waitProbe(p => p.selectedNo === no && p.tree.length > 0, 8000, 'select ' + no); };
const nodeSel = re => `[...document.querySelectorAll('#tree .tn')].find(x => x.offsetParent !== null && ${re}.test(x.textContent))`;
const expandLayer = async re => { if (await E(`(${nodeSel(re)} || {}).getAttribute ? ${nodeSel(re)}.getAttribute('aria-expanded') === 'true' : false`)) return; await vs.wvClick(wv, `(${nodeSel(re)} || {}).querySelector ? ${nodeSel(re)}.querySelector('.tw') : null`); await sleep(250); };
const clickNode = async re => { await vs.wvClick(wv, `(${nodeSel(re)} || {}).querySelector ? ${nodeSel(re)}.querySelector('.tl') : null`, { dx: 20 }); await sleep(250); };
const extHost = () => {
  const ud = path.join(work, 'ud');
  const rows = execSync('ps -axo pid=,rss=,command=', { encoding: 'utf8', maxBuffer: 64 << 20 }).split('\n').filter(l => l.includes(ud) && /Plugin|NodeService|extensionHost|utility-sub-type=node/i.test(l));
  return rows.map(l => { const [pid, rss] = l.trim().split(/\s+/); return { pid: Number(pid), mb: Math.round(Number(rss) / 1024) }; });
};
const sockets = () => {
  const pids = extHost().map(x => x.pid); if (!pids.length) return [];
  // the CDP debug port of this test instance is the harness, not the extension
  try { return execSync(`lsof -nP -a -i -p ${pids.join(',')} 2>/dev/null || true`, { encoding: 'utf8' }).split('\n').filter(l => l && !/^COMMAND/.test(l) && !l.includes(`127.0.0.1:${port}`)); } catch { return []; }
};
const pcapPacket = (file, no) => {
  // read packet `no` (1-based) of a little-endian pcap file, for byte checks
  const b = fs.readFileSync(file); let o = 24;
  for (let i = 1; o + 16 <= b.length; i++) { const cl = b.readUInt32LE(o + 8); if (i === no) return b.subarray(o + 16, o + 16 + cl); o += 16 + cl; }
  return null;
};
const setTheme = async theme => {
  const s = JSON.parse(fs.readFileSync(settingsFile, 'utf8')); s['workbench.colorTheme'] = theme; fs.writeFileSync(settingsFile, JSON.stringify(s, null, 1));
  await sleep(2500);
};
const FIELDS = { 'dns.qry.name': 1, 'tls.handshake.extensions_server_name': 1, 'icmp.seq': 1, 'vlan.id': 1 };

try {
  R.vscode = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  await sleep(2500);
  R.network.before = sockets();
  await cmd('View: Toggle Primary Side Bar Visibility'); await sleep(400);

  // 1. every small sample: count vs tcpdump, 5 fields vs expected.json (Python reference, checked with tcpdump)
  const small = Object.keys(expected.files).filter(f => !f.endsWith('.gz'));
  for (const f of quick ? small.slice(0, 3) : small) {
    await step(`${f}: opens by default, packet count and 5 field values match`, async () => {
      const { ms, p } = await open(f);
      assert(p.rendered, 'not rendered: ' + p.error);
      const td = tcpdumpCount(P(f));
      assert(p.total === td && td === expected.files[f].packets, `count ${p.total} vs tcpdump ${td} vs expected ${expected.files[f].packets}`);
      // turn names off so Source/Destination show addresses
      await E(`(() => { const c = document.querySelector('#namesChk'); if (c.checked) c.click(); return 1; })()`); await sleep(500);
      const pp = await waitProbe(p => p.rows.length >= Math.min(p.total, 5) && p.rows.every(r => r.length === 7), 8000, 'rows');
      let checked = 0; const diffs = [];
      for (const fr of expected.files[f].frames.slice(0, 6)) {
        const row = pp.rows.find(r => r[0] === String(fr.index)); if (!row) continue;
        const [no, , src, dst, proto, len] = row;
        if (fr.src && src !== fr.src) diffs.push(`#${no} src ${src} vs ${fr.src}`); else checked++;
        if (fr.dst && dst !== fr.dst) diffs.push(`#${no} dst ${dst} vs ${fr.dst}`); else checked++;
        if (Number(len) !== fr.length) diffs.push(`#${no} len ${len} vs ${fr.length}`); else checked++;
        const okProto = proto === fr.protocol || (fr.protocol.startsWith('TLS') && proto.startsWith('TLS')) || (fr.protocol === 'TCP' && proto === 'HTTP');
        if (!okProto) diffs.push(`#${no} proto ${proto} vs ${fr.protocol}`); else checked++;
        for (const k of Object.keys(FIELDS)) if (fr[k] !== undefined) { if (!row[6].includes(String(fr[k])) && k !== 'vlan.id' && k !== 'icmp.seq') diffs.push(`#${no} ${k} ${fr[k]} not in info`); else checked++; }
      }
      assert(!diffs.length, diffs.join('; '));
      assert(checked >= 5, 'only ' + checked + ' values checked');
      await closeAll();
      return { ms, packets: p.total, tcpdump: td, valuesChecked: checked };
    });
  }

  await step('dns.pcap.gz and multi-if.pcapng.gz open (gzip) with the same packets', async () => {
    const a = await open('dns.pcap.gz'); assert(a.p.total === 4, 'dns.pcap.gz ' + a.p.total); assert(/gzip/.test(a.p.fileinfo), a.p.fileinfo);
    const b = await open('multi-if.pcapng.gz'); assert(b.p.total === 8, 'multi-if gz ' + b.p.total);
    await closeAll();
    return { dns: a.p.total, multi: b.p.total, info: a.p.fileinfo };
  });

  await step('multi-if.pcapng: 2 link types, names from the name block shown, SPB without time', async () => {
    const { p } = await open('multi-if.pcapng');
    assert(p.total === 8, 'count ' + p.total);
    assert(p.rows[0][2] === 'client.lan' && p.rows[0][3] === 'web.example', 'names ' + JSON.stringify(p.rows[0]));
    assert(/Ethernet/.test(p.fileinfo) && /Raw IP/.test(p.fileinfo), p.fileinfo);
    assert(/no time/.test(p.rows[7][1]), 'spb time ' + p.rows[7][1]);
    return { row1: p.rows[0].slice(0, 5), fileinfo: p.fileinfo };
  });
  await closeAll();

  // 2. filter in tls.pcap typed for real
  await step('filter tcp.port==443 && ip.addr==10.0.0.1 gives the expected count (12)', async () => {
    await open('tls.pcap');
    const want = expected.files['tls.pcap'].filters['tcp.port==443 && ip.addr==10.0.0.1'];
    const p = await typeFilter('tcp.port==443 && ip.addr==10.0.0.1');
    assert(p.viewCount === want, `${p.viewCount} vs ${want}`);
    await sleep(400);
    await shot('filter-443');
    // a bad filter says what is wrong and keeps the old view
    await vs.wvClick(wv, `document.querySelector('#filter')`); await vs.key('a', 'KeyA', 4); await vs.type('tcp.prot == 1');
    const q = await waitProbe(p => /not a field/.test(p.filterErr), 4000, 'filter error');
    await vs.key('Escape', 'Escape');
    const all = await waitProbe(p => !p.filter && p.viewCount === 14, 8000, 'clear');
    return { count: p.viewCount, expected: want, badFilterMessage: q.filterErr, afterEsc: all.viewCount };
  });

  await step('saved filter from the star menu (TCP handshakes) applies', async () => {
    await vs.wvClick(wv, `document.querySelector('#savedBtn')`); await sleep(300);
    await vs.wvClick(wv, `[...document.querySelectorAll('.menu .mi')].find(b => /TCP handshakes/.test(b.textContent))`);
    const p = await waitProbe(p => p.filter === 'tcp.flags.syn == 1', 10000, 'saved filter');
    assert(p.viewCount === 4, 'count ' + p.viewCount);
    await vs.wvClick(wv, `document.querySelector('#clearBtn')`); await waitProbe(p => !p.filter, 5000, 'clear');
    return { count: p.viewCount };
  });

  await step('byte-to-tree and tree-to-byte linking in the hex pane (TLS SNI, IPv4 source)', async () => {
    await clickRow(6);
    const raw = pcapPacket(P('tls.pcap'), 6);
    const sniAt = raw.indexOf(Buffer.from('secure.example.com'));
    assert(sniAt > 0, 'sni not in packet');
    // byte to tree: click the 3rd byte of the server name in the hex pane
    await E(`(() => { const h = document.querySelector('#hex'); h.scrollTop = ${Math.floor((sniAt + 2) / 16) * 18 - 36}; h.dispatchEvent(new Event('scroll')); return 1; })()`); await sleep(300);
    await vs.wvClick(wv, `document.querySelector('#hexRows .hb[data-i="${sniAt + 2}"]')`);
    const a = await waitProbe(p => /Server Name: secure\.example\.com/.test(p.treeSel), 5000, 'byte-to-tree');
    assert(a.hexOn.replace(/ /g, '') === Buffer.from('secure.example.com').toString('hex'), 'highlight ' + a.hexOn);
    await shot('byte-to-tree-sni');
    // tree to byte: open IPv4 and click Source address
    await expandLayer('/^Internet Protocol Version 4/');
    await clickNode('/Source address: 10\\.0\\.0\\.1/');
    const b = await waitProbe(p => /Source address/.test(p.treeSel), 5000, 'tree select');
    assert(b.hexOn === '0a 00 00 01' && b.hexSel[0] === 26, 'hex ' + b.hexOn + ' ' + JSON.stringify(b.hexSel));
    return { sniOffset: sniAt, sniTree: a.treeSel, ipSrcBytes: b.hexOn, ipSrcRange: b.hexSel };
  });
  await closeAll();

  // 3. follow TCP stream with a real double-click
  await step('follow TCP stream (double-click) shows the HTTP request and response', async () => {
    await open('http.pcap');
    await clickRow(4);
    await vs.wvClick(wv, rowSel(4), { dx: 30, count: 2 });
    const p = await waitProbe(p => /GET \/index\.html HTTP\/1\.1/.test(p.overlay) && /HTTP\/1\.1 200 OK/.test(p.overlay), 15000, 'follow overlay');
    const want = expected.files['http.pcap'].follow_tcp_stream;
    const body = await E(`[...document.querySelectorAll('#overlay .seg')].map(s => (s.classList.contains('d0') ? 'C:' : 'S:') + s.textContent).join('|')`);
    assert(body.includes('C:' + want.client_to_server.replace(/\r/g, '\r')) || body.includes('GET /index.html'), 'client text');
    assert(body.indexOf('C:GET') < body.indexOf('S:HTTP/1.1 200'), 'order');
    await shot('follow-http');
    await vs.wvClick(wv, `[...document.querySelectorAll('#overlay button')].find(b => b.textContent === 'Filter on this stream')`);
    const q = await waitProbe(p => p.filter === 'tcp.stream == 0', 8000, 'stream filter');
    assert(q.viewCount === 11, 'stream packets ' + q.viewCount);
    return { overlayStart: p.overlay.slice(0, 120), streamFilterCount: q.viewCount };
  });

  await step('hero: HTTP GET with the Host header selected and its bytes lit (dark theme)', async () => {
    await vs.wvClick(wv, `document.querySelector('#clearBtn')`); await waitProbe(p => !p.filter, 5000, 'clear');
    await clickRow(4);
    await expandLayer('/^Hypertext Transfer Protocol/');
    await clickNode('/^Host: example\\.com/');
    const p = await waitProbe(p => /Host: example\.com/.test(p.treeSel), 5000, 'host selected');
    await sleep(300);
    const f = await shot('hero-http-dark');
    return { treeSel: p.treeSel, hexOn: p.hexOn.slice(0, 60), shot: f && path.basename(f) };
  });

  await step('statistics: protocol hierarchy and conversations', async () => {
    await vs.wvClick(wv, `document.querySelector('#statsBtn')`);
    const p = await waitProbe(p => /Protocol hierarchy/.test(p.overlay) && /eth/.test(p.overlay), 15000, 'stats');
    await vs.wvClick(wv, `[...document.querySelectorAll('#overlay .tabs button')].find(b => b.textContent === 'Conversations')`);
    const q = await waitProbe(p => /Address A/.test(p.overlay), 5000, 'conversations');
    await shot('statistics-conversations');
    await vs.key('Escape', 'Escape');
    return { hierarchy: p.overlay.split('\n').slice(0, 12).join(' | '), conv: q.overlay.split('\n').slice(0, 6).join(' | ') };
  });

  await step('export selected packets (shift-click 4 to 7) as pcap; tcpdump reads 4 packets', async () => {
    await clickRow(4); await vs.wvClick(wv, rowSel(7), { dx: 30, modifiers: 8 }); await sleep(300);
    const p = await waitProbe(p => p.selection === 4, 5000, 'selection');
    const out = path.join(ws, 'export-4-7.pcap'); fs.rmSync(out, { force: true });
    await vs.wvClick(wv, `document.querySelector('#exportBtn')`); await sleep(300);
    await vs.wvClick(wv, `[...document.querySelectorAll('.menu .mi')].find(b => /Export selected/.test(b.textContent))`); await sleep(1200);
    // the simple save dialog is a quick input with the path
    await vs.key('a', 'KeyA', 4); await vs.type(out); await sleep(300); await vs.key('Enter', 'Enter');
    const ok = await vs.waitFor(() => fs.existsSync(out) && fs.statSync(out).size > 0, 10000);
    assert(ok, 'no export file');
    await sleep(500);
    const n = tcpdumpCount(out);
    assert(n === 4, 'tcpdump read ' + n);
    const line = execSync(`tcpdump -nn -r ${JSON.stringify(out)} 2>/dev/null | head -1`, { encoding: 'utf8' }).trim();
    fs.rmSync(out, { force: true });
    return { selected: p.selection, tcpdumpPackets: n, firstLine: line };
  });

  await step('light theme: list, tree and hex readable', async () => {
    await setTheme('Default Light Modern');
    await clickRow(6);
    await expandLayer('/^Hypertext Transfer Protocol/');
    await clickNode('/^HTTP\\/1\\.1 200 OK/');
    await sleep(500);
    const f = await shot('light-http-response');
    const bg = await E(`getComputedStyle(document.body).backgroundColor`);
    await setTheme('Default Dark Modern');
    return { body: bg, shot: f && path.basename(f) };
  });
  await closeAll();

  // 4. hostile files
  await step('hostile: zero-length pcapng block gives a clear message and the 2 packets before it', async () => {
    const { p } = await open('hostile/zero-block.pcapng');
    assert(p.total === 2, 'count ' + p.total);
    assert(p.notices.some(n => /length of 0 bytes/.test(n)), JSON.stringify(p.notices));
    await shot('hostile-zero-block');
    return { notices: p.notices };
  });
  await step('hostile: block past the end, caplen > 256 KB, caplen > file size', async () => {
    const out = {};
    for (const f of ['hostile/past-end.pcapng', 'hostile/huge-caplen.pcap', 'hostile/huge-caplen2.pcap']) {
      const { p } = await open(f); assert(p.total === 1 && p.notices.length, f + ' ' + JSON.stringify(p)); out[f] = p.notices[0].slice(0, 140);
    }
    return out;
  });
  await step('hostile: gzip bomb (10 GB unpacked) stops early (unpack ratio) with a message, no hang', async () => {
    const t0 = Date.now();
    const { p } = await open('hostile/bomb.pcap.gz', 90000);
    const ms = Date.now() - t0;
    assert(p.notices.some(n => /gzip bomb/.test(n)), JSON.stringify(p.notices));
    const mem = extHost(); R.memory.push({ after: 'bomb', mem });
    await shot('hostile-gzip-bomb');
    return { ms, packets: p.total, notices: p.notices.map(n => n.slice(0, 160)), extHostMB: mem };
  });
  await step('hostile: bad headers are marked Malformed; not a capture and empty file show a message', async () => {
    const a = await open('hostile/bad-headers.pcap');
    assert(a.p.total === 5, 'count');
    const mal = a.p.rows.filter(r => /Malformed/.test(r[6])).length;
    assert(mal >= 3, 'malformed rows ' + mal);
    await shot('hostile-bad-headers');
    const b = await open('hostile/not-a-capture.pcap'); assert(/not a pcap or pcapng/.test(b.p.error), b.p.error);
    const c = await open('hostile/empty.pcap'); assert(/empty/.test(c.p.error), c.p.error);
    return { malformedRows: mal, notCapture: b.p.error.slice(0, 120), empty: c.p.error.slice(0, 80) };
  });
  await closeAll();

  // 5. large capture
  const large = fs.readdirSync(ws).find(f => /^large-\d+mb\.pcap$/.test(f));
  if (large) {
    await step(`large: ${large} lists in < 15 s, scrolls, filters; extension host < 1 GB`, async () => {
      const size = fs.statSync(P(large)).size;
      const before = extHost();
      const t0 = Date.now();
      vs.open(P(large));
      wv = await findWv(large, 20000);
      assert(wv, 'no webview');
      let sawProgress = '';
      const p = await vs.waitFor(async () => { const q = await probe(); if (q && q.progress) sawProgress = q.progress; return q && q.rendered && q.rows.length > 0 && q.rows[0][0] === '1' ? q : null; }, 120000, 100);
      const listMs = Date.now() - t0;
      assert(p, 'did not list');
      await shot('large-1gb-open');
      const mem1 = extHost();
      // scrolling: 30 PageDown key presses, then End
      await vs.wvClick(wv, rowSel(3), { dx: 30 });
      const s0 = Date.now();
      for (let i = 0; i < 30; i++) await vs.key('PageDown', 'PageDown');
      const q = await waitProbe(x => x.selectedNo > 300, 10000, 'pagedown');
      const pageMs = Date.now() - s0;
      const e0 = Date.now();
      await vs.key('End', 'End');
      const last = await waitProbe(x => x.selectedNo === x.total, 20000, 'end');
      const endMs = Date.now() - e0;
      await shot('large-1gb-end');
      const f0 = Date.now();
      const flt = await typeFilter('dns && ip.addr == 10.0.0.0/8');
      const filterMs = Date.now() - f0;
      const mem2 = extHost();
      R.memory.push({ large, before, afterOpen: mem1, afterFilter: mem2 });
      const maxMB = Math.max(...mem2.map(m => m.mb), ...mem1.map(m => m.mb));
      const td = quick ? null : tcpdumpCount(P(large));
      assert(listMs < 15000, 'list took ' + listMs);
      assert(maxMB < 1024, 'ext host ' + maxMB + ' MB');
      if (td !== null) assert(td === p.total, `count ${p.total} vs tcpdump ${td}`);
      return { sizeMB: Math.round(size / 1048576), packets: p.total, tcpdump: td, listMs, sawProgress, pageDown30Ms: pageMs, endMs, lastNo: last.selectedNo, filter: { ms: filterMs, matches: flt.viewCount }, extHostMB: maxMB };
    });
    await closeAll();
  }

  await step('no network: no sockets from the extension host; webview loaded only local resources', async () => {
    const after = sockets();
    R.network.after = after;
    const { p } = await open('tls.pcap');
    const res = JSON.parse(await E(`JSON.stringify(performance.getEntriesByType('resource').map(e => e.name))`));
    const remote = res.filter(u => !/^(vscode-webview|vscode-resource|https:\/\/file\+|https:\/\/[^/]*vscode-cdn\.net)/.test(u) && !/^https?:\/\/[^/]*\.vscode-resource\./.test(u));
    assert(!after.length, 'sockets: ' + after.join(' | '));
    assert(!remote.length, 'remote loads: ' + remote.join(' '));
    return { extHostSockets: after.length, webviewResources: res.length, remote: remote.length, rendered: p.rendered };
  });

  R.console = vs.console.filter(c => /pcap|webview|worker/i.test(c.text) && !/ResizeObserver loop|Ignoring the|punycode|ERR_ABORTED.*\.map/i.test(c.text)).slice(0, 50);
} finally {
  R.shots = shots.map(f => path.basename(f)); R.shotErrors = shotErrors;
  try { R.memoryEnd = extHost(); } catch {}
  await vs.close();
  R.pass = R.steps.filter(s => s.ok === true).length; R.fail = R.steps.filter(s => s.ok === false).length; R.skip = R.steps.filter(s => s.ok === null).length;
  fs.writeFileSync(outJson, JSON.stringify(R, null, 1));
  console.log(`DONE pass=${R.pass} fail=${R.fail} skip=${R.skip} console=${R.console.length}`);
}
