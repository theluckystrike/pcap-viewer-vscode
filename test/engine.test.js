'use strict';
// Engine tests on generated captures (scripts/make_samples.py) checked against its expected.json, which was
// itself checked with tcpdump. Fixtures live in ~/pcap-viewer-work (not the temp folder) and are deleted after.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { Engine } = require('../src/core/engine');
const { compile } = require('../src/core/filter');
const { dissect } = require('../src/core/dissect');

const WORK = path.join(os.homedir(), 'pcap-viewer-work', 'unit-' + process.pid);
const S = path.join(WORK, 's');
let expected;

test.before(() => {
  fs.mkdirSync(WORK, { recursive: true });
  execFileSync('python3', [path.join(__dirname, '..', 'scripts', 'make_samples.py'), S, '--bomb'], { stdio: 'ignore' });
  expected = JSON.parse(fs.readFileSync(path.join(S, 'expected.json'), 'utf8'));
});
test.after(() => { fs.rmSync(WORK, { recursive: true, force: true }); });

async function open(file, opts = {}) {
  const e = new Engine(() => {});
  const info = await e.open(path.join(S, file), { gz: file.endsWith('.gz'), maxGzipMB: opts.maxGzipMB || 512 });
  return { e, info };
}

// Wireshark labels a reassembled HTTP response on its last segment; this viewer labels each segment
// (the first as HTTP, the next as HTTP continuation), so HTTP stands in for TCP on a port-80 data segment.
const PROTO_OK = (got, want, r) => got === want || (want === 'TCP' && got === 'HTTP' && r && r.l4 && r.l4.len > 0) || (want.startsWith('TLS') && got.startsWith('TLS')) || (want === 'HTTP' && got === 'HTTP') || (want === 'MDNS' && got === 'DNS');
const FIELD_KEYS = ['dns.qry.name', 'dns.a', 'dns.aaaa', 'http.host', 'tls.handshake.extensions_server_name', 'icmp.seq', 'vlan.id', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'dhcp.option.hostname'];

test('every sample: packet count, source, destination, protocol, length and key fields match expected.json', async () => {
  let checked = 0, fields = 0;
  for (const [file, exp] of Object.entries(expected.files)) {
    const { e, info } = await open(file);
    assert.equal(info.error, '', file);
    assert.equal(info.count, exp.packets, `${file} packet count`);
    for (const fr of exp.frames || []) {
      const i = fr.index - 1;
      const r = e.dissectAt(i, false);
      if (fr.src) assert.equal(r.src, fr.src, `${file} #${fr.index} src`);
      if (fr.dst) assert.equal(r.dst, fr.dst, `${file} #${fr.index} dst`);
      if (fr.protocol) assert.ok(PROTO_OK(r.proto, fr.protocol, r), `${file} #${fr.index} protocol ${r.proto} vs ${fr.protocol}`);
      if (fr.length) assert.equal(e.idx.orig[i], fr.length, `${file} #${fr.index} length`);
      for (const k of FIELD_KEYS) {
        if (fr[k] === undefined) continue;
        const v = r.f[k];
        const vs = Array.isArray(v) ? v : [v];
        assert.ok(vs.map(String).includes(String(fr[k])), `${file} #${fr.index} ${k}: ${JSON.stringify(v)} vs ${fr[k]}`);
        fields++;
      }
      checked++;
    }
    e.close();
  }
  assert.ok(checked >= 80, `checked ${checked} frames`);
  assert.ok(fields >= 100, `checked ${fields} fields`);
});

test('time stamps: microsecond, nanosecond and big-endian files give the expected absolute times', async () => {
  for (const file of ['dns.pcap', 'nanosecond.pcap', 'bigendian.pcap', 'multi-if.pcapng']) {
    const { e } = await open(file);
    for (const fr of expected.files[file].frames) {
      if (!fr.time) continue;
      const want = fr.time.replace('T', ' ').replace('Z', '');
      const got = e.absTime(fr.index - 1, 'utc');
      assert.ok(got.startsWith(want.slice(0, 26)) || want.startsWith(got), `${file} #${fr.index}: ${got} vs ${want}`);
    }
    e.close();
  }
});

test('filter tcp.port==443 && ip.addr==10.0.0.1 gives the count from expected.json', async () => {
  const { e } = await open('tls.pcap');
  for (const [expr, n] of Object.entries(expected.files['tls.pcap'].filters)) {
    const r = await e.filter(expr, 1);
    assert.equal(r.count, n, expr);
  }
  const more = { 'tls': 4, 'dns': 2, '!tcp': 2, 'tcp.flags.syn == 1': 4, 'tls.sni == "secure.example.com"': 1, 'ip.addr == 10.0.0.0/24 && udp': 2, 'tcp.port in {443 80}': 12, 'frame.len > 300': 1, 'dns.qry.name contains "secure"': 2, 'tcp.stream == 1': 3 };
  for (const [expr, n] of Object.entries(more)) assert.equal((await e.filter(expr, 2)).count, n, expr);
  const bad = await e.filter('ip.adr == 1', 3);
  assert.equal(bad.ok, false);
  assert.match(bad.error, /not a field/);
  e.close();
});

test('filter parser: operators, words, sets, CIDR, errors with a position', () => {
  const f = { _proto: ['frame', 'eth', 'ip', 'tcp'], 'ip.addr': ['10.0.0.1', '93.184.216.34'], 'tcp.port': [51000, 80], 'frame.len': 66, 'http.host': 'example.com' };
  const t = s => compile(s).test(f);
  assert.equal(t('tcp'), true); assert.equal(t('udp'), false); assert.equal(t('!udp'), true); assert.equal(t('not udp and tcp'), true);
  assert.equal(t('ip.addr == 10.0.0.1'), true); assert.equal(t('ip.addr eq 10.0.0.2'), false); assert.equal(t('ip.addr != 10.0.0.1'), false);
  assert.equal(t('ip.addr == 10.0.0.0/8'), true); assert.equal(t('ip.addr == 192.168.0.0/16'), false);
  assert.equal(t('tcp.port == 80 || udp.port == 53'), true); assert.equal(t('(tcp.port == 81 || tcp.port == 0x50) && frame.len >= 66'), true);
  assert.equal(t('tcp.port in {443 8443}'), false); assert.equal(t('http.host contains "ample"'), true); assert.equal(t('http.host matches "^EXAMPLE"'), true);
  const e1 = compile('tcp.port == '); assert.equal(e1.ok, false);
  const e2 = compile('ip.addr == 1.2.3.4 &&'); assert.equal(e2.ok, false);
  const e3 = compile('foo.bar'); assert.equal(e3.ok, false); assert.equal(e3.at, 0);
  const e4 = compile('(tcp'); assert.equal(e4.ok, false); assert.match(e4.error, /\)/);
  assert.equal(compile('').ok, true);
});

test('follow TCP stream shows the HTTP request and the response, in order', async () => {
  const { e } = await open('http.pcap');
  const r = await e.follow(4);
  const want = expected.files['http.pcap'].follow_tcp_stream;
  const dec = b => Buffer.from(b).toString('latin1');
  const c2s = r.segments.filter(s => s.dir === 0).map(s => dec(s.bytes)).join('');
  const s2c = r.segments.filter(s => s.dir === 1).map(s => dec(s.bytes)).join('');
  const wc = want.client_to_server ?? want['client->server'] ?? Object.values(want)[0];
  const ws = want.server_to_client ?? want['server->client'] ?? Object.values(want)[1];
  assert.equal(c2s, wc); assert.equal(s2c, ws);
  assert.match(c2s, /^GET \/index\.html HTTP\/1\.1/); assert.match(s2c, /^HTTP\/1\.1 200 OK/);
  assert.equal(r.filter, 'tcp.stream == 0');
  e.close();
});

test('protocol tree: every field range is inside the packet; clicking a byte finds a field', async () => {
  for (const file of Object.keys(expected.files)) {
    const { e } = await open(file);
    for (let no = 1; no <= e.idx.n; no++) {
      const p = e.packet(no);
      const walk = ns => { for (const n of ns) { assert.ok(n.s >= 0 && n.l >= 0 && n.s + n.l <= p.bytes.length, `${file} #${no} "${n.n}" ${n.s}+${n.l} > ${p.bytes.length}`); if (n.c) walk(n.c); } };
      walk(p.tree);
    }
    e.close();
  }
  const { e } = await open('tls.pcap');
  const p = e.packet(6);
  // find the SNI node and check its bytes are the host name
  const all = []; const walk = ns => { for (const n of ns) { all.push(n); if (n.c) walk(n.c); } }; walk(p.tree);
  const sni = all.find(n => /^Server Name: /.test(n.n));
  assert.ok(sni);
  assert.equal(Buffer.from(p.bytes.subarray(sni.s, sni.s + sni.l)).toString(), 'secure.example.com');
  e.close();
});

test('names come from DNS answers and the pcapng name block, never from the network', async () => {
  const { e, info } = await open('multi-if.pcapng');
  assert.ok(info.names >= 3);
  assert.equal(e.name('10.0.0.1'), 'client.lan');
  assert.equal(e.name('93.184.216.34'), 'web.example');
  const r = e.rows(0, 3, { names: true });
  assert.equal(r.rows[0].src, 'client.lan');
  assert.equal(r.rows[0].srcAddr, '10.0.0.1');
  e.close();
  const t = await open('tls.pcap');
  assert.equal(t.e.name('93.184.216.34'), 'secure.example.com');
  t.e.close();
});

test('statistics: hierarchy, conversations and endpoints', async () => {
  const { e } = await open('tls.pcap');
  const s = await e.stats();
  const tcpConv = s.conversations.filter(c => c.kind === 'TCP');
  assert.equal(tcpConv.length, 2);
  assert.equal(tcpConv.reduce((t, c) => t + c.packets, 0), 12);
  assert.ok(s.hierarchy.some(h => h.path === 'eth/ip/udp/dns'));
  assert.ok(s.endpoints.some(x => x.kind === 'IPv4' && x.addr === '10.0.0.1' && x.packets === 14));
  e.close();
});

test('export: selected packets and the filtered view write a pcap that reads back the same', async () => {
  const { e } = await open('tls.pcap');
  const out = path.join(WORK, 'exp.pcap');
  const r = e.exportTo(out, [6, 8, 3]);
  assert.equal(r.count, 3); assert.equal(r.format, 'pcap');
  const b = new Engine(() => {}); const bi = await b.open(out, {});
  assert.equal(bi.count, 3);
  assert.deepEqual([...b.bytes(0)], [...e.bytes(2)]);
  assert.equal(b.absTime(1, 'utc').slice(0, 26), e.absTime(5, 'utc'));
  b.close();
  await e.filter('dns', 9);
  const r2 = e.exportTo(out, 'view'); assert.equal(r2.count, 2);
  e.close();
  // two link types in one export -> pcapng
  const m = await open('multi-if.pcapng');
  const r3 = m.e.exportTo(out, [1, 2]); assert.equal(r3.format, 'pcapng');
  const c = new Engine(() => {}); const ci = await c.open(out, {}); assert.equal(ci.count, 2); assert.equal(c.lt(1), 101); c.close();
  m.e.close();
});

test('hostile files: clear messages, packets before the damage, no hang', async () => {
  const cases = {
    'hostile/zero-block.pcapng': [2, /length of 0 bytes/],
    'hostile/past-end.pcapng': [1, /only \d+ bytes are left/],
    'hostile/huge-caplen.pcap': [1, /more than the 262,144-byte limit/],
    'hostile/huge-caplen2.pcap': [1, /file ends/],
  };
  for (const [f, [n, re]] of Object.entries(cases)) {
    const { e, info } = await open(f);
    assert.equal(info.count, n, f);
    assert.ok(info.warnings.some(w => re.test(w)), f + ': ' + info.warnings.join(' | '));
    e.close();
  }
  for (const [f, re] of Object.entries({ 'hostile/empty.pcap': /empty/, 'hostile/not-a-capture.pcap': /not a pcap/, 'hostile/truncated-header.pcap': /cut off/ })) {
    const { info } = await open(f);
    assert.equal(info.count, 0); assert.match(info.error, re, f);
  }
  const { e } = await open('hostile/bad-headers.pcap');
  const rows = e.rows(0, 10, {}).rows;
  assert.equal(rows.length, 5);
  assert.match(rows[0].info, /IHL 3 < 5/);
  assert.match(rows[1].info, /data offset 60 goes past/);
  assert.match(rows[3].info, /pointer loop/);
  for (let no = 1; no <= 5; no++) assert.ok(e.packet(no).tree.length > 0);
  e.close();
});

test('gzip bomb (10 GB unpacked) stops at the cap with a message, quickly and with flat memory', async () => {
  const t0 = Date.now();
  const { e, info } = await open('hostile/bomb.pcap.gz', { maxGzipMB: 512 });
  const ms = Date.now() - t0;
  assert.ok(info.capped, 'capped');
  // stopped by the unpack ratio long before the 512 MB cap
  assert.ok(info.warnings.some(w => /times its packed size/.test(w)), info.warnings.join(' | '));
  assert.ok(info.size < 80 * 1048576, String(info.size));
  assert.ok(info.warnings.some(w => /gzip bomb/.test(w)));
  assert.ok(info.warnings.some(w => /only zero bytes/.test(w)));
  assert.ok(info.count < 100, String(info.count));
  assert.ok(ms < 20000, ms + ' ms');
  e.close();
});

test('dissector never throws on random bytes for every link type', () => {
  let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (const lt of [0, 1, 101, 105, 113, 127, 228, 229, 276, 999]) {
    for (let k = 0; k < 400; k++) {
      const n = Math.floor(rnd() * 300), b = new Uint8Array(n);
      for (let i = 0; i < n; i++) b[i] = Math.floor(rnd() * 256);
      if (lt === 1 && n > 14) { b[12] = 8; b[13] = 0; b[14] = 0x45; }
      const r = dissect(b, lt, { tree: true });
      assert.ok(typeof r.info === 'string');
    }
  }
});
