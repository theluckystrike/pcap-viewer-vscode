'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { buildHtml } = require('../src/html');
const { validate } = require('../src/protocol');

test('webview CSP: default-src none, scripts by nonce, no connect-src, no remote origin', () => {
  const html = buildHtml({ cspSource: 'vscode-webview://x', scriptUri: 'vscode-webview://x/dist/webview.js', styleUri: 'vscode-webview://x/media/webview.css', title: 'a.pcap', nonce: 'abc' });
  const csp = /content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'nonce-abc'/);
  assert.match(csp, /img-src vscode-webview:\/\/x blob: data:/);
  assert.doesNotMatch(csp, /connect-src|https?:/);
});

test('webview messages are checked before the host acts', () => {
  assert.equal(validate(null), null);
  assert.equal(validate({ type: 'nope' }), null);
  assert.equal(validate({ type: 'rows', start: -1, count: 10, seq: 1 }), null);
  assert.equal(validate({ type: 'rows', start: 0, count: 5000, seq: 1 }), null);
  assert.deepEqual(validate({ type: 'rows', start: 0, count: 200, seq: 2, names: 1, time: 'evil' }), { type: 'rows', start: 0, count: 200, seq: 2, names: true, time: 'relative' });
  assert.equal(validate({ type: 'packet', no: 0 }), null);
  assert.equal(validate({ type: 'filter', expr: 'x'.repeat(5000), seq: 1 }), null);
  assert.equal(validate({ type: 'export', which: [1, 'a'] }), null);
  assert.deepEqual(validate({ type: 'export', which: 'view' }), { type: 'export', which: 'view' });
  assert.equal(validate({ type: 'saveFilter', expr: '   ' }), null);
});

test('bundles: no network modules or calls, only GitHub and Marketplace links', () => {
  const dist = path.join(__dirname, '..', 'dist');
  for (const f of ['extension.js', 'worker.js', 'webview.js']) {
    const src = fs.readFileSync(path.join(dist, f), 'utf8');
    for (const bad of ['require("http")', 'require("https")', 'require("net")', 'require("dns")', 'require("dgram")', 'require("tls")', 'fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'dns.lookup', 'dns.reverse']) {
      assert.ok(!src.includes(bad), `${f} contains ${bad}`);
    }
    const urls = src.match(/https?:\/\/[^\s"'`)<>]+/g) || [];
    for (const u of urls) assert.match(u, /^https:\/\/(github\.com\/theluckystrike|marketplace\.visualstudio\.com|github\.com\/sponsors|www\.paypal\.com|paypal\.me)/, `${f}: ${u}`);
  }
});

test('package.json: engines floor, name words, default editors', () => {
  const pk = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.equal(pk.engines.vscode, '^1.90.0');
  for (const phrase of ['pcap viewer', 'pcapng', 'packet capture', 'pcap']) for (const w of phrase.split(' ')) assert.ok(pk.displayName.toLowerCase().includes(w), w);
  assert.ok(!/wireshark/i.test(pk.displayName));
  const sel = pk.contributes.customEditors[0].selector.map(s => s.filenamePattern);
  for (const p of ['*.pcap', '*.pcapng', '*.pcap.gz', '*.pcapng.gz']) assert.ok(sel.includes(p), p);
});
