'use strict';
// Display filter: a subset of the Wireshark syntax.
//   tcp            a protocol name: packets that have it
//   ip.addr == 10.0.0.1, ip.src != 10.0.0.0/8, tcp.port in {80 443}, frame.len > 1000
//   dns.qry.name contains "example", http.request.method == "GET"
//   && and, || or, ! not, ( )
// compile() returns { ok, test(fields) } or { ok: false, error, at } with a plain-words error.

const PROTOCOLS = new Set(['frame', 'eth', 'vlan', 'sll', 'arp', 'ip', 'ipv6', 'icmp', 'icmpv6', 'tcp', 'udp', 'dns', 'mdns', 'dhcp', 'bootp', 'http', 'tls', 'ssl', 'quic', 'data', 'llc', 'wlan', 'radiotap', 'null', 'raw', 'igmp', 'gre', 'esp', 'sctp', 'ospf', 'pim', 'vrrp', 'lldp', 'mpls', 'ipip', 'ipv6.hopopts']);
const ALIASES = {
  ssl: 'tls', bootp: 'dhcp', 'tls.sni': 'tls.handshake.extensions_server_name', 'ssl.sni': 'tls.handshake.extensions_server_name',
  'tls.alpn': 'tls.handshake.extensions_alpn_str', 'ip.ttl': 'ip.ttl', 'dns.name': 'dns.qry.name', 'http.method': 'http.request.method',
  'http.uri': 'http.request.uri', 'http.code': 'http.response.code', 'eth.mac': 'eth.addr', 'ipv6.hlim': 'ipv6.hlim', 'frame.length': 'frame.len',
  'icmp.ident': 'icmp.ident', 'vlan': 'vlan', 'bootp.option.hostname': 'dhcp.option.hostname',
};
const FIELDS = new Set([
  'frame.len', 'frame.cap_len', 'frame.number', 'frame.time_relative', 'frame.interface_id',
  'eth.src', 'eth.dst', 'eth.addr', 'eth.type', 'vlan.id', 'vlan.priority', 'sll.src',
  'arp.opcode', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4', 'arp.src.hw_mac',
  'ip.src', 'ip.dst', 'ip.addr', 'ip.proto', 'ip.ttl', 'ip.len', 'ip.id', 'ip.version', 'ip.flags.df', 'ip.flags.mf', 'ip.frag_offset',
  'ipv6.src', 'ipv6.dst', 'ipv6.addr', 'ipv6.hlim', 'ipv6.plen', 'ipv6.nxt', 'ipv6.ext',
  'icmp.type', 'icmp.code', 'icmp.ident', 'icmp.seq', 'icmpv6.type', 'icmpv6.code', 'icmpv6.echo.seq', 'icmpv6.nd.target',
  'tcp.srcport', 'tcp.dstport', 'tcp.port', 'tcp.seq', 'tcp.ack', 'tcp.len', 'tcp.window_size', 'tcp.flags', 'tcp.flags.syn', 'tcp.flags.ack',
  'tcp.flags.fin', 'tcp.flags.reset', 'tcp.flags.push', 'tcp.stream',
  'udp.srcport', 'udp.dstport', 'udp.port', 'udp.length', 'udp.stream',
  'dns.id', 'dns.flags.response', 'dns.flags.rcode', 'dns.qry.name', 'dns.qry.type', 'dns.a', 'dns.aaaa', 'dns.cname', 'dns.resp.name', 'dns.count.answers', 'dns.ptr.domain_name',
  'dhcp.id', 'dhcp.ip.your', 'dhcp.hw.mac_addr', 'dhcp.option.dhcp', 'dhcp.option.hostname', 'dhcp.option.requested_ip_address',
  'http.request', 'http.response', 'http.request.method', 'http.request.uri', 'http.response.code', 'http.response.phrase', 'http.host', 'http.user_agent',
  'http.content_type', 'http.content_length', 'http.server', 'http.cookie', 'http.continuation',
  'tls.record.content_type', 'tls.record.version', 'tls.handshake.type', 'tls.handshake.extensions_server_name', 'tls.handshake.extensions_alpn_str',
  'tls.handshake.ciphersuite', 'tls.handshake.extensions.supported_version',
  'quic.version', 'quic.dcid', 'quic.scid', 'quic.long.packet_type', 'data.len', 'wlan.ra', 'wlan.ta', '_ws.malformed', '_ws.name',
]);

function tokenize(s) {
  const out = []; let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    const two = s.slice(i, i + 2);
    if (['==', '!=', '>=', '<=', '&&', '||'].includes(two)) { out.push({ t: 'op', v: two, at: i }); i += 2; continue; }
    if ('()!<>{},'.includes(c)) { out.push({ t: c === '!' || c === '<' || c === '>' ? 'op' : c, v: c, at: i }); i++; continue; }
    if (c === '=' ) { out.push({ t: 'op', v: '==', at: i }); i++; continue; }
    if (c === '"' || c === "'") {
      let j = i + 1, v = '';
      while (j < s.length && s[j] !== c) { if (s[j] === '\\' && j + 1 < s.length) { v += s[j + 1]; j += 2; } else v += s[j++]; }
      if (j >= s.length) return { error: 'A quoted text has no closing quote.', at: i };
      out.push({ t: 'str', v, at: i }); i = j + 1; continue;
    }
    let j = i;
    while (j < s.length && !/[\s()!<>={},"']/.test(s[j])) j++;
    if (j === i) return { error: `Unexpected character "${c}".`, at: i };
    out.push({ t: 'word', v: s.slice(i, j), at: i }); i = j;
  }
  return { tokens: out };
}

const WORD_OPS = { eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=', contains: 'contains', matches: 'matches', in: 'in', and: '&&', or: '||', not: '!' };

function parse(src) {
  const tk = tokenize(src);
  if (tk.error) return { ok: false, error: tk.error, at: tk.at };
  const t = tk.tokens.map(x => (x.t === 'word' && WORD_OPS[x.v.toLowerCase()] ? { t: 'op', v: WORD_OPS[x.v.toLowerCase()], at: x.at } : x));
  let i = 0;
  const peek = () => t[i], fail = (msg, at) => { throw Object.assign(new Error(msg), { at: at ?? (t[i] ? t[i].at : src.length) }); };
  const isOp = v => t[i] && t[i].t === 'op' && t[i].v === v;
  function orE() { let l = andE(); while (isOp('||')) { i++; l = { k: 'or', l, r: andE() }; } return l; }
  function andE() { let l = notE(); while (isOp('&&')) { i++; l = { k: 'and', l, r: notE() }; } return l; }
  function notE() { if (isOp('!')) { i++; return { k: 'not', e: notE() }; } return prim(); }
  function prim() {
    const x = peek();
    if (!x) fail('The filter ends too early.');
    if (x.t === '(') { i++; const e = orE(); if (!t[i] || t[i].t !== ')') fail('A "(" has no matching ")".'); i++; return e; }
    if (x.t !== 'word') fail(`Expected a field or protocol name, found "${x.v}".`, x.at);
    i++;
    let name = x.v.toLowerCase();
    name = ALIASES[name] || name;
    if (!PROTOCOLS.has(name) && !FIELDS.has(name)) fail(`"${x.v}" is not a field this viewer knows. Try ip.addr, tcp.port, udp.port, dns.qry.name, http.host, tls.sni or a protocol name such as tcp or dns.`, x.at);
    const op = peek();
    if (!op || op.t !== 'op' || ['&&', '||', '!'].includes(op.v)) return { k: 'has', name };
    i++;
    if (op.v === 'in') {
      if (!t[i] || t[i].t !== '{') fail('"in" needs a set such as {80 443}.');
      i++; const vals = [];
      while (t[i] && t[i].t !== '}') { if (t[i].t === ',') { i++; continue; } if (t[i].t !== 'word' && t[i].t !== 'str') fail('Expected a value in the set.'); vals.push(t[i].v); i++; }
      if (!t[i]) fail('A "{" has no matching "}".');
      i++;
      return { k: 'in', name, vals: vals.map(v => value(name, v, '==')) };
    }
    const v = peek();
    if (!v || (v.t !== 'word' && v.t !== 'str')) fail(`"${x.v} ${op.v}" needs a value after it.`);
    i++;
    return { k: 'cmp', name, op: op.v, val: value(name, v.v, op.v, v.at) };
  }
  function value(name, raw, op, at) {
    if (op === 'matches') { try { return { re: new RegExp(raw, 'i') }; } catch (e) { fail(`"${raw}" is not a valid regular expression.`, at); } }
    if (op === 'contains') return { s: raw };
    const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(raw);
    if (cidr) {
      const bits = Number(cidr[2]);
      if (bits > 32) fail(`"${raw}": a prefix length is 0 to 32.`, at);
      return { net: ip4num(cidr[1]), mask: bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0 };
    }
    if (/^(0x[0-9a-f]+|\d+(\.\d+)?)$/i.test(raw) && !/^\d+\.\d+\.\d+/.test(raw)) return { n: Number(raw), s: raw };
    if (raw === 'true') return { n: 1, s: raw };
    if (raw === 'false') return { n: 0, s: raw };
    return { s: /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(raw) ? raw.toLowerCase().replace(/-/g, ':') : raw };
  }
  try {
    if (!t.length) return { ok: true, ast: null };
    const ast = orE();
    if (i < t.length) fail(`Unexpected "${t[i].v}". Join conditions with && or ||.`, t[i].at);
    return { ok: true, ast };
  } catch (e) {
    return { ok: false, error: e.message, at: e.at };
  }
}

function ip4num(s) { const p = s.split('.').map(Number); return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0; }

function match1(fv, op, val) {
  if (val.net !== undefined) {
    if (typeof fv !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(fv)) return false;
    const inNet = ((ip4num(fv) & val.mask) >>> 0) === ((val.net & val.mask) >>> 0);
    return op === '!=' ? !inNet : inNet;
  }
  if (op === 'contains') return String(fv).includes(val.s);
  if (op === 'matches') return val.re.test(String(fv));
  if (typeof fv === 'number' && val.n !== undefined) {
    switch (op) { case '==': return fv === val.n; case '!=': return fv !== val.n; case '>': return fv > val.n; case '<': return fv < val.n; case '>=': return fv >= val.n; case '<=': return fv <= val.n; }
  }
  const a = String(fv), b = val.s;
  if (op === '==') return typeof fv === 'string' && /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(a) ? a === b.toLowerCase() : a === b;
  if (op === '!=') return a !== b;
  switch (op) { case '>': return a > b; case '<': return a < b; case '>=': return a >= b; case '<=': return a <= b; }
  return false;
}

function evalAst(n, f) {
  switch (n.k) {
    case 'and': return evalAst(n.l, f) && evalAst(n.r, f);
    case 'or': return evalAst(n.l, f) || evalAst(n.r, f);
    case 'not': return !evalAst(n.e, f);
    case 'has': {
      if (PROTOCOLS.has(n.name) && !FIELDS.has(n.name)) { const p = f._proto; return Array.isArray(p) ? p.includes(n.name) : p === n.name; }
      return f[n.name] !== undefined;
    }
    case 'in': {
      const v = f[n.name]; if (v === undefined) return false;
      const vs = Array.isArray(v) ? v : [v];
      return vs.some(x => n.vals.some(val => match1(x, '==', val)));
    }
    case 'cmp': {
      const v = f[n.name]; if (v === undefined) return false;
      const vs = Array.isArray(v) ? v : [v];
      // != is true when no value equals (Wireshark 4 meaning: "all not equal").
      if (n.op === '!=') return !vs.some(x => match1(x, '==', n.val));
      return vs.some(x => match1(x, n.op, n.val));
    }
  }
  return false;
}

function compile(src) {
  const p = parse(String(src || '').trim());
  if (!p.ok) return p;
  if (!p.ast) return { ok: true, empty: true, test: () => true };
  return { ok: true, empty: false, test: f => evalAst(p.ast, f) };
}

module.exports = { compile, parse, PROTOCOLS, FIELDS };
