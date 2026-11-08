'use strict';
// Packet dissectors in plain JS. dissect() returns the columns of the packet list, the fields the display
// filter reads, and (when asked) a protocol tree whose nodes carry the byte range they came from, so the hex
// pane can link a field to its bytes and a byte to its field. Every read is checked against the packet end:
// a short or damaged header gives a "Malformed" node, never an exception or a read past the data.
const { ipv6Str } = require('./capture');

const ETHERTYPES = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q VLAN', 0x88a8: '802.1ad QinQ', 0x8847: 'MPLS', 0x88cc: 'LLDP', 0x8863: 'PPPoE Discovery', 0x8864: 'PPPoE Session', 0x0842: 'Wake-on-LAN', 0x88e5: 'MACsec', 0x8035: 'RARP' };
const IPPROTO = { 0: 'Hop-by-Hop', 1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 43: 'Routing', 44: 'Fragment', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 59: 'No Next Header', 60: 'Destination Options', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP' };
const LINKTYPES = { 0: 'BSD loopback', 1: 'Ethernet', 101: 'Raw IP', 105: 'IEEE 802.11', 108: 'OpenBSD loopback', 113: 'Linux cooked (SLL)', 127: 'IEEE 802.11 + radiotap', 228: 'Raw IPv4', 229: 'Raw IPv6', 276: 'Linux cooked v2 (SLL2)', 12: 'Raw IP', 14: 'Raw IP' };
const DNSTYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY', 257: 'CAA' };
const DNSRCODE = ['No error', 'Format error', 'Server failure', 'No such name', 'Not implemented', 'Refused'];
const DHCPTYPES = ['', 'Discover', 'Offer', 'Request', 'Decline', 'ACK', 'NAK', 'Release', 'Inform'];
const TLSCT = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat' };
const TLSHS = { 0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
const TLSVER = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const TLSEXT = { 0: 'server_name', 1: 'max_fragment_length', 5: 'status_request', 10: 'supported_groups', 11: 'ec_point_formats', 13: 'signature_algorithms', 16: 'application_layer_protocol_negotiation', 18: 'signed_certificate_timestamp', 21: 'padding', 22: 'encrypt_then_mac', 23: 'extended_master_secret', 35: 'session_ticket', 41: 'pre_shared_key', 43: 'supported_versions', 45: 'psk_key_exchange_modes', 51: 'key_share', 57: 'quic_transport_parameters', 65281: 'renegotiation_info', 17513: 'application_settings' };
const ICMPTYPES = { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply' };
const ICMP6TYPES = { 1: 'Destination Unreachable', 2: 'Packet Too Big', 3: 'Time Exceeded', 4: 'Parameter Problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router Solicitation', 134: 'Router Advertisement', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement', 137: 'Redirect', 143: 'Multicast Listener Report v2' };
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'];
const TLS_PORTS = new Set([443, 8443, 465, 993, 995, 636, 853, 5061, 6443, 9443]);

function hex2(n) { return n.toString(16).padStart(2, '0'); }
function hexN(n, w) { return '0x' + (n >>> 0).toString(16).padStart(w, '0'); }
function mac(b, o) { return `${hex2(b[o])}:${hex2(b[o + 1])}:${hex2(b[o + 2])}:${hex2(b[o + 3])}:${hex2(b[o + 4])}:${hex2(b[o + 5])}`; }
function ip4(b, o) { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }
function u16(b, o) { return (b[o] << 8) | b[o + 1]; }
function u32(b, o) { return ((b[o] << 24) >>> 0) + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]); }
function ascii(b, s, e) { let t = ''; for (let i = s; i < e; i++) { const c = b[i]; t += c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; } return t; }
function latin(b, s, e) { let t = ''; for (let i = s; i < e; i++) t += String.fromCharCode(b[i]); return t; }

/** Tree builder: nodes are [label, start, length, children?]. With tree off every call is a no-op. */
class Tree {
  constructor(on) { this.on = on; this.root = []; }
  add(parent, label, s, l) {
    if (!this.on) return null;
    const n = { n: label, s, l };
    (parent ? (parent.c || (parent.c = [])) : this.root).push(n);
    return n;
  }
}

/** Collects filter fields. Multi-valued fields become arrays. */
function setF(f, k, v) {
  const o = f[k];
  if (o === undefined) f[k] = v; else if (Array.isArray(o)) o.push(v); else f[k] = [o, v];
}

function bad(ctx, parent, what, s, l) {
  ctx.malformed = true;
  ctx.t.add(parent, `[Malformed: ${what}]`, s, Math.max(0, l));
  if (!ctx.expert) ctx.expert = what;
}

/**
 * Dissect one packet.
 * @param {Uint8Array} d packet bytes (caplen)
 * @param {number} linktype
 * @param {{tree?:boolean, orig?:number, number?:number}} opts
 */
function dissect(d, linktype, opts = {}) {
  const ctx = { d, end: d.length, t: new Tree(!!opts.tree), f: {}, protos: [], proto: '', src: '', dst: '', info: '', malformed: false, expert: '', l4: null };
  ctx.f['frame.len'] = opts.orig ?? d.length;
  ctx.f['frame.cap_len'] = d.length;
  if (opts.number !== undefined) ctx.f['frame.number'] = opts.number;
  ctx.protos.push('frame');
  const fr = ctx.t.add(null, `Frame ${opts.number ?? ''}: ${opts.orig ?? d.length} bytes on wire, ${d.length} bytes captured${linktype in LINKTYPES ? ` (${LINKTYPES[linktype]})` : ''}`, 0, d.length);
  if (fr) {
    ctx.t.add(fr, `Link type: ${LINKTYPES[linktype] || 'unknown'} (${linktype})`, 0, 0);
    if (opts.time) ctx.t.add(fr, `Arrival time: ${opts.time}`, 0, 0);
    if (opts.comment) ctx.t.add(fr, `Comment: ${opts.comment}`, 0, 0);
    if ((opts.orig ?? d.length) > d.length) ctx.t.add(fr, `[Packet cut to ${d.length} of ${opts.orig} bytes when it was captured]`, 0, 0);
  }
  try {
    link(ctx, linktype);
  } catch (e) {
    bad(ctx, null, 'dissector error ' + (e && e.message), 0, 0);
  }
  if (!ctx.proto) ctx.proto = ctx.protos[ctx.protos.length - 1].toUpperCase();
  if (ctx.malformed && ctx.expert) ctx.info = (ctx.info ? ctx.info + ' ' : '') + `[Malformed: ${ctx.expert}]`;
  for (const p of ctx.protos) setF(ctx.f, '_proto', p);
  return { proto: ctx.proto, src: ctx.src, dst: ctx.dst, info: ctx.info, protos: ctx.protos, f: ctx.f, tree: ctx.t.root, malformed: ctx.malformed, l4: ctx.l4, dnsAnswers: ctx.dnsAnswers || null };
}

function link(ctx, lt) {
  const { d } = ctx;
  if (lt === 1) return ether(ctx, 0);
  if (lt === 101 || lt === 12 || lt === 14 || lt === 228 || lt === 229) return rawip(ctx, 0);
  if (lt === 0 || lt === 108) {
    if (d.length < 4) return bad(ctx, null, 'loopback header shorter than 4 bytes', 0, d.length);
    // The family is in the byte order of the machine that wrote it; 2 is IPv4, 24/28/30 are IPv6.
    let fam = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24);
    if (fam > 0xffff) fam = u32(d, 0);
    const n = ctx.t.add(null, `Null/Loopback, family: ${fam === 2 ? 'IPv4' : [24, 28, 30].includes(fam) ? 'IPv6' : fam} (${fam})`, 0, 4);
    ctx.t.add(n, `Family: ${fam}`, 0, 4);
    ctx.protos.push('null');
    if (fam === 2) return ipv4(ctx, 4);
    if (fam === 24 || fam === 28 || fam === 30) return ipv6(ctx, 4);
    return data(ctx, 4, null);
  }
  if (lt === 113) return sll(ctx);
  if (lt === 276) return sll2(ctx);
  if (lt === 105) return wlan(ctx, 0);
  if (lt === 127) {
    if (d.length < 4) return bad(ctx, null, 'radiotap header too short', 0, d.length);
    const rl = d[2] | (d[3] << 8);
    const n = ctx.t.add(null, `Radiotap header, length ${rl}`, 0, Math.min(rl, d.length));
    ctx.t.add(n, `Header length: ${rl}`, 2, 2);
    ctx.protos.push('radiotap');
    if (rl > d.length) return bad(ctx, null, 'radiotap length past the packet end', 0, d.length);
    return wlan(ctx, rl);
  }
  ctx.proto = LINKTYPES[lt] || `Link type ${lt}`;
  ctx.info = `Link type ${lt} is not decoded; the bytes are in the hex pane.`;
  ctx.t.add(null, `Data (${d.length} bytes, link type ${lt})`, 0, d.length);
}

function ether(ctx, o) {
  const { d } = ctx;
  if (d.length - o < 14) return bad(ctx, null, `Ethernet header needs 14 bytes, ${d.length - o} captured`, o, d.length - o);
  const dst = mac(d, o), src = mac(d, o + 6);
  let type = u16(d, o + 12);
  const n = ctx.t.add(null, `Ethernet II, Src: ${src}, Dst: ${dst}`, o, 14);
  ctx.t.add(n, `Destination: ${dst}`, o, 6);
  ctx.t.add(n, `Source: ${src}`, o + 6, 6);
  ctx.protos.push('eth');
  setF(ctx.f, 'eth.dst', dst); setF(ctx.f, 'eth.src', src); setF(ctx.f, 'eth.addr', dst); setF(ctx.f, 'eth.addr', src);
  ctx.src = src; ctx.dst = dst;
  if (type <= 1500) {
    ctx.t.add(n, `Length: ${type}`, o + 12, 2);
    ctx.proto = 'LLC'; ctx.protos.push('llc');
    ctx.info = `802.3 frame, ${type} bytes`;
    ctx.t.add(null, 'Logical-Link Control', o + 14, Math.min(3, d.length - o - 14));
    return;
  }
  ctx.t.add(n, `Type: ${ETHERTYPES[type] || 'Unknown'} (${hexN(type, 4)})`, o + 12, 2);
  setF(ctx.f, 'eth.type', type);
  return ethertype(ctx, type, o + 14);
}

function ethertype(ctx, type, o) {
  const { d } = ctx;
  if (type === 0x8100 || type === 0x88a8) {
    if (d.length - o < 4) return bad(ctx, null, '802.1Q tag cut off', o, d.length - o);
    const tci = u16(d, o), id = tci & 0x0fff, pcp = tci >> 13, inner = u16(d, o + 2);
    const n = ctx.t.add(null, `802.1Q Virtual LAN, PRI: ${pcp}, DEI: ${(tci >> 12) & 1}, ID: ${id}`, o, 4);
    ctx.t.add(n, `Priority: ${pcp}`, o, 1);
    ctx.t.add(n, `ID: ${id}`, o, 2);
    ctx.t.add(n, `Type: ${ETHERTYPES[inner] || 'Unknown'} (${hexN(inner, 4)})`, o + 2, 2);
    ctx.protos.push('vlan');
    setF(ctx.f, 'vlan.id', id); setF(ctx.f, 'vlan.priority', pcp);
    return ethertype(ctx, inner, o + 4);
  }
  if (type === 0x0800) return ipv4(ctx, o);
  if (type === 0x86dd) return ipv6(ctx, o);
  if (type === 0x0806 || type === 0x8035) return arp(ctx, o);
  ctx.proto = ETHERTYPES[type] || `0x${type.toString(16).padStart(4, '0')}`;
  ctx.protos.push((ETHERTYPES[type] || 'ethertype').toLowerCase().replace(/[^a-z0-9]/g, ''));
  ctx.info = `Ethernet type ${hexN(type, 4)}${ETHERTYPES[type] ? ` (${ETHERTYPES[type]})` : ''}, ${d.length - o} bytes`;
  ctx.t.add(null, `Data (${d.length - o} bytes)`, o, d.length - o);
}

function sll(ctx) {
  const { d } = ctx;
  if (d.length < 16) return bad(ctx, null, 'Linux cooked header needs 16 bytes', 0, d.length);
  const ptype = u16(d, 0), alen = u16(d, 4), proto = u16(d, 14);
  const pt = ['Unicast to us', 'Broadcast', 'Multicast', 'Unicast to another host', 'Sent by us'][ptype] || ptype;
  const addr = alen === 6 ? mac(d, 6) : [...d.subarray(6, 6 + Math.min(alen, 8))].map(hex2).join(':');
  const n = ctx.t.add(null, `Linux cooked capture v1, ${pt}, Source: ${addr}`, 0, 16);
  ctx.t.add(n, `Packet type: ${pt} (${ptype})`, 0, 2);
  ctx.t.add(n, `Link-layer address type: ${u16(d, 2)}`, 2, 2);
  ctx.t.add(n, `Link-layer address length: ${alen}`, 4, 2);
  ctx.t.add(n, `Source: ${addr}`, 6, 8);
  ctx.t.add(n, `Protocol: ${ETHERTYPES[proto] || 'Unknown'} (${hexN(proto, 4)})`, 14, 2);
  ctx.protos.push('sll'); ctx.src = addr;
  setF(ctx.f, 'sll.src', addr);
  return ethertype(ctx, proto, 16);
}

function sll2(ctx) {
  const { d } = ctx;
  if (d.length < 20) return bad(ctx, null, 'Linux cooked v2 header needs 20 bytes', 0, d.length);
  const proto = u16(d, 0), ifindex = u32(d, 4), ptype = d[10], alen = d[11];
  const pt = ['Unicast to us', 'Broadcast', 'Multicast', 'Unicast to another host', 'Sent by us'][ptype] || ptype;
  const addr = alen === 6 ? mac(d, 12) : [...d.subarray(12, 12 + Math.min(alen, 8))].map(hex2).join(':');
  const n = ctx.t.add(null, `Linux cooked capture v2, ${pt}, interface ${ifindex}, Source: ${addr}`, 0, 20);
  ctx.t.add(n, `Protocol: ${ETHERTYPES[proto] || 'Unknown'} (${hexN(proto, 4)})`, 0, 2);
  ctx.t.add(n, `Interface index: ${ifindex}`, 4, 4);
  ctx.t.add(n, `Link-layer address type: ${u16(d, 8)}`, 8, 2);
  ctx.t.add(n, `Packet type: ${pt} (${ptype})`, 10, 1);
  ctx.t.add(n, `Link-layer address length: ${alen}`, 11, 1);
  ctx.t.add(n, `Source: ${addr}`, 12, 8);
  ctx.protos.push('sll'); ctx.src = addr;
  setF(ctx.f, 'sll.src', addr);
  return ethertype(ctx, proto, 20);
}

function wlan(ctx, o) {
  const { d } = ctx;
  if (d.length - o < 10) return bad(ctx, null, '802.11 header too short', o, d.length - o);
  const fc = d[o] | (d[o + 1] << 8), type = (fc >> 2) & 3, sub = (fc >> 4) & 15;
  const kinds = ['Management', 'Control', 'Data', 'Extension'];
  const mgmt = { 0: 'Association Request', 1: 'Association Response', 4: 'Probe Request', 5: 'Probe Response', 8: 'Beacon', 10: 'Disassociation', 11: 'Authentication', 12: 'Deauthentication', 13: 'Action' };
  const ctrl = { 8: 'Block Ack Request', 9: 'Block Ack', 11: 'RTS', 12: 'CTS', 13: 'Ack' };
  const name = type === 0 ? (mgmt[sub] || `Management subtype ${sub}`) : type === 1 ? (ctrl[sub] || `Control subtype ${sub}`) : type === 2 ? (sub & 8 ? 'QoS Data' : 'Data') : 'Extension';
  const a1 = mac(d, o + 4), a2 = d.length - o >= 16 ? mac(d, o + 10) : '';
  const hl = type === 1 ? (d.length - o >= 16 ? 16 : 10) : Math.min(24 + (type === 2 && (sub & 8) ? 2 : 0), d.length - o);
  const n = ctx.t.add(null, `IEEE 802.11 ${name}`, o, hl);
  ctx.t.add(n, `Frame control: ${kinds[type]} frame, subtype ${sub} (${hexN(fc, 4)})`, o, 2);
  ctx.t.add(n, `Duration: ${d[o + 2] | (d[o + 3] << 8)}`, o + 2, 2);
  ctx.t.add(n, `Receiver address: ${a1}`, o + 4, 6);
  if (a2) ctx.t.add(n, `Transmitter address: ${a2}`, o + 10, 6);
  if (type !== 1 && d.length - o >= 24) ctx.t.add(n, `BSS Id: ${mac(d, o + 16)}`, o + 16, 6);
  ctx.protos.push('wlan');
  setF(ctx.f, 'wlan.ra', a1); if (a2) setF(ctx.f, 'wlan.ta', a2);
  ctx.proto = '802.11'; ctx.src = a2 || ''; ctx.dst = a1;
  ctx.info = name + (type === 2 ? ' (body not decoded; 802.11 decoding covers the header only)' : '');
  if (d.length - o > hl) ctx.t.add(null, `Frame body (${d.length - o - hl} bytes, not decoded)`, o + hl, d.length - o - hl);
}

function rawip(ctx, o) {
  const { d } = ctx;
  if (d.length - o < 1) return bad(ctx, null, 'empty packet', o, 0);
  const v = d[o] >> 4;
  ctx.protos.push('raw');
  if (v === 4) return ipv4(ctx, o);
  if (v === 6) return ipv6(ctx, o);
  return bad(ctx, null, `raw IP packet with version ${v}`, o, 1);
}

function arp(ctx, o) {
  const { d } = ctx;
  if (d.length - o < 8) return bad(ctx, null, 'ARP header cut off', o, d.length - o);
  const hlen = d[o + 4], plen = d[o + 5], op = u16(d, o + 6);
  const n = ctx.t.add(null, `Address Resolution Protocol (${op === 1 ? 'request' : op === 2 ? 'reply' : 'opcode ' + op})`, o, Math.min(8 + 2 * hlen + 2 * plen, d.length - o));
  ctx.t.add(n, `Hardware type: ${u16(d, o)}`, o, 2);
  ctx.t.add(n, `Protocol type: ${hexN(u16(d, o + 2), 4)}`, o + 2, 2);
  ctx.t.add(n, `Hardware size: ${hlen}`, o + 4, 1);
  ctx.t.add(n, `Protocol size: ${plen}`, o + 5, 1);
  ctx.t.add(n, `Opcode: ${op === 1 ? 'request' : op === 2 ? 'reply' : op} (${op})`, o + 6, 2);
  ctx.protos.push('arp'); ctx.proto = 'ARP';
  setF(ctx.f, 'arp.opcode', op);
  if (hlen !== 6 || plen !== 4 || d.length - o < 28) { ctx.info = `ARP opcode ${op}`; if (d.length - o < 8 + 2 * hlen + 2 * plen) bad(ctx, n, 'ARP addresses cut off', o + 8, d.length - o - 8); return; }
  const sha = mac(d, o + 8), spa = ip4(d, o + 14), tha = mac(d, o + 18), tpa = ip4(d, o + 24);
  ctx.t.add(n, `Sender MAC address: ${sha}`, o + 8, 6);
  ctx.t.add(n, `Sender IP address: ${spa}`, o + 14, 4);
  ctx.t.add(n, `Target MAC address: ${tha}`, o + 18, 6);
  ctx.t.add(n, `Target IP address: ${tpa}`, o + 24, 4);
  setF(ctx.f, 'arp.src.proto_ipv4', spa); setF(ctx.f, 'arp.dst.proto_ipv4', tpa); setF(ctx.f, 'arp.src.hw_mac', sha);
  ctx.info = op === 1 ? `Who has ${tpa}? Tell ${spa}` : op === 2 ? `${spa} is at ${sha}` : `ARP opcode ${op}`;
}

function ipv4(ctx, o) {
  const { d } = ctx;
  if (d.length - o < 20) return bad(ctx, null, `IPv4 header needs 20 bytes, ${d.length - o} captured`, o, d.length - o);
  const ver = d[o] >> 4, ihl = (d[o] & 15) * 4, tos = d[o + 1], tlen = u16(d, o + 2), id = u16(d, o + 4);
  const fl = u16(d, o + 6), ttl = d[o + 8], proto = d[o + 9], ck = u16(d, o + 10);
  const src = ip4(d, o + 12), dst = ip4(d, o + 16);
  const n = ctx.t.add(null, `Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, o, Math.min(Math.max(ihl, 20), d.length - o));
  ctx.t.add(n, `Version: ${ver}`, o, 1);
  ctx.t.add(n, `Header length: ${ihl} bytes (${d[o] & 15})`, o, 1);
  ctx.t.add(n, `Differentiated services: ${hexN(tos, 2)} (DSCP ${tos >> 2}, ECN ${tos & 3})`, o + 1, 1);
  ctx.t.add(n, `Total length: ${tlen}`, o + 2, 2);
  ctx.t.add(n, `Identification: ${hexN(id, 4)} (${id})`, o + 4, 2);
  const df = (fl >> 14) & 1, mf = (fl >> 13) & 1, foff = (fl & 0x1fff) * 8;
  ctx.t.add(n, `Flags: ${hexN(fl >> 13, 1)}${df ? ', Don\'t fragment' : ''}${mf ? ', More fragments' : ''}; fragment offset ${foff}`, o + 6, 2);
  ctx.t.add(n, `Time to live: ${ttl}`, o + 8, 1);
  ctx.t.add(n, `Protocol: ${IPPROTO[proto] || 'Unknown'} (${proto})`, o + 9, 1);
  ctx.t.add(n, `Header checksum: ${hexN(ck, 4)}`, o + 10, 2);
  ctx.t.add(n, `Source address: ${src}`, o + 12, 4);
  ctx.t.add(n, `Destination address: ${dst}`, o + 16, 4);
  ctx.protos.push('ip');
  const F = ctx.f;
  setF(F, 'ip.src', src); setF(F, 'ip.dst', dst); setF(F, 'ip.addr', src); setF(F, 'ip.addr', dst);
  setF(F, 'ip.proto', proto); setF(F, 'ip.ttl', ttl); setF(F, 'ip.len', tlen); setF(F, 'ip.id', id); setF(F, 'ip.version', 4);
  setF(F, 'ip.flags.df', df); setF(F, 'ip.flags.mf', mf); setF(F, 'ip.frag_offset', foff);
  ctx.src = src; ctx.dst = dst; ctx.proto = 'IPv4';
  ctx.info = `${IPPROTO[proto] || 'Protocol ' + proto}`;
  if (ver !== 4) return bad(ctx, n, `IP version field is ${ver}, not 4`, o, 1);
  if (ihl < 20) return bad(ctx, n, `IPv4 header length ${ihl} is less than 20 bytes (IHL ${d[o] & 15} < 5)`, o, 1);
  if (o + ihl > d.length) return bad(ctx, n, `IPv4 header length ${ihl} goes past the captured data`, o, d.length - o);
  if (ihl > 20) ctx.t.add(n, `Options (${ihl - 20} bytes)`, o + 20, ihl - 20);
  if (tlen < ihl) return bad(ctx, n, `IPv4 total length ${tlen} is less than the header length ${ihl}`, o + 2, 2);
  const end = Math.min(d.length, o + tlen);
  if (o + tlen > d.length && ctx.f['frame.len'] === d.length) bad(ctx, n, `IPv4 total length ${tlen} is more than the ${d.length - o} bytes in the packet`, o + 2, 2);
  if (foff > 0) {
    ctx.info = `Fragmented IP protocol (proto=${IPPROTO[proto] || proto} ${proto}, off=${foff}, ID=${id.toString(16)})`;
    ctx.proto = 'IPv4';
    ctx.t.add(null, `Fragment data (${end - o - ihl} bytes)`, o + ihl, end - o - ihl);
    return;
  }
  ctx.ipEnd = end;
  return ipPayload(ctx, proto, o + ihl, end, src, dst, 4, ttl);
}

function ipv6(ctx, o) {
  const { d } = ctx;
  if (d.length - o < 40) return bad(ctx, null, `IPv6 header needs 40 bytes, ${d.length - o} captured`, o, d.length - o);
  const vtf = u32(d, o), plen = u16(d, o + 4);
  let nxt = d[o + 6];
  const hlim = d[o + 7], src = ipv6Str(d, o + 8), dst = ipv6Str(d, o + 24);
  const n = ctx.t.add(null, `Internet Protocol Version 6, Src: ${src}, Dst: ${dst}`, o, 40);
  ctx.t.add(n, `Version: ${vtf >>> 28}`, o, 1);
  ctx.t.add(n, `Traffic class: ${hexN((vtf >>> 20) & 0xff, 2)}`, o, 2);
  ctx.t.add(n, `Flow label: ${hexN(vtf & 0xfffff, 5)}`, o + 1, 3);
  ctx.t.add(n, `Payload length: ${plen}`, o + 4, 2);
  ctx.t.add(n, `Next header: ${IPPROTO[nxt] || 'Unknown'} (${nxt})`, o + 6, 1);
  ctx.t.add(n, `Hop limit: ${hlim}`, o + 7, 1);
  ctx.t.add(n, `Source address: ${src}`, o + 8, 16);
  ctx.t.add(n, `Destination address: ${dst}`, o + 24, 16);
  ctx.protos.push('ipv6');
  const F = ctx.f;
  setF(F, 'ipv6.src', src); setF(F, 'ipv6.dst', dst); setF(F, 'ipv6.addr', src); setF(F, 'ipv6.addr', dst);
  setF(F, 'ipv6.hlim', hlim); setF(F, 'ipv6.plen', plen);
  ctx.src = src; ctx.dst = dst; ctx.proto = 'IPv6'; ctx.info = 'IPv6';
  const end = Math.min(d.length, o + 40 + plen);
  let p = o + 40;
  // Extension headers: Hop-by-Hop, Routing, Destination Options and Fragment.
  for (let k = 0; k < 8 && [0, 43, 60, 44, 51].includes(nxt); k++) {
    if (p + 8 > end) return bad(ctx, null, `IPv6 ${IPPROTO[nxt]} header cut off`, p, end - p);
    const hn = d[p], hl = nxt === 44 ? 8 : nxt === 51 ? (d[p + 1] + 2) * 4 : (d[p + 1] + 1) * 8;
    if (p + hl > end) return bad(ctx, null, `IPv6 ${IPPROTO[nxt]} header length ${hl} goes past the packet`, p, end - p);
    const e = ctx.t.add(null, `IPv6 ${IPPROTO[nxt]} header`, p, hl);
    ctx.t.add(e, `Next header: ${IPPROTO[hn] || 'Unknown'} (${hn})`, p, 1);
    ctx.t.add(e, `Length: ${hl} bytes`, p + 1, 1);
    setF(F, 'ipv6.ext', nxt);
    if (nxt === 0) ctx.protos.push('ipv6.hopopts');
    if (nxt === 44) {
      const fo = u16(d, p + 2) & 0xfff8;
      ctx.t.add(e, `Offset: ${fo}, More fragments: ${d[p + 3] & 1}`, p + 2, 2);
      if (fo > 0) { ctx.info = `IPv6 fragment (off=${fo})`; return; }
    }
    nxt = hn; p += hl;
  }
  setF(F, 'ipv6.nxt', nxt);
  ctx.ipEnd = end;
  return ipPayload(ctx, nxt, p, end, src, dst, 6, hlim);
}

function ipPayload(ctx, proto, o, end, src, dst, ver, ttl) {
  if (proto === 6) return tcp(ctx, o, end, src, dst, ver);
  if (proto === 17) return udp(ctx, o, end, src, dst, ver);
  if (proto === 1) return icmp(ctx, o, end, ttl);
  if (proto === 58) return icmpv6(ctx, o, end);
  if (proto === 4) { ctx.protos.push('ipip'); return ipv4(ctx, o); }
  if (proto === 41) return ipv6(ctx, o);
  ctx.proto = IPPROTO[proto] || (ver === 4 ? 'IPv4' : 'IPv6');
  ctx.protos.push((IPPROTO[proto] || 'ipproto').toLowerCase().replace(/[^a-z0-9]/g, ''));
  ctx.info = `${IPPROTO[proto] || 'IP protocol ' + proto}, ${end - o} bytes`;
  if (end > o) ctx.t.add(null, `${IPPROTO[proto] || 'Data'} (${end - o} bytes)`, o, end - o);
}

function icmp(ctx, o, end, ttl) {
  const { d } = ctx;
  if (end - o < 4) return bad(ctx, null, 'ICMP header cut off', o, end - o);
  const type = d[o], code = d[o + 1];
  const n = ctx.t.add(null, 'Internet Control Message Protocol', o, end - o);
  ctx.t.add(n, `Type: ${type} (${ICMPTYPES[type] || 'Unknown'})`, o, 1);
  ctx.t.add(n, `Code: ${code}`, o + 1, 1);
  ctx.t.add(n, `Checksum: ${hexN(u16(d, o + 2), 4)}`, o + 2, 2);
  ctx.protos.push('icmp'); ctx.proto = 'ICMP';
  setF(ctx.f, 'icmp.type', type); setF(ctx.f, 'icmp.code', code);
  ctx.info = ICMPTYPES[type] || `Type ${type}, code ${code}`;
  if ((type === 0 || type === 8 || type === 13 || type === 14) && end - o >= 8) {
    const id = u16(d, o + 4), seq = u16(d, o + 6);
    ctx.t.add(n, `Identifier (BE): ${id} (${hexN(id, 4)})`, o + 4, 2);
    ctx.t.add(n, `Sequence number (BE): ${seq} (${hexN(seq, 4)})`, o + 6, 2);
    if (end - o > 8) ctx.t.add(n, `Data (${end - o - 8} bytes)`, o + 8, end - o - 8);
    setF(ctx.f, 'icmp.ident', id); setF(ctx.f, 'icmp.seq', seq);
    ctx.info += ` id=${hexN(id, 4)}, seq=${seq}/${((seq & 0xff) << 8) | (seq >> 8)}, ttl=${ttl}`;
  } else if (end - o > 8) ctx.t.add(n, `Data (${end - o - 8} bytes)`, o + 8, end - o - 8);
}

function icmpv6(ctx, o, end) {
  const { d } = ctx;
  if (end - o < 4) return bad(ctx, null, 'ICMPv6 header cut off', o, end - o);
  const type = d[o], code = d[o + 1];
  const n = ctx.t.add(null, 'Internet Control Message Protocol v6', o, end - o);
  ctx.t.add(n, `Type: ${ICMP6TYPES[type] || 'Unknown'} (${type})`, o, 1);
  ctx.t.add(n, `Code: ${code}`, o + 1, 1);
  ctx.t.add(n, `Checksum: ${hexN(u16(d, o + 2), 4)}`, o + 2, 2);
  ctx.protos.push('icmpv6'); ctx.proto = 'ICMPv6';
  setF(ctx.f, 'icmpv6.type', type); setF(ctx.f, 'icmpv6.code', code);
  ctx.info = ICMP6TYPES[type] || `Type ${type}`;
  if ((type === 128 || type === 129) && end - o >= 8) {
    const id = u16(d, o + 4), seq = u16(d, o + 6);
    ctx.t.add(n, `Identifier: ${hexN(id, 4)}`, o + 4, 2);
    ctx.t.add(n, `Sequence: ${seq}`, o + 6, 2);
    setF(ctx.f, 'icmpv6.echo.seq', seq);
    ctx.info += ` id=${hexN(id, 4)}, seq=${seq}`;
  }
  if ((type === 135 || type === 136) && end - o >= 24) {
    const tgt = ipv6Str(d, o + 8);
    ctx.t.add(n, `Target address: ${tgt}`, o + 8, 16);
    setF(ctx.f, 'icmpv6.nd.target', tgt);
    ctx.info += type === 135 ? ` for ${tgt}` : ` ${tgt}`;
  }
}

function tcp(ctx, o, end, src, dst, ver) {
  const { d } = ctx;
  if (end - o < 20) return bad(ctx, null, `TCP header needs 20 bytes, ${end - o} captured`, o, end - o);
  const sp = u16(d, o), dp = u16(d, o + 2), seq = u32(d, o + 4), ack = u32(d, o + 8);
  const doff = (d[o + 12] >> 4) * 4, flags = ((d[o + 12] & 1) << 8) | d[o + 13], win = u16(d, o + 14);
  const names = [];
  const FL = [[0x02, 'SYN'], [0x10, 'ACK'], [0x01, 'FIN'], [0x04, 'RST'], [0x08, 'PSH'], [0x20, 'URG'], [0x40, 'ECE'], [0x80, 'CWR']];
  for (const [b, nm] of FL) if (flags & b) names.push(nm);
  const n = ctx.t.add(null, `Transmission Control Protocol, Src Port: ${sp}, Dst Port: ${dp}, Seq: ${seq}${flags & 0x10 ? `, Ack: ${ack}` : ''}`, o, Math.min(Math.max(doff, 20), end - o));
  ctx.t.add(n, `Source port: ${sp}`, o, 2);
  ctx.t.add(n, `Destination port: ${dp}`, o + 2, 2);
  ctx.t.add(n, `Sequence number: ${seq}`, o + 4, 4);
  ctx.t.add(n, `Acknowledgment number: ${ack}`, o + 8, 4);
  ctx.t.add(n, `Header length: ${doff} bytes (${d[o + 12] >> 4})`, o + 12, 1);
  ctx.t.add(n, `Flags: ${hexN(flags, 3)} (${names.join(', ') || 'none'})`, o + 12, 2);
  ctx.t.add(n, `Window: ${win}`, o + 14, 2);
  ctx.t.add(n, `Checksum: ${hexN(u16(d, o + 16), 4)}`, o + 16, 2);
  ctx.t.add(n, `Urgent pointer: ${u16(d, o + 18)}`, o + 18, 2);
  ctx.protos.push('tcp'); ctx.proto = 'TCP';
  const F = ctx.f;
  setF(F, 'tcp.srcport', sp); setF(F, 'tcp.dstport', dp); setF(F, 'tcp.port', sp); setF(F, 'tcp.port', dp);
  setF(F, 'tcp.seq', seq); setF(F, 'tcp.ack', ack); setF(F, 'tcp.window_size', win); setF(F, 'tcp.flags', flags);
  setF(F, 'tcp.flags.syn', flags & 2 ? 1 : 0); setF(F, 'tcp.flags.ack', flags & 16 ? 1 : 0); setF(F, 'tcp.flags.fin', flags & 1 ? 1 : 0);
  setF(F, 'tcp.flags.reset', flags & 4 ? 1 : 0); setF(F, 'tcp.flags.push', flags & 8 ? 1 : 0);
  ctx.info = `${sp} → ${dp} [${names.join(', ')}] Seq=${seq}${flags & 0x10 ? ` Ack=${ack}` : ''} Win=${win}`;
  if (doff < 20) { setF(F, 'tcp.len', 0); return bad(ctx, n, `TCP header length ${doff} is less than 20 bytes`, o + 12, 1); }
  if (o + doff > end) { setF(F, 'tcp.len', 0); return bad(ctx, n, `TCP data offset ${doff} goes past the end of the packet (${end - o} TCP bytes)`, o + 12, 1); }
  if (doff > 20) tcpOptions(ctx, n, o + 20, o + doff);
  const plen = end - (o + doff);
  setF(F, 'tcp.len', plen);
  ctx.info += ` Len=${plen}`;
  ctx.l4 = { proto: 'tcp', src, dst, sp, dp, off: o + doff, len: plen, seq, flags };
  if (plen <= 0) return;
  return tcpPayload(ctx, o + doff, end, sp, dp);
}

function tcpOptions(ctx, parent, o, end) {
  const { d } = ctx;
  const n = ctx.t.add(parent, `Options (${end - o} bytes)`, o, end - o);
  const parts = [];
  while (o < end) {
    const k = d[o];
    if (k === 0) { ctx.t.add(n, 'End of option list', o, 1); break; }
    if (k === 1) { ctx.t.add(n, 'No-operation (NOP)', o, 1); o++; continue; }
    if (o + 1 >= end) break;
    const l = d[o + 1];
    if (l < 2 || o + l > end) { bad(ctx, n, 'TCP option length is wrong', o, end - o); break; }
    let label = `Option kind ${k}`;
    if (k === 2 && l === 4) { label = `Maximum segment size: ${u16(d, o + 2)} bytes`; parts.push(`MSS=${u16(d, o + 2)}`); }
    else if (k === 3 && l === 3) { label = `Window scale: ${d[o + 2]} (multiply by ${1 << Math.min(d[o + 2], 14)})`; parts.push(`WS=${1 << Math.min(d[o + 2], 14)}`); }
    else if (k === 4) { label = 'SACK permitted'; parts.push('SACK_PERM'); }
    else if (k === 5) label = `SACK (${(l - 2) / 8} blocks)`;
    else if (k === 8 && l === 10) { label = `Timestamps: TSval ${u32(d, o + 2)}, TSecr ${u32(d, o + 6)}`; parts.push(`TSval=${u32(d, o + 2)}`); }
    ctx.t.add(n, label, o, l);
    o += l;
  }
  if (parts.length) ctx.tcpOpt = parts.join(' ');
}

function looksTls(d, o, end) {
  return end - o >= 5 && d[o] >= 20 && d[o] <= 24 && d[o + 1] === 3 && d[o + 2] <= 4;
}

function isHttpStart(d, o, end) {
  const head = latin(d, o, Math.min(end, o + 8));
  if (head.startsWith('HTTP/1.')) return true;
  for (const m of HTTP_METHODS) if (head.startsWith(m + ' ')) return true;
  return false;
}

function tcpPayload(ctx, o, end, sp, dp) {
  const { d } = ctx;
  if ((sp === 53 || dp === 53) && end - o >= 14) {
    const l = u16(d, o);
    const n = ctx.t.add(null, `DNS over TCP, length ${l}`, o, 2);
    if (n) n.n = `Length: ${l}`;
    return dns(ctx, o + 2, Math.min(end, o + 2 + l), false);
  }
  if (isHttpStart(d, o, end)) return http(ctx, o, end);
  if (looksTls(d, o, end) && (TLS_PORTS.has(sp) || TLS_PORTS.has(dp) || d[o] === 22)) return tls(ctx, o, end);
  if (TLS_PORTS.has(sp) || TLS_PORTS.has(dp)) {
    ctx.t.add(null, `TLS continuation data (${end - o} bytes)`, o, end - o);
    ctx.proto = 'TLS'; ctx.protos.push('tls'); ctx.info = `Continuation data, ${end - o} bytes`;
    return;
  }
  if (sp === 80 || dp === 80 || sp === 8080 || dp === 8080) {
    ctx.t.add(null, `HTTP continuation or body (${end - o} bytes)`, o, end - o);
    ctx.protos.push('http'); ctx.proto = 'HTTP'; ctx.info = `Continuation, ${end - o} bytes: ${ascii(d, o, Math.min(end, o + 40))}`;
    setF(ctx.f, 'http.continuation', 1);
    return;
  }
  data(ctx, o, end);
}

function data(ctx, o, end) {
  end = end ?? ctx.d.length;
  if (end <= o) return;
  ctx.t.add(null, `Data (${end - o} bytes): ${ascii(ctx.d, o, Math.min(end, o + 48))}`, o, end - o);
  ctx.protos.push('data');
  setF(ctx.f, 'data.len', end - o);
}

function udp(ctx, o, end, src, dst, ver) {
  const { d } = ctx;
  if (end - o < 8) return bad(ctx, null, `UDP header needs 8 bytes, ${end - o} captured`, o, end - o);
  const sp = u16(d, o), dp = u16(d, o + 2), len = u16(d, o + 4);
  const n = ctx.t.add(null, `User Datagram Protocol, Src Port: ${sp}, Dst Port: ${dp}`, o, 8);
  ctx.t.add(n, `Source port: ${sp}`, o, 2);
  ctx.t.add(n, `Destination port: ${dp}`, o + 2, 2);
  ctx.t.add(n, `Length: ${len}`, o + 4, 2);
  ctx.t.add(n, `Checksum: ${hexN(u16(d, o + 6), 4)}`, o + 6, 2);
  ctx.protos.push('udp'); ctx.proto = 'UDP';
  const F = ctx.f;
  setF(F, 'udp.srcport', sp); setF(F, 'udp.dstport', dp); setF(F, 'udp.port', sp); setF(F, 'udp.port', dp); setF(F, 'udp.length', len);
  ctx.info = `${sp} → ${dp} Len=${Math.max(0, len - 8)}`;
  let pend = end;
  if (len < 8) bad(ctx, n, `UDP length ${len} is less than 8`, o + 4, 2);
  else if (o + len > end) { if (ctx.f['frame.len'] === d.length) bad(ctx, n, `UDP length ${len} is more than the ${end - o} bytes in the packet`, o + 4, 2); }
  else pend = o + len;
  const p = o + 8;
  ctx.l4 = { proto: 'udp', src, dst, sp, dp, off: p, len: Math.max(0, pend - p) };
  if (pend <= p) return;
  if (sp === 53 || dp === 53 || sp === 5353 || dp === 5353 || sp === 5355 || dp === 5355) return dns(ctx, p, pend, sp === 5353 || dp === 5353);
  if ((sp === 67 || sp === 68) && (dp === 67 || dp === 68)) return dhcp(ctx, p, pend);
  if ((sp === 443 || dp === 443 || sp === 4433 || dp === 4433) && quic(ctx, p, pend)) return;
  data(ctx, p, pend);
}

/** Read a DNS name with compression; at most 128 jumps and 255 characters, so a pointer loop ends. */
function dnsName(d, o, start, end) {
  const labels = []; let jumps = 0, len = 0, next = -1, p = o, bad = '';
  while (true) {
    if (p >= end) { bad = 'name runs past the end'; break; }
    const l = d[p];
    if (l === 0) { p++; break; }
    if ((l & 0xc0) === 0xc0) {
      if (p + 1 >= end) { bad = 'compression pointer cut off'; break; }
      const ptr = start + (((l & 0x3f) << 8) | d[p + 1]);
      if (next < 0) next = p + 2;
      if (++jumps > 128 || ptr >= end || ptr === p) { bad = 'compression pointer loop'; break; }
      p = ptr; continue;
    }
    if (l & 0xc0) { bad = 'bad label type'; break; }
    if (p + 1 + l > end) { bad = 'label runs past the end'; break; }
    labels.push(latin(d, p + 1, p + 1 + l)); len += l + 1;
    if (len > 255) { bad = 'name longer than 255 bytes'; break; }
    p += 1 + l;
  }
  return { name: labels.join('.') || '<Root>', next: next >= 0 ? next : p, bad };
}

function dns(ctx, o, end, mdns) {
  const { d } = ctx;
  ctx.protos.push(mdns ? 'mdns' : 'dns'); ctx.proto = mdns ? 'MDNS' : 'DNS';
  if (end - o < 12) return bad(ctx, null, 'DNS header cut off', o, end - o);
  const id = u16(d, o), fl = u16(d, o + 2), qd = u16(d, o + 4), an = u16(d, o + 6), ns = u16(d, o + 8), ar = u16(d, o + 10);
  const resp = fl >> 15, opcode = (fl >> 11) & 15, rcode = fl & 15;
  const n = ctx.t.add(null, `Domain Name System (${resp ? 'response' : 'query'})`, o, end - o);
  ctx.t.add(n, `Transaction ID: ${hexN(id, 4)}`, o, 2);
  const fn = ctx.t.add(n, `Flags: ${hexN(fl, 4)} ${resp ? 'Standard query response' : 'Standard query'}${resp ? ', ' + (DNSRCODE[rcode] || 'rcode ' + rcode) : ''}`, o + 2, 2);
  ctx.t.add(fn, `Response: ${resp ? 'Message is a response' : 'Message is a query'}`, o + 2, 1);
  ctx.t.add(fn, `Recursion desired: ${(fl >> 8) & 1}`, o + 2, 1);
  if (resp) ctx.t.add(fn, `Reply code: ${DNSRCODE[rcode] || rcode} (${rcode})`, o + 3, 1);
  ctx.t.add(n, `Questions: ${qd}`, o + 4, 2);
  ctx.t.add(n, `Answer RRs: ${an}`, o + 6, 2);
  ctx.t.add(n, `Authority RRs: ${ns}`, o + 8, 2);
  ctx.t.add(n, `Additional RRs: ${ar}`, o + 10, 2);
  const F = ctx.f;
  setF(F, 'dns.id', id); setF(F, 'dns.flags.response', resp); setF(F, 'dns.flags.rcode', rcode);
  let p = o + 12;
  const qs = [], ans = [];
  const qn = qd ? ctx.t.add(n, 'Queries', p, 0) : null;
  for (let i = 0; i < Math.min(qd, 64); i++) {
    const nm = dnsName(d, p, o, end);
    if (nm.bad) { bad(ctx, n, `DNS ${nm.bad}`, p, end - p); return dnsInfo(ctx, id, resp, rcode, qs, ans, opcode); }
    if (nm.next + 4 > end) { bad(ctx, n, 'DNS question cut off', p, end - p); return dnsInfo(ctx, id, resp, rcode, qs, ans, opcode); }
    const t = u16(d, nm.next), c = u16(d, nm.next + 2);
    ctx.t.add(qn, `${nm.name}: type ${DNSTYPES[t] || t}, class ${c === 1 ? 'IN' : c & 0x7fff}`, p, nm.next + 4 - p);
    setF(F, 'dns.qry.name', nm.name); setF(F, 'dns.qry.type', t);
    qs.push([nm.name, t]);
    p = nm.next + 4;
  }
  if (qn) qn.l = p - qn.s;
  const secs = [['Answers', an], ['Authoritative nameservers', ns], ['Additional records', ar]];
  for (const [title, count] of secs) {
    if (!count) continue;
    const sn = ctx.t.add(n, title, p, 0);
    for (let i = 0; i < Math.min(count, 256); i++) {
      const nm = dnsName(d, p, o, end);
      if (nm.bad) { bad(ctx, sn || n, `DNS ${nm.bad}`, p, end - p); return dnsInfo(ctx, id, resp, rcode, qs, ans, opcode); }
      const q = nm.next;
      if (q + 10 > end) { bad(ctx, sn || n, 'DNS record cut off', p, end - p); return dnsInfo(ctx, id, resp, rcode, qs, ans, opcode); }
      const t = u16(d, q), ttl = u32(d, q + 4), rl = u16(d, q + 8), r = q + 10;
      if (r + rl > end) { bad(ctx, sn || n, 'DNS record data runs past the end', p, end - p); return dnsInfo(ctx, id, resp, rcode, qs, ans, opcode); }
      let val = `${rl} bytes`;
      if (t === 1 && rl === 4) { val = ip4(d, r); if (title === 'Answers') setF(F, 'dns.a', val); }
      else if (t === 28 && rl === 16) { val = ipv6Str(d, r); if (title === 'Answers') setF(F, 'dns.aaaa', val); }
      else if (t === 5 || t === 2 || t === 12) { const x = dnsName(d, r, o, end); val = x.bad ? `[${x.bad}]` : x.name; if (t === 5) setF(F, 'dns.cname', val); if (t === 12) setF(F, 'dns.ptr.domain_name', val); }
      else if (t === 15 && rl >= 3) { const x = dnsName(d, r + 2, o, end); val = `${u16(d, r)} ${x.name}`; }
      else if (t === 16) { val = '"' + ascii(d, r + 1, Math.min(r + rl, r + 1 + d[r])) + '"'; }
      else if (t === 41) val = `OPT, UDP payload size ${u16(d, q + 2)}`;
      ctx.t.add(sn, `${nm.name}: type ${DNSTYPES[t] || t}${t === 41 ? '' : `, ttl ${ttl}`}, ${val}`, p, r + rl - p);
      if (title === 'Answers') { ans.push([nm.name, t, val]); setF(F, 'dns.resp.name', nm.name); }
      p = r + rl;
    }
    if (sn) sn.l = p - sn.s;
  }
  setF(F, 'dns.count.answers', an);
  return dnsInfo(ctx, id, resp, rcode, qs, ans, opcode);
}

function dnsInfo(ctx, id, resp, rcode, qs, ans, opcode) {
  const q = qs.map(([nm, t]) => `${DNSTYPES[t] || t} ${nm}`).join(' ');
  let s = `Standard query${resp ? ' response' : ''} ${hexN(id, 4)}${opcode ? ` opcode ${opcode}` : ''}${resp && rcode ? ' ' + (DNSRCODE[rcode] || 'rcode ' + rcode) : ''} ${q}`;
  if (ans.length) s += ' ' + ans.slice(0, 6).map(([, t, v]) => `${DNSTYPES[t] || t} ${v}`).join(' ') + (ans.length > 6 ? ' ...' : '');
  ctx.info = s.trim();
  ctx.dnsAnswers = ans;
}

function dhcp(ctx, o, end) {
  const { d } = ctx;
  ctx.protos.push('dhcp'); ctx.proto = 'DHCP';
  if (end - o < 240) return bad(ctx, null, 'DHCP message shorter than 240 bytes', o, end - o);
  const op = d[o], xid = u32(d, o + 4);
  const ci = ip4(d, o + 12), yi = ip4(d, o + 16), si = ip4(d, o + 20), ch = mac(d, o + 28);
  const n = ctx.t.add(null, 'Dynamic Host Configuration Protocol', o, end - o);
  ctx.t.add(n, `Message type: ${op === 1 ? 'Boot Request' : 'Boot Reply'} (${op})`, o, 1);
  ctx.t.add(n, `Transaction ID: ${hexN(xid, 8)}`, o + 4, 4);
  ctx.t.add(n, `Client IP address: ${ci}`, o + 12, 4);
  ctx.t.add(n, `Your (client) IP address: ${yi}`, o + 16, 4);
  ctx.t.add(n, `Next server IP address: ${si}`, o + 20, 4);
  ctx.t.add(n, `Client MAC address: ${ch}`, o + 28, 6);
  setF(ctx.f, 'dhcp.id', xid); setF(ctx.f, 'dhcp.ip.your', yi); setF(ctx.f, 'dhcp.hw.mac_addr', ch);
  let type = 0;
  if (u32(d, o + 236) !== 0x63825363) { ctx.info = `BOOTP ${op === 1 ? 'request' : 'reply'} - Transaction ID ${hexN(xid, 8)}`; ctx.proto = 'BOOTP'; return; }
  ctx.t.add(n, 'Magic cookie: DHCP', o + 236, 4);
  let p = o + 240;
  const ON = { 1: 'Subnet Mask', 3: 'Router', 6: 'Domain Name Server', 12: 'Host Name', 15: 'Domain Name', 50: 'Requested IP Address', 51: 'IP Address Lease Time', 53: 'DHCP Message Type', 54: 'DHCP Server Identifier', 55: 'Parameter Request List', 57: 'Maximum DHCP Message Size', 60: 'Vendor class identifier', 61: 'Client identifier', 81: 'Client Fully Qualified Domain Name' };
  while (p < end) {
    const k = d[p];
    if (k === 255) { ctx.t.add(n, 'Option: (255) End', p, 1); break; }
    if (k === 0) { p++; continue; }
    if (p + 1 >= end || p + 2 + d[p + 1] > end) { bad(ctx, n, 'DHCP option runs past the end', p, end - p); break; }
    const l = d[p + 1], v = p + 2;
    let val = '';
    if (k === 53 && l >= 1) { type = d[v]; val = DHCPTYPES[type] || String(type); setF(ctx.f, 'dhcp.option.dhcp', type); }
    else if ((k === 1 || k === 3 || k === 6 || k === 50 || k === 54) && l >= 4) { const ips = []; for (let i = 0; i + 4 <= l; i += 4) ips.push(ip4(d, v + i)); val = ips.join(', '); if (k === 50) setF(ctx.f, 'dhcp.option.requested_ip_address', ips[0]); }
    else if (k === 12 || k === 15 || k === 60) { val = ascii(d, v, v + l); if (k === 12) setF(ctx.f, 'dhcp.option.hostname', val); }
    else if (k === 51 && l === 4) val = `${u32(d, v)} s`;
    else val = `${l} bytes`;
    ctx.t.add(n, `Option: (${k}) ${ON[k] || 'Option'}${val ? ': ' + val : ''}`, p, 2 + l);
    p = v + l;
  }
  ctx.info = `DHCP ${DHCPTYPES[type] || 'message'} - Transaction ID ${hexN(xid, 8)}`;
}

function http(ctx, o, end) {
  const { d } = ctx;
  ctx.protos.push('http'); ctx.proto = 'HTTP';
  // Headers end at the first empty line; look at most 64 KB.
  const lim = Math.min(end, o + 65536);
  let hend = -1;
  for (let i = o; i + 3 < lim; i++) if (d[i] === 13 && d[i + 1] === 10 && d[i + 2] === 13 && d[i + 3] === 10) { hend = i + 4; break; }
  const n = ctx.t.add(null, 'Hypertext Transfer Protocol', o, (hend > 0 ? hend : lim) - o);
  let p = o, first = true;
  const F = ctx.f;
  let ctype = '';
  while (p < (hend > 0 ? hend - 2 : lim)) {
    let e = p; while (e < lim && !(d[e] === 13 && d[e + 1] === 10) && d[e] !== 10) e++;
    const line = latin(d, p, e);
    const ll = e - p + (d[e] === 13 ? 2 : 1);
    if (first) {
      first = false;
      ctx.t.add(n, line, p, ll);
      const m = /^([A-Z]+) (\S+) (HTTP\/\d\.\d)/.exec(line);
      const r = /^(HTTP\/\d\.\d) (\d{3}) ?(.*)$/.exec(line);
      if (m) { setF(F, 'http.request.method', m[1]); setF(F, 'http.request.uri', m[2]); setF(F, 'http.request', 1); ctx.info = line; }
      else if (r) { setF(F, 'http.response.code', Number(r[2])); setF(F, 'http.response.phrase', r[3]); setF(F, 'http.response', 1); ctx.info = line; }
      else ctx.info = line.slice(0, 120);
    } else if (line) {
      ctx.t.add(n, line, p, ll);
      const c = line.indexOf(':');
      if (c > 0) {
        const k = line.slice(0, c).trim().toLowerCase(), v = line.slice(c + 1).trim();
        if (k === 'host') setF(F, 'http.host', v);
        if (k === 'user-agent') setF(F, 'http.user_agent', v);
        if (k === 'content-type') { setF(F, 'http.content_type', v); ctype = v.split(';')[0]; }
        if (k === 'content-length') setF(F, 'http.content_length', Number(v) || 0);
        if (k === 'server') setF(F, 'http.server', v);
        if (k === 'cookie') setF(F, 'http.cookie', v);
      }
    }
    p = e + (d[e] === 13 ? 2 : 1);
  }
  if (hend < 0) ctx.t.add(n, '[Headers continue in the next segment]', lim, 0);
  else if (hend < end) ctx.t.add(null, `Body (${end - hend} bytes${ctype ? ', ' + ctype : ''}): ${ascii(d, hend, Math.min(end, hend + 48))}`, hend, end - hend);
  if (ctype && F['http.response']) ctx.info += `  (${ctype})`;
}

function tls(ctx, o, end) {
  const { d } = ctx;
  ctx.protos.push('tls'); ctx.proto = 'TLS';
  const infos = [];
  let p = o, helloVer = 0;
  for (let k = 0; k < 32 && p + 5 <= end; k++) {
    const ct = d[p], rv = u16(d, p + 1), rl = u16(d, p + 3);
    if (ct < 20 || ct > 24 || d[p + 1] !== 3) { ctx.t.add(null, `TLS data (${end - p} bytes, not a record start)`, p, end - p); break; }
    const avail = Math.min(rl, end - p - 5);
    const n = ctx.t.add(null, `Transport Layer Security, ${TLSVER[rv] || hexN(rv, 4)} Record: ${TLSCT[ct]}${avail < rl ? ` [${avail} of ${rl} bytes in this segment]` : ''}`, p, 5 + avail);
    ctx.t.add(n, `Content type: ${TLSCT[ct]} (${ct})`, p, 1);
    ctx.t.add(n, `Version: ${TLSVER[rv] || hexN(rv, 4)} (${hexN(rv, 4)})`, p + 1, 2);
    ctx.t.add(n, `Length: ${rl}`, p + 3, 2);
    setF(ctx.f, 'tls.record.content_type', ct); setF(ctx.f, 'tls.record.version', rv);
    if (ct === 22 && avail >= 4) {
      const hs = tlsHandshake(ctx, n, p + 5, p + 5 + avail);
      infos.push(hs.label); if (hs.ver) helloVer = hs.ver;
    } else if (ct === 23) { infos.push('Application Data'); ctx.t.add(n, `Encrypted application data (${avail} bytes)`, p + 5, avail); }
    else if (ct === 21) { infos.push(avail === 2 ? `Alert (Level: ${d[p + 5] === 2 ? 'Fatal' : 'Warning'}, Description: ${d[p + 6]})` : 'Encrypted Alert'); }
    else if (ct === 20) infos.push('Change Cipher Spec');
    else infos.push(TLSCT[ct]);
    p += 5 + rl;
  }
  // The record version is fixed at 1.0 or 1.2 for compatibility; only hellos tell the real version.
  if (helloVer === 0x0304) ctx.proto = 'TLSv1.3'; else if (helloVer === 0x0303) ctx.proto = 'TLSv1.2'; else if (helloVer === 0x0302) ctx.proto = 'TLSv1.1'; else if (helloVer === 0x0301) ctx.proto = 'TLSv1';
  ctx.info = [...new Set(infos)].join(', ') || 'TLS';
}

function tlsHandshake(ctx, parent, o, end) {
  const { d } = ctx;
  const type = d[o], len = (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
  const name = TLSHS[type] || `Handshake type ${type}`;
  const n = ctx.t.add(parent, `Handshake Protocol: ${name}`, o, Math.min(4 + len, end - o));
  ctx.t.add(n, `Handshake type: ${name} (${type})`, o, 1);
  ctx.t.add(n, `Length: ${len}`, o + 1, 3);
  setF(ctx.f, 'tls.handshake.type', type);
  const out = { label: name, ver: 0 };
  if (type !== 1 && type !== 2) return out;
  if (len > end - o - 4) { ctx.t.add(n, '[Hello continues in the next segment]', end, 0); }
  const e = Math.min(end, o + 4 + len);
  let p = o + 4;
  if (p + 34 > e) return out;
  const hv = u16(d, p);
  out.ver = hv;
  ctx.t.add(n, `Version: ${TLSVER[hv] || hexN(hv, 4)} (${hexN(hv, 4)})`, p, 2);
  ctx.t.add(n, 'Random: ' + [...d.subarray(p + 2, p + 34)].map(hex2).join(''), p + 2, 32);
  p += 34;
  if (p + 1 > e) return out;
  const sl = d[p]; ctx.t.add(n, `Session ID length: ${sl}`, p, 1); p += 1 + sl;
  if (type === 1) {
    if (p + 2 > e) return out;
    const cl = u16(d, p); ctx.t.add(n, `Cipher suites (${cl / 2 | 0} suites)`, p, 2 + cl); p += 2 + cl;
    if (p + 1 > e) return out;
    const ml = d[p]; ctx.t.add(n, `Compression methods (${ml})`, p, 1 + ml); p += 1 + ml;
  } else {
    if (p + 3 > e) return out;
    const cs = u16(d, p); ctx.t.add(n, `Cipher suite: ${hexN(cs, 4)}`, p, 2); setF(ctx.f, 'tls.handshake.ciphersuite', cs); p += 3;
  }
  if (p + 2 > e) return out;
  const el = u16(d, p), eend = Math.min(e, p + 2 + el);
  const en = ctx.t.add(n, `Extensions length: ${el}`, p, Math.min(2 + el, e - p));
  p += 2;
  while (p + 4 <= eend) {
    const et = u16(d, p), xl = u16(d, p + 2), v = p + 4;
    if (v + xl > eend) { bad(ctx, en, 'TLS extension runs past the end', p, eend - p); break; }
    const xn = ctx.t.add(en, `Extension: ${TLSEXT[et] || 'unknown'} (len=${xl})`, p, 4 + xl);
    if (et === 0 && xl >= 5) {
      let q = v + 2;
      while (q + 3 <= v + xl) {
        const nt = d[q], nl = u16(d, q + 1);
        if (q + 3 + nl > v + xl) break;
        if (nt === 0) {
          const sni = latin(d, q + 3, q + 3 + nl);
          ctx.t.add(xn, `Server Name: ${sni}`, q + 3, nl);
          setF(ctx.f, 'tls.handshake.extensions_server_name', sni);
          out.label = `${name} (SNI=${sni})`;
        }
        q += 3 + nl;
      }
    } else if (et === 16 && xl >= 2) {
      let q = v + 2; const list = [];
      while (q < v + xl) { const l = d[q]; if (q + 1 + l > v + xl) break; const s = latin(d, q + 1, q + 1 + l); list.push(s); ctx.t.add(xn, `ALPN Next Protocol: ${s}`, q, 1 + l); setF(ctx.f, 'tls.handshake.extensions_alpn_str', s); q += 1 + l; }
    } else if (et === 43) {
      if (type === 2 && xl === 2) { out.ver = u16(d, v); ctx.t.add(xn, `Supported version: ${TLSVER[out.ver] || hexN(out.ver, 4)}`, v, 2); setF(ctx.f, 'tls.handshake.extensions.supported_version', out.ver); }
      else if (type === 1 && xl >= 3) {
        for (let q = v + 1; q + 1 < v + 1 + d[v] && q + 1 < v + xl; q += 2) { const sv = u16(d, q); if ((sv & 0x0f0f) === 0x0a0a) continue; if (sv <= 0x0304 && sv > out.ver) out.ver = sv; ctx.t.add(xn, `Supported version: ${TLSVER[sv] || hexN(sv, 4)}`, q, 2); setF(ctx.f, 'tls.handshake.extensions.supported_version', sv); }
      }
    }
    p = v + xl;
  }
  return out;
}

function varint(d, p, end) {
  if (p >= end) return null;
  const l = 1 << (d[p] >> 6);
  if (p + l > end) return null;
  let v = d[p] & 0x3f;
  for (let i = 1; i < l; i++) v = v * 256 + d[p + i];
  return { v, l };
}

function quic(ctx, o, end) {
  const { d } = ctx;
  if (end - o < 7 || !(d[o] & 0x80) || !(d[o] & 0x40)) {
    if (end - o >= 1 && (d[o] & 0x40) && !(d[o] & 0x80)) {
      ctx.protos.push('quic'); ctx.proto = 'QUIC'; ctx.info = 'Protected Payload (short header)';
      ctx.t.add(null, `QUIC IETF, short header (${end - o} bytes, encrypted)`, o, end - o);
      return true;
    }
    return false;
  }
  const ver = u32(d, o + 1);
  const dl = d[o + 5];
  if (dl > 20 || o + 6 + dl >= end) return false;
  const dcid = [...d.subarray(o + 6, o + 6 + dl)].map(hex2).join('');
  const sp = o + 6 + dl, sl = d[sp];
  if (sl > 20 || sp + 1 + sl > end) return false;
  const scid = [...d.subarray(sp + 1, sp + 1 + sl)].map(hex2).join('');
  const lt = (d[o] >> 4) & 3;
  const kinds = ver === 0 ? 'Version Negotiation' : (['Initial', '0-RTT', 'Handshake', 'Retry'][lt]);
  const n = ctx.t.add(null, `QUIC IETF, ${kinds}`, o, end - o);
  ctx.t.add(n, `Header form: Long header (${hexN(d[o], 2)})`, o, 1);
  ctx.t.add(n, `Version: ${ver === 1 ? '1 (RFC 9000)' : ver === 0x6b3343cf ? '2 (RFC 9369)' : hexN(ver, 8)}`, o + 1, 4);
  ctx.t.add(n, `Destination connection ID length: ${dl}`, o + 5, 1);
  if (dl) ctx.t.add(n, `Destination connection ID: ${dcid}`, o + 6, dl);
  ctx.t.add(n, `Source connection ID length: ${sl}`, sp, 1);
  if (sl) ctx.t.add(n, `Source connection ID: ${scid}`, sp + 1, sl);
  let p = sp + 1 + sl;
  if (lt === 0 && ver !== 0) {
    const tl = varint(d, p, end);
    if (tl) { ctx.t.add(n, `Token length: ${tl.v}`, p, tl.l); p += tl.l + tl.v; }
  }
  if (ver !== 0 && lt !== 3) {
    const ln = varint(d, p, end);
    if (ln) { ctx.t.add(n, `Length: ${ln.v}`, p, ln.l); p += ln.l; if (p < end) ctx.t.add(n, `Protected payload (${Math.min(ln.v, end - p)} bytes)`, p, Math.min(ln.v, end - p)); }
  }
  ctx.protos.push('quic'); ctx.proto = 'QUIC';
  setF(ctx.f, 'quic.version', ver); setF(ctx.f, 'quic.dcid', dcid); setF(ctx.f, 'quic.scid', scid); setF(ctx.f, 'quic.long.packet_type', lt);
  ctx.info = `${kinds}, DCID=${dcid}${scid ? ', SCID=' + scid : ''}`;
  return true;
}

/** Names from the DNS answers in one packet, for the name column: [[address, name], ...] or null. */
function dnsNames(d, linktype) {
  const r = dissect(d, linktype, { tree: false });
  if (!r.dnsAnswers || !r.f['dns.flags.response']) return null;
  const out = [];
  for (const [name, t, val] of r.dnsAnswers) if ((t === 1 || t === 28) && name && name !== '<Root>') out.push([val, name]);
  return out.length ? out : null;
}

module.exports = { dissect, dnsNames, LINKTYPES, IPPROTO, DNSTYPES, latin, ascii, u16, u32 };
