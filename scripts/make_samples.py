#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate packet-capture sample files for the PCAP viewer tests.

Usage:
  python3 make_samples.py <outdir> [--large-mb N] [--bomb]

Writes small pcap/pcapng samples, <outdir>/hostile/ edge cases and
<outdir>/expected.json. --large-mb N adds large-<N>mb.pcap (streamed,
constant memory). --bomb adds hostile/bomb.pcap.gz (~10 MB -> ~10 GB).
Pure Python 3 standard library; all packets are synthetic.
"""
import argparse
import gzip
import ipaddress
import json
import os
import random
import struct
import sys
import time
import zlib

T0 = 1794132000 * 10**9            # 2026-11-08 10:00:00 UTC, in ns
RNG = random.Random(20261108)
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
A, CNAME, AAAA = 1, 5, 28
CLIENT, WEB, GW_IP = '10.0.0.1', '93.184.216.34', '10.0.0.254'
CLIENT_MAC, GW_MAC = '3c:22:fb:a1:b2:c3', '00:0d:b9:4f:1e:01'
MACS = {
    CLIENT: CLIENT_MAC, '2001:db8::1': CLIENT_MAC, '0.0.0.0': CLIENT_MAC,
    '10.0.0.2': '52:54:00:12:34:02', '2001:db8::2': '52:54:00:12:34:02',
    GW_IP: GW_MAC, '255.255.255.255': 'ff:ff:ff:ff:ff:ff',
    'ff02::1:ff00:2': '33:33:ff:00:00:02',
    '10.1.0.5': '00:50:56:aa:00:05', '10.1.0.6': '00:50:56:aa:00:06',
}
LOCAL = {CLIENT, '2001:db8::1', '0.0.0.0'}
LINKTYPE_NAMES = {0: 'NULL', 1: 'ETHERNET', 101: 'RAW', 113: 'LINUX_SLL', 276: 'LINUX_SLL2'}
SYN_OPTS = bytes.fromhex('020405b4' '01030306' '0101' '0402')     # MSS, WS, SACK_PERM
SYNACK_OPTS = bytes.fromhex('020405b4' '0101' '0402' '01030307')

# ---------------------------------------------------------------- helpers
def ip(s): return ipaddress.ip_address(s).packed
def mac(s): return bytes.fromhex(s.replace(':', ''))
def mac_of(addr): return MACS.get(addr, GW_MAC)

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def iso(ts, nano):
    sec, frac = divmod(ts, 10**9)
    base = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(sec))
    return base + ('.%09d' % frac if nano else '.%06d' % (frac // 1000)) + 'Z'

def u8l(b): return bytes([len(b)]) + b
def u16l(b): return struct.pack('!H', len(b)) + b

def flag_str(f):
    names = [(FIN, 'FIN'), (SYN, 'SYN'), (RST, 'RST'), (PSH, 'PSH'), (ACK, 'ACK')]
    return ', '.join(n for bit, n in names if f & bit)

# ---------------------------------------------------------------- layers
def eth(dst, src, etype, payload, vlan=None):
    if vlan:
        vid, pcp = vlan
        return mac(dst) + mac(src) + struct.pack('!HHH', 0x8100, (pcp << 13) | vid, etype) + payload
    return mac(dst) + mac(src) + struct.pack('!H', etype) + payload

_ident = [0x3a00]

def ipv4(src, dst, proto, payload, ttl=64, hbh=False):
    _ident[0] = (_ident[0] + 1) & 0xffff
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), _ident[0], 0x4000,
                      ttl, proto, 0, ip(src), ip(dst))
    return hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:] + payload

def ipv6(src, dst, nh, payload, ttl=64, hbh=False):
    ext = b''
    if hbh:                                  # Hop-by-Hop header with one PadN option
        ext, nh = bytes([nh, 0, 1, 4, 0, 0, 0, 0]), 0
    return struct.pack('!IHBB16s16s', 0x60000000, len(ext) + len(payload), nh, ttl,
                       ip(src), ip(dst)) + ext + payload

def l4_csum(src, dst, proto, seg, off):
    s, d = ip(src), ip(dst)
    if len(s) == 4:
        ph = s + d + struct.pack('!BBH', 0, proto, len(seg))
    else:
        ph = s + d + struct.pack('!I3xB', len(seg), proto)
    c = csum(ph + seg) or (0xffff if proto == 17 else 0)
    return seg[:off] + struct.pack('!H', c) + seg[off + 2:]

def tcp_seg(src, dst, sp, dp, seq, ack, flags, data=b'', opts=b'', win=65535):
    seg = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opts)) // 4) << 4,
                      flags, win, 0, 0) + opts + data
    return l4_csum(src, dst, 6, seg, 16)

def udp_seg(src, dst, sp, dp, data):
    return l4_csum(src, dst, 17, struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data, 6)

def icmp4(typ, ident, seq, data):
    m = struct.pack('!BBHHH', typ, 0, 0, ident, seq) + data
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]

def icmp6(src, dst, typ, body):
    return l4_csum(src, dst, 58, struct.pack('!BBH', typ, 0, 0) + body, 2)

def arp(op, smac, sip, tmac, tip):
    return struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, mac(smac), ip(sip), mac(tmac), ip(tip))

def qname(name): return b''.join(u8l(p.encode()) for p in name.split('.') if p) + b'\0'

PTR_Q = b'\xc0\x0c'                          # compression pointer to the first question

def dns(ident, flags, qs, ans=()):
    m = struct.pack('!HHHHHH', ident, flags, len(qs), len(ans), 0, 0)
    for name, qt in qs:
        m += qname(name) + struct.pack('!HH', qt, 1)
    for owner, rt, ttl, rdata in ans:
        m += owner + struct.pack('!HHIH', rt, 1, ttl, len(rdata)) + rdata
    return m

def ping_payload(seq): return struct.pack('!II', T0 // 10**9 + seq, seq * 1000) + bytes(range(8, 56))

# ---------------------------------------------------------------- capture model
class Cap:
    """Ordered packets plus the per-frame expectations written to expected.json."""

    def __init__(self, linktype=1, nano=False):
        self.linktype, self.nano = linktype, nano
        self.pkts, self.notes = [], []
        self.t, self.next_ts, self.jitter = T0, None, 0
        self.vlan = self.ifid = None

    def add(self, frame, proto, src, dst, fields=None, origlen=None):
        if self.next_ts is not None:
            self.t, self.next_ts = self.next_ts, None
        elif self.pkts:
            self.t += RNG.randint(150, 25000) * 1000
        ts, orig = self.t + self.jitter, origlen or len(frame)
        self.pkts.append((ts, frame, orig, self.ifid))
        n = dict(index=len(self.pkts), time=iso(ts, self.nano), src=src, dst=dst,
                 protocol=proto, length=orig)
        if orig != len(frame):
            n['caplen'] = len(frame)
        if self.ifid is not None:
            n['interface'] = self.ifid
        n.update(fields or {})
        self.notes.append(n)

    def wrap(self, l3, etype, src, dst):
        lt, out = self.linktype, src in LOCAL
        if lt == 1:
            return eth(mac_of(dst), mac_of(src), etype, l3, self.vlan)
        if lt == 101:
            return l3
        if lt == 0:                          # BSD loopback, host (little-endian) order
            return struct.pack('<I', 30 if etype == 0x86dd else 2) + l3
        if lt == 113:
            return struct.pack('!HHH8sH', 4 if out else 0, 1, 6, mac(mac_of(src)), etype) + l3
        if lt == 276:
            return struct.pack('!HHIHBB8s', etype, 0, 2, 1, 4 if out else 0, 6,
                               mac(mac_of(src))) + l3
        raise ValueError(lt)

    def ip(self, src, dst, proto, seg, name, fields=None, ttl=64, hbh=False):
        v6 = ':' in src
        l3 = (ipv6 if v6 else ipv4)(src, dst, proto, seg, ttl, hbh)
        f = {'vlan.id': self.vlan[0], 'vlan.priority': self.vlan[1]} if self.vlan else {}
        f.update(fields or {})
        self.add(self.wrap(l3, 0x86dd if v6 else 0x0800, src, dst), name, src, dst, f)

    def tcp(self, src, dst, sp, dp, seq, ack, flags, data=b'', name='TCP', fields=None,
            opts=b'', **kw):
        f = {'tcp.srcport': sp, 'tcp.dstport': dp, 'tcp.flags': flag_str(flags),
             'tcp.seq_raw': seq, 'tcp.ack_raw': ack, 'tcp.len': len(data)}
        f.update(fields or {})
        self.ip(src, dst, 6, tcp_seg(src, dst, sp, dp, seq, ack, flags, data, opts), name, f, **kw)

    def udp(self, src, dst, sp, dp, data, name='UDP', fields=None, **kw):
        f = {'udp.srcport': sp, 'udp.dstport': dp, 'udp.length': 8 + len(data)}
        f.update(fields or {})
        self.ip(src, dst, 17, udp_seg(src, dst, sp, dp, data), name, f, **kw)

class Conn:
    """One TCP connection with tracked sequence numbers."""

    def __init__(self, cap, c, s, cp, sp, cisn, sisn):
        self.cap, self.ends = cap, {True: (c, cp), False: (s, sp)}
        self.seq = {True: cisn, False: sisn}
        self.data = {True: b'', False: b''}

    def pkt(self, fc, flags, data=b'', name='TCP', fields=None, opts=b''):
        (src, sp), (dst, dp) = self.ends[fc], self.ends[not fc]
        ack = self.seq[not fc] if flags & ACK else 0
        self.cap.tcp(src, dst, sp, dp, self.seq[fc], ack, flags, data, name, fields, opts,
                     ttl=64 if fc else 56)
        self.seq[fc] = (self.seq[fc] + len(data) + (1 if flags & (SYN | FIN) else 0)) & 0xffffffff
        self.data[fc] += data

    def handshake(self):
        self.pkt(True, SYN, opts=SYN_OPTS)
        self.pkt(False, SYN | ACK, opts=SYNACK_OPTS)
        self.pkt(True, ACK)

    def close(self):
        self.pkt(True, FIN | ACK)
        self.pkt(False, FIN | ACK)
        self.pkt(True, ACK)

# ---------------------------------------------------------------- writers
def pcap_header(linktype, nano=False, big=False, snaplen=262144):
    return struct.pack(('>' if big else '<') + 'IHHiIII', 0xa1b23c4d if nano else 0xa1b2c3d4,
                       2, 4, 0, 0, snaplen, linktype)

def pcap_record(ts, data, orig, nano=False, big=False):
    sec, frac = divmod(ts, 10**9)
    return struct.pack(('>' if big else '<') + 'IIII', sec, frac if nano else frac // 1000,
                       len(data), orig) + data

def write_pcap(path, cap, big=False):
    with open(path, 'wb') as f:
        f.write(pcap_header(cap.linktype, cap.nano, big))
        for ts, data, orig, _ in cap.pkts:
            f.write(pcap_record(ts, data, orig, cap.nano, big))

def pad4(b): return b + b'\0' * (-len(b) % 4)
def opt(code, val): return struct.pack('<HH', code, len(val)) + pad4(val)
def opts(*items): return b''.join(items) + struct.pack('<HH', 0, 0) if items else b''

def block(btype, body):
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

def shb(o=b''): return block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1) + o)
def idb(linktype, o=b''): return block(1, struct.pack('<HHI', linktype, 0, 262144) + o)

def epb(ifid, ts_units, data, orig=None, o=b''):
    return block(6, struct.pack('<IIIII', ifid, ts_units >> 32, ts_units & 0xffffffff,
                                len(data), orig or len(data)) + pad4(data) + o)

def spb(data): return block(3, struct.pack('<I', len(data)) + pad4(data))

def save(out, exp, name, cap, big=False, **extra):
    write_pcap(os.path.join(out, name), cap, big)
    exp[name] = dict(format='pcap', packets=len(cap.pkts), linktypes=[cap.linktype],
                     linktype_names=[LINKTYPE_NAMES[cap.linktype]],
                     ts_resolution='ns' if cap.nano else 'us',
                     byte_order='big' if big else 'little', **extra)
    exp[name]['frames'] = cap.notes

# ---------------------------------------------------------------- small samples
def build_dns(out, exp):
    c = Cap()
    q1 = dns(0x1a2b, 0x0100, [('example.com', A)])
    c.udp(CLIENT, '8.8.8.8', 53001, 53, q1, 'DNS',
          {'dns.id': 0x1a2b, 'dns.qry.name': 'example.com', 'dns.qry.type': 'A'})
    r1 = dns(0x1a2b, 0x8180, [('example.com', A)],
             [(PTR_Q, A, 3600, ip(WEB)), (b'\x03www' + PTR_Q, CNAME, 3600, PTR_Q)])
    c.udp('8.8.8.8', CLIENT, 53, 53001, r1, 'DNS',
          {'dns.id': 0x1a2b, 'dns.qry.name': 'example.com', 'dns.a': WEB,
           'dns.cname': 'example.com', 'dns.count.answers': 2}, ttl=118)
    q2 = dns(0x3c4d, 0x0100, [('ipv6.example.net', AAAA)])
    c.udp(CLIENT, '8.8.8.8', 53002, 53, q2, 'DNS',
          {'dns.id': 0x3c4d, 'dns.qry.name': 'ipv6.example.net', 'dns.qry.type': 'AAAA'})
    r2 = dns(0x3c4d, 0x8180, [('ipv6.example.net', AAAA)], [(PTR_Q, AAAA, 300, ip('2001:db8::10'))])
    c.udp('8.8.8.8', CLIENT, 53, 53002, r2, 'DNS',
          {'dns.id': 0x3c4d, 'dns.qry.name': 'ipv6.example.net', 'dns.aaaa': '2001:db8::10'}, ttl=118)
    save(out, exp, 'dns.pcap', c)

HTML = (b'<!doctype html>\n<html><head><title>Example Domain</title></head>\n'
        b'<body><h1>Example Domain</h1><p>Sample page from make_samples.py.</p></body></html>\n')

def http_response(body, ctype=b'text/html'):
    return (b'HTTP/1.1 200 OK\r\nDate: Sun, 08 Nov 2026 10:00:00 GMT\r\nServer: sample\r\n'
            b'Content-Type: ' + ctype + b'\r\nContent-Length: ' + str(len(body)).encode()
            + b'\r\nConnection: close\r\n\r\n' + body)

def http_get(path, host='example.com'):
    return ('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\n\r\n'
            % (path, host)).encode()

def build_http(out, exp):
    c = Cap()
    k = Conn(c, CLIENT, WEB, 51000, 80, 1000000, 3000000)
    k.handshake()
    k.pkt(True, PSH | ACK, http_get('/index.html'), 'HTTP',
          {'http.request.method': 'GET', 'http.request.uri': '/index.html', 'http.host': 'example.com'})
    k.pkt(False, ACK)
    resp = http_response(HTML)
    cut = resp.index(b'\n', resp.index(b'\r\n\r\n') + 4) + 1   # after first body line
    k.pkt(False, ACK, resp[:cut], 'TCP', {'note': 'first segment of reassembled HTTP response'})
    k.pkt(False, PSH | ACK, resp[cut:], 'HTTP',
          {'http.response.code': 200, 'http.content_type': 'text/html',
           'http.content_length': len(HTML), 'reassembled_from_frames': [6, 7]})
    k.pkt(True, ACK)
    k.close()
    save(out, exp, 'http.pcap', c, follow_tcp_stream={
        'client_to_server': k.data[True].decode(), 'server_to_client': k.data[False].decode()})

def ext(t, body): return struct.pack('!HH', t, len(body)) + body

def tls_hs(htype, body, rec_ver=b'\x03\x03'):
    hs = bytes([htype]) + len(body).to_bytes(3, 'big') + body
    return b'\x16' + rec_ver + u16l(hs)

def client_hello(sni, rng):
    key = bytes(rng.randrange(256) for _ in range(32))
    exts = (ext(0x0000, u16l(b'\0' + u16l(sni.encode())))
            + ext(0x000a, u16l(struct.pack('!3H', 0x001d, 0x0017, 0x0018)))
            + ext(0x000d, u16l(struct.pack('!4H', 0x0403, 0x0804, 0x0401, 0x0503)))
            + ext(0x0010, u16l(u8l(b'h2') + u8l(b'http/1.1')))
            + ext(0x002b, u8l(struct.pack('!2H', 0x0304, 0x0303)))
            + ext(0x0033, u16l(struct.pack('!HH', 0x001d, 32) + key)))
    body = (b'\x03\x03' + bytes(rng.randrange(256) for _ in range(32))
            + u8l(bytes(rng.randrange(256) for _ in range(32)))
            + u16l(struct.pack('!3H', 0x1301, 0x1302, 0x1303)) + b'\x01\x00' + u16l(exts))
    return tls_hs(1, body, b'\x03\x01')

def server_hello(rng):
    exts = (ext(0x002b, b'\x03\x04')
            + ext(0x0033, struct.pack('!HH', 0x001d, 32) + bytes(rng.randrange(256) for _ in range(32))))
    body = (b'\x03\x03' + bytes(rng.randrange(256) for _ in range(32))
            + u8l(bytes(rng.randrange(256) for _ in range(32))) + b'\x13\x01\x00' + u16l(exts))
    return tls_hs(2, body)

def tls_appdata(n, rng): return b'\x17\x03\x03' + u16l(bytes(rng.randrange(256) for _ in range(n)))

def build_tls(out, exp):
    rng, c = random.Random(443), Cap()
    sni = 'secure.example.com'
    c.udp(CLIENT, '8.8.8.8', 53010, 53, dns(0x5e5e, 0x0100, [(sni, A)]), 'DNS',
          {'dns.qry.name': sni})
    c.udp('8.8.8.8', CLIENT, 53, 53010, dns(0x5e5e, 0x8180, [(sni, A)], [(PTR_Q, A, 60, ip(WEB))]),
          'DNS', {'dns.qry.name': sni, 'dns.a': WEB}, ttl=118)
    k = Conn(c, CLIENT, WEB, 51001, 443, 2000000, 4000000)
    k.handshake()
    k.pkt(True, PSH | ACK, client_hello(sni, rng), 'TLSv1.3',
          {'protocol_alt': ['TLS', 'TLSv1'], 'tls.handshake.type': 1,
           'tls.handshake.extensions_server_name': sni,
           'tls.handshake.extensions_alpn_str': ['h2', 'http/1.1'],
           'tls.record.version': '0x0301'})
    k.pkt(False, ACK)
    k.pkt(False, PSH | ACK, server_hello(rng), 'TLSv1.3',
          {'protocol_alt': ['TLS'], 'tls.handshake.type': 2,
           'tls.handshake.extensions.supported_version': '0x0304'})
    k.pkt(True, PSH | ACK, tls_appdata(120, rng), 'TLSv1.3',
          {'protocol_alt': ['TLS'], 'tls.record.content_type': 23})
    k.pkt(False, PSH | ACK, tls_appdata(310, rng), 'TLSv1.3',
          {'protocol_alt': ['TLS'], 'tls.record.content_type': 23})
    k.pkt(True, ACK)
    Conn(c, '10.0.0.2', CLIENT, 52000, 443, 7000000, 9000000).handshake()
    match = sum(1 for n in c.notes if CLIENT in (n['src'], n['dst'])
                and 443 in (n.get('tcp.srcport'), n.get('tcp.dstport')))
    save(out, exp, 'tls.pcap', c, filters={'tcp.port==443 && ip.addr==10.0.0.1': match})

def build_icmp(out, exp):
    c = Cap()
    req = arp(1, CLIENT_MAC, CLIENT, '00:00:00:00:00:00', GW_IP)
    c.add(eth('ff:ff:ff:ff:ff:ff', CLIENT_MAC, 0x0806, req), 'ARP', CLIENT_MAC, 'ff:ff:ff:ff:ff:ff',
          {'arp.opcode': 1, 'info': 'Who has 10.0.0.254? Tell 10.0.0.1'})
    rep = arp(2, GW_MAC, GW_IP, CLIENT_MAC, CLIENT) + bytes(18)   # padded to 60 bytes
    c.add(eth(CLIENT_MAC, GW_MAC, 0x0806, rep), 'ARP', GW_MAC, CLIENT_MAC,
          {'arp.opcode': 2, 'info': '10.0.0.254 is at ' + GW_MAC})
    for seq in (1, 2, 3):
        c.ip(CLIENT, '1.1.1.1', 1, icmp4(8, 0x1234, seq, ping_payload(seq)), 'ICMP',
             {'icmp.type': 8, 'icmp.ident': 0x1234, 'icmp.seq': seq})
        c.ip('1.1.1.1', CLIENT, 1, icmp4(0, 0x1234, seq, ping_payload(seq)), 'ICMP',
             {'icmp.type': 0, 'icmp.ident': 0x1234, 'icmp.seq': seq}, ttl=57)
    save(out, exp, 'icmp.pcap', c)

def dhcp_msg(op, xid, mtype, yiaddr='0.0.0.0', options=b''):
    m = struct.pack('!BBBBIHH4s4s4s4s16s64s128sI', op, 1, 6, 0, xid, 0, 0x8000, ip('0.0.0.0'),
                    ip(yiaddr), ip('0.0.0.0'), ip('0.0.0.0'), mac(CLIENT_MAC), b'', b'', 0x63825363)
    m += bytes([53, 1, mtype]) + options + b'\xff'
    return m + bytes(max(0, 300 - len(m)))

def build_dhcp(out, exp):
    c, xid, lease = Cap(), 0x5a17c0de, '10.0.0.23'
    o = lambda code, val: bytes([code, len(val)]) + val       # noqa: E731
    host, prl = o(12, b'laptop'), o(55, bytes([1, 3, 6, 12, 15, 51]))
    srv = (o(54, ip(GW_IP)) + o(51, struct.pack('!I', 86400)) + o(1, ip('255.255.255.0'))
           + o(3, ip(GW_IP)) + o(6, ip('8.8.8.8') + ip('1.1.1.1')))
    msgs = [(CLIENT, 1, 'Discover', '0.0.0.0', o(50, ip(lease)) + host + prl),
            (GW_IP, 2, 'Offer', lease, srv),
            (CLIENT, 3, 'Request', '0.0.0.0', o(50, ip(lease)) + o(54, ip(GW_IP)) + host + prl),
            (GW_IP, 5, 'ACK', lease, srv + host)]
    for who, mtype, label, yi, extra in msgs:
        client = who == CLIENT
        src = '0.0.0.0' if client else GW_IP
        f = {'dhcp.option.dhcp': label, 'dhcp.id': '0x%08x' % xid, 'dhcp.ip.your': yi}
        if b'laptop' in extra:
            f['dhcp.option.hostname'] = 'laptop'
        c.udp(src, '255.255.255.255', 68 if client else 67, 67 if client else 68,
              dhcp_msg(1 if client else 2, xid, mtype, yi, extra), 'DHCP', f, ttl=64 if client else 128)
    save(out, exp, 'dhcp.pcap', c)

def build_ipv6(out, exp):
    c, a, b = Cap(), '2001:db8::1', '2001:db8::2'
    for typ, s, d in ((128, a, b), (129, b, a)):
        c.ip(s, d, 58, icmp6(s, d, typ, struct.pack('!HH', 0x0042, 1) + b'ipv6 ping payload'), 'ICMPv6',
             {'icmpv6.type': typ, 'icmpv6.echo.identifier': 0x42, 'icmpv6.echo.sequence_number': 1,
              'ipv6.hopopts': True}, hbh=True)
    ns = struct.pack('!I16s', 0, ip(b)) + bytes([1, 1]) + mac(CLIENT_MAC)
    c.ip(a, 'ff02::1:ff00:2', 58, icmp6(a, 'ff02::1:ff00:2', 135, ns), 'ICMPv6',
         {'icmpv6.type': 135, 'icmpv6.nd.ns.target_address': b}, ttl=255)
    c.udp(a, '2001:db8::53', 53100, 53, dns(0x6666, 0x0100, [('example.com', AAAA)]), 'DNS',
          {'dns.qry.name': 'example.com', 'dns.qry.type': 'AAAA'})
    k = Conn(c, a, b, 40000, 80, 11000000, 12000000)
    k.pkt(True, SYN, opts=SYN_OPTS)
    k.pkt(False, SYN | ACK, opts=SYNACK_OPTS)
    save(out, exp, 'ipv6.pcap', c)

def build_vlan(out, exp):
    c = Cap()
    c.vlan = (100, 3)
    for i in range(4):
        c.udp('10.1.0.5', '10.1.0.6', 5000, 6000, b'hello vlan', 'UDP', {'data.text': 'hello vlan'})
    save(out, exp, 'vlan.pcap', c)

def build_sll(out, exp, linktype, name):
    c = Cap(linktype)
    k = Conn(c, CLIENT, '10.0.0.2', 43000, 22, 5550000, 6660000)
    k.pkt(True, SYN, opts=SYN_OPTS)
    k.pkt(False, SYN | ACK, opts=SYNACK_OPTS)
    k.pkt(True, ACK)
    c.udp(CLIENT, '8.8.8.8', 53020, 53, dns(0x7777, 0x0100, [('example.org', A)]), 'DNS',
          {'dns.qry.name': 'example.org'})
    save(out, exp, name, c)

def build_nano(out, exp):
    c = Cap(nano=True)
    for i, frac in enumerate((123456789, 223456781, 323456792, 999999999, 1)):
        c.next_ts = T0 + i * 10**9 + frac
        c.udp(CLIENT, '10.0.0.2', 40000, 40002, ('ns sample %d' % i).encode(), 'UDP',
              {'frame.time_epoch': '%d.%09d' % (T0 // 10**9 + i, frac)})
    save(out, exp, 'nanosecond.pcap', c)

def build_bigendian(out, exp):
    c = Cap()
    c.ip(CLIENT, '1.1.1.1', 1, icmp4(8, 0x0be0, 1, ping_payload(1)), 'ICMP', {'icmp.seq': 1})
    c.ip('1.1.1.1', CLIENT, 1, icmp4(0, 0x0be0, 1, ping_payload(1)), 'ICMP', {'icmp.seq': 1}, ttl=57)
    c.udp(CLIENT, '8.8.8.8', 53030, 53, dns(0x0b1e, 0x0100, [('big.example', A)]), 'DNS',
          {'dns.qry.name': 'big.example'})
    save(out, exp, 'bigendian.pcap', c, big=True)

def build_raw_and_null(out, exp):
    c = Cap(101)
    for s, d in ((CLIENT, '10.0.0.2'), ('10.0.0.2', CLIENT), ('2001:db8::1', '2001:db8::2'),
                 ('2001:db8::2', '2001:db8::1')):
        sp, dp = (40010, 40011) if s in LOCAL else (40011, 40010)
        c.udp(s, d, sp, dp, ('raw %s' % s).encode(), 'UDP', {'ip.version': 6 if ':' in s else 4})
    save(out, exp, 'raw-ipv4.pcap', c)
    c = Cap(0)
    c.tcp('127.0.0.1', '127.0.0.1', 50000, 8080, 123456, 0, SYN, opts=SYN_OPTS,
          fields={'null.family': 2})
    c.udp('::1', '::1', 50001, 50002, b'loopback v6', 'UDP', {'null.family': 30})
    save(out, exp, 'null-loopback.pcap', c)

def build_quic(out, exp):
    rng, c = random.Random(1200), Cap()
    dcid, scid = bytes(rng.randrange(256) for _ in range(8)), bytes(rng.randrange(256) for _ in range(8))
    for first, d, s, pn, pnlen, src, dst, sp, dp in (
            (0xC3, dcid, scid, 0, 4, CLIENT, WEB, 55000, 443),
            (0xC1, scid, bytes(rng.randrange(256) for _ in range(8)), 0, 2, WEB, CLIENT, 443, 55000)):
        hdr = bytes([first]) + struct.pack('!I', 1) + u8l(d) + u8l(s) + b'\x00'   # token len 0
        length = 1200 - len(hdr) - 2
        body = pn.to_bytes(pnlen, 'big') + bytes(rng.randrange(256) for _ in range(240))
        pkt = hdr + struct.pack('!H', 0x4000 | length) + body + bytes(length - len(body))
        c.udp(src, dst, sp, dp, pkt, 'QUIC',
              {'quic.long.packet_type': 'Initial', 'quic.version': '0x00000001',
               'quic.dcid': d.hex(), 'quic.scid': s.hex(), 'quic.length': length})
    save(out, exp, 'quic.pcap', c)

def build_pcapng(out, exp):
    c = Cap()
    k = Conn(c, CLIENT, WEB, 51002, 80, 8000000, 8800000)

    def iface(n):
        c.ifid, c.linktype, c.nano, c.jitter = n, (1, 101)[n], bool(n), 789 * n

    sends = [(True, SYN, b'', SYN_OPTS), (False, SYN | ACK, b'', SYNACK_OPTS),
             (True, ACK, b'', b''), (True, PSH | ACK, http_get('/'), b'')]
    for i, (fc, flags, data, o) in enumerate(sends):
        iface(0)
        k.pkt(fc, flags, data, 'HTTP' if data else 'TCP',
              {'http.host': 'example.com'} if data else None, o)
        if i < 3:
            iface(1)
            c.udp('10.8.0.2', '10.8.0.1', 41000, 41001, ('tun0 datagram %d' % i).encode(), 'UDP')
    iface(0)
    c.udp(CLIENT, '8.8.8.8', 53040, 53, dns(0x0bad, 0x0100, [('spb.example', A)]), 'DNS',
          {'dns.qry.name': 'spb.example', 'block': 'SPB'})
    c.notes[-1]['time'] = None                    # SPBs carry no timestamp
    c.notes[0]['frame.comment'] = 'hello comment'
    nrb = (struct.pack('<HH', 1, 4 + 11) + pad4(ip(CLIENT) + b'client.lan\0')
           + struct.pack('<HH', 1, 4 + 12) + pad4(ip(WEB) + b'web.example\0')
           + struct.pack('<HH', 2, 16 + 11) + pad4(ip('2001:db8::1') + b'v6host.lan\0')
           + struct.pack('<HH', 0, 0))
    blocks = [shb(opts(opt(4, b'make_samples'))),
              idb(1, opts(opt(2, b'eth0'))),
              idb(101, opts(opt(2, b'tun0'), opt(9, b'\x09'))),
              block(4, nrb)]
    for i, (ts, data, orig, ifid) in enumerate(c.pkts[:-1]):
        o = opts(opt(1, b'hello comment')) if i == 0 else b''
        blocks.append(epb(ifid, ts if ifid else ts // 1000, data, orig, o))
        if i == 2:
            blocks.append(block(0x00000BAD, b'unknown block body, readers must skip\0\0\0'))
    blocks.append(spb(c.pkts[-1][1]))
    blocks.append(block(5, struct.pack('<III', 0, (c.t // 1000) >> 32, (c.t // 1000) & 0xffffffff)
                        + opts(opt(4, struct.pack('<Q', 5)), opt(5, struct.pack('<Q', 0)))))
    with open(os.path.join(out, 'multi-if.pcapng'), 'wb') as f:
        f.write(b''.join(blocks))
    exp['multi-if.pcapng'] = dict(
        format='pcapng', packets=len(c.pkts), linktypes=[1, 101], linktype_names=['ETHERNET', 'RAW'],
        ts_resolution=['us', 'ns'],
        shb_userappl='make_samples',
        interfaces=[{'id': 0, 'linktype': 1, 'if_name': 'eth0', 'if_tsresol': 6},
                    {'id': 1, 'linktype': 101, 'if_name': 'tun0', 'if_tsresol': 9}],
        name_resolution={CLIENT: 'client.lan', WEB: 'web.example', '2001:db8::1': 'v6host.lan'},
        blocks=['SHB', 'IDB', 'IDB', 'NRB', 'EPB', 'EPB', 'EPB', 'UNKNOWN(0x00000BAD)', 'EPB',
                'EPB', 'EPB', 'EPB', 'SPB', 'ISB'],
        isb={'interface': 0, 'isb_ifrecv': 5, 'isb_ifdrop': 0}, frames=c.notes)

# ---------------------------------------------------------------- hostile files
def build_hostile(out, exp, bomb):
    h = os.path.join(out, 'hostile')
    os.makedirs(h, exist_ok=True)
    hx = exp['hostile'] = {}

    def put(name, data, why, **extra):
        with open(os.path.join(h, name), 'wb') as f:
            f.write(data)
        hx[name] = dict(description=why, size=len(data), **extra)

    c = Cap()
    for i in range(3):
        c.udp(CLIENT, '10.0.0.2', 40000, 40001, b'hostile %d' % i)
    e = [epb(0, ts // 1000, d) for ts, d, _, _ in c.pkts]
    head = shb() + idb(1)
    put('zero-block.pcapng', head + e[0] + e[1] + struct.pack('<II', 6, 0) + bytes(8),
        'SHB+IDB+2 EPBs, then a block whose total length is 0', valid_packets=2)
    tail = struct.pack('<II', 6, (1 << 20) + 64) + bytes(40)
    put('past-end.pcapng', head + e[0] + tail, 'EPB whose length points 1 MB past EOF',
        valid_packets=1)
    good = pcap_header(1) + pcap_record(c.pkts[0][0], c.pkts[0][1], len(c.pkts[0][1]))
    put('huge-caplen.pcap', good + struct.pack('<IIII', T0 // 10**9 + 1, 0, 300000, 300000)
        + bytes(100), 'second record caplen 300000 > 262144', valid_packets=1)
    put('huge-caplen2.pcap', good + struct.pack('<IIII', T0 // 10**9 + 1, 0, 100000, 100000)
        + bytes(64), 'second record caplen 100000 > file size', valid_packets=1)

    b = Cap()
    l3 = bytearray(ipv4(CLIENT, '10.0.0.2', 17, udp_seg(CLIENT, '10.0.0.2', 1, 2, b'ihl3')))
    l3[0] = 0x43
    b.add(eth(mac_of('10.0.0.2'), CLIENT_MAC, 0x0800, bytes(l3)), 'IPv4', CLIENT, '10.0.0.2')
    seg = bytearray(tcp_seg(CLIENT, WEB, 51100, 80, 1, 0, SYN, opts=bytes(10)))
    seg[12] = 0xF0                                   # data offset 15 (60 bytes), only 30 present
    b.add(eth(GW_MAC, CLIENT_MAC, 0x0800, ipv4(CLIENT, WEB, 6, bytes(seg))), 'TCP', CLIENT, WEB)
    useg = bytearray(udp_seg(CLIENT, '10.0.0.2', 40100, 40101, b'short udp payload!!!'))
    useg[4:6] = struct.pack('!H', 2000)
    b.add(eth(mac_of('10.0.0.2'), CLIENT_MAC, 0x0800, ipv4(CLIENT, '10.0.0.2', 17, bytes(useg))),
          'UDP', CLIENT, '10.0.0.2')
    q = dns(0x1001, 0x8180, [('loop.example', A)])
    loop = q[:6] + b'\x00\x01' + q[8:]
    loop += struct.pack('!H', 0xC000 | len(loop)) + struct.pack('!HHIH', A, 1, 60, 4) + ip(WEB)
    b.udp('8.8.8.8', CLIENT, 53, 53050, loop, 'DNS')
    full = eth(CLIENT_MAC, GW_MAC, 0x0800, ipv4(WEB, CLIENT, 6, tcp_seg(
        WEB, CLIENT, 80, 51200, 5, 6, PSH | ACK, http_response(HTML * 8))))
    b.add(full[:128], 'HTTP', WEB, CLIENT, origlen=len(full))
    with open(os.path.join(h, 'bad-headers.pcap'), 'wb') as f:
        f.write(pcap_header(1) + b''.join(pcap_record(ts, d, o) for ts, d, o, _ in b.pkts))
    hx['bad-headers.pcap'] = dict(
        packets=5, description='IPv4 IHL=3; TCP doff=15 with 30 bytes; UDP len 2000 short; '
        'DNS self-pointing compression loop; truncated HTTP (caplen 128 < origlen)')

    put('not-a-capture.pcap', bytes(random.Random(4096).randrange(256) for _ in range(4096)),
        '4 KB of seeded random bytes')
    put('empty.pcap', b'', 'zero bytes')
    put('truncated-header.pcap', pcap_header(1)[:10], '10 bytes of a pcap global header')
    if bomb:
        write_bomb(os.path.join(h, 'bomb.pcap.gz'))
        hx['bomb.pcap.gz'] = dict(description='gzip members expanding to ~10 GB (24-byte pcap '
                                  'header + 100 x 100 MiB of zeros)',
                                  size=os.path.getsize(os.path.join(h, 'bomb.pcap.gz')),
                                  uncompressed=24 + 100 * (100 << 20))

def write_bomb(path, members=100, member_mb=100):
    co, chunk = zlib.compressobj(9, zlib.DEFLATED, 31), bytes(1 << 20)
    member = b''.join([co.compress(chunk) for _ in range(member_mb)] + [co.flush()])
    with open(path, 'wb') as f:
        f.write(gzip.compress(pcap_header(1), mtime=0))
        for _ in range(members):
            f.write(member)

# ---------------------------------------------------------------- large mode
def large_templates():
    """Return [(frames, server_port)], each frame = (dir, head, tail, has_ports)."""
    rng, caps = random.Random(99), []
    for size in (0, 600, 1800, 4000, 9000, 20000, 45000, 90000):
        c = Cap()
        k = Conn(c, CLIENT, WEB, 50000, 80, rng.getrandbits(32), rng.getrandbits(32))
        k.handshake()
        k.pkt(True, PSH | ACK, http_get('/assets/%d.bin' % size))
        resp = http_response(b'x' * size, b'application/octet-stream')
        for n, i in enumerate(range(0, len(resp), 1460)):
            k.pkt(False, PSH | ACK if i + 1460 >= len(resp) else ACK, resp[i:i + 1460])
            if n % 2:
                k.pkt(True, ACK)
        k.close()
        caps.append((c, 80))
    for i, size in enumerate((200, 1500, 6000, 16000, 50000)):
        c = Cap()
        k = Conn(c, CLIENT, WEB, 50000, 443, rng.getrandbits(32), rng.getrandbits(32))
        k.handshake()
        k.pkt(True, PSH | ACK, client_hello('cdn%d.example.com' % i, rng))
        k.pkt(False, ACK)
        k.pkt(False, PSH | ACK, server_hello(rng))
        k.pkt(True, PSH | ACK, tls_appdata(300, rng))
        data = b''.join(tls_appdata(min(16000, size - j), rng) for j in range(0, size, 16000))
        for j in range(0, len(data), 1460):
            k.pkt(False, ACK, data[j:j + 1460])
        k.pkt(True, ACK)
        k.close()
        caps.append((c, 443))
    for i in range(40):
        c, name = Cap(), 'host%d.example%d.com' % (i, i % 7)
        c.udp(CLIENT, WEB, 50000, 53, dns(i, 0x0100, [(name, A)]))
        c.udp(WEB, CLIENT, 53, 50000, dns(i, 0x8180, [(name, A)], [(PTR_Q, A, 300, ip(WEB))]))
        caps.append((c, 53))
    c = Cap()
    for seq in range(1, 4):
        c.ip(CLIENT, WEB, 1, icmp4(8, 7, seq, ping_payload(seq)), 'ICMP')
        c.ip(WEB, CLIENT, 1, icmp4(0, 7, seq, ping_payload(seq)), 'ICMP')
    caps.append((c, 0))
    out, me = [], ip(CLIENT)
    for c, sport in caps:
        frames = []
        for _, f, _, _ in c.pkts:
            proto, head = f[23], f[:24] + b'\0\0'          # IP checksum zeroed
            if proto == 6:
                tail = f[38:50] + b'\0\0' + f[52:]
            elif proto == 17:
                tail = f[38:40] + b'\0\0' + f[42:]
            else:
                tail = f[34:]
            tail += bytes(max(0, 60 - len(f)))
            frames.append((0 if f[26:30] == me else 1, head, tail, proto != 1))
        out.append((frames, sport))
    return out

def write_large(path, mb):
    rng, target = random.Random(2000), mb << 20
    clients = [bytes([10, 20 + i // 250, i % 250, 1 + i % 200]) for i in range(1000)]
    servers = [bytes([rng.choice((23, 31, 52, 93, 104, 142, 151, 185, 203)), rng.randrange(256),
                      rng.randrange(256), rng.randrange(1, 255)]) for _ in range(1000)]
    tpls = large_templates()
    weights = [{80: 3, 443: 4}.get(sp, 1) for _, sp in tpls]
    steps = [rng.randint(20, 1500) for _ in range(1024)]
    pk = struct.Struct('<IIII').pack
    pp = struct.Struct('!HH').pack

    def session(n):
        frames, sp = rng.choices(tpls, weights)[0]
        cp = 49152 + (n * 7) % 16000
        return [frames, 0, rng.choice(clients), rng.choice(servers), pp(cp, sp), pp(sp, cp)]

    active = [session(i) for i in range(16)]
    t_us, n, written, buf = T0 // 1000, 0, 24, []
    with open(path, 'wb', buffering=1 << 20) as f:
        f.write(pcap_header(1))
        while written < target:
            k = n & 15
            s = active[k]
            d, head, tail, has_ports = s[0][s[1]]
            if d:
                src, dst, ports = s[3], s[2], s[5]
            else:
                src, dst, ports = s[2], s[3], s[4]
            if not has_ports:
                ports = b''
            ln = 34 + len(ports) + len(tail)
            sec, usec = divmod(t_us, 1000000)
            buf.append(pk(sec, usec, ln, ln) + head + src + dst + ports + tail)
            written += 16 + ln
            t_us += steps[n & 1023]
            n += 1
            s[1] += 1
            if s[1] == len(s[0]):
                active[k] = session(n)
            if len(buf) >= 4096:
                f.write(b''.join(buf))
                buf = []
        f.write(b''.join(buf))
    return n, written

# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('outdir')
    ap.add_argument('--large-mb', type=int, metavar='N', help='also write large-<N>mb.pcap')
    ap.add_argument('--bomb', action='store_true', help='also write hostile/bomb.pcap.gz')
    a = ap.parse_args(argv)
    os.makedirs(a.outdir, exist_ok=True)
    files = {}
    exp = {'generator': 'make_samples.py', 'epoch_start': '2026-11-08T10:00:00Z', 'files': files}
    build_dns(a.outdir, files)
    build_http(a.outdir, files)
    build_tls(a.outdir, files)
    build_icmp(a.outdir, files)
    build_dhcp(a.outdir, files)
    build_ipv6(a.outdir, files)
    build_vlan(a.outdir, files)
    build_sll(a.outdir, files, 113, 'sll.pcap')
    build_sll(a.outdir, files, 276, 'sll2.pcap')
    build_nano(a.outdir, files)
    build_bigendian(a.outdir, files)
    build_raw_and_null(a.outdir, files)
    build_pcapng(a.outdir, files)
    build_quic(a.outdir, files)
    for src in ('dns.pcap', 'multi-if.pcapng'):
        with open(os.path.join(a.outdir, src), 'rb') as f:
            data = gzip.compress(f.read(), mtime=0)
        with open(os.path.join(a.outdir, src + '.gz'), 'wb') as f:
            f.write(data)
        files[src + '.gz'] = dict(files[src], gzip=True, gunzipped=src)
    build_hostile(a.outdir, exp, a.bomb)
    with open(os.path.join(a.outdir, 'expected.json'), 'w') as f:
        json.dump(exp, f, indent=1)
        f.write('\n')
    print('wrote %d sample files + hostile/ to %s' % (len(files), a.outdir))
    if a.large_mb:
        t = time.time()
        n, size = write_large(os.path.join(a.outdir, 'large-%dmb.pcap' % a.large_mb), a.large_mb)
        print('large-%dmb.pcap: %d packets, %d bytes, %.1fs' % (a.large_mb, n, size, time.time() - t))

if __name__ == '__main__':
    sys.exit(main())
