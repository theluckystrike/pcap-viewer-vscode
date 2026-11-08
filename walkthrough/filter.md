# Filter packets

Type a display filter in the box above the packet list and press Enter. The box turns green when the filter is valid and red when it is not; the message under it says what is wrong and where.

| Filter | Shows |
|---|---|
| `tcp`, `udp`, `dns`, `http`, `tls`, `quic`, `arp`, `icmp`, `dhcp` | packets with that protocol |
| `ip.addr == 10.0.0.1` | packets from or to that address (`ip.src`, `ip.dst` for one side) |
| `ip.addr == 10.0.0.0/24` | a whole subnet |
| `tcp.port == 443`, `udp.port in {53 5353}` | a port, or a set of ports |
| `dns.qry.name contains "example"` | text inside a field |
| `tls.sni == "example.com"` | TLS Client Hellos for one server name |
| `frame.len > 1000` | large frames |
| `tcp.stream == 3` | one TCP connection |

Join conditions with `&&` (and), `||` (or) and `!` (not), with brackets where needed: `tcp.port == 443 && !(ip.addr == 10.0.0.1)`.

The star button keeps filters you use often. Esc in the filter box shows every packet again.
