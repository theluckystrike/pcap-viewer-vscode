# Changelog

## 0.1.0 (2026-11-08)

First release.

- Opens .pcap (microsecond and nanosecond, little and big-endian), .pcapng and both as .gz. Default editor for .pcap, .pcapng, .pcap.gz, .pcapng.gz and .ntar; "Open in PCAP Viewer" for .cap and any other file.
- Packet list with time, source, destination, protocol, length and info, drawn on demand, so a 1 GB capture lists in about 2 seconds.
- Protocol tree for Ethernet, VLAN, Linux cooked capture v1 and v2, raw IP, loopback, 802.11 headers, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, DHCP, HTTP/1.x, TLS (SNI and ALPN) and QUIC long headers.
- Hex pane linked both ways: a tree field lights its bytes, a byte selects its field.
- Display filters with fields, protocol names, ==, !=, <, >, contains, matches, in {...}, subnets, &&, || and !, checked as you type. Saved filters in the star menu.
- Follow TCP or UDP stream as ASCII, UTF-8 or a hex dump; copy or save it.
- Statistics: protocol hierarchy, conversations, endpoints and the names found in the capture.
- Names from DNS answers and pcapng name blocks; nothing is looked up on the network.
- Export selected or filtered packets as pcap (pcapng when the link types differ).
- Clear messages for damaged files (zero-length or oversized blocks, packets past the end of the file, packets over 256 KB) and for gzip bombs.
