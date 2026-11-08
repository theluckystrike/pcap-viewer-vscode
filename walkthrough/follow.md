# Follow a stream and see the bytes

- Double-click a TCP or UDP packet, or press Enter, to open Follow stream. It shows the data of the whole connection in order: client to server in red, server to client in blue. Pick ASCII, UTF-8 or a hex dump, one direction or both, then Copy or Save as.
- "Filter on this stream" puts `tcp.stream == N` in the filter box.
- Click a line in the protocol tree to light up its bytes in the hex pane. Click a byte in the hex pane to select the field it belongs to; the tree opens to show it.
- Right-click a packet to filter on its source, its destination, the conversation or the protocol, to copy the row, or to export the selected packets as a pcap file.
- Statistics lists the protocol hierarchy, conversations and endpoints. Click a row to filter on it.
