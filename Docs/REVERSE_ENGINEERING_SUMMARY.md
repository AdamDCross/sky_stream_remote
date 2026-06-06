# Reverse Engineering Summary

This repository is based on a combination of static APK analysis and live validation against a real Sky box.

- The APK assets exposed the discovery service name, pairing fields, bundled client certificates, and command names.
- Live LAN testing confirmed the device discovery flow, TLS/WebSocket upgrade, Pair Request, Bind Request, and Key Command Request sequence.
- The auth token derivation was verified against working sessions and is captured in `SKY_REMOTE_PROTOCOL.md`.
- Additional button experiments were used to separate working keys from rejected ones; both the verified keys and rejected candidates are listed in `SKY_REMOTE_PROTOCOL.md`.

## Practical outcome

The Home Assistant integration and standalone Python remote in this repository both implement the same verified LAN protocol:

1. Discover the box over `_rdk-rics._tcp.local.`.
2. Connect over TLS to port `8091` and upgrade to `/iptarget` WebSocket.
3. Pair, derive the auth token, bind, and then send `keyatomic` key commands.
4. Use Wake-on-LAN where a box is in standby and a MAC address is available.
