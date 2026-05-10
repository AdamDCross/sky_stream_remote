# Live Capture Plan

_Last updated: 2026-03-12_

This document provides practical workflows for collecting clean LAN evidence from the Sky Remote app now that the basic control protocol is already known.

Known validated indicators:

- mDNS/DNS-SD discovery hints: `_services._dns-sd._udp`, `_rdk-rics._tcp`
- control channel: `wss://<service-host>:8091/iptarget`
- message flow: `Pair Request` -> `Bind Request` -> `Key Command Request`
- auth fields of interest: `pairingcode`, `stbnonce`, `tid`, `controllernonce`, `authtoken`

Current capture goal:

- get short, clean, current sessions that can be compared against the existing protocol map
- preserve enough raw context to rule out any hidden assumptions before attempting runtime instrumentation

---

## Before You Start

- Force-close the app before the run if you want a fresh connect/pair/bind sequence.
- Keep the capture short; 20-60 seconds is usually enough.
- Record exact user actions and timestamps.
- Prefer keeping one full capture and then making filtered copies for analysis, rather than only saving a pre-filtered export.
- If possible, do one "real box" session first; oracle/bridge tests are still useful, but they should be compared against a fresh real session.

---

## Workflow A — Remote LAN Capture via Home Assistant Side

Use this when the TV/device is on a network you can access via SSH/Home Assistant.

## A1) Preconditions

- The capture host must be on the same L2/VLAN as the target device and phone running the app.
- You need a shell with packet tools (`tcpdump` at minimum).
- If commands are unavailable in HAOS host shell, run from:
  - another Linux host on that LAN, or
  - a suitable add-on/container with host networking.

## A2) Identify interface

```bash
ip -br a
ip route
```

Pick the active LAN interface (examples: `eth0`, `enp3s0`, `wlan0`).

## A3) Capture mDNS discovery

Start this before opening the device picker in the app:

```bash
sudo tcpdump -i <iface> -n -vv -s0 udp port 5353 -w mdns_discovery.pcap
```

What to look for in Wireshark/tshark:

- PTR query/response involving `_services._dns-sd._udp.local`
- PTR/SRV/TXT for `_rdk-rics._tcp.local`
- SRV answer gives target hostname + port (this is critical)
- A/AAAA answer maps hostname to device IP

Optional quick text check:

```bash
tshark -r mdns_discovery.pcap -Y "dns" -T fields \
  -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.resp.name
```

## A4) Capture control-session traffic

After you know the discovered service port (replace `<port>`):

```bash
sudo tcpdump -i <iface> -n -vv -s0 \
  "(udp port 5353) or (host <device_ip> and tcp port <port>)" \
  -w remote_session.pcap
```

Exercise deterministic button sequence in app (for correlation):

1. Power
2. Home
3. Arrow Right
4. Arrow Down
5. Enter
6. Back

## A5) Check for TLS / mTLS

Open `remote_session.pcap` in Wireshark and inspect TLS handshake on app -> device TCP flow.

mTLS indicator:

- Server sends `CertificateRequest`
- Client sends `Certificate`

Without decryption, still useful:

- packet timing and record-size patterns per button press
- connection lifecycle (reconnects, keepalives)

## A6) If port 8091 is suspected

- Do not assume 8091 first.
- Confirm actual runtime port from SRV record for `_rdk-rics._tcp`.
- Then re-run capture filter using discovered port.

---

## Workflow B — macOS Local Capture

Use this when your Mac is on the same LAN as app/device (or if the app itself runs on a phone on that same segment and your Mac can monitor relevant traffic path).

## B1) Identify interface

```bash
networksetup -listallhardwareports
ifconfig
route -n get default
```

Typical interfaces:

- Wi-Fi: `en0`
- Ethernet: `enX`

## B2) Capture mDNS

```bash
sudo tcpdump -i en0 -n -vv -s0 udp port 5353 -w mdns_discovery_mac.pcap
```

Trigger app discovery and stop capture after device appears.

Optional quick parse:

```bash
tshark -r mdns_discovery_mac.pcap -Y "dns" -T fields \
  -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.resp.name
```

## B3) Capture device control flow

After finding service IP/port from SRV/A records:

```bash
sudo tcpdump -i en0 -n -vv -s0 \
  "(udp port 5353) or (host <device_ip> and tcp port <port>)" \
  -w remote_session_mac.pcap
```

Run the same deterministic button sequence as Workflow A.

## B4) TLS/mTLS validation on macOS

In Wireshark:

- Follow TLS handshake packets
- Check for `CertificateRequest` from server
- Confirm whether client cert is presented

If packets are encrypted and app uses cert pinning/mTLS, payload decoding may still be unavailable without session keys or runtime instrumentation.

---

## Expected Success Criteria

You have enough evidence to model protocol when all are true:

1. `_rdk-rics._tcp` discovered via mDNS
2. SRV gives host/port and A/AAAA gives reachable device IP
3. App opens TCP session to discovered endpoint
4. Pair/Bind traffic can be correlated to the known JSON schema
5. Button presses create reproducible post-bind traffic bursts
6. Handshake characteristics (TLS/mTLS) are identified

If the session is especially clean, you should also be able to extract or confirm:

- the exact `Pair Request` / `Pair Response` / `Bind Request` sequence
- whether any extra messages appear before or after bind
- whether the captured `authtoken` family behaves consistently with prior sessions

---

## Practical Notes

- mDNS is link-local multicast; cross-VLAN visibility usually requires multicast reflection.
- If capturing on a non-bridged host, you may only see that host's own traffic.
- If you cannot install tools on HAOS host shell, use another LAN node (Linux/macOS) for capture.
- Keep captures short and action-labeled to simplify correlation.
- For tomorrow's retest, bias toward fewer actions and cleaner labeling rather than trying to capture every possible key in one run.

---

## Suggested Capture Naming Convention

Use timestamped names for reproducibility:

- `YYYYMMDD-HHMM-mdns.pcap`
- `YYYYMMDD-HHMM-session-power-home-vol3-chan2-back.pcap`

This makes it easier to compare multiple runs and protocol revisions.
