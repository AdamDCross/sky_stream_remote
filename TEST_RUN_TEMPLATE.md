# Test Run Template (Single Session)

_Last updated: 2026-03-12_

Purpose: run one deterministic, low-noise capture session and collect enough evidence to validate the current Pair/Bind/keypress model against a fresh real-box session.

Related docs:

- `LIVE_CAPTURE_PLAN.md`
- `PROTOCOL_DRAFT.md`
- `DISCOVERY.md`
- `FLUTTER_UI_FLOWS.md`

---

## 1) Pre-Run Setup

## A) Fill environment

- Capture host: ********\_\_\_\_********
- Interface: ********\_\_\_\_********
- Device under test IP (if known): ********\_\_\_\_********
- Date/time: ********\_\_\_\_********

## B) Start capture

Use one of:

```bash
sudo tcpdump -i <iface> -n -vv -s0 '(udp port 5353) or (tcp)' -w run01_full.pcap
```

or targeted (after device IP/port are known):

```bash
sudo tcpdump -i <iface> -n -vv -s0 '(udp port 5353) or (host <device_ip> and tcp port <port>)' -w run01_targeted.pcap
```

---

## 2) Deterministic App Action Script

Record actual timestamps as you execute:

1. Force-close app
2. Start capture
3. Open app
4. Open device discovery/list screen
5. Wait until first device appears (or timeout at 30s)
6. Select target device
7. Complete pairing flow (if prompted)
8. Once connected, press buttons in this exact order:
   - `Power`
   - `Home`
   - `Arrow Right`
   - `Arrow Down`
   - `Enter`
   - `Back`
9. Leave the app idle for 5-10 seconds
10. Return to remote/home screen if needed
11. Stop capture

---

## 3) Timestamp Log Sheet

| Step | Action                   | Timestamp (local) | Notes |
| ---- | ------------------------ | ----------------- | ----- |
| 1    | App force-closed         |                   |       |
| 2    | Capture started          |                   |       |
| 3    | App opened               |                   |       |
| 4    | Discovery screen shown   |                   |       |
| 5    | Device first seen        |                   |       |
| 6    | Device selected          |                   |       |
| 7    | Pair completed / skipped |                   |       |
| 8a   | Power                    |                   |       |
| 8b   | Home                     |                   |       |
| 8c   | Arrow Right              |                   |       |
| 8d   | Arrow Down               |                   |       |
| 8e   | Enter                    |                   |       |
| 8f   | Back                     |                   |       |
| 9    | Idle window started      |                   |       |
| 10   | Final app state noted    |                   |       |
| 11   | Capture stopped          |                   |       |

---

## 4) Quick Validation Checklist

## Discovery

- [ ] `_services._dns-sd._udp.local` observed
- [ ] `_rdk-rics._tcp.local` observed
- [ ] SRV provides host+port
- [ ] A/AAAA provides matching address(es)

## Session/Auth

- [ ] App connects to SRV-derived endpoint
- [ ] Pair/auth exchange visible after select/pair action
- [ ] `Pair Request` / `Pair Response` / `Bind Request` sequence isolated
- [ ] `authtoken`, `tid`, `controllernonce`, `pairingcode`, `stbnonce` extracted cleanly
- [ ] Connection state transitions visible (connect/disconnect)

## Commands

- [ ] Keypress traffic bursts correlate with button timestamps
- [ ] Post-bind commands remain consistent with `cmd="keyatomic"` expectations

## TLS

- [ ] TLS handshake confirmed
- [ ] Server `CertificateRequest` checked
- [ ] Client certificate presence checked

---

## 5) Evidence Extraction Notes

After capture, extract references to include in your report:

- mDNS packet/frame IDs for PTR/SRV/TXT/A
- TCP 5-tuple for device control channel
- TLS handshake packet/frame IDs
- For each keypress, nearest packet/frame range and size pattern

---

## 6) Result Summary (Fill After Run)

| Hypothesis                                                   | Status (`unverified`/`partial`/`verified`/`contradicted`) | Evidence |
| ------------------------------------------------------------ | --------------------------------------------------------- | -------- |
| Discovery uses mDNS DNS-SD                                   |                                                           |          |
| Target service type is `_rdk-rics._tcp`                      |                                                           |          |
| Control endpoint resolves to the expected `/iptarget` flow   |                                                           |          |
| Pair/auth sequence matches current protocol draft            |                                                           |          |
| Keypress path still maps to `Key Command Request` / `keyatomic` |                                                        |          |
| mTLS characteristics remain unchanged                        |                                                           |          |

---

## 7) Attachments

- Capture file(s): ********\_\_\_\_********
- Filtered export(s): ********\_\_\_\_********
- Screen recording (optional): ********\_\_\_\_********
- Notes/log files: ********\_\_\_\_********
