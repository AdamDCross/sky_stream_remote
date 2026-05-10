# Protocol Draft (Verified + Inferred)

_Last updated: 2026-03-12_

This document started as a static-analysis draft, but now also includes
verified runtime evidence from:

- packet captures,
- direct TLS/WebSocket interception,
- transparent bridge logging to the real box,
- local pairing-oracle experiments.

The remaining major unknown is the exact `authtoken` derivation.

Related notes:

- `DISCOVERY.md`
- `LIVE_CAPTURE_PLAN.md`

---

## 1) Confidence Legend

- **High**: directly supported by explicit constants, method calls, or endpoint strings.
- **Medium**: strongly implied by multiple independent strings/signals.
- **Low**: plausible but requires runtime confirmation.

---

## 2) Transport and Discovery Model (Inferred)

## A) Discovery transport

- **Protocol**: mDNS / DNS-SD
- **Service types observed**:
  - `_services._dns-sd._udp`
  - `_rdk-rics._tcp`
- **Confidence**: **High**

## B) Control transport

- **Observed**: WebSocket over TLS (`wss://...:8091/iptarget`)
- **HTTP upgrade**:
  - `GET /iptarget HTTP/1.1`
  - `Upgrade: websocket`
  - `Sec-WebSocket-Version: 13`
- **TLS**: TLS 1.3
- **mTLS**: app presents a bundled client certificate
- **Confidence**: **High**

## C) Fixed control port (e.g., 8091)

- Runtime discovery and live sessions consistently resolved to port `8091`.
- Port is still service-derived via discovery, but the observed target service used `8091`.
- **Confidence**: **High** for observed `8091`, **High** for service-derived selection.

---

## 3) Operation Namespace / Channel Names

Observed operation-like strings:

- `entos-remote-app/remote_app_discovery/1`
- `entos-remote-app/remote_app_conn_status/1`
- `entos-remote-app/remote_app_keypress/1`

Inferred operation identifiers:

- `remote_app_discovery`
- `remote_app_conn_status`
- `remote_app_keypress`

Confidence: **High** (strings are explicit in native payload).

---

## 4) Discovery Payload Schema (Inferred)

Explicit key names confirmed from DEX NSD bridge (`NsdServiceInfo <-> Map`):

| Field               | Type (guess)    | Meaning (inferred)                     | Evidence                                              | Confidence |
| ------------------- | --------------- | -------------------------------------- | ----------------------------------------------------- | ---------- |
| `service.name`      | string          | DNS-SD service instance name           | DEX constants in NSD mapper                           | High       |
| `service.type`      | string          | DNS-SD service type (`_rdk-rics._tcp`) | DEX constants + service-type strings                  | High       |
| `service.port`      | int             | service TCP port from SRV              | DEX constants + `NsdServiceInfo.getPort/setPort`      | High       |
| `service.host`      | string          | hostname/canonical host                | DEX constants + `getHost/setHost` + InetAddress calls | High       |
| `service.addresses` | array/string    | resolved IP(s)                         | DEX constants + host/address extraction               | High       |
| `service.txt`       | map/string blob | DNS-SD TXT attributes                  | DEX constants + `getAttributes/setAttribute`          | High       |
| `service.version`   | string/int      | service protocol/build version         | native string only                                    | Medium     |
| `service.build`     | string/int      | service build identifier               | native string only                                    | Medium     |
| `service.shaJ`      | string          | unknown integrity/id attribute         | native string only                                    | Low        |

Notes:

- `service.version`, `service.build`, `service.shaJ` were observed in native strings but not confirmed in DEX bridge constants.
- They may come from higher-level parsing of TXT or platform-specific metadata.

---

## 5) Connection / Auth Schema (Observed + Inferred)

Observed field/token candidates:

| Field             | Type          | Meaning                            | Evidence                            | Confidence |
| ----------------- | ------------- | ---------------------------------- | ----------------------------------- | ---------- |
| `command_name`    | string        | command/message type               | live bridge logs                    | High       |
| `tid`             | string        | transaction/session correlation id | live bridge logs                    | High       |
| `name`            | string        | client/device display name         | live bridge logs                    | High       |
| `manufacturer`    | string        | client manufacturer                | live bridge logs                    | High       |
| `model`           | string        | client model                       | live bridge logs                    | High       |
| `controllernonce` | string        | client-side session nonce          | live bridge logs + native strings   | High       |
| `pairingcode`     | string        | server-supplied pairing challenge  | live bridge logs + oracle tests     | High       |
| `stbnonce`        | string        | server-side nonce/challenge input  | live bridge logs + oracle tests     | High       |
| `authtoken`       | base64 string | client-derived auth token          | live bridge logs + oracle tests     | High       |
| `bind_id`         | int           | authenticated session/bind handle  | live bridge logs                    | High       |
| `cmd`             | string        | command subtype                    | live bridge logs (`keyatomic`)      | High       |
| `key`             | string        | logical key name                   | live bridge logs                    | High       |
| `status`          | bool          | success/failure flag               | live bridge logs                    | High       |
| `clientId`        | string        | app/client identity                | native string only                  | Medium     |
| `deviceId`        | string        | selected target identity           | native string + TXT records         | Medium     |
| `challenge`       | object/string | broader auth structure             | native error string mentions format | Medium     |

Additional auth/TLS clues:

- `soft_remote_key.pem` and cert chain PEM bundled in assets.
- Secure socket / X509 APIs present.
- Live tests proved the app presents a client cert with subject `CN=sky.xcal.tv`.
- The app accepted a locally generated server cert on this LAN control channel, so strict server-cert pinning was not observed here.

Confidence for exact auth message format: **High**.

### Verified live message flow

Observed plaintext sequence:

1. Client opens TLS and upgrades to WebSocket:
   - `GET /iptarget HTTP/1.1`
2. Client sends:
   - `{"command_name":"Pair Request","tid":"...","name":"Soft Remote","manufacturer":"Comcast","model":"IPRemote","controllernonce":"..."}`
3. Server replies:
   - `{"command_name":"Pair Request","name":"Living Room","pairingcode":"...","status":true,"stbnonce":"...","tid":"..."}`
4. Client sends:
   - `{"command_name":"Bind Request","tid":"...","authtoken":"..."}`
5. Server replies:
   - `{"bind_id":N,"command_name":"Bind Request","status":true,"tid":"..."}`
6. Client sends key commands:
   - `{"command_name":"Key Command Request","tid":"...","authtoken":"...","bind_id":N,"cmd":"keyatomic","key":"ArrowRight"}`
7. Server acknowledges:
   - `{"command_name":"Key Command Request","status":true,"tid":"..."}`

### Verified auth findings

- `authtoken` is base64-encoded 32 bytes.
- `authtoken` changes every session.
- Exact `pairingcode` formatting matters:
  - leading spaces vs trimmed vs digits-only produced different `authtoken` values.
- `stbnonce` content matters:
  - changing only `stbnonce` also changed `authtoken`.
- Fixed-input oracle runs showed that the token is deterministic inside one reused app session context:
  - same `pairingcode` + same `stbnonce` + same `tid` + same `controllernonce` -> same `authtoken`
  - new `tid` / `controllernonce` family -> new `authtoken`
- The app still produced valid repeated tokens with mobile data disabled, so a mandatory live cloud call per bind is unlikely.
- Simple SHA-256, HMAC-SHA256, and PBKDF2 combinations over the observed
  `pairingcode`, `stbnonce`, `controllernonce`, and `tid` did **not** reproduce the token.
- A broader scripted search over 5,807 candidate formulas first found no match across 6 captured sessions, and a fresh 10-session clean bridge retest on 2026-03-12 increased the checked set to 11 total sessions with the same result.

### Static auth-tracing clues

- `libapp.so` contains explicit anchors for `Pair Request`, `Bind Request`, `pairingcode`,
  `stbnonce`, `controllernonce`, and `authtoken`.
- Blutter's `out/pp.txt` places those protocol strings next to SHA-256 IV constants,
  hex-encoding helpers, and base64-related strings.
- The most promising remaining static trail is the digest/helper cluster around:
  - `out/asm/ich.dart`
  - `out/asm/ifh.dart`
  - `out/asm/nPg.dart`
  - `out/asm/lPg.dart`
- Earlier recovered code in `Zgh`, `ehh`, and `FPg` looks much more like parser/model
  plumbing than token derivation logic.

---

## 6) Keypress Command Schema (Observed + Inferred)

Explicit keypress field names observed:

| Field               | Type (guess)    | Meaning (inferred)            | Evidence      | Confidence |
| ------------------- | --------------- | ----------------------------- | ------------- | ---------- |
| `keypress.category` | string/enum     | command category              | native string | High       |
| `keypress.code`     | string/int enum | actual key command            | native string | High       |
| `keyCode`           | string/int enum | key code alias/platform value | native string | Medium     |
| `IPKeyCode`         | enum/model name | internal key enum/model       | native string | Medium     |

Likely keypress values seen in strings:

- Power/control: `Power`, `Mute`, `Home`, `Back`, `Guide`, `Menu`, `Info`, `Select`, `ok`
- Media: `Play`, `Pause`, `Stop`, `Record`, `forward`
- Channel: `ChannelUp`, `ChannelDown`
- Numeric: `Numpad0`..`Numpad9` (subset observed explicitly)

Verified on wire:

- `ArrowRight`
- `ArrowDown`
- `ArrowLeft`
- `ArrowUp`
- `Enter`
- `Settings`
- `AccessMenu`
- `Plus`
- `Home`
- `Dismiss`
- `Option`
- `Digit1`
- `Digit2`
- `Digit3`
- `Power`

Verified command envelope:

- `command_name = "Key Command Request"`
- `cmd = "keyatomic"`
- `key = "<logical key name>"`
- `authtoken` and `bind_id` are included on command messages after bind.

Confidence for exact enum spellings on wire: **High**.

---

## 7) Connection State Model (Observed + Inferred)

Observed state tokens:

- `CONNECTED`
- `DISCONNECTED`
- `Connecting` / `connecting`
- `Disconnected` / `disconnected`
- `socket-disconnected`
- `SiftRemoteAppConnectionStatus`

Likely state machine:

1. Discovery starts
2. Service discovered (`onServiceDiscovered`)
3. Connect attempt (`connecting`)
4. Auth/pair negotiation (token/challenge/nonces)
5. Session active (`connected`)
6. Command streaming (`remote_app_keypress`)
7. Failure/teardown (`socket-disconnected` / `disconnected`)

Observed reconnect behavior:

- If the WebSocket is closed after bind, the app surfaces a disconnect/reconnect prompt.
- The app will reconnect and repeat Pair -> Bind on the next session.

Confidence: **High**.

---

## 8) Callback/Event Surface (Observed)

Discovery callbacks:

- `onDiscoveryStartSuccessful`
- `onDiscoveryStartFailed`
- `onDiscoveryStopSuccessful`
- `onDiscoveryStopFailed`
- `onServiceDiscovered`
- `onServiceLost`

Inferred role:

- App likely forwards these events into Flutter domain as map payloads.

Confidence: **High**.

---

## 9) End-to-End Flow

1. Browse mDNS for `_services._dns-sd._udp` and/or `_rdk-rics._tcp`.
2. Resolve service record to host + port + TXT attrs.
3. Open TLS 1.3 session to discovered endpoint.
4. Upgrade to WebSocket on `/iptarget`.
5. Send `Pair Request` with `tid` + `controllernonce`.
6. Receive pairing response with `pairingcode` + `stbnonce`.
7. Send `Bind Request` with derived `authtoken`.
8. Receive `bind_id`.
9. Send `Key Command Request` messages using `cmd="keyatomic"` and logical `key` names.
10. Maintain connection until disconnect/reconnect.

Confidence: **High** overall for the control-path message flow.

---

## 10) Open Questions for Live Validation

1. Exact `authtoken` derivation algorithm.
2. Whether additional async server messages exist outside the captured Pair/Bind/Key flow.
3. Whether there are any functionally relevant side-channel inputs beyond the visible session fields and app-local state.
4. Whether this trust behavior is universal across firmware/builds.

---

## 11) Validation Checklist Mapped to This Draft

- [x] Confirm `_rdk-rics._tcp` SRV/TXT in packet capture.
- [x] Record discovered `service.port` and `service.host` values.
- [x] Confirm control channel is WebSocket over TLS.
- [x] Observe client certificate presented by app.
- [x] Recover plaintext Pair/Bind/Key messages with MITM bridge.
- [x] Verify `cmd="keyatomic"` and representative key names.
- [x] Confirm reconnect behavior after forced close.
- [ ] Determine exact `authtoken` algorithm.
- [ ] Determine whether parallel side-channel traffic matters functionally.

This draft now contains both verified and inferred sections; remaining work is focused on `authtoken` derivation, validating fresh captures against the current model, and only then deciding whether runtime instrumentation is needed.

---

## 12) Runtime Evidence Template (Fill During Capture)

Use these tables during live tests to convert inferred items into verified behavior.

### A) Discovery Evidence Log

| Timestamp | Action in App                | mDNS Observation                       | Parsed Field(s)                               | Expected vs Observed        | Verdict |
| --------- | ---------------------------- | -------------------------------------- | --------------------------------------------- | --------------------------- | ------- |
|           | Open device discovery screen | PTR for `_services._dns-sd._udp.local` | service.type                                  | Expected `_rdk-rics._tcp`   |         |
|           | Device appears               | SRV answer                             | service.host, service.port                    | Expected dynamic host+port  |         |
|           | Device details update        | TXT answer                             | service.txt (+optional service.version/build) | Expected attributes present |         |
|           | Device list refresh          | A/AAAA answer                          | service.addresses                             | Expected IPs resolved       |         |

### B) Session / Auth Evidence Log

| Timestamp | Action in App     | Network Observation                | Candidate Field(s)                    | Expected vs Observed              | Verdict |
| --------- | ----------------- | ---------------------------------- | ------------------------------------- | --------------------------------- | ------- |
|           | Tap device        | TCP connect to discovered endpoint | service.host/service.port             | Should match SRV-derived target   |         |
|           | Pair prompt shown | Handshake/first app payload        | pairingcode, deviceId, clientId       | Pairing flow triggered            |         |
|           | Pair submit       | Auth exchange                      | challenge, controllernonce, authtoken | Nonce/challenge semantics visible |         |
|           | Connected state   | Post-auth session activity         | remote_app_conn_status                | Connected token/state reflected   |         |

### C) Keypress Evidence Log

| Timestamp | Button Pressed | Packet/Message Signature | Inferred Mapping      | Expected Field(s)                 | Verdict |
| --------- | -------------- | ------------------------ | --------------------- | --------------------------------- | ------- |
|           | Power          |                          | `keypress.code=Power` | keypress.category + keypress.code |         |
|           | Home           |                          | `keypress.code=Home`  | keypress.category + keypress.code |         |
|           | Back           |                          | `keypress.code=Back`  | keypress.category + keypress.code |         |
|           | Play/Pause     |                          | media command         | keypress.category + keypress.code |         |
|           | ChannelUp      |                          | channel command       | keypress.category + keypress.code |         |
|           | Numpad digit   |                          | numeric command       | keypress.category + keypress.code |         |

### D) TLS / mTLS Evidence Log

| Timestamp | Flow                     | TLS Observation                     | Expected Signal           | Verdict |
| --------- | ------------------------ | ----------------------------------- | ------------------------- | ------- |
|           | Client -> device connect | TLS ClientHello                     | TLS in use                |         |
|           | Server handshake         | `CertificateRequest` present/absent | mTLS indicator            |         |
|           | Client handshake         | Client Certificate sent/absent      | mTLS confirmed/rejected   |         |
|           | Session active           | App data records pattern            | Encrypted command channel |         |

### E) Verification Status Rollup

| Item                                | Current Status | Evidence Pointer (pcap frame/time) | Notes |
| ----------------------------------- | -------------- | ---------------------------------- | ----- |
| `_rdk-rics._tcp` discovery verified |                |                                    |       |
| Dynamic service port verified       |                |                                    |       |
| Control channel endpoint verified   |                |                                    |       |
| Keypress payload structure verified |                |                                    |       |
| mTLS requirement verified           |                |                                    |       |

Suggested status values: `unverified`, `partial`, `verified`, `contradicted`.
