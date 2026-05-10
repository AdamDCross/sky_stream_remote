# Sky Remote APK Discovery Notes

_Last updated: 2026-03-13_

## Scope and Context

This document summarizes static analysis findings from the unpacked APK workspace:

- Package folder: `com.entos.monarch.remote.uk.apk/`
- Base split archive: `../com.entos.monarch.remote.uk.apk.zip`
- Additional splits observed:
  - `../config.arm64_v8a.apk`
  - `../config.en.apk`
  - `../config.mdpi.apk`
  - `../config.zh.apk`

No source project was available; findings are from packaged artifacts (DEX, resources, Flutter assets, native libraries, manifests).

---

## 1) App Packaging and Stack

### High-level packaging

- This app is distributed as split APKs (base + ABI + locale + density).
- Base APK contains Java/Kotlin DEX (`classes.dex`, `classes2.dex`), Android resources, and Flutter assets.
- ARM64 split contains native libraries, including:
  - `lib/arm64-v8a/libapp.so`
  - `lib/arm64-v8a/libflutter.so`

### Technology signals

- Flutter assets present under `assets/flutter_assets/`.
- Kotlin/Gradle metadata present in `kotlin-tooling-metadata.json`.
- AndroidX dependency/version markers present in `META-INF/`.

---

## 2) Manifest/Component Summary (decoded from binary manifest)

### App identity

- Package: `com.entos.monarch.remote.uk`
- Version name: `1.0.7291`
- Version code: `1007291`
- Min SDK: `24`
- Target SDK: `36`
- Main activity: `com.entos.monarch.remote.uk.MainActivity`

### Declared permissions (observed)

- `android.permission.INTERNET`
- `android.permission.CHANGE_WIFI_MULTICAST_STATE`
- `android.permission.RECORD_AUDIO`
- `com.android.vending.CHECK_LICENSE`
- `com.entos.monarch.remote.uk.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`

### Components (observed)

- Activities:
  - `com.entos.monarch.remote.uk.MainActivity`
  - `com.pairip.licensecheck.LicenseActivity`
  - `io.flutter.plugins.urllauncher.WebViewActivity`
- Receivers:
  - `androidx.profileinstaller.ProfileInstallReceiver`
- Providers:
  - `androidx.startup.InitializationProvider`
  - `com.pairip.licensecheck.LicenseContentProvider`

### Security-relevant manifest posture (observed via attributes)

- `usesCleartextTraffic`: not explicitly set
- `networkSecurityConfig`: not explicitly set
- `extractNativeLibs`: `false`

---

## 3) Network Endpoint and SDK Signals

## A) Internet endpoint strings observed (primarily in `libapp.so`)

High-confidence endpoint strings:

- `https://prod-eu-1-metricscollector.lp.xcal.tv:18082`
- `https://prod-eu-1-metricscollector.lp.xcal.tv:18082/postMetrics?client=sky_uk_soft_remote`
- `https://api.eu1.honeycomb.io/v1/traces`
- `https://clientsdk.launchdarkly.com/msdk/evalx/contexts/`
- `https://mobile.launchdarkly.com/mobile/events/bulk`
- `https://www.sky.com/help/articles/privacy-hub-home`
- `https://static.cimcontent.net/common-web-assets/fonts/sky-text/...`

Interpretation:

- Metrics/telemetry: likely Xcal metrics collector + Honeycomb traces.
- Feature flags/config: LaunchDarkly mobile SDK endpoints.
- UX/legal/static content: Sky privacy page, hosted font assets.

## B) Local discovery / LAN communication signals

Observed in native Flutter side (`libapp.so`) and permissions:

- Service discovery strings:
  - `_services._dns-sd._udp`
  - `_rdk-rics._tcp`
- Discovery lifecycle strings:
  - `startDiscovery`, `stopDiscovery`, `onServiceDiscovered`
  - `onDiscoveryStartSuccessful`, `onDiscoveryStopSuccessful`
  - `discovery_error`, `discovered_services`, `1 TV device found`
  - `entos-remote-app/remote_app_discovery/1`
- Manifest capability consistent with multicast discovery:
  - `android.permission.CHANGE_WIFI_MULTICAST_STATE`

Interpretation:

- Strong evidence for mDNS/DNS-SD-based local service discovery.
- `_rdk-rics._tcp` appears to be a key service type to locate target devices.

---

## 4) Protocol and Command Surface Clues

### Inferred operation namespaces (string evidence)

- `entos-remote-app/remote_app_discovery/1`
- `entos-remote-app/remote_app_conn_status/1`
- `entos-remote-app/remote_app_keypress/1`

These strongly suggest operation/channel names for discovery, connection state, and keypress commands.

### Keypress and command schema clues (string evidence)

Observed tokens include:

- `keypress`
- `keypress.code`
- `keypress.category`
- `keyCode`
- `IPKeyCode`
- `SiftRemoteAppKeyPress`

Likely command vocabulary tokens observed:

- Navigation/media/power examples:
  - `Power`, `Mute`, `Guide`, `Home`, `Back`, `Menu`, `Info`
  - `Play`, `Pause`, `Stop`, `Record`
  - `ChannelUp`, `ChannelDown`
  - `Select`, `ok`
  - numeric inputs (`Numpad0`..`Numpad9` observed subset)

Interpretation:

- The remote-control command path likely serializes keypress events with at least a category + code concept.

---

## 5) Pairing / Authentication / TLS Clues

### Pairing/auth strings

Observed strings include:

- `Pair Request`
- `pairingcode`
- `challenge`
- `deviceId`
- `clientId`

### TLS/certificate API strings in native side

Observed strings include:

- `TlsException`
- `X509Certificate`
- `SecurityContext_UseCertificateChainBytes`
- `SecureSocket_RegisterBadCertificateCallback`

### Bundled key/certificate materials in app assets

Files observed:

- `assets/flutter_assets/packages/soft_remote_app/assets/certs/soft_remote_key.pem`
- `assets/flutter_assets/packages/soft_remote_app/assets/certs/xfinity.xcal.tv-ComcastRDKD2DECCICA1-20241014-20241114.pem`

The certificate bundle includes cert chain metadata referencing Comcast/Xfinity/sky.xcal.tv contexts.

Interpretation:

- Strong evidence that certificate-based secure transport is part of the design.
- Possible mTLS and/or certificate pinning behavior for at least some channels.

---

## 6) Confidence-Graded Hypotheses

### High confidence

1. App is Flutter-based (hybrid Android package).
2. App performs LAN device discovery with mDNS/DNS-SD patterns.
3. `_rdk-rics._tcp` is likely a target service type for remote-capable devices.
4. App has a keypress command channel concept (`remote_app_keypress`).
5. App reports telemetry/metrics to cloud endpoints (xcal/honeycomb/launchdarkly usage strings).

### Medium confidence

1. Command path likely uses structured keypress messages (category + code) over a persistent secure channel.
2. Connection/pairing likely includes challenge-based auth semantics.
3. Cert materials in assets likely participate in trust/auth flows (device or service channel).

### Low/Unconfirmed

1. Exact runtime LAN port (e.g., `8091`) is not yet statically confirmed.
2. Exact wire format (JSON vs protobuf vs custom binary) remains unconfirmed from static strings alone.
3. Exact cryptographic handshake details (strict mTLS vs pinning + token auth) are unconfirmed without runtime capture.

---

## 6A) Live Validation Update (2026-03-11)

The earlier static hypotheses were materially validated at runtime.

### Discovery / transport verified

- The app discovers `_rdk-rics._tcp` over mDNS and connects to the advertised endpoint.
- The control channel is `wss://...:8091/iptarget`.
- The app upgrades with:
  - `GET /iptarget HTTP/1.1`
  - `Upgrade: websocket`
  - `Sec-WebSocket-Version: 13`
- TLS 1.3 was observed on the local control channel.
- The app presents a bundled client certificate:
  - subject includes `CN=sky.xcal.tv`

### Trust behavior observed

- The app successfully connected to a locally generated TLS server certificate on the LAN control channel.
- That means strict server-cert pinning was **not** observed for this specific local channel.
- The app still presents its own client certificate, so mTLS-style client auth is in play.

### Plaintext application protocol recovered

Verified message flow:

1. Client sends `Pair Request` with:
   - `tid`
   - `name`
   - `manufacturer`
   - `model`
   - `controllernonce`
2. Server replies with:
   - `pairingcode`
   - `stbnonce`
   - `status`
   - `tid`
3. Client sends `Bind Request` with:
   - `authtoken`
   - `tid`
4. Server replies with:
   - `bind_id`
   - `status`
   - `tid`
5. Client sends `Key Command Request` with:
   - `authtoken`
   - `bind_id`
   - `cmd = "keyatomic"`
   - `key = "<logical key name>"`

Observed key names include:

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

### Auth-token findings

- `authtoken` is a 32-byte value encoded as base64.
- It changes every session.
- It depends on session-specific inputs.
- Changing only `pairingcode` formatting changes the token.
- Changing only `stbnonce` changes the token.
- Repeated fixed-input oracle runs showed that, within one reused app session context, the token is deterministic:
  - same `pairingcode` + same `stbnonce` + same `tid` + same `controllernonce` -> same `authtoken`
  - new `tid` / `controllernonce` family -> new `authtoken`
- The same repeated-token behavior still occurred with mobile data disabled, which makes a mandatory live cloud round-trip for each bind very unlikely.
- A broader scripted search over 5,807 simple candidates first found no match across 6 distinct sessions, and a fresh clean 10-reconnect bridge run on 2026-03-12 increased the checked set to 11 sessions total with the same result.
- Simple SHA-256 / HMAC-SHA256 / PBKDF2 combinations over the observed values did not reproduce the token.

### Current unknown

- The remaining key reverse-engineering target is the exact `authtoken` derivation algorithm.

---

## 6B) Static Auth-Tracing Update (2026-03-12)

Recent `libapp.so` and Blutter work tightened the static picture around the remaining auth problem.

### Confirmed protocol anchors in `libapp.so`

Direct string scanning located the key protocol/auth strings inside the Flutter AOT binary, including:

- `authtoken`
- `Pair Request`
- `Bind Request`
- `pairingcode`
- `stbnonce`
- `controllernonce`

The helper script `tools/scan_libapp_auth_strings.py` was added so these offsets can be rechecked repeatably.

### Blutter output added the strongest crypto clues so far

`out/pp.txt` contains a protocol object-pool cluster with:

- `command_name`
- `Pair Request`
- `tid`
- `Soft Remote`
- `Comcast`
- `IPRemote`
- `controllernonce`
- `status`
- `stbnonce`
- `pairingcode`
- `Key Command Request`
- `authtoken`
- `bind_id`
- `cmd`
- `Bind Request`

Immediately adjacent to that cluster are several crypto/encoding indicators:

- SHA-256 IV constants such as `0x6a09e667` and `0xbb67ae85`
- `0123456789abcdef`
- `Non-hex character detected in `
- `base64` error strings elsewhere in the pool

This is the strongest current evidence that the token path involves a digest/base64 pipeline near the protocol code, even though the exact formula is still unknown.

### Current best static lead

The most promising recovered helper cluster is:

- `out/asm/ich.dart`
- `out/asm/ifh.dart`
- `out/asm/nPg.dart`
- `out/asm/lPg.dart`

By contrast, earlier Ghidra work around `Zgh`, `ehh`, and `FPg` mostly turned out to be parser/model/extractor scaffolding rather than the token algorithm itself.

### First runtime instrumentation helper prepared

A first-cut Frida helper now exists at:

- `tools/frida_authtoken_trace.js`

It targets the current best AOT hook points in `libapp.so`:

- `0x331c50` `feh_::vZb_331c50`
- `0x33041c` `keh_KBa::Aef_33041c`
- `0x563378` `Ich_zya::RPe_563378`
- `0x574bc8` `Ich_Yva::RPe_574bc8`
- `0x4d8cf4` `Ich_uya::_kRe_4d8cf4`
- `0x52eb54` `LPg_Xv::_RCe_52eb54`

The script is intentionally conservative: it does not assume full Dart-object decoding yet, but it should let us validate call order and capture raw pointer-adjacent memory at the most likely digest/finalization points during a live bind.

---

## 7) What Was Not Confirmed Yet

- Exact `authtoken` derivation algorithm.
- Whether any additional non-WebSocket or cloud side-channel traffic materially affects pairing/connection behavior, although current offline/oracle results suggest it is not required per bind.
- Whether all firmware builds behave the same way on certificate trust.

---

## 7A) Rooted Frida Derivation Update (2026-03-12 late)

Recent rooted Frida work materially narrowed the remaining `authtoken` problem from “somewhere in the bind flow” to a much smaller object-construction seam.

### What is now proven

- The serializer is downstream only:
  - `330770 -> 32fd24 -> 32fde4 -> sub_32fe40` consumes an already-built token string.
- The final token string already exists by `33060c` return:
  - `33060c post-arg1 +0x20 +0x8` matches
  - `330770 arg1 +0x8`
  - and the emitted Bind JSON `authtoken`.
  - a later compressed-ref-aware rerun with the smaller `tools/frida_auth_inputs.js` probe directly decoded
    `33060c post-arg1 +0x20 +0x8` as a live Base64 token string, confirming the earlier larger-trace claim without needing the full serializer chain.
- The parsed Pair response flows directly into the bind builder:
  - `33060c arg2` matches the `32e990` parser retval byte-for-byte on the Pair-success leg.
  - the same compressed child walk on that parser object decodes `pairingcode` at `arg2 +0x10 +0x20`.
- `33060c` mutates the bind-parent in place:
  - hit #2 starts from the prior post-state of `arg1`, so the useful mutation is persistent on the parent/context object rather than a fresh rebuild each time.
- The late helper `55c414` is **not** the token builder:
  - static decode shows `0x55c414` is only a tiny allocation stub into the generic allocator.
  - runtime confirms it receives an already-finished bind parent object.
- Static narrowing from the smaller probe:
  - `0x330654` calls `FUN_00330674`, not an anonymous inline blob.
  - `FUN_00330674` allocates wrapper nodes from the live inputs, then immediately calls `FUN_0031b530`.
  - `FUN_0031b530` is now the best static candidate for the exact population step that installs the token-bearing child under the bind parent.
  - later focused reruns show one more live semantic input at the `0x330674` seam:
    - `330674 arg2 +0x10` decodes to `"Living Room"` on the successful path.
    - this means the seam is seeing human-readable device/profile state, not only opaque wrappers.
  - the attempted `330674 arg1 +0x9b` read is not yet the clean source we hoped for:
    - live raw value was `0x7800`, which does not decode as a stable compressed heap ref in the current probe.
  - `0x31b530` remains statically important but still did not produce a clean live Frida hit in the latest narrowed runs.

### Static tracing update after the smaller live probe

The best current static path is no longer just `33060c -> 330674 -> 31b530`. The useful upstream feeder chain is now:

- `FUN_0032c12c`
  - branches into `FUN_0032c5f0` and `FUN_0032c24c` using parent-object children at `+0x2f` / `+0x33`
- `FUN_0032c5f0`
  - consumes parent/object state at `+0x17`, `+0x43`, and `+0xa7`
  - then calls `FUN_0032b1e0(...)`
- `FUN_0032c24c`
  - also feeds into `FUN_0032b1e0(...)` and `FUN_0032b17c(...)`
  - then constructs a small wrapper and calls `FUN_0032b110(...)`
- `FUN_0032b110`
  - extracts two key fields from its source object at:
    - `+0x13`
    - `+0x1f`
  - feeds those into `FUN_0032f0ac(...)`
  - then passes the result into `FUN_0031b530(...)`
- `FUN_0032f0ac`
  - is the strongest static candidate for the exact field-selection/normalization step
  - it conditionally selects up to three values from a descriptor object (`param_5`)
  - when those selector slots are absent, it falls back to the base object fields:
    - `param_2 + 0x7`
    - `param_2 + 0xb`
    - `param_2 + 0xf`
  - it packs the resulting 3-tuple into a fresh wrapper via `FUN_00645710`

Interpretation:

- `31b530` still looks like a population/join step, not the first place where the live field choices are made.
- The exact unresolved “which human-readable fields feed the auth-local tuple?” question is now centered more tightly on:
  - `FUN_0032b110`
  - `FUN_0032f0ac`
- This is a better fit for the remaining uncertainty than the later `330674` seam, because `32b110` explicitly reads two source slots (`+0x13`, `+0x1f`) before `32f0ac` performs conditional tuple selection.

### What `32b110`'s `+0x13` and `+0x1f` are derived from

Static tracing now gives a much more exact answer for the two source fields read by `FUN_0032b110`:

- `FUN_0032b110` reads:
  - `source +0x13`
  - `source +0x1f`
- It then does two different things with them:
  - `source +0x13`
    - is saved unchanged and later passed straight into `FUN_0031b530` as the owner/target object to populate.
    - it is **not** the descriptor that chooses tuple members.
  - `source +0x1f`
    - is passed to `FUN_0032f0ac` as the base object whose fields are used for fallback tuple selection.
    - inside `FUN_0032f0ac`, the fallback members are:
      - `base +0x7`
      - `base +0xb`
      - `base +0xf`

`FUN_0032f0ac` itself is driven by a static descriptor object loaded from `x27 + 0xc5f0`:

- it checks selector metadata at descriptor offsets:
  - `+0x13`
  - `+0x1f`
  - `+0x23`
  - plus the paired entry slots reached later in the same routine
- if those selector slots match the expected global sentinels, it picks values from the descriptor-driven tuple table
- otherwise it falls back to the base object supplied from `source +0x1f`

Most importantly, the source object that owns these fields is itself derived upstream, not created inside `32b110`:

- in the `FUN_0032c24c` path:
  - the `source` object passed to `32b110` is the original `param_2` of `32c24c`
  - `FUN_0032c12c` feeds that `param_2` from:
    - `((parent +0x33) +0x17)`
- in the sibling `FUN_0032ada0` path:
  - the same pattern appears with closely related sibling state:
    - `+0x33`
    - `+0x37`
  - and again the resulting object is handed to `32b110`

So the current best static interpretation is:

- `source +0x13` = the parent/target object later handed to `31b530`
- `source +0x1f` = the base fallback triple object for `32f0ac`
- the actual 3-tuple consumed downstream is chosen in `32f0ac`, with fallback to:
  - `source.+0x1f.+0x7`
  - `source.+0x1f.+0xb`
  - `source.+0x1f.+0xf`

This is the tightest static derivation recovered so far. What remains unresolved is the human meaning of the upstream `source` object reached via the parent-child chain (`parent +0x33 -> +0x17`) and the exact semantic labels of that fallback triple.

### Deep helper chain result

The deeper `32c768 -> 32c7a4 -> 3f3844 -> 3de8b0 -> 3deb7c` path has now been characterized more precisely:

- `3de8b0` is not the key mutator.
  - post-call dumps show the tracked owner slot does not change there.
- `3deb7c` is a structural linker, not a byte-level derivation helper.
  - On early calls it writes the current child into both owner slots `+0x14` and `+0x18`.
  - On later calls it keeps `+0x14` on the previous child and advances only `+0x18` to the current child.
  - This is consistent with maintaining a previous/current chain in an object graph, not producing digest bytes.

### Current best interpretation

- The unresolved work is no longer “what does the linker do?”
- The unresolved work is now upstream population / constructor logic.
- A later rooted rerun (`fridaoutput06.log`) tightened the `3f3844` branch further:
  - the gated `3f3844` dispatch fires twice on a clean successful Bind path
  - its nested object chain is stable across both hits
  - the important field in that chain is not a compressed heap ref after all:
    - the raw bytes at the nested owner object's `+0x8` are
      - `64 20 e3 fd 79 00 00 00`
      - which decode to the raw code pointer `0x79fde32064`
      - i.e. `libapp.so +0x55a064`
  - static decode of `3f3844` matches this:
    - `ldur x9, [x4, #7]`
    - `blr x9`
    - then only later `bl 0x5649ec`
- So the current best upstream target is no longer the allocation seam at `0x5649ec`.
- It is the dynamically dispatched callee reached from `3f3844` at `libapp.so +0x55a064`, because that runs before owner allocation and before the already-finished bind parent reaches `55c414` / `330770`.
- A further rooted rerun (`fridaoutput07.log`) showed that this direct callee is still not the byte-level derivation step:
  - it fires exactly twice on the successful Bind path
  - in both cases it returns `arg0` unchanged
  - its body looks like a short guard / forwarding stub rather than a full constructor
  - however, its inputs are structurally relevant:
    - the first `arg0` later appears multiple times inside the finished bind parent seen at `55c414` / `330770`
    - the shared dispatch-root object also later appears inside that finished parent
  - so the unresolved work has narrowed again:
    - not “what does `0x55a064` compute?”
    - but “which calls immediately after that stub turn those structural inputs into the already-finished bind parent?”
- A further scoped rerun (`fridaoutput08.log`) tightened that answer:
  - inside each gated `3f3844` invocation, the `0x55a064` stub is followed by a repeated loop of:
    - `0x5649ec`
    - then `0x3de8b0`
  - that loop is still structural scaffolding:
    - `0x5649ec` keeps receiving one pinned source object for the whole loop
    - its return value advances each iteration and feeds directly into the next `3de8b0 arg2`
    - but the final bind parent is **not** one of those returned owner objects
  - instead, the finished parent that reaches `55c414` / `330770` reuses the pinned source object repeatedly and carries the shared dispatch root
  - `55c414` then returns a new object that seeds the second scoped dispatch loop and later appears as the serializer-visible `+0x6c` child
  - my first static read of the tail was too aggressive:
    - `0x3f3954: blr x30` is real code in `3f3844`
    - but it sits on the sibling branch taken when the restored `x1` object is **not** class `0x10b7`
    - it is not the branch that produced the repeated `5649ec -> 3de8b0` loop seen on the successful Bind path

- The follow-up rerun (`fridaoutput09.log`) corrected that control-flow interpretation:
  - the attempted inline Frida hook at `0x3f3954` failed to arm, so it produced no dynamic evidence
  - more importantly, fresh Capstone review of `3f3844` shows the useful Bind path does **not** fall through from the loop to `0x3f3954`
  - on the useful path:
    - `3f3844` first dispatches to `0x55a064`
    - then, for class `0x10b7`, runs the repeated `5649ec -> 3de8b0` loop
    - then returns the Dart sentinel back up through `32c7a4` and `32c768`
  - in other words, the interesting mutation is still happening by side effect on the carried object graph during the looped branch; there is no post-loop dynamic callee on the successful Bind path

In other words, the deep linker layer has been demoted, the direct `3f3844` dispatch target has also been demoted to a forwarding seam, and `0x3f3954` is no longer the active lead. The next useful runtime question is how the successful class-`0x10b7` looped branch inside `3f3844` mutates the carried object graph by side effect before control unwinds through `32c7a4` / `32c768`, `55c414`, and finally `330770`.

---

## 8) Ghidra-backed builder refinement (2026-03-12)

Recent static work in Ghidra tightened the useful builder path and corrected which offsets are true function starts versus interior thunk sites.

### Ghidra address mapping

Ghidra loaded this `libapp.so` image at `+0x100000`, so the offsets used in Frida/runtime notes map like this:

- runtime/static `0x32c768` -> Ghidra `0x42c768`
- runtime/static `0x32c7a4` -> Ghidra `0x42c7a4`
- runtime/static `0x3f3844` -> Ghidra `0x4f3844`
- runtime/static `0x55c414` -> Ghidra `0x65c414`
- runtime/static `0x45b6d0` -> Ghidra `0x55b6d0`

This matters because earlier attempts to define functions were landing on the right code bytes but at rebased Ghidra addresses.

### Which offsets are real starts versus interior targets

- `0x32c768`, `0x32c7a4`, and `0x3f3844` do have clean function prologues and are worth naming as real routines.
- `0x55c414` is not a standalone constructor entry.
  - In Ghidra it sits inside a tiny indirect-call thunk that loads globals from `x27` and jumps through `*(x27 + 0x370) + 7`.
  - This matches the runtime result that `55c414` is structural packaging / allocation-adjacent, not token generation.
- `0x5649ec` is also not a clean function start.
  - It is an interior stub inside a larger region and should be treated as a labeled internal target rather than a normal function entry.

### Static late-builder detour: `0x55b6d0` in Ghidra / raw `0x45b6d0`

Ghidra recovered a more useful object-population routine downstream of the `3f3844` loop:

- `FUN_0055b6d0` (raw `0x45b6d0` runtime / `0x55b6d0` Ghidra)
  - writes `child_obj` into `parent_obj + 0x2b`
  - calls `FUN_005397e0(child_obj, parent_obj)`
  - derives `dispatch_node` from the compressed ref at `child_obj + 0xb`
  - computes `dispatch_class_id = classId(dispatch_node)`
  - dispatches through `x21[(dispatch_class_id - 0x167)]`
  - stores that indirect-call result into `parent_obj + 0x2f`

This is important because it is the first late builder seam we statically characterized that clearly:

- reads a child-derived dispatch node,
- chooses behavior by class ID,
- and writes the result back into a stable parent-object slot.

That made it worth one targeted runtime check, but it is no longer the primary live lead.

### What the surrounding helpers now mean

- `0x55c328`
  - packages/schedules wrapper state and returns another structural object
  - likely contributes the extra child branch later visible near serializer parent slot `+0x6c`
- `0x6aef8`
  - just allocates an object of type `0x109f21c` through the generic allocator
- `0x664294`, `0x678674`, `0x6781c4`
  - all remain generic allocation / scheduling helpers rather than token-specific logic

### Why this helps

The investigation no longer needs to guess among broad crypto/base64 helpers or vague dispatcher branches.

We now have:

- the proven successful loop branch in `3f3844`,
- the downstream parent-population seam in `55b6d0`,
- and concrete parent slots (`+0x2b`, `+0x2f`) to watch mutate on the useful Bind path.

That gives the next runtime step a narrow question:

- what class ID is actually seen at `dispatch_node`,
- which indirect target does that resolve to,
- and how does that result relate to the finished serializer-visible parent object?

### Follow-up runtime results: `fridaoutput10.log` and `fridaoutput11.log`

The first rerun after adding the new seam used the wrong raw hook address, because the Ghidra-vs-runtime base correction had not yet been applied consistently:

- `fridaoutput10.log`
  - the attempted `55b6d0` check is not diagnostic
  - the script was still hooking raw `+0x55b6d0` instead of raw `+0x45b6d0`

The next rerun corrected that and is the one that matters:

- `fridaoutput11.log`
  - the script attached cleanly at raw `+0x45b6d0`
  - there was still **no** `ENTER bind_parent_populate_55b6d0` on a clean successful Pair -> Bind path
  - this strongly suggests the Ghidra `55b6d0` seam is statically real but not on the specific successful runtime branch being traced
- The run still completed a normal Bind serialization.
- `55c414` remains on-path and gave the stronger live correlation again:
  - `bind_builder_helper_55c414 retval = 0x78005db209`
  - later serializer parent:
    - `bind_serializer_parent_330770 arg1 + 0x6c = 0x78005db219`
  - so the `55c414` return still lands immediately adjacent to the serializer-visible extra child branch
  - `55c414 post-arg0 + 0x6c` is still empty on entry/exit of that helper, which fits the idea that the helper is packaging around an already-built parent rather than creating the token itself

`fridaoutput12.log` and `fridaoutput13.log` tightened that further:

- the finished bind parent is still already present by inline checkpoint `0x3306fc`
  - `x0 == x1 + 0x20`
  - `x0 + 0x8` is already the final token string object
- `55c414` still receives that finished parent unchanged
- in `fridaoutput13.log`, the serializer-visible extra child is now directly identified:
  - `bind_serializer_parent_330770 arg1 + 0x6c = 0x780059ce09`
  - that is **exactly the same tagged pointer** as `bind_builder_helper_55c414 retval + 0x10`
- timing matters:
  - at `55c414` return time, the adjacent `retval + 0x10` object is still sparse / mostly empty
  - by serializer entry, that same object has become a populated wrapper-like node
    - its `+0x10` points back to the original `55c414` retval object
    - its `+0x8` points to `0x78001fa5e1` metadata/state

This is the first direct proof that the `+0x6c` serializer child is not merely "near" the `55c414` return: it is the same neighboring object, populated later.

Interpretation:

- the new `55b6d0` Ghidra seam was a useful static detour but is not the active runtime branch we are tracing
- the strongest live downstream seam is still the `55c414` / enclosing `55c328` packaging region and its relationship to serializer parent slot `+0x6c`
- the temporary `3f3844` branch classifier was misleading and has been removed from the script

`fridaoutput16.log` and `fridaoutput17.log` resolved the next blocked question inside `4deb7c`:

- after fixing the helper-slot read to the live runtime layout (`+0x14` / `+0x18`), the hook cleanly recovers the existing child pointer
- on the useful later pass, the existing child is stable and readable:
  - `bind_owner_merge_4deb7c existing child classId: 0x6721`
  - repeated 21 times in `fridaoutput17.log`
- the indirect merge target is also stable:
  - runtime raw target `0x3d8f58`
  - Ghidra target `0x4d8f58`
  - runtime address `0x79fde04f58`
  - repeated 21 times in `fridaoutput17.log`
- this class matches the wrapper family already seen on the serializer-visible extra child:
  - allocator `6649ec` seeds objects with descriptor `0x106721c`
  - runtime object class reads as `0x6721`
- the helper post-state now reads cleanly as a chain advance:
  - helper live slot `+0x14` keeps the prior existing child
  - helper live slot `+0x18` advances to the new child B

This is strong evidence that `4deb7c` is not creating the authtoken. It is merging/chaining already-created class-`0x6721` wrapper nodes, and the next useful seam is the resolved class-specific merge callee at raw `0x3d8f58` / Ghidra `0x4d8f58`.

`fridaoutput18.log` added one more concrete behavior signal:

- the direct hook on raw `0x3d8f58` attached, but its first caller gate was too tight and produced no body logs
- even so, the surrounding `4deb7c` snapshots already expose the merge effect
- before the merge, the prior child wrapper has sentinel at its live `+0xc`
- after the merge, that same prior child wrapper now holds the new child B at live `+0xc`
- meanwhile:
  - helper live slot `+0x14` still refers to the prior child
  - helper live slot `+0x18` advances to B

So the current best interpretation is:

- class-`0x6721` merge callee `0x3d8f58` is linking wrapper nodes together
- specifically, it likely splices `existing_child -> new_child_B` through the prior wrapper's live `+0xc`
- that is consistent with a wrapper chain/list builder feeding the serializer-visible `+0x6c` child family, not token generation

The later Ghidra-only pass made the auth conclusion much sharper:

- `0x4d8f58` is only a thunk into `FUN_00642624`
- `FUN_00642624` is a generic Dart identity-hash helper
- `FUN_00664294` is only a thin allocator wrapper over `FUN_006781c4`
- the closure-selected helpers under `0x43060c` are parser/validator machinery, not crypto

Most importantly, the serializer path now shows that the authtoken is *carried through*, not generated locally:

- `FUN_0043060c` stores the first closure-result field `result + 0xf` and later passes that saved object into `FUN_00430770`
- `FUN_00430770` ignores its first incoming argument and serializes that saved object
- `FUN_00430770` passes:
  - saved object `+0x13` into `FUN_004307e0` as the source for `tid`
  - saved object `+0x7` into `FUN_004307e0` as the source for `authtoken`
- `FUN_004307e0` then constructs the outbound Bind-request pair list explicitly:
  - `[pp+0x8c30] "command_name"` -> `[pp+0x8e58] "Bind Request"`
  - `[pp+0x8c40] "tid"` -> `(*(saved_object + 0x13) + 7)`
  - `[pp+0x8e40] "authtoken"` -> `saved_object + 0x7`

So the current strongest conclusion is:

- the app does **not** appear to derive the LAN `authtoken` cryptographically in this path
- by the time execution reaches the proven `0x3306fc` checkpoint, the final token object already exists
- the bind serializer simply reads an already-populated field and labels it `"authtoken"` for the outbound Bind request
- the certificate/key material is therefore much more likely to be transport/TLS-related than the source of the command auth token

That conclusion was correct for the *late serializer corridor*, but the next upstream live branch changes the bigger picture:

- the serializer still does **not** generate the token
- however, the token **is** generated locally one stage earlier, in the live `0x4308c8 -> 0x4309e4` branch

The currently strongest end-to-end model is now:

1. `FUN_00430d58` parses the inbound/auth-handshake object and requires:
   - `"command_name"`
   - `"status"`
   - `"stbnonce"`
   - `"pairingcode"`
   - `"name"`
2. On success, `FUN_00430d58` returns a class-`0x2ee` object built by `FUN_0065c4b8` carrying:
   - `+0x7 = stbnonce`
   - `+0xb = pairingcode`
   - `+0xf = name`
3. `FUN_004308c8` is the live helper branch that consumes that class-`0x2ee` object.
4. `FUN_004308c8` calls `FUN_004309e4(...)` and stores its return value into a class-`0x28e` object at `+0x7`.
5. That class-`0x28e` object is the one later consumed by `FUN_0043060c` / `FUN_00430770`, where `+0x7` is serialized as `"authtoken"`.

So the important correction is:

- the authtoken is **not** simply copied from an inbound `"authtoken"` field
- it is **derived locally** from earlier handshake material
- but it is still **not** sourced from the bundled TLS certificate/key material

Current best read of the derivation recipe in `FUN_004309e4` (based on raw register flow, not just the decompiler) is:

- stage 1:
  - `FUN_00430b78` first normalizes / hex-decodes the carried local field at `+0x13`
  - `FUN_00430b44` then validates/copies the parsed `pairingcode` as text bytes
  - `FUN_002ed738` / `FUN_002ed7b0` build the first byte sequence by appending:
    - decoded local `+0x13`
    - `pairingcode`
    - carried local `+0xb`
  - `FUN_0054a9a8(...)` hashes that first sequence
- stage 2:
  - `FUN_00430b44` validates/copies parsed `stbnonce` as text bytes
  - `FUN_002a70d8` / `FUN_002f88f0` build a second sequence starting with:
    - `stbnonce`
    - then the first digest output
  - `FUN_00430b44` validates/copies hardcoded salt string `pp+0x8d78 = "biT43y"`
  - `FUN_002a745c` / `FUN_002f88f0` append that salt to the second sequence
  - `FUN_0054a9a8(...)` hashes the second sequence
- `FUN_00430b10` then passes the final digest into the codec path
- the surrounding pool contains SHA-256 IV constants:
  - `0x6a09e667`
  - `0xbb67ae85`
  - `0xa54ff53a`
  - `0x510e527f`
  - `0x9b05688c`
  - `0x5be0cd19`
- this is therefore not a single flat `SHA-256(all_inputs)` call; it is a two-stage composition with an intermediate digest
- the digest machinery itself now looks like ordinary SHA-256 rather than a custom variant:
  - `FUN_0051e0ec` seeds the eight standard SHA-256 state words
  - `FUN_00502518` / `FUN_004fff7c` feed the staged byte sequence into that state
  - `FUN_0051e230` finalizes into a 32-byte output buffer
- `FUN_00430b10 -> FUN_005185c0` then hands that 32-byte digest to the codec object at `pp+0x1418`
- the codec pool cluster around `pp+0x1418` contains:
  - `"data"`
  - `"base64"`
  - standard alphabet `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"`
  - padding string `"=="`
  - explicit `"Invalid base64 ..."` error strings
- current best conclusion:
  - no further cryptographic mixing occurs after the second SHA-256 stage
  - the final step is standard Base64 encoding of the 32-byte digest
- direct decompile confirmation from this pass:
  - `FUN_00430b78` is the helper that hex-decodes local `+0x13`
  - `FUN_004309e4` receives:
    - arg1 = local `+0x13`
    - arg2 = local `+0xb`
    - arg3 = parsed `stbnonce`
    - arg5 = parsed `pairingcode`

Current best provenance for the two carried local fields:

- the object whose fields are later read as local `+0xb` / `+0x13` in `FUN_004309e4` is populated upstream by `FUN_0043de9c`
- `FUN_0043de9c` stores:
  - local `+0xb` from its incoming `x3`
  - local `+0x13` from a metadata-selected optional value derived from its `x4` selector list
- on the live caller path (`FUN_0043dd20` / widened from `0x43dce0`), those inputs come from a source object built earlier by `FUN_0043ccbc`
- `FUN_0043ccbc` allocates that source object and stores:
  - source `+0xf = param_2`
  - source `+0x13 = param_3`
  - source `+0x17 = param_4`
  - source `+0x1b = optional value from the metadata list passed in as `param_5`
- `FUN_0043dd20` then converts that source object into the auth-local object:
  - it reads source `+0x17`, passes it through `FUN_0043e74c(...)`, and that transformed value becomes auth-local `+0xb`
  - it reads source `+0x13` and uses it with the source object's selector fields to choose the value later stored as auth-local `+0x13`
- one concrete upstream feeder is `FUN_0043cc60`, which calls `FUN_0043ccbc(...)` with:
  - source `+0x13` coming from an earlier nested object's `+0x17`
  - source `+0x17` coming from that same earlier nested object's `+0x23`
- so, at the current best read:
  - auth-local `+0xb` ultimately descends from an earlier nested object's `+0x23` field
  - auth-local `+0x13` ultimately descends from an earlier nested object's `+0x17` field, filtered through the metadata-list selection logic in `FUN_0043de9c`
- the meaning of those earlier nested fields is now clearer:
  - the earlier nested object is a pool-metadata class `"Zdf"`
  - `Zdf +0x23` is not raw input; `FUN_0043ccbc` derives it as a two-state selector/sentinel (`x22+0x20` vs `x22+0x30`) after comparing the object's `+0xf` value via `FUN_0031fc3c`
  - `Zdf +0x17` is the real carried payload slot; downstream helpers (`FUN_0043dc44`, `FUN_0043dcb0`) dereference it as another nested record/object and pull that child object's `+0x13` / `+0x17`
  - so the strongest current interpretation is:
    - earlier nested `+0x23` = derived branch/mode flag
    - earlier nested `+0x17` = nested payload object, not a final string/enum label
- correction from this pass:
  - the same `Zdf` constructor cluster also embeds `portrait` / `landscape` enum state
  - that makes the `Zdf` branch look like surrounding UI/state plumbing, not proof that the final auth input itself is an orientation string
- important correction from the raw call flow:
  - local `+0x13` is now the strongest candidate for the hex-decoded nonce-like input (and is a better fit for `controllernonce` than local `+0xb`)
  - local `+0xb` is definitely still part of the first digest-stage payload
  - but it now looks more like a transformed controller-profile string than nonce material:
    - `FUN_0043e74c` wraps the upstream value with `TypeArguments: <DBa>` and sends it into `FUN_004265dc`
    - `FUN_004265dc` / `FUN_00426840` / `FUN_004267d8` behave like a generic typed late-field extraction path (`_Pya._dOe` / `Y0`), not a hex/nonce decoder
    - the nearby pool cluster still points at the Pair Request profile family (`qAa.name`, `qAa.waf`, `qAa.Edf`, `"Soft Remote"`, `"Comcast"`, `"IPRemote"`, `"Unnamed Device"`)
    - that profile mapping is now tighter:
      - `qAa.name` lines up with Pair Request `name = "Soft Remote"`
      - `qAa.waf` lines up with Pair Request `manufacturer = "Comcast"`
      - `qAa.Edf` lines up with Pair Request `model = "IPRemote"`
    - so the best current read is that `FUN_0043e74c` is selecting from the controller identity/profile family, but not returning one of those raw wire strings unchanged
  - so the best tightened read is:
    - local `+0xb` is a carried controller-profile string selected out of the `qAa` / `Zdf` wrapper path
    - the remaining uncertainty is the exact normalization/selection inside that profile family, not whether the family itself is the Pair Request identity triple
  - a new targeted live probe is now in place:
    - `tools/frida_auth_inputs.js` additionally hooks `0x4308c8`, `0x4309e4`, `0x43de9c`, `0x43e74c`, and caller-filtered `0x4265dc`
    - the next successful Pair run should directly print the exact runtime text fed into:
      - local `+0xb`
      - local `+0x13` before hex decode
  - important probe correction after the latest `0x43dce0` rerun:
    - the run again hit `0x43dce0` from caller `+43dc94` before the parser/bind path
    - static disassembly of `FUN_0043dce0` confirms that this live path should invoke:
      - `FUN_004265dc` with return sites `+43dd04` and `+43dd1c`
      - `FUN_0043e74c` with return site `+43dd98`
      - `FUN_004265dc` again with return site `+43ddb0`
    - the probe was filtering on the `bl` instruction offsets instead (`+43dd00`, `+43dd18`, `+43dd94`, `+43ddac`, `+43e770`)
    - because Frida reports the return address at callee entry, that filter was off by one instruction
    - so the earlier absence of `FUN_004265dc` / `FUN_0043e74c` is now explained as an observability bug rather than evidence that those functions were not running
    - `tools/frida_auth_inputs.js` has been corrected to filter on the real return sites:
      - `+43dd04`
      - `+43dd1c`
      - `+43dd98`
      - `+43ddb0`
      - `+43e774`
  - latest rerun after that correction still produced no `FUN_004265dc` / `FUN_0043e74c` hits
    - the repeated `0x43dce0` caller value is `+43dc94`, which is the return site of the `FUN_0043ccbc` call inside `FUN_0043dc80`
    - there are no code xrefs to `0x43dce0` or `0x43dd80`
    - best explanation now: those symbols are overlapping helper blocks inside `FUN_0043ccbc`, so hooking them is useful only as a coarse marker and not as proof of a clean function-level path
    - the next probe revision therefore removes caller filtering for `FUN_004265dc` / `FUN_0043e74c` and logs the first live callers verbatim
  - newest unfiltered rerun still shows no `FUN_004265dc` / `FUN_0043e74c` hits anywhere on the Pair-success path
    - this is now strong evidence that the active live route bypasses that selector/profile branch entirely
    - the useful live chain remains:
      - `FUN_0032e990` parser
      - `FUN_003305d0` / hooked at `0x33060c` bind-parent mutation region
      - `FUN_00330674` bind populate
    - static `FUN_00330674` reads an opaque carrier from `arg1 + 0x9b` and passes it into `FUN_0031b530`
    - probe focus therefore moves to decoding the `330674 arg1` carrier object's tagged fields at:
      - `+0x9b`
      - `+0x9f`
      - `+0xa3`
      - `+0x127`
  - newest carrier-field dump narrows that again:
    - `330674 arg1 +0x9f` and `+0x127` are even-tagged values, so treating them as heap object refs was a probe mistake
    - `330674 arg1 +0x9b` and `+0xa3` still look sentinel-/Smi-like (`0x7800`) in this path
    - attempted `0x330710` mid-block hook did fire, but out of expected order relative to `FUN_00330674`, and the app crashed after pairing on that run
    - best current read is that `0x330710` is not a safe unique seam for live tracing in this build/path
    - next probe revisions should stay on stable function-entry hooks and avoid further mid-block instrumentation on this route
  - newest safe rerun confirms the reverted script is stable, but `FUN_0031b530` still does not surface as a clean live Frida hit
    - static follow-up identifies `FUN_0031b4f4` as a tiny safe wrapper:
      - it reads `arg1 + 0x9b`
      - then immediately calls `FUN_0031b530`
    - `tools/frida_auth_inputs.js` is now updated to hook `0x31b4f4` as the safer live seam for that final carried value
  - latest rerun falsifies that on the observed path:
    - `0x31b4f4` never fires
    - static constants used by `FUN_00330674 -> FUN_0031b530` are `pp+0xc620 = "keyboard"` and `pp+0xcaf8 = {-1,-1}`, which makes that seam look more like downstream generic packaging / closure logic than the place where the authtoken is derived
  - more importantly, static re-check shows `0x33060c` is not a real function entry:
    - it is a mid-block instruction inside `FUN_003305d0`
    - earlier `0x33060c` traces therefore captured useful register snapshots, but not a trustworthy call boundary
    - `tools/frida_auth_inputs.js` is now updated to hook the true entrypoint `0x3305d0` and dump its logical stack arguments from `[x15+0x10]` and `[x15+0x18]`
  - latest rerun with the true `0x3305d0` entry hook adds a key cleanup:
    - `0x3305d0` stack inputs are only small tagged immediates (`-5/-6`, `8`) on the observed path
    - the token-bearing object still only becomes directly visible later at the old mid-block `0x33060c` observation point
    - `0x3305d0` is named `keh_KBa::yef_3305d0`
    - the caller return site `+56e340` lands inside `FUN_0056dad0`, a large comparator / ordering closure over candidate objects
    - that caller walks fields such as `+0x13`, `+0x17`, `+0x1b` and uses helpers `FUN_003814fc`, `FUN_00383250`, `FUN_00383cf4`
    - resolving their pool constants shows schema / record-selection material (`englishLike`, obfuscated field-label strings like `AOd`, `AXb`, `ICb`, `JCb`, `KCb`, `qFb`, etc.), not the auth digest recipe itself
  - current best interpretation:
    - the active live path still bypasses the older auth-selector branch
    - the live token first becomes readable where the mutated object gains the Base64 string
    - newly traced upstream layers (`0x31b4f4`, `0x31b530`, `0x3305d0` entry stack, `FUN_0056dad0` comparator helpers) can now be treated as generic packaging/selection/comparison context unless later evidence shows otherwise
  - newest direct object diff at the trusted `0x33060c` seam pins the concrete mutation:
    - on the first `0x33060c` hit:
      - `arg1 +0x20` is replaced (`raw32 0x158749 -> 0x15f729`)
      - its child `+0x8` changes from a non-token object ref to the final Base64 token string
      - sibling child fields `+0xc`, `+0x10`, and `+0x6c` also change in the same transaction
    - on the second `0x33060c` hit:
      - `arg1 +0x20` is replaced again (`raw32 0x15f729 -> 0x598739`)
      - child `+0x8` is cleared (`0x7b690015 -> 0x0`) before the object proceeds to `FUN_00330674`
      - sibling child fields `+0xc`, `+0x10`, and `+0x6c` change again as part of that repack
  - strongest live conclusion so far:
    - `FUN_003305d0` / observed at `0x33060c` performs a two-stage install/repack of the token-bearing child
    - the token is written at `arg1 +0x20 +0x8` during the first stage
    - the second stage repacks/clears that child before `FUN_00330674`
    - `FUN_00330674` is downstream packaging/consumption, not the point where the token is created
  - new offline oracle check against concrete captured sessions now rules out the most obvious raw-field interpretation:
    - using real Pair/Bind samples from the saved bridge/oracle logs, the recovered two-stage recipe was tested with:
      - local `+0x13 = hex_decode(controllernonce with hyphens removed)`
      - local `+0xb` = request `name`, `manufacturer`, `model`, `tid`, and response `name`
      - multiple stage-1 and stage-2 ordering permutations
    - none of those combinations reproduced the live `authtoken`
    - so:
      - local `+0xb` is not simply one of the obvious raw Pair Request strings as serialized on the wire
      - local `+0x13` is not yet proven to be the raw `controllernonce` UUID string with only hyphens stripped
      - the remaining gap is therefore in upstream field selection / normalization, not in the SHA-256 or Base64 conclusion

Bottom line:

- the LAN `authtoken` looks locally generated from handshake inputs (`stbnonce`, `pairingcode`, local context, and `"biT43y"`)
- the serializer only packages that derived value later
- the app certificate is still much more likely to be for TLS transport than for generating the command auth token
- the remaining soft spot is now mainly semantic naming of one carried local payload (`+0xb`), not the digest/codec mechanics

---

## 9) Recommended Next Validation Steps

1. Keep the clean live-path hooks centered on:
   - `0x3306f4`
   - `0x3306fc`
   - `0x55c414`
   - `0x330770`
2. Treat raw `0x45b6d0` / Ghidra `0x55b6d0` as demoted for now.
   - It can be revisited only if a different successful branch appears or another static xref ties it back to the live `33060c` path.
3. Treat `4deb7c` as resolved enough to move one step deeper.
   - The live merge path is class `0x6721`.
   - The resolved class-specific callee is raw `0x3d8f58` / Ghidra `0x4d8f58`.
4. If more precision is needed, continue *upstream*, not downstream.
   - The remaining open question is not token generation but exact source population of the saved object field later serialized as `"authtoken"`.
   - The best next static targets are the producers of the object passed into `FUN_00430770`, especially the first-pass helpers under `FUN_0043060c`.
5. Keep these concrete identities in view:
   - serializer child `arg1 + 0x6c == 55c414 retval + 0x10`
   - that child object's `+0x10 == 55c414 retval`
   - `FUN_004307e0` labels `saved_object + 0x7` as `"authtoken"` in the outbound Bind request

---

## 10) Analyst Notes

- The Android manifest and some APK metadata files are binary-encoded in packaged form.
- Most high-value protocol clues were found in Flutter native AOT payload (`libapp.so`), not in Java DEX.
- Because this is static reverse analysis, runtime behaviors should be validated with packet capture before relying on implementation assumptions.

---

## 11) Additional Deep-Dive Findings (2026-02-22)

Further static investigation identified an Android NSD bridge layer in obfuscated DEX classes.

### Confirmed Android NSD map bridge

String cross-references for `service.host`, `service.port`, etc. point to:

- Class: `Ld0/i;`
- Methods:
  - `d(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/LinkedHashMap;`
  - `b(Ljava/util/Map;)Landroid/net/nsd/NsdServiceInfo;`

Interpretation:

- Method `d(...)` converts Android `NsdServiceInfo` into a map payload.
- Method `b(...)` converts a map payload back into `NsdServiceInfo`.

### Explicit service schema keys confirmed from DEX method constants

From method constant strings in `Ld0/i;`:

- `service.name`
- `service.type`
- `service.port`
- `service.host`
- `service.addresses`
- `service.txt`

This is strong evidence the app serializes/deserializes NSD service records through these exact key names.

### Confirmed NsdServiceInfo method usage

Observed API calls include:

- `NsdServiceInfo.getServiceName / setServiceName`
- `NsdServiceInfo.getServiceType / setServiceType`
- `NsdServiceInfo.getPort / setPort`
- `NsdServiceInfo.getHost / setHost`
- `NsdServiceInfo.getAttributes / setAttribute`
- `InetAddress.getCanonicalHostName`
- `InetAddress.getHostAddress`

Interpretation:

- App likely transports full NSD service detail (not just name/type), including host/address/port/TXT attributes.
- This increases confidence that runtime SRV/TXT-derived port selection is dynamic and may explain why no fixed `8091` literal was recovered.

### Other high-signal field/token confirmations

Additional field-like tokens found in `libapp.so` strings:

- `clientId`, `deviceId`, `authtoken`, `controllernonce`, `pairingcode`
- discovery callbacks: `onServiceDiscovered`, `onServiceLost`, discovery start/stop success/failure
- connection status tokens: `CONNECTED`, `DISCONNECTED`, `socket-disconnected`, `SiftRemoteAppConnectionStatus`

These reinforce a structured state machine: discovery -> connect/pair/auth -> keypress/status events.

---

## 12) Verification Checklist (Inferred vs Verified)

Use this checklist to track live-validation progress.

### Discovery and service resolution

- [ ] **Verified** mDNS browse includes `_services._dns-sd._udp`
- [ ] **Verified** service discovery includes `_rdk-rics._tcp`
- [ ] **Verified** SRV record yields runtime `service.port`
- [ ] **Verified** host/address resolution matches `service.host` / `service.addresses`
- [ ] **Verified** TXT attributes are consumed (mapped to `service.txt`)

### Session, auth, and transport

- [ ] **Verified** app opens socket to discovered host+port (not hardcoded-only)
- [ ] **Verified** handshake type (TLS only vs mTLS)
- [ ] **Verified** auth flow includes token/challenge/nonce semantics
- [ ] **Verified** reconnect behavior when socket drops (`socket-disconnected` path)

### Command path

- [ ] **Verified** keypress channel corresponds to `remote_app_keypress`
- [ ] **Verified** payload carries `keypress.category` and/or `keypress.code`
- [ ] **Verified** representative key set (Power/Home/Back/Play/Pause/Channel/Numpad)

### UX-flow confirmation

- [ ] **Verified** discovery states: searching -> results/empty
- [ ] **Verified** pairing prompt/flow and paired state transition
- [ ] **Verified** settings/legal/privacy routes reached as inferred

---

## 12) Frontend <-> Native Bridge Analysis Status

Yes, this has been analyzed to a meaningful extent from static artifacts.

### What is already confirmed

1. **Flutter platform-channel substrate is present**

- DEX/native strings include `MethodChannel`, `BasicMessageChannel`, `flutter/platform`, and Flutter service channel references.

2. **Android NSD bridge exists in Java/Kotlin side**

- Obfuscated class `Ld0/i;` maps `android.net.nsd.NsdServiceInfo` <-> map payloads.
- Confirmed map keys: `service.name`, `service.type`, `service.port`, `service.host`, `service.addresses`, `service.txt`.

3. **Discovery callbacks are bridged upward**

- Strings include `onServiceDiscovered`, `onServiceLost`, discovery start/stop success/failure.

4. **Flutter/native operational channels are visible in AOT strings**

- `entos-remote-app/remote_app_discovery/1`
- `entos-remote-app/remote_app_conn_status/1`
- `entos-remote-app/remote_app_keypress/1`

### What this means for network-function mapping

- Frontend likely consumes normalized NSD service maps from native Android discovery, then drives connection/keypress channels in Flutter domain.
- This gives a strong mapping chain:
  - Android NSD discovery -> map (`service.*`) -> Flutter logic -> connection status + keypress operations.

### What is still unresolved (requires runtime evidence)

- Exact Flutter channel names used at runtime for each bridge leg.
- Exact payload envelope format on wire (JSON/protobuf/custom framing).
- Definitive confirmation of mTLS requirements per device/firmware.

---

## 13) Latest static auth-builder verification

This pass tightened the auth-token story with direct decompiles of the key branch around
`FUN_004307e0`, `FUN_004308c8`, `FUN_004309e4`, and `FUN_00430d58`.

### Corrected request-serializer mapping

- Re-reading the whole `0x4305d4 -> 0x43060c -> 0x430770 -> 0x4307e0` cluster shows that
  `FUN_004307e0` is **not** the Pair Request serializer.

- `FUN_004307e0` is part of the **Bind Request** path and writes:
  - `"command_name"` = `"Bind Request"`
  - `"tid"` = carried object field
  - `"authtoken"` = carried object field

- So the earlier conclusion that this function proved a saved local field `+0xb = controllernonce`
  was incorrect and is now withdrawn.

- The nearby pool still clearly contains:
  - `"command_name"`
  - `"Pair Request"`
  - `"tid"`
  - `"Soft Remote"`
  - `"Comcast"`
  - `"IPRemote"`
  - `"controllernonce"`
  but those constants are not established as being consumed by `FUN_004307e0`.

### Confirmed inbound Pair-success parse keys

- `FUN_00430d58` now decompiles cleanly enough to confirm that it validates and extracts:
  - `"command_name"`
  - `"status"`
  - `"stbnonce"`
  - `"pairingcode"`
  - `"name"`

- On success it returns the already-noted class-`0x2ee` object carrying:
  - `+0x7 = stbnonce`
  - `+0xb = pairingcode`
  - `+0xf = name`

### Confirmed `FUN_004309e4` argument order

- `FUN_004308c8` is now directly confirmed to call `FUN_004309e4(...)` as:
  - arg1 = local object `+0x13`
  - arg2 = local object `+0xb`
  - arg3 = parsed `stbnonce`
  - arg4 = local object pointer / context object
  - arg5 = parsed `pairingcode`

- `FUN_004309e4` still decompiles consistently with the two-stage recipe:
  1. hex-decode local `+0x13`
  2. append `pairingcode`
  3. append local `+0xb`
  4. hash
  5. append `stbnonce`
  6. append digest1
  7. append `"biT43y"`
  8. hash again
  9. Base64-encode the final 32-byte digest

That means the core recipe is no longer just a raw-register hypothesis; the argument ordering is now
decompile-confirmed.

### Important caution about the upstream selector branch

- The upstream object-building path around:
  - `FUN_0043dd20`
  - `FUN_0043de9c`
  - `FUN_0043ccbc`
  - `FUN_0043e74c`
  - `FUN_004265dc`
  is still the best static candidate for where local `+0xb` / `+0x13` are chosen.

- Pool constants now confirm this path is selecting through:
  - `Zdf`
  - `yAa`
  - `rAa`
  - `vAa`
  - `DBa`

- However, this branch should still be treated carefully:
  - part of `FUN_0043de9c` is clearly generic object construction / closure wiring
  - the exact business meaning of the value written to local `+0xb` is still not proven from this pass alone
  - the prior hypothesis that it ultimately comes from the `qAa` identity/profile family remains plausible, but not yet final
  - one more structural tightening from the latest pass:
    - `FUN_0043dcb0` replays the same auth-local mapping directly from `Zdf +0x17`
      - auth-local `+0xb` still comes from `FUN_0043e74c(source +0x17, ...)`
      - auth-local `+0x13` still comes from the selector/list path into `FUN_0043de9c(...)`
    - `FUN_0043dc44` feeds `FUN_0043ccbc(...)` from `Zdf +0x17`, passing child `+0x13` and `+0x17` onward as the source tuple
    - so the field-flow itself is now reinforced by the small `Zdf` accessors, not just by the larger `FUN_0043dd20` wrapper
  - one useful structural tightening from this pass:
    - `qAa` is now confirmed to expose only three late fields:
      - `name`
      - `waf`
      - `Edf`
    - and the nearby pooled instance values are:
      - `"Soft Remote"`
      - `"Comcast"`
      - `"IPRemote"`
    - there is no nonce field on `qAa`
    - so if the candidate `qAa` path really feeds auth-local `+0xb`, that slot is more likely a
      profile/identity string than raw `controllernonce`
    - which makes auth-local `+0x13` the better remaining `controllernonce` candidate
  - a useful falsification from this pass:
    - nearby helpers around `0x33e1ac` / `0x33e49c` / `0x33e704` / `0x33dc44`, which sit in the same pool neighborhood as `yAa` / `Zdh` entries, decompile as double-based geometry/layout transforms
    - so name/pool proximity to `qAa` / `yAa` is not enough by itself to prove those closures are selecting the auth string used as local `+0xb`

### Updated bottom line after this pass

- The LAN `authtoken` is still best explained as a locally derived Pair-success digest, not something
  taken from the app certificate.
- The certificate/key pair remains transport material for the TLS/mTLS channel, not the source of the
  command token itself.
- The main remaining unknown is narrower than before:
  - not the digest recipe
  - but the exact semantic content and normalization of local field `+0xb`
- Current strongest read after the correction:
  - auth-local `+0x13` remains the better `controllernonce` candidate
  - auth-local `+0xb` remains more likely to be a selected profile/identity string than raw nonce
