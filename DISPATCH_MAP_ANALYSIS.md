# FLUTTER AOT STATIC DISPATCH/FIELD-ACCESS MAP - Sky Remote Protocol

## EXECUTIVE SUMMARY

This analysis traces three protocol message types (Pair Request, Bind Request, KeyCommand Request) through their dispatch chain in Flutter AOT binaries via two **static late-final Map fields** that act as command/field validators.

**KEY FINDING:** Two nested dispatch maps separate concerns:
1. **feh_::vwb_32fd70** (0x32fd70) → command_name dispatcher (Pair)
2. **feh_::vZb_331c50** (0x331c50) → field/error validators (Bind + KeyCommand)

---

## 1. WHICH FUNCTION DISPATCHES ON COMMAND_NAME

**PRIMARY DISPATCHER: feh_::vwb_32fd70 (0x32fd70)**

**Definition:**
```
[pp+0x8ce0] Field <::.vwb>: static late final (offset: 0xd14)
[pp+0x8d18] AnonymousClosure: static (0x32fde4), in [feh] ::vwb (0x32fd70)
```

**Type Signature:**
- `static late final <Map, dynamic> vwb`
- Key: String (command_name from "Pair Request")
- Value: dynamic (handler closure)

**Initialization Closure:**
- `feh_::_anon_closure_32fde4` (0x32fde4) [static initializer]
- Builds Map<String, dynamic> at runtime
- Registers command handlers

**Pool References:**
```
[pp+0x8c38] String: "Pair Request"           ← Request type identifier
[pp+0x8c30] String: "command_name"           ← Dispatch key
[pp+0x8c40] String: "tid"                    ← Expected field
[pp+0x8c48] String: "Soft Remote"            ← Device type
[pp+0x8c50] String: "Comcast"                ← Device brand
[pp+0x8c58] String: "IPRemote"               ← Device model
[pp+0x8c60] String: "controllernonce"        ← Optional field
```

**Evidence Chain:**
```
pp+0x8ce0 (Field definition) 
  → pp+0x8c38 ("Pair Request" location)
  → pp+0x8c30 (command_name key)
  → pp+0x8d18 (static initializer closure 0x32fde4)
```

---

## 2. WHICH FUNCTION EXTRACTS/VALIDATES FIELDS

**SECONDARY DISPATCHER: feh_::vZb_331c50 (0x331c50)**

**Definition:**
```
[pp+0x8d28] Field <::.vZb>: static late final (offset: 0xd10)
[pp+0x8e90] AnonymousClosure: static (0x331cc4), in [feh] ::vZb (0x331c50)
```

**Type Signature:**
- `static late final <Map> vZb`
- Key: String (error type or field name)
- Value: Validation/extraction handler

**Field Names in Pool (pp+0x8e10-0x8e50):**

| Category | Offset | Field Name | Protocol Type |
|----------|--------|-----------|---------------|
| BIND | pp+0x8e10 | "status" | Bind Request |
| BIND | pp+0x8e18 | "stbnonce" | Bind Request |
| BIND | pp+0x8e20 | "pairingcode" | Bind Request |
| KEYCOMMAND | pp+0x8e40 | "authtoken" | KeyCommand Request |
| KEYCOMMAND | pp+0x8e48 | "bind_id" | KeyCommand Request |
| KEYCOMMAND | pp+0x8e50 | "cmd" | KeyCommand Request |

### Extraction Functions by Request Type

**Pair Request:**
- `feh_RAa::_anon_closure_32fd24` (0x32fd24)
  - [pp+0x8ce8] AnonymousClosure: (0x32fd24), of [feh] RAa
  - **Purpose:** Extract/validate "command_name" field
  - **Attached to:** feh_::vwb dispatch map
  
- `feh_RAa::_anon_closure_3304f8` (0x3304f8)
  - [pp+0x8d40] AnonymousClosure: (0x3304f8), of [feh] RAa
  - **Purpose:** Secondary validation (tid, controllernonce, stbnonce)
  - **Attached to:** feh_::vZb dispatch map

**Bind Request (3-part validation pipeline):**

- `keh_HBa::cff_330878` (0x330878)
  - [pp+0x8d68] AnonymousClosure: (0x330878), of [keh] HBa
  - **Validates:** status (boolean), authtoken, bind_id
  - **Error paths:**
    - [pp+0x8e60] "BindCommandNameError: unexpected command name"
    - [pp+0x8e70] "BindRequiredFieldsError: missing one or more required fields"
    - [pp+0x8e68] "BindBadStatusError: error status is false"
  
- `keh_IBa::cff_331184` (0x331184)
  - [pp+0x8d60] AnonymousClosure: (0x331184), of [keh] IBa
  - **Validates:** status field specifically (boolean check)
  - **Error path:** [pp+0x8e68] "BindBadStatusError: error status is false"
  
- `keh_JBa::cff_3317c4` (0x3317c4)
  - [pp+0x8d58] AnonymousClosure: (0x3317c4), of [keh] JBa
  - **Validates:** Required field presence (authtoken, bind_id)
  - **Error path:** [pp+0x8e70] "BindRequiredFieldsError: missing one or more required fields"

**KeyCommand Request:**

- `keh_KBa::yef_3305d0` (0x3305d0)
  - [pp+0x8d38] AnonymousClosure: (0x3305d0), of [keh] KBa
  - **Validates:** cmd field
  - **Error path:** [pp+0x8e78] "KeyCommandNameError: unexpected command name"
  
- `keh_KBa::Aef_33041c` (0x33041c)
  - [pp+0x8d48] AnonymousClosure: (0x33041c), of [keh] KBa
  - **Validates:** authtoken, bind_id (same as Bind)
  - **Error path:** [pp+0x8e80] "KeyCommandRequiredFieldsError: missing one or more required fields"

---

## 3. BIND-SPECIFIC VERSUS KEYCOMMAND-SPECIFIC FUNCTIONS

### Error Message Discrimination Test

The pp.txt pool reveals error strings that unambiguously map handlers to types:

**BIND-SPECIFIC ERROR MESSAGES:**
```
[pp+0x8e60] "BindCommandNameError: unexpected command name"
[pp+0x8e68] "BindBadStatusError: error status is false"           ← BIND ONLY
[pp+0x8e70] "BindRequiredFieldsError: missing one or more required fields"
```

**KEYCOMMAND-SPECIFIC ERROR MESSAGES:**
```
[pp+0x8e78] "KeyCommandNameError: unexpected command name"
[pp+0x8e80] "KeyCommandRequiredFieldsError: ..."                  ← KEYCOMMAND ONLY
```

### Handler Mapping

**BIND-SPECIFIC:**
- **keh_IBa::cff_331184** (0x331184)
  - Directly handles "BindBadStatusError" → dedicated status validator
  - [pp+0x8e68] is immediately after this closure in pool
  
- **keh_HBa::cff_330878** (0x330878)
  - Handles both BindCommandNameError + BindRequiredFieldsError
  - Coordinate check: [pp+0x8d68] references this immediately after error string section

- **keh_JBa::cff_3317c4** (0x3317c4)
  - Handles BindRequiredFieldsError
  - [pp+0x8d58] is closest to error section

**KEYCOMMAND-SPECIFIC:**
- **keh_KBa::yef_3305d0** (0x3305d0)
  - Handles KeyCommandNameError (cmd field validation)
  - [pp+0x8d38] precedes the KeyCommand error zone
  
- **keh_KBa::Aef_33041c** (0x33041c)
  - Handles KeyCommandRequiredFieldsError
  - [pp+0x8d48] references this in the KeyCommand error range

**SHARED (used by BOTH):**
- **heh_XAa::Vef_331690** (0x331690)
  - [pp+0x8e30] AnonymousClosure: (0x331690), of [heh] XAa
  - Located BETWEEN "pairingcode" (0x8e20) and "Key Command Request" (0x8e38)
  - **Likely role:** Type discriminator between Bind/KeyCommand
  - **Evidence:** No error message reference → classification function only

### Evidence Table

| Function | Bind-Specific | KeyCmd-Specific | Likely Role |
|----------|---------------|-----------------|-------------|
| keh_HBa::cff_330878 (0x330878) | ✓ | - | Bind validator (multi-field) |
| keh_IBa::cff_331184 (0x331184) | ✓ | ✗ | Bind status validator |
| keh_JBa::cff_3317c4 (0x3317c4) | ✓ | ✗ | Bind required-field validator |
| keh_KBa::yef_3305d0 (0x3305d0) | ✗ | ✓ | KeyCmd cmd validator |
| keh_KBa::Aef_33041c (0x33041c) | ✗ | ✓ | KeyCmd required-field validator |
| heh_XAa::Vef_331690 (0x331690) | dual | dual | Type discriminator |

---

## 4. STATIC LINKS: OBJECT-POOL STRINGS AND HANDLERS

### Control Flow Topology

```
        ┌──────────────────────────────────────────────┐
        │  Wdh_::_anon_closure_32b8fc (0x32b8fc)      │
        │  [pp+0x16478] Top-level dispatcher          │
        └─────────────────┬──────────────────────────┘
                          │
                          ├─── "Pair Request"
                          │    └────→ feh_::vwb_32fd70 (0x32fd70)
                          │           [pp+0x8ce0]
                          │           Dispatches on "command_name" key
                          │           ├─→ feh_RAa::_anon_closure_32fd24 (0x32fd24)
                          │           │   Extract "command_name"
                          │           └─→ feh_RAa::_anon_closure_3304f8 (0x3304f8)
                          │               Validate {tid, stbnonce, pairingcode}
                          │
                          ├─── "Bind Request"
                          │    └────→ feh_::vZb_331c50 (0x331c50)
                          │           [pp+0x8d28]
                          │           ├─→ keh_HBa::cff_330878 (0x330878) [multi-field]
                          │           ├─→ keh_IBa::cff_331184 (0x331184) [status check]
                          │           ├─→ keh_JBa::cff_3317c4 (0x3317c4) [required fields]
                          │           └─→ heh_XAa::Vef_331690 (0x331690) [discriminator]
                          │
                          └─── "Key Command Request"
                               └────→ feh_::vZb_331c50 (0x331c50)
                                      [pp+0x8d28] (SHARED with Bind)
                                      ├─→ keh_KBa::yef_3305d0 (0x3305d0) [cmd validator]
                                      ├─→ keh_KBa::Aef_33041c (0x33041c) [required fields]
                                      └─→ heh_XAa::Vef_331690 (0x331690) [discriminator]
```

### String-to-Handler Proximity Analysis

**Zone A: Pair Fields (pp+0x8c38-0x8c60)**
```
[pp+0x8c30] "command_name" 
              ↓ (lookup key)
[pp+0x8c38] "Pair Request"
              ↓ (message type)
[pp+0x8c40] "tid"
[pp+0x8c48] "Soft Remote"
[pp+0x8c50] "Comcast"
[pp+0x8c58] "IPRemote"
[pp+0x8c60] "controllernonce"
```

**Zone B: Dispatch Map Definitions (pp+0x8ce0-0x8d28)**
```
[pp+0x8ce0] Field <::.vwb>: static late final
[pp+0x8ce8] → feh_RAa::_anon_closure_32fd24 (0x32fd24) 
             [PAIR extractor]
             
[pp+0x8d18] → static _anon_closure_32fde4 (0x32fde4)
             [initializer for vwb]
             
[pp+0x8d28] Field <::.vZb>: static late final

[pp+0x8d38] → keh_KBa::yef_3305d0 (0x3305d0)
             [KEYCOMMAND cmd validator]
             
[pp+0x8d40] → feh_RAa::_anon_closure_3304f8 (0x3304f8)
             [PAIR validator - secondary]
             
[pp+0x8d48] → keh_KBa::Aef_33041c (0x33041c)
             [KEYCOMMAND required-field validator]
             
[pp+0x8d58] → keh_JBa::cff_3317c4 (0x3317c4)
             [BIND required-field validator]
             
[pp+0x8d60] → keh_IBa::cff_331184 (0x331184)
             [BIND status validator]
             
[pp+0x8d68] → keh_HBa::cff_330878 (0x330878)
             [BIND multi-field validator]
```

**Zone C: Error Messages (pp+0x8e10-0x8e80)**
```
[pp+0x8e10] "status"              → keh_IBa (0x331184)
[pp+0x8e18] "stbnonce"            → feh_RAa (0x3304f8)
[pp+0x8e20] "pairingcode"         → feh_RAa (0x3304f8)
[pp+0x8e38] "Key Command Request"
[pp+0x8e40] "authtoken"           → keh_KBa (0x33041c)
[pp+0x8e48] "bind_id"             → keh_KBa (0x33041c)
[pp+0x8e50] "cmd"                 → keh_KBa (0x3305d0)
[pp+0x8e58] "Bind Request"
[pp+0x8e60] "BindCommandNameError: ..."           → keh_HBa (0x330878)
[pp+0x8e68] "BindBadStatusError: ..."             → keh_IBa (0x331184) ✓ PROOF
[pp+0x8e70] "BindRequiredFieldsError: ..."        → keh_HBa, keh_JBa
[pp+0x8e78] "KeyCommandNameError: ..."            → keh_KBa (0x3305d0)
[pp+0x8e80] "KeyCommandRequiredFieldsError: ..."  → keh_KBa (0x33041c)
```

---

## 5. BEST NEXT INSPECTION TARGETS

### PRIORITY 1: Initializer Functions (decode the Maps)

1. **feh_::_anon_closure_32fde4** (0x32fde4) [static]
   - Builds `feh_::vwb_32fd70` late-final map
   - **Questions:**
     - Which command_name keys does it register?
     - What are the handler signatures?

2. **feh_::_anon_closure_331cc4** (0x331cc4) [static]
   - Builds `feh_::vZb_331c50` late-final map
   - **Questions:**
     - Does it register separate handlers for Bind vs KeyCommand?
     - How is `heh_XAa::Vef_331690` (0x331690) embedded?

### PRIORITY 2: Top-Level Dispatcher (understand entry point)

3. **Wdh_::_anon_closure_32b8fc** (0x32b8fc)
   - [pp+0x16478] AnonymousClosure: static (0x32b8fc), of [Wdh]
   - **To find:**
     - How it reads message type from wire format
     - How it dispatches to feh_::vwb vs feh_::vZb
     - Whether there's a third path (Pair vs Bind+KeyCmd routing)

### PRIORITY 3: Type Discriminator (Bind vs KeyCommand)

4. **heh_XAa::Vef_331690** (0x331690)
   - [pp+0x8e30] AnonymousClosure: (0x331690), of [heh] XAa
   - **To find:**
     - Is it a type guard (enum check)?
     - Does it read a field to distinguish Bind vs KeyCommand?
     - What preconditions must be true for each branch?

### PRIORITY 4: Field Extractors (understand JSON/protobuf parsing)

5. **keh_IBa::cff_331184** (0x331184) [BIND status check]
   - Single-field validator → easiest to reverse
   - **To find:**
     - Locate status field read
     - Find boolean type check
     - Locate error string reference

6. **feh_RAa::_anon_closure_32fd24** (0x32fd24) [PAIR command_name]
   - If simpler than Bind, disassemble for:
     - String extraction pattern
     - Map lookup pattern
     - Fallback behavior

---

## SUMMARY TABLE

| Function | Type | Offset | Error String Key | Role |
|----------|------|--------|------------------|------|
| Wdh_::_anon_closure_32b8fc | static | 0x32b8fc | (none) | Top dispatcher |
| feh_::vwb_32fd70 | map | 0x32fd70 | (command_name key) | Pair dispatcher |
| feh_::_anon_closure_32fde4 | static | 0x32fde4 | (none) | vwb init |
| feh_RAa::_anon_closure_32fd24 | closure | 0x32fd24 | Pair Request | Extract cmd_name |
| feh_RAa::_anon_closure_3304f8 | closure | 0x3304f8 | pairingcode | Pair validator |
| feh_::vZb_331c50 | map | 0x331c50 | (Bind+KeyCmd keys) | Field validator |
| feh_::_anon_closure_331cc4 | static | 0x331cc4 | (none) | vZb init |
| keh_HBa::cff_330878 | closure | 0x330878 | BindCommandNameError | Bind multi-field |
| keh_IBa::cff_331184 | closure | 0x331184 | BindBadStatusError | Bind status ✓ |
| keh_JBa::cff_3317c4 | closure | 0x3317c4 | BindRequiredFieldsErr | Bind required |
| keh_KBa::yef_3305d0 | closure | 0x3305d0 | KeyCommandNameError | KeyCmd cmd |
| keh_KBa::Aef_33041c | closure | 0x33041c | KeyCommandRequiredErr | KeyCmd req |
| heh_XAa::Vef_331690 | closure | 0x331690 | (type check only) | Discriminator |

---

## Analysis Artifacts

- **Source:** out/pp.txt (object pool analysis)
- **IDA Script:** out/ida_script/addNames.py (symbol registration)
- **Original Offsets:** addNames.py lines 9716-9909
- **pp.txt Lines:** 6040-6140, 18495-18510

---

## 6. Superseding runtime/builder update (2026-03-12)

The map/validator analysis above is still useful for understanding Pair/Bind parsing, but it is no longer the primary authtoken lead.

### What changed

Rooted Frida tracing plus Ghidra review have now pushed the active authtoken work much further downstream into the bind-builder object graph:

`33060c -> 32c768 -> 32c7a4 -> 3f3844 -> 55c414 / 55c328 / 55b6d0 -> 330770`

### What is now known

- `330770` and the serializer chain are downstream only.
  - The final token string object already exists before serializer entry.
- `3f3844` has two distinct behaviors.
  - the useful successful Bind path takes the class-`0x10b7` loop branch
  - that branch does:
    - first dynamic dispatch to `0x55a064`
    - repeated `5649ec -> 3de8b0` loop scaffolding
    - return of the Dart sentinel back up through `32c7a4` / `32c768`
  - the sibling `0x3f3954` dispatch is real code but is **not** the branch seen on successful Bind runs
- `55c414` is not a standalone constructor entry.
  - it sits inside a tiny indirect-call thunk and remains a structural packaging site
- `5649ec` is also an interior thunk target, not a trusted function start

### Static late-builder detour from Ghidra

One useful static detour was Ghidra function `0x55b6d0`, which corresponds to raw runtime offset `0x45b6d0`:

- writes `child_obj` into `parent_obj + 0x2b`
- derives `dispatch_node` from compressed ref `child_obj + 0xb`
- computes `dispatch_class_id = classId(dispatch_node)`
- dispatches through `x21[(dispatch_class_id - 0x167)]`
- stores the indirect-call result into `parent_obj + 0x2f`

Why it mattered:

- this is the first late builder seam that clearly uses a child-derived class-selected dispatch and writes the result back into a stable parent slot
- it was therefore worth a targeted runtime check

### Ghidra note

In the current Ghidra project, `libapp.so` is rebased by `+0x100000`.

Examples:

- runtime `0x32c768` -> Ghidra `0x42c768`
- runtime `0x3f3844` -> Ghidra `0x4f3844`
- runtime `0x45b6d0` -> Ghidra `0x55b6d0`

### Runtime correction from `fridaoutput11.log`

- the corrected raw `+0x45b6d0` hook attached cleanly
- but it still did **not** fire on the successful Pair -> Bind path
- meanwhile `55c414` still fired on-path, and its return again sat immediately adjacent to serializer parent slot `+0x6c`
- so `55b6d0` is now demoted from "best next runtime seam" to "static side path worth remembering"

### Runtime refinement from `fridaoutput13.log`

- by inline checkpoint `0x3306fc`, the finished bind parent is already live in both:
  - `x0`
  - `x1 + 0x20`
- its `+0x8` child is already the final token string object
- `55c414` still receives that finished parent unchanged
- the serializer-visible extra child is now directly tied back to the `55c414` return neighborhood:
  - serializer parent `arg1 + 0x6c == 55c414 retval + 0x10`
  - that `+0x6c` child object's `+0x10 == 55c414 retval`
- the child is still sparse at `55c414` return time and only appears populated by serializer entry

So the best static question is now very narrow: where, after `55c414` returns, is the neighboring object at `retval + 0x10` populated into the final serializer-visible wrapper?

This file therefore remains accurate for the parser/validator stage, but the live authtoken investigation is now centered on the already-proven `33060c -> ... -> 55c414 -> 330770` path, especially the tiny inline mutation block before `55c414`.

### Runtime refinement from `fridaoutput17.log`

The late merge-helper question is now also resolved enough to move downstream with confidence:

- correcting the helper-slot decode to the live runtime layout (`+0x14` / `+0x18`) made `4deb7c` readable on the useful path
- the existing child is now cleanly recovered as a real heap object
- that existing child's runtime class is stable:
  - `classId(existing_child) = 0x6721`
  - repeated 21 times in the run
- the resolved class-table target is also stable:
  - raw runtime offset `0x3d8f58`
  - Ghidra offset `0x4d8f58`
  - repeated 21 times in the run
- this class is not a surprise:
  - allocator `6649ec` builds the serializer-visible wrapper family from descriptor `0x106721c`
  - the runtime class decoder reports that family as class `0x6721`
- helper post-state shows a chain/merge advance, not token creation:
  - the prior child remains visible in live slot `+0x14`
  - the new child B advances into live slot `+0x18`

So the active runtime question is no longer "what class does `4deb7c` merge?" It is now: what exactly does the class-`0x6721` merge callee at raw `0x3d8f58` / Ghidra `0x4d8f58` do with the existing child and the new B wrapper before serializer entry?

### Runtime refinement from `fridaoutput18.log`

The first direct hook on raw `0x3d8f58` attached correctly, but its initial caller gate was too tight and did not emit callee-body lines.

Even without that direct body, the effect of the merge is already visible from the surrounding `4deb7c` snapshots:

- before the class-specific merge, the prior wrapper node has sentinel at live `+0xc`
- after the merge, that same prior wrapper node now holds the new child B at live `+0xc`
- helper state still advances in the same step:
  - live slot `+0x14` keeps the prior node
  - live slot `+0x18` advances to B

So the best current interpretation is that class-`0x6721` callee `0x3d8f58` links wrapper nodes into a chain/list by writing `existing_child.live_+0xc = new_child_B`.

### Upstream static conclusion from `0x43060c` / `0x430770` / `0x4307e0`

The later Ghidra pass makes the authtoken handling conclusion much stronger:

- the late `4de8b0` / `4deb7c` / `0x3d8f58` corridor is structural scaffolding
- the closure-selected helpers under `0x43060c` are parser/validator transformers
- by the time execution reaches the proven inline runtime checkpoint `0x3306fc`, the final token object already exists

Most importantly, the serializer itself does not compute the token:

- `FUN_0043060c` saves a first-pass helper result object and later passes that saved object into `FUN_00430770`
- `FUN_00430770` reads fields from that saved object and forwards them into `FUN_004307e0`
- `FUN_004307e0` then constructs the outbound Bind-request pair list with explicit pool constants:
  - `"command_name"` -> `"Bind Request"`
  - `"tid"` -> derived from the saved object's nested `+0x13` field
  - `"authtoken"` -> taken directly from the saved object's `+0x7` field

So the current best-supported conclusion is that the app is *not* locally generating the authtoken in this late bind-builder path. It is serializing an already-populated field from an upstream object.

### Superseding live-generator result from `0x4308c8` / `0x4309e4`

The later upstream pass identifies the actual local generation site.

The key branch split is now:

- `FUN_004311d4` / `FUN_004312e8` is a sibling parser/normalizer path that carries `bind_id`
- the live authtoken-generation path is `FUN_004308c8`

`FUN_004308c8` behaves as follows:

1. Calls `FUN_00430d58` to parse a handshake object.
2. `FUN_00430d58` validates/extracts:
   - `"command_name"`
   - `"status"`
   - `"stbnonce"`
   - `"pairingcode"`
   - `"name"`
3. On success, `FUN_00430d58` returns a class-`0x2ee` object built by `FUN_0065c4b8` with:
   - `+0x7 = stbnonce`
   - `+0xb = pairingcode`
   - `+0xf = name`
4. `FUN_004308c8` then calls `FUN_004309e4(...)`.
5. The return value of `FUN_004309e4(...)` is written into a class-`0x28e` object at `+0x7` via `FUN_0065c4a0`.
6. That class-`0x28e` object is the one later consumed by `FUN_0043060c`, and `FUN_00430770 / FUN_004307e0` serialize its `+0x7` field as outbound `"authtoken"`.

So the corrected full interpretation is:

- the serializer still does **not** generate the authtoken
- but the app **does** derive it locally one stage earlier in `FUN_004309e4`

Current best read of `FUN_004309e4`:

- raw register flow shows a two-stage composition:
  - stage 1 input sequence:
    - decoded local `+0x13`
    - `pairingcode`
    - local `+0xb`
  - digest stage 1 through `FUN_0054a9a8`
  - stage 2 input sequence:
    - `stbnonce`
    - digest stage 1 output
    - hardcoded salt string `pp+0x8d78 = "biT43y"`
  - digest stage 2 through `FUN_0054a9a8`
- it repeatedly transforms/composes byte sequences with helpers such as:
  - `FUN_00430b78`
  - `FUN_00430b44`
  - `FUN_002ed738`
  - `FUN_002ed7b0`
  - `FUN_002a70d8`
  - `FUN_002a745c`
- it hashes intermediate buffers through `FUN_0054a9a8`
- digest internals now look like standard SHA-256:
  - `FUN_0051e0ec` loads the standard SHA-256 IV constants
  - `FUN_00502518` / `FUN_004fff7c` feed the bytes
  - `FUN_0051e230` finalizes a 32-byte output
- the final digest is then passed through `FUN_00430b10 -> FUN_005185c0` into the codec object at `pp+0x1418`
- the adjacent pool strings include `"base64"`, the standard Base64 alphabet, `"=="`, and explicit invalid-base64 error messages, so this path now looks like standard Base64 encoding rather than another custom transform

Current best upstream provenance for the carried local fields:

- the local object consumed by `FUN_004309e4` is populated by `FUN_0043de9c`
- `FUN_0043de9c` writes:
  - local `+0xb` from its incoming `x3`
  - local `+0x13` from a metadata-selected optional value
- on the traced caller path (`FUN_0043dd20`, widened from `0x43dce0`), those values come from a source object previously allocated by `FUN_0043ccbc`
- `FUN_0043ccbc` stores:
  - source `+0xf = param_2`
  - source `+0x13 = param_3`
  - source `+0x17 = param_4`
  - source `+0x1b = optional metadata-selected value`
- the tightened read of local `+0xb` is:
  - source `+0x17` is not copied directly; it is transformed by `FUN_0043e74c -> FUN_004265dc`
  - that helper path uses generic typed late-field extraction machinery (`TypeArguments: <DBa>`, `_Pya._dOe`, type parameter `Y0`)
  - together with nearby `qAa.name` / `qAa.waf` / `qAa.Edf` metadata and Pair Request identity strings, this makes local `+0xb` look like a carried controller-profile string rather than a nonce
  - exact field label is still not fully closed
  - source `+0x17 = param_4`
  - source `+0x1b = metadata-selected optional`
- `FUN_0043dd20` then maps that source object into the auth-local object:
  - auth-local `+0xb` = `FUN_0043e74c(source +0x17, ...)`
  - auth-local `+0x13` = selector/list-derived value keyed off source `+0x13`
- one confirmed feeder is `FUN_0043cc60`, which constructs the source object with:
  - source `+0x13` copied from an earlier nested object's `+0x17`
  - source `+0x17` copied from that earlier nested object's `+0x23`
- so the current best lineage is:
  - local `+0xb` <- source `+0x17` <- earlier nested `+0x23`
  - local `+0x13` <- selector(source `+0x13`) <- earlier nested `+0x17`
- the semantics of that earlier nested object's fields now look like:
  - the object family is pool class `"Zdf"`
  - `Zdf +0x23` is a derived two-state selector/sentinel chosen inside `FUN_0043ccbc` after a comparison on the object's `+0xf` value
  - `Zdf +0x17` is the carried nested payload object/value; downstream helpers dereference it again and extract that child object's `+0x13` / `+0x17`
  - therefore `+0x23` looks like control-flow state, while `+0x17` looks like the substantive carried payload
  - after correcting for the raw AArch64 argument flow, local `+0x13` is now the strongest candidate for the nonce-like hex-decoded input, while local `+0xb` remains an unresolved carried text payload used in stage 1

Net result:

- the LAN auth token is locally derived from pairing-handshake material, not copied from a literal inbound `"authtoken"` field
- the bundled certificate still does not appear to be the source of that token
