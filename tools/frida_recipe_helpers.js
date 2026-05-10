'use strict';

/*
 * frida_recipe_helpers.js
 *
 * Hooks the actual crypto/encoding helpers called inside FUN_004309e4
 * (the auth-token derivation function) to capture live input values.
 *
 * Targets:
 *   0x430b78  — hex-decode of local+0x13
 *   0x430b44  — validate/copy (called for pairingcode, stbnonce, "biT43y", local+0xb)
 *   0x54a9a8  — SHA-256 wrapper (called twice: stage 1 and stage 2)
 *   0x430b10  — Base64 encoder wrapper
 *   0x4309e4  — the recipe function itself (to confirm it fires)
 *   0x4308c8  — the parent that calls 4309e4
 *
 * Also keeps the proven liveness hooks:
 *   0x32e990  — parser (confirms Pair response received)
 *   0x33060c  — bind-builder mid-block (confirms token installed)
 *
 * Fallback low-level SHA-256 hooks (if high-level wrappers don't fire):
 *   0x51e0ec  — SHA-256 IV init (seeds state words)
 *   0x502518  — SHA-256 update/feed
 *   0x4fff7c  — SHA-256 feed (second helper)
 *   0x51e230  — SHA-256 finalize
 */

const TARGET_MODULE = 'libapp.so';
const RETRY_MS = 200;
const GHIDRA_BASE = 0x100000;  // Ghidra image base offset
let installed = false;

// Convert Ghidra address to runtime offset
function g2r(ghidraAddr) {
  return ghidraAddr - GHIDRA_BASE;
}

function log(msg) {
  console.log('[recipe] ' + msg);
}

/* ── Dart compressed-ref helpers (proven in earlier probes) ── */

function decompressRef(raw32, moduleBase) {
  const heapBase = moduleBase.and(ptr('0xFFFFFF0000'));
  return heapBase.add(raw32);
}

function tryReadDartString(objAddr) {
  try {
    if (objAddr.isNull()) return null;
    const tagged = objAddr;
    // 64-bit Dart AOT layout for OneByteString:
    //   raw+0:  8-byte header
    //   raw+8:  8-byte Smi length (lower 32 bits: lenWord, Smi decode = lenWord >>> 1)
    //   raw+16: string data (= tagged + 0xf)
    const lenWord = tagged.add(7).readU32();
    const len = lenWord >>> 1;  // Smi decode
    if (len <= 0 || len > 2048) return null;
    const data = tagged.add(0xf).readUtf8String(len);
    return data;
  } catch (_e) {
    return null;
  }
}

function dumpDartObj(label, addr) {
  try {
    if (addr.isNull() || (addr.toUInt32() & 0xFFFFFFFF) < 0x1000) {
      log('  ' + label + ' = ' + addr + ' (not a heap object)');
      return;
    }
    // Try string read first
    const str = tryReadDartString(addr);
    if (str !== null) {
      log('  ' + label + ' = "' + str + '"');
      return;
    }
    // Dump raw bytes for manual inspection
    const raw = addr.sub(1); // remove tag bit
    const header = raw.readU64();
    const classId = (header >>> 12) & 0xFFFFF;
    log('  ' + label + ' classId=0x' + classId.toString(16) + ' raw: ' + hexDump(raw, 96));
  } catch (_e) {
    log('  ' + label + ' = ' + addr + ' (unreadable)');
  }
}

function tryReadCompressedDartString(parentAddr, offset, moduleBase) {
  try {
    const raw32 = parentAddr.add(offset).readU32();
    if (raw32 === 0) return null;
    const addr = decompressRef(raw32, moduleBase);
    return tryReadDartString(addr);
  } catch (_e) {
    return null;
  }
}

function hexDump(addr, len) {
  try {
    const bytes = addr.readByteArray(len);
    if (!bytes) return '<null>';
    return Array.from(new Uint8Array(bytes))
      .map(b => ('0' + b.toString(16)).slice(-2))
      .join(' ');
  } catch (_e) {
    return '<unreadable>';
  }
}

function tryReadDartStringFromReg(reg) {
  try {
    if (reg.isNull()) return null;
    return tryReadDartString(reg);
  } catch (_e) {
    return null;
  }
}

/* ── Install hooks ── */

function safeHook(base, offset, label, callbacks) {
  try {
    Interceptor.attach(base.add(offset), callbacks);
    log('  hooked ' + label + ' at +0x' + offset.toString(16));
  } catch (e) {
    log('  SKIP ' + label + ' at +0x' + offset.toString(16) + ': ' + e.message);
  }
}

function installHooks(base) {
  log('libapp.so base: ' + base);

  // ──────────────────────────────────────────────
  // LIVENESS: parser 0x32e990
  // ──────────────────────────────────────────────
  safeHook(base, 0x32e990, 'PARSER', {
    onEnter() { log('PARSER 0x32e990 hit'); }
  });

  // ──────────────────────────────────────────────
  // LIVENESS: bind-builder mid-block 0x33060c
  // ──────────────────────────────────────────────
  safeHook(base, 0x33060c, 'BIND-BUILDER', {
    onEnter() {
      log('BIND-BUILDER 0x33060c hit');
      // Try to read the token at arg1+0x20+0x8
      try {
        const x0 = this.context.x0;
        const raw20 = x0.add(0x20).readU32();
        const child = decompressRef(raw20, base);
        const token = tryReadDartString(child.add(0x8).readPointer ? child.add(8) : child.add(8));
        // Try compressed ref for the +0x8 field
        const tokenStr = tryReadCompressedDartString(child, 0x8, base);
        if (tokenStr) {
          log('BIND-BUILDER token at +0x20+0x8: "' + tokenStr + '"');
        }
      } catch (_e) {}
    }
  });

  // ──────────────────────────────────────────────
  // TARGET: FUN_004308c8 — parent of recipe
  // ──────────────────────────────────────────────
  safeHook(base, g2r(0x4308c8), 'FUN_004308c8', {
    onEnter() {
      log('>>> FUN_004308c8 HIT <<<');
      const x15 = this.context.x15;
      // param_2 is in x1, the carrier object with +0xb and +0x13
      const x1 = this.context.x1;
      log('  param_2 (carrier) = ' + x1);
      // Read carrier +0xb and +0x13 as compressed refs
      const valB = tryReadCompressedDartString(x1, 0xb, base);
      const val13 = tryReadCompressedDartString(x1, 0x13, base);
      log('  carrier+0xb  = ' + (valB !== null ? '"' + valB + '"' : '<not a string>'));
      log('  carrier+0x13 = ' + (val13 !== null ? '"' + val13 + '"' : '<not a string>'));
      // Also dump raw hex for both fields
      log('  carrier+0xb raw:  ' + hexDump(x1.add(0xb), 4));
      log('  carrier+0x13 raw: ' + hexDump(x1.add(0x13), 4));
    }
  });

  // ──────────────────────────────────────────────
  // TARGET: FUN_004309e4 — the recipe function
  // ──────────────────────────────────────────────
  let recipeHitCount = 0;
  safeHook(base, g2r(0x4309e4), 'FUN_004309e4-RECIPE', {
    onEnter() {
      recipeHitCount++;
      log('>>> FUN_004309e4 (RECIPE) HIT #' + recipeHitCount + ' <<<');
      // In the Dart ABI for this function:
      //   x0 = param_1 (parsed class-0x2ee object)
      //   x1 = param_2 = local+0x13 (the hex-encoded nonce)
      //   x2 = param_3 = local+0xb (the profile string)
      //   x3 = param_4 = stbnonce
      //   x4 = param_5 = carrier object
      //   x5 = param_6 = pairingcode
      const x0 = this.context.x0;
      const x1 = this.context.x1;
      const x2 = this.context.x2;
      const x3 = this.context.x3;
      const x4 = this.context.x4;
      const x5 = this.context.x5;

      log('  param_1 (parsed obj)  = ' + x0);
      dumpDartObj('param_2 (local+0x13)', x1);
      dumpDartObj('param_3 (local+0xb)', x2);
      dumpDartObj('param_4 (stbnonce)', x3);
      log('  param_5 (carrier)     = ' + x4);
      dumpDartObj('param_6 (pairingcode)', x5);
    },
    onLeave(retval) {
      log('>>> FUN_004309e4 RECIPE RETURN <<<');
      dumpDartObj('recipe retval (authtoken)', retval);
    }
  });

  // ──────────────────────────────────────────────
  // TARGET: FUN_00430b78 — hex-decode of local+0x13
  // ──────────────────────────────────────────────
  safeHook(base, g2r(0x430b78), 'FUN_00430b78-HEXDECODE', {
    onEnter() {
      log('>>> FUN_00430b78 (HEX-DECODE) HIT <<<');
      const x0 = this.context.x0;
      const x1 = this.context.x1;
      dumpDartObj('x0', x0);
      dumpDartObj('x1 (local+0x13 pre-decode)', x1);
    },
    onLeave(retval) {
      log('  hex-decode retval = ' + retval);
      // Try to read the decoded bytes
      try {
        const len = retval.add(7).readU32() >>> 1;
        if (len > 0 && len <= 64) {
          log('  decoded hex (' + len + ' bytes): ' + hexDump(retval.add(0xb), len));
        }
      } catch (_e) {}
    }
  });

  // ──────────────────────────────────────────────
  // TARGET: FUN_00430b44 — validate/copy string
  // Called for: pairingcode, local+0xb (in stage 1),
  //             stbnonce (stage 2), "biT43y" (stage 2)
  // ──────────────────────────────────────────────
  let validateHitCount = 0;
  safeHook(base, g2r(0x430b44), 'FUN_00430b44-VALIDATE', {
    onEnter() {
      validateHitCount++;
      log('>>> FUN_00430b44 (VALIDATE/COPY) HIT #' + validateHitCount + ' <<<');
      const x2 = this.context.x2;
      const x3 = this.context.x3;
      dumpDartObj('x2 (string arg)', x2);
      dumpDartObj('x3 (aux arg)', x3);
    }
  });

  // ──────────────────────────────────────────────
  // TARGET: FUN_0054a9a8 — SHA-256 wrapper
  // Called twice: stage 1 digest, stage 2 digest
  // ──────────────────────────────────────────────
  let sha256HitCount = 0;
  safeHook(base, g2r(0x54a9a8), 'FUN_0054a9a8-SHA256', {
    onEnter() {
      sha256HitCount++;
      log('>>> FUN_0054a9a8 (SHA-256) HIT #' + sha256HitCount + ' <<<');
      const x2 = this.context.x2;
      log('  x2 (input data) = ' + x2);
      // Try to read as a Uint8List / _GrowableList containing the staged bytes
      try {
        // Dump as raw: try multiple potential data offsets
        log('  raw from x2+0x7: ' + hexDump(x2.add(0x7), 64));
        log('  raw from x2+0xb: ' + hexDump(x2.add(0xb), 64));
        // Also try interpreting length
        const lenWord = x2.add(7).readU32();
        const len = lenWord >>> 1;
        if (len > 0 && len <= 512) {
          log('  interpreted len=' + len + ' data: ' + hexDump(x2.add(0xb), Math.min(len, 128)));
          try {
            const text = x2.add(0xb).readUtf8String(Math.min(len, 128));
            log('  as text: "' + text + '"');
          } catch (_) {}
        }
      } catch (_e) {
        log('  (could not read input data)');
      }
    }
  });

  // ──────────────────────────────────────────────
  // TARGET: FUN_00430b10 — Base64 encoder
  // ──────────────────────────────────────────────
  safeHook(base, g2r(0x430b10), 'FUN_00430b10-BASE64', {
    onEnter() {
      this._b64hit = true;
      log('>>> FUN_00430b10 (BASE64-ENCODE) HIT <<<');
      const x0 = this.context.x0;
      const x1 = this.context.x1;
      log('  x0 (digest obj) = ' + x0);
      log('  x1 = ' + x1);
      // Try to read 32-byte digest at multiple offsets
      try {
        log('  digest raw+0xf: ' + hexDump(x0.add(0xf), 32));
        log('  digest raw+0xb: ' + hexDump(x0.add(0xb), 32));
        log('  digest raw+0x17: ' + hexDump(x0.add(0x17), 32));
      } catch (_e) {}
      // Also try x1 if different
      if (!x1.equals(x0)) {
        try {
          log('  x1 raw+0xf: ' + hexDump(x1.add(0xf), 32));
        } catch (_e2) {}
      }
    },
    onLeave(retval) {
      if (this._b64hit) {
        log('  BASE64-ENCODE retval = ' + retval);
        dumpDartObj('base64 result', retval);
      }
    }
  });

  // ──────────────────────────────────────────────
  // FALLBACK: low-level SHA-256 primitives
  // ──────────────────────────────────────────────
  safeHook(base, g2r(0x51e0ec), 'SHA256-INIT', {
    onEnter() { log('SHA256-INIT 0x51e0ec hit'); }
  });
  safeHook(base, g2r(0x502518), 'SHA256-UPDATE', {
    onEnter() { log('SHA256-UPDATE 0x502518 hit'); }
  });
  safeHook(base, g2r(0x4fff7c), 'SHA256-FEED', {
    onEnter() { log('SHA256-FEED 0x4fff7c hit'); }
  });

  // ──────────────────────────────────────────────
  // LIVENESS: auth branch A/B (for comparison)
  // ──────────────────────────────────────────────
  let branchACount = 0, branchBCount = 0;
  safeHook(base, 0x43d47c, 'auth-branch-A', {
    onEnter() {
      branchACount++;
      if (branchACount <= 3) log('auth-branch-A 0x43d47c hit #' + branchACount);
    }
  });
  safeHook(base, 0x43ced8, 'auth-branch-B', {
    onEnter() {
      branchBCount++;
      if (branchBCount <= 3) log('auth-branch-B 0x43ced8 hit #' + branchBCount);
    }
  });

  log('All hooks installed. Waiting for Pair flow...');
}

/* ── Poll for libapp.so ── */

function pollForModule() {
  if (installed) return;
  const mod = Process.findModuleByName(TARGET_MODULE);
  if (mod) {
    installed = true;
    installHooks(mod.base);
  } else {
    setTimeout(pollForModule, RETRY_MS);
  }
}

pollForModule();
