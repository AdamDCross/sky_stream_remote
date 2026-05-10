'use strict';

const TARGET_MODULE = 'libapp.so';
const RETRY_MS = 200;
let installed = false;

const MAX_DETAILED_HITS = 2;
const AUTH_SELECTOR_LOG_LIMIT = 12;
const AUTH_BRANCH_A_CALLERS = new Set(['43ce8c', '43e1d8', '1a6d90']);
const AUTH_BRANCH_B_CALLERS = new Set(['43cec0', '43c9e0']);

function log(message) {
  console.log('[auth-inputs] ' + message);
}

function formatCodeLocation(address, moduleBase) {
  if (address === null || address.isNull()) {
    return '<null>';
  }
  try {
    const module = Process.findModuleByAddress(address);
    if (module !== null && module.name === TARGET_MODULE) {
      return '+' + address.sub(moduleBase).toString(16);
    }
    return address.toString() + ' ' + DebugSymbol.fromAddress(address);
  } catch (_err) {
    return address.toString();
  }
}

function normalizeTagged(ptrValue) {
  if (ptrValue === undefined || ptrValue === null || typeof ptrValue.isNull !== 'function') {
    return null;
  }
  if (ptrValue.isNull()) {
    return null;
  }
  try {
    return ptrValue.and(ptr('0xfffffffffffffffe'));
  } catch (_err) {
    return null;
  }
}

function readPrintable(ptrValue, byteCount) {
  try {
    const buf = ptrValue.readByteArray(byteCount);
    const u8 = new Uint8Array(buf);
    let out = '';
    for (let i = 0; i < u8.length; i += 1) {
      const b = u8[i];
      out += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    }
    return out;
  } catch (_err) {
    return null;
  }
}

function readDartOneByteString(taggedPtr) {
  const raw = normalizeTagged(taggedPtr);
  if (raw === null) {
    return null;
  }
  try {
    const length = raw.add(0x8).readU32();
    if (length === 0 || length > 4096) {
      return null;
    }
    const bytes = raw.add(0x10).readByteArray(length);
    const u8 = new Uint8Array(bytes);
    let out = '';
    for (let i = 0; i < u8.length; i += 1) {
      out += String.fromCharCode(u8[i]);
    }
    return out;
  } catch (_err) {
    return null;
  }
}

function readTaggedField(basePtr, offset) {
  try {
    return ptr(basePtr.add(offset).readU32()).or(ptr('0x7800000000')).add(1);
  } catch (_err) {
    return null;
  }
}

function readStackPointer(framePtr, offset) {
  try {
    return framePtr.add(offset).readPointer();
  } catch (_err) {
    return null;
  }
}

function getPointerInfo(ptrValue) {
  if (ptrValue.isNull()) {
    return null;
  }
  const normalized = normalizeTagged(ptrValue);
  if (normalized === null) {
    return null;
  }
  const range = Process.findRangeByAddress(normalized);
  if (range === null || range.protection.indexOf('r') === -1) {
    return null;
  }
  return { normalized, range };
}

function resolveCompressedRef(ownerPtr, offset) {
  const info = getPointerInfo(ownerPtr);
  if (info === null) {
    return null;
  }
  let rawField;
  try {
    rawField = info.normalized.add(offset).readU32();
  } catch (_err) {
    return null;
  }
  if (rawField === 0 || (rawField & 1) === 0) {
    return null;
  }
  const candidate = info.normalized.and(ptr('0xffffffff00000000')).add(rawField);
  const candidateInfo = getPointerInfo(candidate);
  if (candidateInfo === null) {
    return null;
  }
  return candidate;
}

function describeCompressedField(label, ownerPtr, offset) {
  const info = getPointerInfo(ownerPtr);
  if (info === null) {
    log(label + ': <unreadable owner>');
    return;
  }
  let rawField;
  try {
    rawField = info.normalized.add(offset).readU32();
  } catch (_err) {
    log(label + ': <unreadable field>');
    return;
  }
  log(label + ' raw32: 0x' + rawField.toString(16));
  if (rawField === 0) {
    return;
  }
  const candidate = info.normalized.and(ptr('0xffffffff00000000')).add(rawField);
  describePtr(label + ' candidate', candidate);
}

function describeRawCompressedCandidate(label, ownerPtr, offset) {
  const info = getPointerInfo(ownerPtr);
  if (info === null) {
    log(label + ': <unreadable owner>');
    return;
  }
  let rawField;
  try {
    rawField = info.normalized.add(offset).readU32();
  } catch (_err) {
    log(label + ': <unreadable field>');
    return;
  }
  if (rawField === 0) {
    log(label + ': 0x0');
    return;
  }
  const base = info.normalized.and(ptr('0xffffffff00000000')).add(rawField);
  log(label + ' raw32: 0x' + rawField.toString(16));
  log(label + ' base: ' + base);
  describePtr(label + ' base', base);
  describePtr(label + ' tagged', base.add(1));
}

function describeRawField(label, ownerPtr, offset) {
  const info = getPointerInfo(ownerPtr);
  if (info === null) {
    log(label + ': <unreadable owner>');
    return;
  }
  let rawField;
  try {
    rawField = info.normalized.add(offset).readU32();
  } catch (_err) {
    log(label + ': <unreadable field>');
    return;
  }
  const smi = rawField >> 1;
  log(label + ' raw32: 0x' + rawField.toString(16) + ' smi?: ' + smi);
}

function describePtr(label, ptrValue) {
  if (ptrValue === undefined || ptrValue === null) {
    log(label + ': <undefined>');
    return;
  }
  const str = readDartOneByteString(ptrValue);
  if (str !== null) {
    log(label + ': ' + JSON.stringify(str));
    return;
  }

  const raw = normalizeTagged(ptrValue);
  if (raw !== null) {
    const ascii = readPrintable(raw, 0x80);
    if (ascii !== null) {
      log(label + ' raw: ' + ascii);
      return;
    }
  }

  log(label + ': ' + ptrValue);
}

function describeObjectFields(label, taggedPtr, offsets) {
  const raw = normalizeTagged(taggedPtr);
  if (raw === null) {
    log(label + ': <non-tagged/null>');
    return;
  }

  offsets.forEach((offset) => {
    const child = readTaggedField(raw, offset);
    if (child === null) {
      log(label + ' +' + offset.toString(16) + ': <unreadable>');
      return;
    }
    describePtr(label + ' +' + offset.toString(16), child);
  });
}

function describeChildFields(label, ownerTaggedPtr, childOffset, grandchildOffsets) {
  const raw = normalizeTagged(ownerTaggedPtr);
  if (raw === null) {
    log(label + ': <non-tagged/null>');
    return;
  }
  const child = readTaggedField(raw, childOffset);
  if (child === null) {
    log(label + ' +' + childOffset.toString(16) + ': <unreadable>');
    return;
  }
  describePtr(label + ' +' + childOffset.toString(16), child);
  describeObjectFields(label + ' +' + childOffset.toString(16) + ' object', child, grandchildOffsets);
}

function describeCompressedChain(label, ownerPtr, offsets) {
  let current = ownerPtr;
  let pathLabel = label;
  for (let i = 0; i < offsets.length; i += 1) {
    const offset = offsets[i];
    const next = resolveCompressedRef(current, offset);
    pathLabel += ' +' + offset.toString(16);
    if (next === null) {
      log(pathLabel + ': <unreadable compressed ref>');
      return;
    }
    describePtr(pathLabel, next);
    current = next;
  }
}

function tryReadRaw32(basePtr, offset) {
  try {
    return '0x' + basePtr.add(offset).readU32().toString(16);
  } catch (_err) {
    return '<unreadable>';
  }
}

function describeTaggedValue(ptrValue) {
  if (ptrValue === null) {
    return '<null>';
  }
  const str = readDartOneByteString(ptrValue);
  if (str !== null) {
    return JSON.stringify(str);
  }
  return ptrValue.toString();
}

function captureTaggedObjectState(taggedPtr, directOffsets, childSpecs) {
  const state = {};
  const raw = normalizeTagged(taggedPtr);
  if (raw === null) {
    state['self'] = '<non-tagged/null>';
    return state;
  }

  state.self = raw.toString();
  directOffsets.forEach((offset) => {
    const key = '+' + offset.toString(16);
    state[key + '.raw32'] = tryReadRaw32(raw, offset);
    const child = readTaggedField(raw, offset);
    state[key] = describeTaggedValue(child);
  });

  childSpecs.forEach((spec) => {
    const child = readTaggedField(raw, spec.offset);
    const childKey = '+' + spec.offset.toString(16);
    if (child === null) {
      state[childKey + '.child'] = '<null>';
      return;
    }
    const childRaw = normalizeTagged(child);
    state[childKey + '.child'] = describeTaggedValue(child);
    if (childRaw === null) {
      return;
    }
    spec.fields.forEach((fieldOffset) => {
      const key = childKey + '+' + fieldOffset.toString(16);
      state[key + '.raw32'] = tryReadRaw32(childRaw, fieldOffset);
      const grandchild = readTaggedField(childRaw, fieldOffset);
      state[key] = describeTaggedValue(grandchild);
    });
  });

  return state;
}

function logStateDiff(label, beforeState, afterState) {
  const keys = Array.from(new Set(Object.keys(beforeState).concat(Object.keys(afterState)))).sort();
  let changed = 0;
  keys.forEach((key) => {
    const beforeValue = Object.prototype.hasOwnProperty.call(beforeState, key) ? beforeState[key] : '<missing>';
    const afterValue = Object.prototype.hasOwnProperty.call(afterState, key) ? afterState[key] : '<missing>';
    if (beforeValue !== afterValue) {
      changed += 1;
      log(label + ' ' + key + ': ' + beforeValue + ' -> ' + afterValue);
    }
  });
  if (changed === 0) {
    log(label + ': no tracked field changes');
  }
}

function safeAttach(label, address, callbacks) {
  log('hooking ' + label + ' @ ' + address);
  try {
    Interceptor.attach(address, callbacks);
  } catch (err) {
    log('failed to hook ' + label + ': ' + err.message);
  }
}

function attachHooks(moduleBase) {
  if (installed) {
    return;
  }
  installed = true;

  const parserPtr = moduleBase.add(0x32e990);
  const bindBuilderEntryPtr = moduleBase.add(0x3305d0);
  const bindBuilderPtr = moduleBase.add(0x33060c);
  const bindPopulatePtr = moduleBase.add(0x330674);
  const selectorBridgePtr = moduleBase.add(0x32b110);
  const selectorBridgeCallA = moduleBase.add(0x32afc0);
  const selectorBridgeCallB = moduleBase.add(0x32b070);
  const selectorBridgeCallC = moduleBase.add(0x32c46c);
  const selectorBridgeCallD = moduleBase.add(0x32c594);
  const selectorNormalizePtr = moduleBase.add(0x32f0ac);
  const selectorNormalizeCallPtr = moduleBase.add(0x32b14c);
  const selectorComposePtr = moduleBase.add(0x32b1e0);
  const selectorFinalizePtr = moduleBase.add(0x32b17c);
  const parentWrapperPtr = moduleBase.add(0x31b4f4);
  const parentPopulatePtr = moduleBase.add(0x31b530);
  const authEntryPtr = moduleBase.add(0x4308c8);
  const authDigestPtr = moduleBase.add(0x4309e4);
  const authBranchA = moduleBase.add(0x43d47c);
  const authBranchB = moduleBase.add(0x43ced8);
  const authBuilderLivePtr = moduleBase.add(0x43dce0);
  const authBuilderEntryPtr = moduleBase.add(0x43dc80);
  const authBuilderAltPtr = moduleBase.add(0x43dd80);
  const authLocalPtr = moduleBase.add(0x43de9c);
  const authProfilePtr = moduleBase.add(0x43e74c);
  const authSelectorPtr = moduleBase.add(0x4265dc);
  let seenParser = 0;
  let seenBindEntry = 0;
  let seenBind = 0;
  let seenPopulate = 0;
  let seenSelectorBridge = 0;
  let seenSelectorNormalize = 0;
  let seenSelectorBridgeCall = 0;
  let seenSelectorNormalizeCall = 0;
  let seenSelectorCompose = 0;
  let seenSelectorFinalize = 0;
  let seenParentWrapper = 0;
  let seenParentPopulate = 0;
  let seenAuthEntry = 0;
  let seenAuthDigest = 0;
  let seenAuthBranchA = 0;
  let seenAuthBranchB = 0;
  let seenAuthBuilderLive = 0;
  let seenAuthBuilderEntry = 0;
  let seenAuthBuilderAlt = 0;
  let seenAuthLocal = 0;
  let seenAuthProfile = 0;
  let seenAuthSelector = 0;

  safeAttach('parser 0x32e990', parserPtr, {
    onEnter() {
      seenParser += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenParser <= MAX_DETAILED_HITS;
      log('ENTER parser 0x32e990 hit #' + seenParser + ' caller +' + this.callerOffset);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('parser retval caller +' + this.callerOffset, retval);
      describeObjectFields('parser retval object caller +' + this.callerOffset, retval, [0x7, 0xb, 0xf, 0x10, 0x1c]);
      describeChildFields('parser retval object caller +' + this.callerOffset, retval, 0x10, [0x20, 0x24]);
      describeCompressedChain('parser retval compressed caller +' + this.callerOffset, retval, [0x10, 0x20]);
      describeCompressedChain('parser retval compressed caller +' + this.callerOffset, retval, [0x10, 0x24]);
    },
  });

  safeAttach('bind builder entry 0x3305d0', bindBuilderEntryPtr, {
    onEnter() {
      seenBindEntry += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenBindEntry <= MAX_DETAILED_HITS;
      const framePtr = ptr(this.context.x15);
      this.stackArg10 = readStackPointer(framePtr, 0x10);
      this.stackArg18 = readStackPointer(framePtr, 0x18);
      log('ENTER bind builder entry 0x3305d0 hit #' + seenBindEntry + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('3305d0 stack +10 caller +' + this.callerOffset, this.stackArg10);
      describeObjectFields('3305d0 stack +10 object caller +' + this.callerOffset, this.stackArg10, [0x7, 0xb, 0xf, 0x10, 0x1c]);
      describeCompressedChain('3305d0 stack +10 caller +' + this.callerOffset, this.stackArg10, [0x10, 0x20]);
      describeCompressedChain('3305d0 stack +10 caller +' + this.callerOffset, this.stackArg10, [0x10, 0x24]);

      describePtr('3305d0 stack +18 caller +' + this.callerOffset, this.stackArg18);
      describeObjectFields('3305d0 stack +18 object caller +' + this.callerOffset, this.stackArg18, [0x17]);
      describeChildFields('3305d0 stack +18 object caller +' + this.callerOffset, this.stackArg18, 0x17, [0xf]);
      describeCompressedChain('3305d0 stack +18 caller +' + this.callerOffset, this.stackArg18, [0x17]);
      describeCompressedChain('3305d0 stack +18 caller +' + this.callerOffset, this.stackArg18, [0x17, 0xf]);
      describeCompressedChain('3305d0 stack +18 caller +' + this.callerOffset, this.stackArg18, [0x17, 0xf, 0x17]);
    },
  });

  safeAttach('bind builder mid 0x33060c', bindBuilderPtr, {
    onEnter(args) {
      seenBind += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenBind <= MAX_DETAILED_HITS;
      this.arg1 = ptr(args[1]);
      this.arg2 = ptr(args[2]);
      this.arg1StateBefore = captureTaggedObjectState(this.arg1, [0x20, 0x24], [
        { offset: 0x20, fields: [0x8, 0xc, 0x10, 0x6c] },
        { offset: 0x24, fields: [0x8, 0x10] },
      ]);
      log('ENTER bind builder mid 0x33060c hit #' + seenBind + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('33060c arg1 caller +' + this.callerOffset, args[1]);
      describeObjectFields('33060c arg1 object caller +' + this.callerOffset, args[1], [0x8, 0x20, 0x24]);
      describeChildFields('33060c arg1 object caller +' + this.callerOffset, args[1], 0x20, [0x8, 0xc, 0x10, 0x6c]);
      describeCompressedChain('33060c arg1 compressed caller +' + this.callerOffset, args[1], [0x20]);
      describeCompressedChain('33060c arg1 compressed caller +' + this.callerOffset, args[1], [0x20, 0x8]);
      describeCompressedChain('33060c arg1 compressed caller +' + this.callerOffset, args[1], [0x24]);
      describeCompressedChain('33060c arg1 compressed caller +' + this.callerOffset, args[1], [0x24, 0x8]);
      describeCompressedChain('33060c arg1 compressed caller +' + this.callerOffset, args[1], [0x24, 0x10]);

      describePtr('33060c arg2 caller +' + this.callerOffset, args[2]);
      describeObjectFields('33060c arg2 object caller +' + this.callerOffset, args[2], [0x7, 0xb, 0xf, 0x10, 0x1c]);
      describeChildFields('33060c arg2 object caller +' + this.callerOffset, args[2], 0x10, [0x20, 0x24]);
      describeCompressedChain('33060c arg2 compressed caller +' + this.callerOffset, args[2], [0x10, 0x20]);
      describeCompressedChain('33060c arg2 compressed caller +' + this.callerOffset, args[2], [0x10, 0x24]);
    },
    onLeave(retval) {
      if (!this.detail || this.arg1 === undefined) {
        return;
      }
      describePtr('33060c retval caller +' + this.callerOffset, retval);
      describePtr('33060c post-arg1 caller +' + this.callerOffset, this.arg1);
      describeObjectFields('33060c post-arg1 object caller +' + this.callerOffset, this.arg1, [0x20, 0x24]);
      describeChildFields('33060c post-arg1 object caller +' + this.callerOffset, this.arg1, 0x20, [0x8]);
      describeChildFields('33060c post-arg1 object caller +' + this.callerOffset, this.arg1, 0x24, [0x8, 0x10]);
      describeCompressedChain('33060c post-arg1 compressed caller +' + this.callerOffset, this.arg1, [0x20]);
      describeCompressedChain('33060c post-arg1 compressed caller +' + this.callerOffset, this.arg1, [0x20, 0x8]);
      describeCompressedChain('33060c post-arg1 compressed caller +' + this.callerOffset, this.arg1, [0x24]);
      describeCompressedChain('33060c post-arg1 compressed caller +' + this.callerOffset, this.arg1, [0x24, 0x8]);
      describeCompressedChain('33060c post-arg1 compressed caller +' + this.callerOffset, this.arg1, [0x24, 0x10]);
      logStateDiff('33060c arg1 diff caller +' + this.callerOffset, this.arg1StateBefore, captureTaggedObjectState(this.arg1, [0x20, 0x24], [
        { offset: 0x20, fields: [0x8, 0xc, 0x10, 0x6c] },
        { offset: 0x24, fields: [0x8, 0x10] },
      ]));
      describePtr('33060c post-arg2 caller +' + this.callerOffset, this.arg2);
    },
  });

  safeAttach('selector bridge 0x32b110', selectorBridgePtr, {
    onEnter(args) {
      seenSelectorBridge += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenSelectorBridge <= MAX_DETAILED_HITS * 3;
      this.param2 = ptr(args[1]);
      this.param3 = ptr(args[2]);
      log('ENTER selector bridge 0x32b110 hit #' + seenSelectorBridge + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('32b110 arg1 caller +' + this.callerOffset, args[1]);
      describeObjectFields('32b110 arg1 object caller +' + this.callerOffset, args[1], [0xb, 0x13, 0x17, 0x1f, 0x33, 0x3f]);
      describeCompressedChain('32b110 arg1 compressed caller +' + this.callerOffset, args[1], [0xb]);
      describeCompressedChain('32b110 arg1 compressed caller +' + this.callerOffset, args[1], [0x13]);
      describeCompressedChain('32b110 arg1 compressed caller +' + this.callerOffset, args[1], [0x17]);
      describeCompressedChain('32b110 arg1 compressed caller +' + this.callerOffset, args[1], [0x1f]);

      describePtr('32b110 arg2 caller +' + this.callerOffset, args[2]);
      describeObjectFields('32b110 arg2 object caller +' + this.callerOffset, args[2], [0x7, 0xb, 0xf, 0x17, 0x1f, 0x27, 0x2b]);
      describeCompressedChain('32b110 arg2 compressed caller +' + this.callerOffset, args[2], [0x7]);
      describeCompressedChain('32b110 arg2 compressed caller +' + this.callerOffset, args[2], [0xb]);
      describeCompressedChain('32b110 arg2 compressed caller +' + this.callerOffset, args[2], [0xf]);
    },
  });

  function attachSelectorBridgeCallsite(label, address) {
    safeAttach(label, address, {
      onEnter() {
        seenSelectorBridgeCall += 1;
        this.detail = seenSelectorBridgeCall <= MAX_DETAILED_HITS * 4;
        log('ENTER ' + label + ' hit #' + seenSelectorBridgeCall);
        if (!this.detail) {
          return;
        }
        describePtr(label + ' x1', this.context.x1);
        describeObjectFields(label + ' x1 object', this.context.x1, [0xb, 0x13, 0x17, 0x1f, 0x33, 0x3f]);
        describeCompressedChain(label + ' x1 compressed', this.context.x1, [0x13]);
        describeCompressedChain(label + ' x1 compressed', this.context.x1, [0x17]);
        describeCompressedChain(label + ' x1 compressed', this.context.x1, [0x1f]);

        describePtr(label + ' x2', this.context.x2);
        describeObjectFields(label + ' x2 object', this.context.x2, [0x7, 0xb, 0xf, 0x17, 0x1f, 0x27, 0x2b]);
        describeCompressedChain(label + ' x2 compressed', this.context.x2, [0x7]);
        describeCompressedChain(label + ' x2 compressed', this.context.x2, [0xb]);
        describeCompressedChain(label + ' x2 compressed', this.context.x2, [0xf]);
      },
    });
  }

  attachSelectorBridgeCallsite('selector bridge call 0x32afc0', selectorBridgeCallA);
  attachSelectorBridgeCallsite('selector bridge call 0x32b070', selectorBridgeCallB);
  attachSelectorBridgeCallsite('selector bridge call 0x32c46c', selectorBridgeCallC);
  attachSelectorBridgeCallsite('selector bridge call 0x32c594', selectorBridgeCallD);

  safeAttach('selector normalize 0x32f0ac', selectorNormalizePtr, {
    onEnter(args) {
      seenSelectorNormalize += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenSelectorNormalize <= MAX_DETAILED_HITS * 4;
      log('ENTER selector normalize 0x32f0ac hit #' + seenSelectorNormalize + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('32f0ac arg0 caller +' + this.callerOffset, args[0]);
      describeObjectFields('32f0ac arg0 object caller +' + this.callerOffset, args[0], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f, 0x23]);
      describePtr('32f0ac arg1 caller +' + this.callerOffset, args[1]);
      describeObjectFields('32f0ac arg1 object caller +' + this.callerOffset, args[1], [0x13, 0x1f, 0x23]);
      describePtr('32f0ac arg4 caller +' + this.callerOffset, args[4]);
      describeObjectFields('32f0ac arg4 object caller +' + this.callerOffset, args[4], [0x13, 0x1f, 0x23, 0x27, 0x2b, 0x2f]);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('32f0ac retval caller +' + this.callerOffset, retval);
      describeObjectFields('32f0ac retval object caller +' + this.callerOffset, retval, [0x7, 0xb, 0xf]);
      describeCompressedChain('32f0ac retval compressed caller +' + this.callerOffset, retval, [0x7]);
      describeCompressedChain('32f0ac retval compressed caller +' + this.callerOffset, retval, [0xb]);
      describeCompressedChain('32f0ac retval compressed caller +' + this.callerOffset, retval, [0xf]);
    },
  });

  safeAttach('selector normalize call 0x32b14c', selectorNormalizeCallPtr, {
    onEnter() {
      seenSelectorNormalizeCall += 1;
      this.detail = seenSelectorNormalizeCall <= MAX_DETAILED_HITS * 4;
      log('ENTER selector normalize call 0x32b14c hit #' + seenSelectorNormalizeCall);
      if (!this.detail) {
        return;
      }
      describePtr('32b14c x0', this.context.x0);
      describeObjectFields('32b14c x0 object', this.context.x0, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f, 0x23]);
      describePtr('32b14c x1', this.context.x1);
      describeObjectFields('32b14c x1 object', this.context.x1, [0x13, 0x1f, 0x23]);
      describePtr('32b14c x4', this.context.x4);
      describeObjectFields('32b14c x4 object', this.context.x4, [0x13, 0x1f, 0x23, 0x27, 0x2b, 0x2f]);
    },
  });

  safeAttach('selector compose 0x32b1e0', selectorComposePtr, {
    onEnter(args) {
      seenSelectorCompose += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenSelectorCompose <= MAX_DETAILED_HITS * 4;
      log('ENTER selector compose 0x32b1e0 hit #' + seenSelectorCompose + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('32b1e0 arg1 caller +' + this.callerOffset, args[1]);
      describeObjectFields('32b1e0 arg1 object caller +' + this.callerOffset, args[1], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1f, 0x33, 0x3f]);
      describeCompressedChain('32b1e0 arg1 compressed caller +' + this.callerOffset, args[1], [0x7]);
      describeCompressedChain('32b1e0 arg1 compressed caller +' + this.callerOffset, args[1], [0xb]);
      describeCompressedChain('32b1e0 arg1 compressed caller +' + this.callerOffset, args[1], [0xf]);
      describeCompressedChain('32b1e0 arg1 compressed caller +' + this.callerOffset, args[1], [0x17]);
      describeCompressedChain('32b1e0 arg1 compressed caller +' + this.callerOffset, args[1], [0x1f]);
      describePtr('32b1e0 arg2 caller +' + this.callerOffset, args[2]);
      describeObjectFields('32b1e0 arg2 object caller +' + this.callerOffset, args[2], [0x7, 0xb, 0xf, 0x17, 0x1f, 0x27, 0x2b]);
      describePtr('32b1e0 arg3 caller +' + this.callerOffset, args[3]);
      describeObjectFields('32b1e0 arg3 object caller +' + this.callerOffset, args[3], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      describePtr('32b1e0 arg5 caller +' + this.callerOffset, args[5]);
      describeObjectFields('32b1e0 arg5 object caller +' + this.callerOffset, args[5], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('32b1e0 retval caller +' + this.callerOffset, retval);
      describeObjectFields('32b1e0 retval object caller +' + this.callerOffset, retval, [0x7, 0xb, 0xf, 0x13]);
      describeCompressedChain('32b1e0 retval compressed caller +' + this.callerOffset, retval, [0x7]);
      describeCompressedChain('32b1e0 retval compressed caller +' + this.callerOffset, retval, [0xb]);
      describeCompressedChain('32b1e0 retval compressed caller +' + this.callerOffset, retval, [0xf]);
      describeCompressedChain('32b1e0 retval compressed caller +' + this.callerOffset, retval, [0x13]);
    },
  });

  safeAttach('selector finalize 0x32b17c', selectorFinalizePtr, {
    onEnter(args) {
      seenSelectorFinalize += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenSelectorFinalize <= MAX_DETAILED_HITS * 4;
      log('ENTER selector finalize 0x32b17c hit #' + seenSelectorFinalize + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('32b17c arg1 caller +' + this.callerOffset, args[1]);
      describeObjectFields('32b17c arg1 object caller +' + this.callerOffset, args[1], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1f]);
      describeCompressedChain('32b17c arg1 compressed caller +' + this.callerOffset, args[1], [0x7]);
      describeCompressedChain('32b17c arg1 compressed caller +' + this.callerOffset, args[1], [0xf]);
      describeCompressedChain('32b17c arg1 compressed caller +' + this.callerOffset, args[1], [0x1f]);
      describePtr('32b17c arg2 caller +' + this.callerOffset, args[2]);
      describeObjectFields('32b17c arg2 object caller +' + this.callerOffset, args[2], [0x7, 0xb, 0xf, 0x13]);
      describeCompressedChain('32b17c arg2 compressed caller +' + this.callerOffset, args[2], [0xb]);
      describeCompressedChain('32b17c arg2 compressed caller +' + this.callerOffset, args[2], [0xf]);
    },
  });

  safeAttach('auth entry 0x4308c8', authEntryPtr, {
    onEnter(args) {
      seenAuthEntry += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenAuthEntry <= MAX_DETAILED_HITS;
      this.localObj = ptr(args[1]);
      log('ENTER auth entry 0x4308c8 hit #' + seenAuthEntry + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('4308c8 arg1 auth-local caller +' + this.callerOffset, args[1]);
      describeObjectFields('4308c8 arg1 auth-local caller +' + this.callerOffset, args[1], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      describePtr('4308c8 arg2 parser payload caller +' + this.callerOffset, args[2]);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('4308c8 retval caller +' + this.callerOffset, retval);
      describeObjectFields('4308c8 post-auth-local caller +' + this.callerOffset, this.localObj, [0x7, 0xb, 0xf, 0x13]);
    },
  });

  safeAttach('auth builder entry 0x43dc80', authBuilderEntryPtr, {
    onEnter(args) {
      seenAuthBuilderEntry += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenAuthBuilderEntry <= MAX_DETAILED_HITS;
      log('ENTER auth builder entry 0x43dc80 hit #' + seenAuthBuilderEntry + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('43dc80 arg0 caller +' + this.callerOffset, args[0]);
      describePtr('43dc80 arg2 caller +' + this.callerOffset, args[2]);
      describePtr('43dc80 arg3 caller +' + this.callerOffset, args[3]);
      describeObjectFields('43dc80 arg0 object caller +' + this.callerOffset, args[0], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      describeObjectFields('43dc80 arg2 object caller +' + this.callerOffset, args[2], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      describeObjectFields('43dc80 arg3 object caller +' + this.callerOffset, args[3], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      [args[2], args[3]].forEach((value, index) => {
        [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b].forEach((offset) => {
          describeRawCompressedCandidate(
            '43dc80 arg' + (index === 0 ? '2' : '3') + ' raw-compressed caller +' + this.callerOffset + ' +' + offset.toString(16),
            value,
            offset
          );
        });
      });
    },
  });

  safeAttach('auth builder live 0x43dce0', authBuilderLivePtr, {
    onEnter(args) {
      seenAuthBuilderLive += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenAuthBuilderLive <= MAX_DETAILED_HITS;
      this.liveObj = ptr(args[0]);
      this.liveStateBefore = captureTaggedObjectState(this.liveObj, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f], []);
      log('ENTER auth builder live 0x43dce0 hit #' + seenAuthBuilderLive + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('43dce0 arg0 caller +' + this.callerOffset, args[0]);
      describeObjectFields('43dce0 arg0 object caller +' + this.callerOffset, args[0], [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b].forEach((offset) => {
        describeCompressedField(
          '43dce0 arg0 compressed caller +' + this.callerOffset + ' +' + offset.toString(16),
          args[0],
          offset
        );
        describeRawCompressedCandidate(
          '43dce0 arg0 raw-compressed caller +' + this.callerOffset + ' +' + offset.toString(16),
          args[0],
          offset
        );
        describeCompressedChain(
          '43dce0 arg0 compressed caller +' + this.callerOffset,
          args[0],
          [offset]
        );
      });
    },
    onLeave(retval) {
      if (!this.detail || this.liveObj === undefined) {
        return;
      }
      describePtr('43dce0 retval caller +' + this.callerOffset, retval);
      describeObjectFields('43dce0 post-arg0 object caller +' + this.callerOffset, this.liveObj, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
      [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b].forEach((offset) => {
        describeCompressedField(
          '43dce0 post-arg0 compressed caller +' + this.callerOffset + ' +' + offset.toString(16),
          this.liveObj,
          offset
        );
        describeRawCompressedCandidate(
          '43dce0 post-arg0 raw-compressed caller +' + this.callerOffset + ' +' + offset.toString(16),
          this.liveObj,
          offset
        );
        describeCompressedChain(
          '43dce0 post-arg0 compressed caller +' + this.callerOffset,
          this.liveObj,
          [offset]
        );
      });
      logStateDiff(
        '43dce0 arg0 diff caller +' + this.callerOffset,
        this.liveStateBefore,
        captureTaggedObjectState(this.liveObj, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f], [])
      );
    },
  });

  safeAttach('auth builder alt 0x43dd80', authBuilderAltPtr, {
    onEnter(args) {
      seenAuthBuilderAlt += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenAuthBuilderAlt <= MAX_DETAILED_HITS;
      log('ENTER auth builder alt 0x43dd80 hit #' + seenAuthBuilderAlt + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('43dd80 arg2 caller +' + this.callerOffset, args[2]);
      describePtr('43dd80 arg3 caller +' + this.callerOffset, args[3]);
    },
  });

  safeAttach('auth digest 0x4309e4', authDigestPtr, {
    onEnter(args) {
      seenAuthDigest += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenAuthDigest <= MAX_DETAILED_HITS;
      log('ENTER auth digest 0x4309e4 hit #' + seenAuthDigest + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('4309e4 local +0x13 caller +' + this.callerOffset, args[1]);
      describePtr('4309e4 local +0xb caller +' + this.callerOffset, args[2]);
      describePtr('4309e4 stbnonce caller +' + this.callerOffset, args[3]);
      describePtr('4309e4 auth-local caller +' + this.callerOffset, args[4]);
      describePtr('4309e4 pairingcode caller +' + this.callerOffset, args[5]);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('4309e4 retval caller +' + this.callerOffset, retval);
    },
  });

  safeAttach('auth branch A 0x43d47c', authBranchA, {
    onEnter(args) {
      seenAuthBranchA += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = AUTH_BRANCH_A_CALLERS.has(this.callerOffset) && seenAuthBranchA <= AUTH_SELECTOR_LOG_LIMIT;
      log('ENTER auth branch A 0x43d47c hit #' + seenAuthBranchA + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      const x15 = ptr(this.context.x15);
      describePtr('43d47c arg0 caller +' + this.callerOffset, args[0]);
      describePtr('43d47c arg1 caller +' + this.callerOffset, args[1]);
      describePtr('43d47c arg2 caller +' + this.callerOffset, args[2]);
      describePtr('43d47c arg3 caller +' + this.callerOffset, args[3]);
      describePtr('43d47c arg4 caller +' + this.callerOffset, args[4]);
      [0x0, 0x8, 0x10, 0x18, 0x20].forEach((offset) => {
        const slot = readStackPointer(x15, offset);
        describePtr('43d47c x15+' + offset.toString(16) + ' caller +' + this.callerOffset, slot);
        if (slot !== null) {
          describeObjectFields('43d47c x15+' + offset.toString(16) + ' object caller +' + this.callerOffset, slot, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
          if (offset === 0x18 || offset === 0x20) {
            [0xb, 0xf, 0x13, 0x17, 0x1f].forEach((fieldOffset) => {
              describeRawCompressedCandidate(
                '43d47c x15+' + offset.toString(16) + ' raw-compressed caller +' + this.callerOffset + ' +' + fieldOffset.toString(16),
                slot,
                fieldOffset
              );
              describeCompressedChain(
                '43d47c x15+' + offset.toString(16) + ' compressed caller +' + this.callerOffset,
                slot,
                [fieldOffset]
              );
            });
          }
        }
      });
    },
  });

  safeAttach('auth branch B 0x43ced8', authBranchB, {
    onEnter(args) {
      seenAuthBranchB += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = AUTH_BRANCH_B_CALLERS.has(this.callerOffset) && seenAuthBranchB <= AUTH_SELECTOR_LOG_LIMIT;
      log('ENTER auth branch B 0x43ced8 hit #' + seenAuthBranchB + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      const x15 = ptr(this.context.x15);
      describePtr('43ced8 arg0 caller +' + this.callerOffset, args[0]);
      describePtr('43ced8 arg1 caller +' + this.callerOffset, args[1]);
      describePtr('43ced8 arg2 caller +' + this.callerOffset, args[2]);
      describePtr('43ced8 arg3 caller +' + this.callerOffset, args[3]);
      describePtr('43ced8 arg4 caller +' + this.callerOffset, args[4]);
      [0x0, 0x8, 0x10, 0x18, 0x20, 0x28].forEach((offset) => {
        const slot = readStackPointer(x15, offset);
        describePtr('43ced8 x15+' + offset.toString(16) + ' caller +' + this.callerOffset, slot);
        if (slot !== null) {
          describeObjectFields('43ced8 x15+' + offset.toString(16) + ' object caller +' + this.callerOffset, slot, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
          if (offset === 0x18 || offset === 0x20 || offset === 0x28) {
            [0xb, 0xf, 0x13, 0x17, 0x1f].forEach((fieldOffset) => {
              describeRawCompressedCandidate(
                '43ced8 x15+' + offset.toString(16) + ' raw-compressed caller +' + this.callerOffset + ' +' + fieldOffset.toString(16),
                slot,
                fieldOffset
              );
              describeCompressedChain(
                '43ced8 x15+' + offset.toString(16) + ' compressed caller +' + this.callerOffset,
                slot,
                [fieldOffset]
              );
            });
          }
        }
      });
    },
  });

  safeAttach('auth local 0x43de9c', authLocalPtr, {
    onEnter(args) {
      seenAuthLocal += 1;
      this.callerOffset = this.returnAddress.sub(moduleBase).toString(16);
      this.detail = seenAuthLocal <= MAX_DETAILED_HITS;
      this.localObj = ptr(args[1]);
      log('ENTER auth local 0x43de9c hit #' + seenAuthLocal + ' caller +' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('43de9c auth-local caller +' + this.callerOffset, args[1]);
      describePtr('43de9c candidate +0xb caller +' + this.callerOffset, args[3]);
      describePtr('43de9c selector arg6 caller +' + this.callerOffset, args[5]);
      describePtr('43de9c selector arg7 caller +' + this.callerOffset, args[6]);
    },
    onLeave() {
      if (!this.detail) {
        return;
      }
      describeObjectFields('43de9c post-auth-local caller +' + this.callerOffset, this.localObj, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x1f]);
    },
  });

  safeAttach('auth profile 0x43e74c', authProfilePtr, {
    onEnter(args) {
      this.callerOffset = formatCodeLocation(this.returnAddress, moduleBase);
      seenAuthProfile += 1;
      this.detail = seenAuthProfile <= AUTH_SELECTOR_LOG_LIMIT;
      log('ENTER auth profile 0x43e74c hit #' + seenAuthProfile + ' caller ' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('43e74c source caller ' + this.callerOffset, args[0]);
      describePtr('43e74c typeargs caller ' + this.callerOffset, args[1]);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('43e74c retval caller ' + this.callerOffset, retval);
    },
  });

  safeAttach('auth selector 0x4265dc', authSelectorPtr, {
    onEnter(args) {
      this.callerOffset = formatCodeLocation(this.returnAddress, moduleBase);
      seenAuthSelector += 1;
      this.detail = seenAuthSelector <= AUTH_SELECTOR_LOG_LIMIT;
      log('ENTER auth selector 0x4265dc hit #' + seenAuthSelector + ' caller ' + this.callerOffset);
      if (!this.detail) {
        return;
      }
      describePtr('4265dc arg0 caller ' + this.callerOffset, args[0]);
      describePtr('4265dc arg1 caller ' + this.callerOffset, args[1]);
      describePtr('4265dc arg2 caller ' + this.callerOffset, args[2]);
      describePtr('4265dc arg3 caller ' + this.callerOffset, args[3]);
    },
    onLeave(retval) {
      if (!this.detail) {
        return;
      }
      describePtr('4265dc retval caller ' + this.callerOffset, retval);
    },
  });

  safeAttach('bind populate 0x330674', bindPopulatePtr, {
    onEnter(args) {
      seenPopulate += 1;
      this.callerLabel = formatCodeLocation(this.returnAddress, moduleBase);
      this.detail = seenPopulate <= MAX_DETAILED_HITS;
      this.arg2 = ptr(args[2]);
      this.arg2StateBefore = captureTaggedObjectState(this.arg2, [0x10, 0x20, 0x24], [
        { offset: 0x10, fields: [0x20, 0x24] },
        { offset: 0x20, fields: [0x8, 0xc, 0x10, 0x6c] },
      ]);
      log('ENTER bind populate 0x330674 hit #' + seenPopulate + ' caller ' + this.callerLabel);
      if (!this.detail) {
        return;
      }
      describePtr('330674 arg0 caller ' + this.callerLabel, args[0]);
      describePtr('330674 arg1 caller ' + this.callerLabel, args[1]);
      describePtr('330674 arg2 caller ' + this.callerLabel, args[2]);
      describeObjectFields('330674 arg1 tagged caller ' + this.callerLabel, args[1], [0x9b, 0x9f, 0xa3, 0x127]);
      describeChildFields('330674 arg1 tagged caller ' + this.callerLabel, args[1], 0x9f, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x23, 0x27]);
      describeChildFields('330674 arg1 tagged caller ' + this.callerLabel, args[1], 0x127, [0x7, 0xb, 0xf, 0x13, 0x17, 0x1b, 0x23, 0x27]);
      describeRawField('330674 arg1 raw caller ' + this.callerLabel + ' +9b', args[1], 0x9b);
      describeRawField('330674 arg1 raw caller ' + this.callerLabel + ' +9f', args[1], 0x9f);
      describeRawField('330674 arg1 raw caller ' + this.callerLabel + ' +a3', args[1], 0xa3);
      describeRawField('330674 arg1 raw caller ' + this.callerLabel + ' +127', args[1], 0x127);
      describeCompressedField('330674 arg1 field caller ' + this.callerLabel + ' +9b', args[1], 0x9b);
      describeCompressedField('330674 arg1 field caller ' + this.callerLabel + ' +9f', args[1], 0x9f);
      describeCompressedField('330674 arg1 field caller ' + this.callerLabel + ' +a3', args[1], 0xa3);
      describeCompressedField('330674 arg1 field caller ' + this.callerLabel + ' +127', args[1], 0x127);
      describeCompressedChain('330674 arg1 compressed caller ' + this.callerLabel, args[1], [0x9b]);
      describeCompressedChain('330674 arg1 compressed caller ' + this.callerLabel, args[1], [0x9f]);
      describeCompressedChain('330674 arg1 compressed caller ' + this.callerLabel, args[1], [0xa3]);
      describeCompressedChain('330674 arg1 compressed caller ' + this.callerLabel, args[1], [0x127]);
      describeCompressedChain('330674 arg2 compressed caller ' + this.callerLabel, args[2], [0x10, 0x20]);
      describeCompressedChain('330674 arg2 compressed caller ' + this.callerLabel, args[2], [0x10, 0x24]);
    },
    onLeave() {
      if (!this.detail || this.arg2 === undefined) {
        return;
      }
      const afterState = captureTaggedObjectState(this.arg2, [0x10, 0x20, 0x24], [
        { offset: 0x10, fields: [0x20, 0x24] },
        { offset: 0x20, fields: [0x8, 0xc, 0x10, 0x6c] },
      ]);
      logStateDiff('330674 arg2 diff caller ' + this.callerLabel, this.arg2StateBefore, afterState);
    },
  });

  safeAttach('parent wrapper 0x31b4f4', parentWrapperPtr, {
    onEnter(args) {
      seenParentWrapper += 1;
      this.callerLabel = formatCodeLocation(this.returnAddress, moduleBase);
      this.detail = seenParentWrapper <= MAX_DETAILED_HITS;
      log('ENTER parent wrapper 0x31b4f4 hit #' + seenParentWrapper + ' caller ' + this.callerLabel);
      if (!this.detail) {
        return;
      }
      describePtr('31b4f4 arg1 caller ' + this.callerLabel, args[1]);
      describeObjectFields('31b4f4 arg1 tagged caller ' + this.callerLabel, args[1], [0x9b, 0x9f, 0xa3, 0x127]);
      describeRawField('31b4f4 arg1 raw caller ' + this.callerLabel + ' +9b', args[1], 0x9b);
      describeCompressedField('31b4f4 arg1 field caller ' + this.callerLabel + ' +9b', args[1], 0x9b);
      describePtr('31b4f4 derived +9b caller ' + this.callerLabel, readTaggedField(normalizeTagged(args[1]), 0x9b));
    },
  });

  safeAttach('parent populate 0x31b530', parentPopulatePtr, {
    onEnter(args) {
      seenParentPopulate += 1;
      this.callerLabel = formatCodeLocation(this.returnAddress, moduleBase);
      this.detail = seenParentPopulate <= MAX_DETAILED_HITS;
      log('ENTER parent populate 0x31b530 hit #' + seenParentPopulate + ' caller ' + this.callerLabel);
      if (!this.detail) {
        return;
      }
      describePtr('31b530 arg1 caller ' + this.callerLabel, args[1]);
      describePtr('31b530 arg2 caller ' + this.callerLabel, args[2]);
      describePtr('31b530 arg3 caller ' + this.callerLabel, args[3]);
      describeCompressedChain('31b530 arg1 compressed caller ' + this.callerLabel, args[1], [0xb]);
      describeCompressedChain('31b530 arg2 compressed caller ' + this.callerLabel, args[2], [0xb]);
      describeCompressedChain('31b530 arg2 compressed caller ' + this.callerLabel, args[2], [0xf]);
    },
  });

  log('ready; launch Pair flow');
}

function waitForModule() {
  const module = Process.findModuleByName(TARGET_MODULE);
  if (module !== null) {
    log('found ' + TARGET_MODULE + ' @ ' + module.base);
    attachHooks(module.base);
    return;
  }

  setTimeout(waitForModule, RETRY_MS);
}

setImmediate(waitForModule);
