'use strict';

/*
 * Frida helper for tracing the most likely Flutter AOT auth-token path in
 * libapp.so. This is intentionally conservative: it hooks a small set of
 * candidate functions and logs call order, backtraces, register values, and
 * readable memory around likely Dart object pointers.
 *
 * Suggested usage:
 *   frida -U -f com.entos.monarch.remote.uk -l tools/frida_authtoken_trace.js
 *
 * Current hook points cover both the narrow digest candidates and the nearby
 * parser / dispatcher / serializer functions. If reconnects only hit the feh
 * path, that usually means the app is reusing cached state instead of deriving
 * a fresh token on that code path.
 */

const TARGET_MODULE = 'libapp.so';
const POINTER_DUMP_BYTES = 0x60;
const BACKTRACE_FRAMES = 8;
const RETRY_MS = 200;
const ASCII_MIN_LEN = 4;
const ASCII_MAX_CANDIDATES = 4;
const PARSER_RETVAL_TTL_MS = 5000;

const recentParserRetvalsByThread = new Map();
const activeBindTraceByThread = new Map();
const activeDispatchScopeByThread = new Map();

const WRAPPER_CHILD_TARGETS = [
  { offset: 0x8, size: 0x80 },
  {
    offset: 0x20,
    size: 0x80,
    summarizeCompressed: 16,
    followOffsets: [
      { offset: 0x8, size: 0x80, summarizeCompressed: 16 },
    ],
  },
  { offset: 0x24, size: 0x80 },
];

const BIND_PARENT_TARGETS = [
  { offset: 0x8, size: 0x80 },
  { offset: 0xc, size: 0x80 },
  { offset: 0x10, size: 0x80, summarizeCompressed: 16 },
];

const NESTED_REF_TARGETS = [
  { offset: 0x7, size: 0x80, summarizeCompressed: 16 },
];

const BIND_SLOT_14_18_TARGETS = [
  { offset: 0x14, size: 0x80, summarizeCompressed: 16 },
  { offset: 0x18, size: 0x80, summarizeCompressed: 16 },
];

const BIND_CHILD_LINK_TARGETS = [
  { offset: 0x10, size: 0x80, summarizeCompressed: 16 },
];

const BIND_HELPER_LINK_TARGETS = [
  { offset: 0x14, size: 0x80, summarizeCompressed: 16 },
  { offset: 0x18, size: 0x80, summarizeCompressed: 16 },
];

const DISPATCH_RESOLUTION_TARGETS = [
  {
    offset: 0x8,
    size: 0x80,
    summarizeCompressed: 16,
    followOffsets: [
      {
        offset: 0x18,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x40, summarizeCompressed: 8 },
        ],
      },
    ],
  },
];

const HOOKS = [
  {
    name: 'feh_::_anon_closure_331cc4',
    offset: 0x331cc4,
    dumpArgs: 2,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
  },
  {
    name: 'sub_32e990',
    offset: 0x32e990,
    dumpArgs: 1,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x120,
    logCaller: true,
    summarizeRetval: 24,
    summarizeCompressedRetval: 16,
    dumpCompressedRetvalTargets: [
      {
        offset: 0x10,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x20, size: 0x80, summarizeCompressed: 24 },
          { offset: 0x24, size: 0x80, summarizeCompressed: 24 },
        ],
      },
      { offset: 0x1c, size: 0x80 },
    ],
  },
  {
    name: 'feh_::_anon_closure_32fde4',
    offset: 0x32fde4,
    requiresActiveBindTrace: true,
    dumpArgs: 2,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
  },
  {
    name: 'feh_RAa::_anon_closure_32fd24',
    offset: 0x32fd24,
    requiresActiveBindTrace: true,
    dumpArgs: 2,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
    summarizeCompressedArgs: [0, 32],
    dumpCompressedTargets: [[], [
      {
        offset: 0x10,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x20, size: 0x80, summarizeCompressed: 24 },
          { offset: 0x24, size: 0x80, summarizeCompressed: 24 },
        ],
      },
      { offset: 0x1c, size: 0x80 },
    ]],
  },
  {
    name: 'bind_builder_helper_32c768',
    offset: 0x32c768,
    requiresActiveBindTrace: true,
    allowedCallerOffsets: [0x3306d8, 0x330750],
    dumpArgs: 3,
    dumpPostArgs: [0],
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
    postSummarizeArgs: 16,
    summarizeCompressedArgs: [24, 24, 24],
    postSummarizeCompressedArgs: [24],
    dumpCompressedTargets: [[
      { offset: 0x8, size: 0x80 },
      {
        offset: 0x20,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x80, summarizeCompressed: 16 },
        ],
      },
    ], [], []],
    postDumpCompressedTargets: [[
      { offset: 0x8, size: 0x80 },
      {
        offset: 0x20,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x80, summarizeCompressed: 16 },
        ],
      },
      { offset: 0x24, size: 0x80 },
    ]],
    summarizeCompressedRetval: 16,
    dumpCompressedRetvalTargets: [
      { offset: 0x8, size: 0x80 },
      {
        offset: 0x20,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x80, summarizeCompressed: 16 },
        ],
      },
    ],
    onEnter(scope, args) {
      this.bindHelperArg0Key = pointerKey(args[0]);
      this.bindHelperCallerOffset = scope.returnOffset;
    },
    onLeave(scope) {
      const state = getActiveBindTrace(scope.threadId);
      if (state === null) {
        return;
      }
      if (this.bindHelperCallerOffset === 0x3306d8 && this.bindHelperArg0Key === state.wrapperKey) {
        state.inlineArmed = true;
        return;
      }
      if (this.bindHelperCallerOffset === 0x330750) {
        state.inlineArmed = false;
      }
    },
  },
  {
    name: 'bind_builder_helper_32c7a4',
    offset: 0x32c7a4,
    requiresActiveBindTrace: true,
    allowedCallerOffsets: [0x32c78c],
    dumpArgs: 3,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
    summarizeCompressedArgs: [16, 24, 16],
    dumpCompressedTargets: [[], NESTED_REF_TARGETS, []],
  },
  {
    name: 'bind_dynamic_dispatch_3f3844',
    offset: 0x3f3844,
    requiresActiveBindTrace: true,
    allowedCallerOffsets: [0x32c7c8],
    dumpArgs: 3,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 24,
    summarizeCompressedArgs: [24, 24, 24],
    dumpCompressedTargets: [[], DISPATCH_RESOLUTION_TARGETS, []],
    onEnter(scope, args) {
      enterDispatchScope(scope.threadId);
      const dispatchRoot = resolveCompressedRef(args[1], 0x8);
      const dispatchOwner = dispatchRoot === null ? null : resolveCompressedRef(dispatchRoot, 0x18);
      if (dispatchOwner === null) {
        return;
      }

      const dispatchOwnerInfo = getPointerInfo(dispatchOwner);
      if (dispatchOwnerInfo === null) {
        return;
      }

      let dispatchTarget = null;
      let dispatchFallback = null;
      try {
        dispatchTarget = dispatchOwnerInfo.normalized.add(0x8).readPointer();
      } catch (_err) {
      }
      try {
        dispatchFallback = dispatchOwnerInfo.normalized.add(0x38).readPointer();
      } catch (_err) {
      }

      if (dispatchTarget !== null) {
        const targetInfo = getPointerInfo(dispatchTarget);
        if (targetInfo !== null && targetInfo.range !== null && targetInfo.range.protection.indexOf('x') !== -1) {
          try {
            logLine(`bind_dynamic_dispatch_3f3844 raw target +0x8: ${describePointer(dispatchTarget)} ${DebugSymbol.fromAddress(targetInfo.normalized)}`);
          } catch (_err) {
            logLine(`bind_dynamic_dispatch_3f3844 raw target +0x8: ${describePointer(dispatchTarget)}`);
          }
        } else {
          logLine(`bind_dynamic_dispatch_3f3844 raw target +0x8: ${describePointer(dispatchTarget)}`);
        }
      }

      if (dispatchFallback !== null) {
        const fallbackInfo = getPointerInfo(dispatchFallback);
        if (fallbackInfo !== null && fallbackInfo.range !== null && fallbackInfo.range.protection.indexOf('x') !== -1) {
          try {
            logLine(`bind_dynamic_dispatch_3f3844 raw target +0x38: ${describePointer(dispatchFallback)} ${DebugSymbol.fromAddress(fallbackInfo.normalized)}`);
          } catch (_err) {
            logLine(`bind_dynamic_dispatch_3f3844 raw target +0x38: ${describePointer(dispatchFallback)}`);
          }
        } else {
          logLine(`bind_dynamic_dispatch_3f3844 raw target +0x38: ${describePointer(dispatchFallback)}`);
        }
      }
    },
    onLeave(scope) {
      leaveDispatchScope(scope.threadId);
    },
  },
  {
    name: 'bind_dispatch_target_55a064',
    offset: 0x55a064,
    requiresActiveBindTrace: true,
    allowedCallerOffsets: [0x3f38a4],
    dumpArgs: 3,
    dumpPostArgs: [0, 2],
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 24,
    postSummarizeArgs: 24,
    summarizeCompressedArgs: [24, 24, 24],
    postSummarizeCompressedArgs: [24, 0, 24],
  },
  {
    name: 'bind_owner_alloc_5649ec',
    offset: 0x5649ec,
    requiresActiveBindTrace: true,
    requiresActiveDispatchScope: true,
    allowedCallerOffsets: [0x3f3914],
    dumpArgs: 3,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 24,
    summarizeCompressedArgs: [24, 24, 24],
    summarizeCompressedRetval: 24,
  },
  {
    name: 'bind_owner_link_3de8b0',
    offset: 0x3de8b0,
    requiresActiveBindTrace: true,
    requiresActiveDispatchScope: true,
    allowedCallerOffsets: [0x3f392c],
    dumpArgs: 3,
    dumpPostArgs: [1],
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 24,
    postSummarizeArgs: 24,
    summarizeCompressedArgs: [0, 24, 24],
    postSummarizeCompressedArgs: [0, 24],
  },
  {
    name: 'bind_owner_merge_4deb7c',
    offset: 0x3deb7c,
    requiresActiveBindTrace: true,
    requiresActiveDispatchScope: true,
    allowedCallerOffsets: [0x3de93c],
    dumpArgs: 3,
    dumpPostArgs: [1],
    backtrace: false,
    dumpRetval: false,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 24,
    postSummarizeArgs: 24,
    summarizeCompressedArgs: [0, 24, 24],
    postSummarizeCompressedArgs: [0, 24],
    dumpCompressedTargets: [[], BIND_HELPER_LINK_TARGETS, BIND_CHILD_LINK_TARGETS],
    postDumpCompressedTargets: [[], BIND_HELPER_LINK_TARGETS],
    onEnter(scope, args) {
      const existingChild = resolveCompressedRef(args[1], 0x18);
      if (existingChild === null) {
        logLine('bind_owner_merge_4deb7c existing child: NULL');
        return;
      }

      logLine(`bind_owner_merge_4deb7c existing child: ${describePointer(existingChild)}`);
      dumpPointer('bind_owner_merge_4deb7c existing child', existingChild, 0x80);
      summarizeCompressedHeapRefs('bind_owner_merge_4deb7c existing child', existingChild, 16);

      const existingClassId = readObjectClassId(existingChild);
      if (existingClassId === null) {
        return;
      }

      logLine(`bind_owner_merge_4deb7c existing child classId: 0x${existingClassId.toString(16)}`);

      const dispatchTableBase = getPointerInfo(scope.context.x21);
      if (dispatchTableBase === null || dispatchTableBase.ptrValue.isNull() || dispatchTableBase.range === null) {
        return;
      }

      const slotIndex = existingClassId - 0x8e9;
      if (slotIndex < 0) {
        return;
      }

      try {
        const resolvedTarget = dispatchTableBase.ptrValue.add(slotIndex * Process.pointerSize).readPointer();
        const targetInfo = getPointerInfo(resolvedTarget);
        if (targetInfo !== null && targetInfo.range !== null && targetInfo.range.protection.indexOf('x') !== -1) {
          try {
            logLine(`bind_owner_merge_4deb7c resolved target: ${describePointer(resolvedTarget)} ${DebugSymbol.fromAddress(targetInfo.normalized)}`);
          } catch (_err) {
            logLine(`bind_owner_merge_4deb7c resolved target: ${describePointer(resolvedTarget)}`);
          }
        } else {
          logLine(`bind_owner_merge_4deb7c resolved target: ${describePointer(resolvedTarget)}`);
        }
      } catch (_err) {
      }
    },
  },
  {
    name: 'bind_owner_merge_class_6721_4d8f58',
    offset: 0x3d8f58,
    requiresActiveBindTrace: true,
    requiresActiveDispatchScope: true,
    dumpArgs: 0,
    dumpPostArgs: [1],
    backtrace: false,
    dumpRetval: false,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    postSummarizeArgs: 24,
    postSummarizeCompressedArgs: [0, 24],
    postDumpCompressedTargets: [[], BIND_CHILD_LINK_TARGETS],
    onEnter(_scope, args) {
      let classId = 0;
      try {
        classId = args[0].toUInt32();
      } catch (_err) {
      }

      logLine(`bind_owner_merge_class_6721_4d8f58 classId arg0: 0x${classId.toString(16)}`);

      dumpPointer('bind_owner_merge_class_6721_4d8f58 existing child', args[1], 0x80);
      summarizePointerFields('bind_owner_merge_class_6721_4d8f58 existing child', args[1], 24);
      summarizeCompressedHeapRefs('bind_owner_merge_class_6721_4d8f58 existing child', args[1], 24);
      dumpCompressedRefTargets(
        'bind_owner_merge_class_6721_4d8f58 existing child',
        args[1],
        BIND_CHILD_LINK_TARGETS,
      );

      dumpPointer('bind_owner_merge_class_6721_4d8f58 new child', args[2], 0x80);
      summarizePointerFields('bind_owner_merge_class_6721_4d8f58 new child', args[2], 24);
      summarizeCompressedHeapRefs('bind_owner_merge_class_6721_4d8f58 new child', args[2], 24);
      dumpCompressedRefTargets(
        'bind_owner_merge_class_6721_4d8f58 new child',
        args[2],
        BIND_CHILD_LINK_TARGETS,
      );
    },
  },
  {
    name: 'bind_builder_helper_55c414',
    offset: 0x55c414,
    requiresActiveBindTrace: true,
    allowedCallerOffsets: [0x330738],
    dumpArgs: 3,
    dumpPostArgs: [0],
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
    postSummarizeArgs: 16,
    summarizeCompressedArgs: [32, 32, 32],
    postSummarizeCompressedArgs: [32],
    summarizeCompressedRetval: 16,
    postDumpCompressedTargets: [[
      { offset: 0x8, size: 0x80 },
      {
        offset: 0x10,
        size: 0x80,
        summarizeCompressed: 16,
      },
      {
        offset: 0xc,
        size: 0x80,
      },
    ]],
    dumpCompressedRetvalTargets: [
      { offset: 0x8, size: 0x80 },
      { offset: 0x20, size: 0x80, summarizeCompressed: 16 },
    ],
    onEnter(scope) {
      const state = getActiveBindTrace(scope.threadId);
      if (state !== null) {
        state.inlineArmed = false;
      }
    },
    onLeave(_scope, retval) {
      const retvalInfo = getPointerInfo(retval);
      if (retvalInfo === null || retvalInfo.range === null) {
        return;
      }

      try {
        const adjacentCandidate = retvalInfo.normalized.add(0x10).add(1);
        dumpPointer('bind_builder_helper_55c414 retval adjacent +0x10', adjacentCandidate, 0x80);
        summarizeCompressedHeapRefs('bind_builder_helper_55c414 retval adjacent +0x10', adjacentCandidate, 16);
      } catch (_err) {
      }
    },
  },
  {
    name: 'bind_parent_builder_33060c',
    offset: 0x33060c,
    dumpArgs: 3,
    dumpPostArgs: [1],
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    postDumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
    postSummarizeArgs: 16,
    summarizeCompressedArgs: [0, 32, 32],
    postSummarizeCompressedArgs: [0, 32],
    dumpCompressedTargets: [[], [
      { offset: 0x8, size: 0x80 },
      {
        offset: 0x20,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x80, summarizeCompressed: 16 },
        ],
      },
      { offset: 0x24, size: 0x80 },
    ], [
      {
        offset: 0x10,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x20, size: 0x80, summarizeCompressed: 24 },
          { offset: 0x24, size: 0x80, summarizeCompressed: 24 },
        ],
      },
      { offset: 0x1c, size: 0x80 },
    ]],
    postDumpCompressedTargets: [[], [
      {
        offset: 0x20,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x80, summarizeCompressed: 16 },
        ],
      },
      { offset: 0x24, size: 0x80 },
    ]],
    shouldLog(scope, args) {
      return startBindTraceFromBuilder(scope.threadId, args[1], args[2]);
    },
  },
  {
    name: 'bind_inline_checkpoint_3306f4',
    offset: 0x3306f4,
    requiresInlineArm: true,
    dumpContextRegs: [
      { reg: 'x0', size: 0x60, summarizeCompressed: 16, dumpCompressedTargets: BIND_PARENT_TARGETS },
      { reg: 'x1', size: 0x60, summarizeCompressed: 16, dumpCompressedTargets: WRAPPER_CHILD_TARGETS },
    ],
  },
  {
    name: 'bind_inline_checkpoint_3306fc',
    offset: 0x3306fc,
    requiresInlineArm: true,
    dumpContextRegs: [
      { reg: 'x0', size: 0x60, summarizeCompressed: 16, dumpCompressedTargets: BIND_PARENT_TARGETS },
      { reg: 'x1', size: 0x60, summarizeCompressed: 16, dumpCompressedTargets: WRAPPER_CHILD_TARGETS },
    ],
  },
  {
    name: 'bind_serializer_parent_330770',
    offset: 0x330770,
    requiresActiveBindTrace: true,
    dumpArgs: 2,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x80,
    logCaller: true,
    summarizeArgs: 16,
    summarizeCompressedArgs: [0, 32],
    dumpCompressedTargets: [[], [
      { offset: 0x8, size: 0x80 },
      {
        offset: 0x6c,
        size: 0x80,
        summarizeCompressed: 16,
        followOffsets: [
          { offset: 0x8, size: 0x80 },
          { offset: 0x10, size: 0x80, summarizeCompressed: 16 },
        ],
      },
    ]],
  },
  {
    name: 'sub_32fe40',
    offset: 0x32fe40,
    requiresActiveBindTrace: true,
    dumpArgs: 1,
    backtrace: false,
    dumpRetval: true,
    dumpBytes: 0x200,
    logCaller: true,
    summarizeArgs: 24,
    onLeave(scope, retval) {
      const bytes = safeReadByteArray(retval, 0x200);
      if (bufferContainsAscii(bytes, '"command_name":"Bind Request"')) {
        clearActiveBindTrace(scope.threadId);
      }
    },
  },
];

function logLine(message) {
  console.log(`[authtoken-trace] ${message}`);
}

function getThreadId() {
  try {
    return Process.getCurrentThreadId();
  } catch (_err) {
    return -1;
  }
}

function getPointerInfo(rawPtr) {
  if (rawPtr === undefined || rawPtr === null) {
    return null;
  }

  let ptrValue;
  try {
    ptrValue = ptr(rawPtr);
  } catch (_err) {
    return null;
  }

  if (ptrValue.isNull()) {
    return {
      ptrValue,
      tagged: false,
      normalized: ptrValue,
      range: null,
    };
  }

  let tagged = false;
  let normalized = ptrValue;
  try {
    if (!ptrValue.and(1).isNull()) {
      tagged = true;
      normalized = ptrValue.and(ptr('0xfffffffffffffffe'));
    }
  } catch (_err) {
    normalized = ptrValue;
  }

  return {
    ptrValue,
    tagged,
    normalized,
    range: Process.findRangeByAddress(normalized),
  };
}

function describePointer(rawPtr) {
  const info = getPointerInfo(rawPtr);
  if (info === null) {
    return String(rawPtr);
  }

  if (info.ptrValue.isNull()) {
    return 'NULL';
  }

  const rangeText = info.range
    ? `${info.range.protection} ${info.range.base}..${info.range.base.add(info.range.size)}`
    : 'unmapped';

  return `${info.ptrValue}${info.tagged ? ` (untagged ${info.normalized})` : ''} [${rangeText}]`;
}

function pointerKey(rawPtr) {
  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull()) {
    return null;
  }
  return info.normalized.toString();
}

function safeReadByteArray(rawPtr, size) {
  const info = getPointerInfo(rawPtr);
  if (info === null) {
    return null;
  }

  if (info.ptrValue.isNull() || info.range === null || info.range.protection.indexOf('r') === -1) {
    return null;
  }

  const maxReadable = Number(info.range.base.add(info.range.size).sub(info.normalized));
  if (!Number.isFinite(maxReadable) || maxReadable <= 0) {
    return null;
  }

  const length = Math.min(size, maxReadable);
  if (length <= 0) {
    return null;
  }

  try {
    return info.normalized.readByteArray(length);
  } catch (_err) {
    return null;
  }
}

function extractAsciiCandidates(bytes) {
  if (!(bytes instanceof ArrayBuffer)) {
    return [];
  }

  const view = new Uint8Array(bytes);
  const results = [];
  const seen = new Set();
  let current = '';

  function flush() {
    if (current.length >= ASCII_MIN_LEN && !seen.has(current)) {
      seen.add(current);
      results.push(current);
    }
    current = '';
  }

  for (let i = 0; i < view.length; i += 1) {
    const value = view[i];
    if (value >= 0x20 && value <= 0x7e) {
      current += String.fromCharCode(value);
    } else {
      flush();
      if (results.length >= ASCII_MAX_CANDIDATES) {
        break;
      }
    }
  }
  flush();

  return results.slice(0, ASCII_MAX_CANDIDATES);
}

function bufferContainsAscii(bytes, needle) {
  if (!(bytes instanceof ArrayBuffer) || typeof needle !== 'string' || needle.length === 0) {
    return false;
  }

  return extractAsciiCandidates(bytes).some((candidate) => candidate.indexOf(needle) !== -1);
}

function resolveCompressedRef(rawPtr, offset) {
  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull() || info.range === null) {
    return null;
  }

  const maxBytes = Number(info.range.base.add(info.range.size).sub(info.normalized));
  if (!Number.isFinite(maxBytes) || offset < 0 || offset + 4 > maxBytes) {
    return null;
  }

  let rawField;
  try {
    rawField = info.normalized.add(offset).readU32();
  } catch (_err) {
    return null;
  }

  if (rawField === 0) {
    return null;
  }

  const heapHighBits = info.normalized.and(ptr('0xffffffff00000000'));
  const candidate = heapHighBits.add(rawField);
  const candidateInfo = getPointerInfo(candidate);
  if (candidateInfo === null || candidateInfo.range === null) {
    return null;
  }

  return candidate;
}

function readObjectU32(rawPtr, offset) {
  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull() || info.range === null) {
    return null;
  }

  const fieldAddress = info.normalized.add(offset);
  const fieldRange = Process.findRangeByAddress(fieldAddress);
  if (fieldRange === null || fieldRange.protection.indexOf('r') === -1) {
    return null;
  }

  try {
    return fieldAddress.readU32();
  } catch (_err) {
    return null;
  }
}

function readObjectClassId(rawPtr) {
  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull()) {
    return null;
  }

  const headerAddress = info.normalized.sub(1);
  const headerRange = Process.findRangeByAddress(headerAddress);
  if (headerRange === null || headerRange.protection.indexOf('r') === -1) {
    return null;
  }

  let headerLow;
  try {
    headerLow = headerAddress.readU32();
  } catch (_err) {
    return null;
  }

  return (headerLow >>> 12) & 0xfffff;
}

function parserLooksLikePairSuccess(parserPtr) {
  const level1 = resolveCompressedRef(parserPtr, 0x10);
  if (level1 === null) {
    return false;
  }

  const level2a = resolveCompressedRef(level1, 0x20);
  const level2b = resolveCompressedRef(level1, 0x24);
  const targets = [level2a, level2b].filter((value) => value !== null);

  return targets.some((target) => {
    const bytes = safeReadByteArray(target, 0x80);
    return bufferContainsAscii(bytes, 'pairingcode');
  });
}

function dumpPointer(label, rawPtr, size) {
  logLine(`${label}: ${describePointer(rawPtr)}`);
  const info = getPointerInfo(rawPtr);
  const bytes = safeReadByteArray(rawPtr, size);
  if (bytes === null) {
    return;
  }

  try {
    const dump = hexdump(bytes, {
      offset: 0,
      length: bytes.byteLength,
      header: false,
      ansi: false,
    });
    logLine(`${label} hexdump:\n${dump}`);
  } catch (err) {
    logLine(`${label} hexdump failed: ${err}`);
  }

  if (info !== null && info.range !== null && info.range.protection.indexOf('x') === -1) {
    const strings = extractAsciiCandidates(bytes);
    if (strings.length > 0) {
      logLine(`${label} ascii: ${strings.join(' | ')}`);
    }
  }
}

function summarizePointerFields(label, rawPtr, slotCount) {
  if (!slotCount || slotCount <= 0) {
    return;
  }

  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull() || info.range === null || info.range.protection.indexOf('r') === -1) {
    return;
  }

  const maxSlots = Math.floor(Number(info.range.base.add(info.range.size).sub(info.normalized)) / Process.pointerSize);
  const limit = Math.min(slotCount, maxSlots);
  const entries = [];

  for (let slot = 0; slot < limit; slot += 1) {
    const fieldAddress = info.normalized.add(slot * Process.pointerSize);
    let rawField;
    try {
      rawField = fieldAddress.readPointer();
    } catch (_err) {
      continue;
    }

    const fieldInfo = getPointerInfo(rawField);
    if (fieldInfo === null || fieldInfo.ptrValue.isNull() || fieldInfo.range === null) {
      continue;
    }

    let symbolText = '';
    if (fieldInfo.range.protection.indexOf('x') !== -1) {
      try {
        symbolText = ` ${DebugSymbol.fromAddress(fieldInfo.normalized)}`;
      } catch (_err) {
        symbolText = '';
      }
    }

    entries.push(`+0x${(slot * Process.pointerSize).toString(16)} = ${describePointer(rawField)}${symbolText}`);
  }

  if (entries.length > 0) {
    logLine(`${label} fields:\n  ${entries.join('\n  ')}`);
  }
}

function summarizeCompressedHeapRefs(label, rawPtr, wordCount) {
  if (!wordCount || wordCount <= 0) {
    return;
  }

  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull() || info.range === null || info.range.protection.indexOf('r') === -1) {
    return;
  }

  const maxWords = Math.floor(Number(info.range.base.add(info.range.size).sub(info.normalized)) / 4);
  const limit = Math.min(wordCount, maxWords);
  const heapHighBits = info.normalized.and(ptr('0xffffffff00000000'));
  const entries = [];

  for (let word = 0; word < limit; word += 1) {
    const fieldAddress = info.normalized.add(word * 4);
    let rawField;
    try {
      rawField = fieldAddress.readU32();
    } catch (_err) {
      continue;
    }

    if (rawField === 0 || (rawField & 1) === 0) {
      continue;
    }

    const candidate = heapHighBits.add(rawField);
    const candidateInfo = getPointerInfo(candidate);
    if (candidateInfo === null || candidateInfo.range === null) {
      continue;
    }

    entries.push(`+0x${(word * 4).toString(16)} = 0x${rawField.toString(16)} -> ${describePointer(candidate)}`);
  }

  if (entries.length > 0) {
    logLine(`${label} compressed refs:\n  ${entries.join('\n  ')}`);
  }
}

function dumpCompressedRefTargets(label, rawPtr, targets) {
  if (!Array.isArray(targets) || targets.length === 0) {
    return;
  }

  const info = getPointerInfo(rawPtr);
  if (info === null || info.ptrValue.isNull() || info.range === null || info.range.protection.indexOf('r') === -1) {
    return;
  }

  const maxWords = Math.floor(Number(info.range.base.add(info.range.size).sub(info.normalized)) / 4);
  const heapHighBits = info.normalized.and(ptr('0xffffffff00000000'));

  targets.forEach((target) => {
    const offset = typeof target === 'number' ? target : target.offset;
    if (!Number.isInteger(offset) || offset < 0) {
      return;
    }

    const wordIndex = Math.floor(offset / 4);
    if (wordIndex >= maxWords) {
      return;
    }

    let rawField;
    try {
      rawField = info.normalized.add(offset).readU32();
    } catch (_err) {
      return;
    }

    if (rawField === 0 || (rawField & 1) === 0) {
      return;
    }

    const candidate = heapHighBits.add(rawField);
    const candidateInfo = getPointerInfo(candidate);
    if (candidateInfo === null || candidateInfo.range === null) {
      return;
    }

    const size = typeof target === 'object' && target !== null && Number.isInteger(target.size)
      ? target.size
      : POINTER_DUMP_BYTES;
    const targetLabel = `${label} compressed target +0x${offset.toString(16)}`;
    dumpPointer(targetLabel, candidate, size);

    if (typeof target === 'object' && target !== null) {
      if (Number.isInteger(target.summarizeCompressed) && target.summarizeCompressed > 0) {
        summarizeCompressedHeapRefs(targetLabel, candidate, target.summarizeCompressed);
      }

      if (Array.isArray(target.followOffsets) && target.followOffsets.length > 0) {
        dumpCompressedRefTargets(targetLabel, candidate, target.followOffsets);
      }
    }
  });
}

function dumpContextRegisters(hookName, context, registerSpecs, defaultDumpBytes) {
  if (!Array.isArray(registerSpecs) || registerSpecs.length === 0 || !context) {
    return;
  }

  registerSpecs.forEach((spec) => {
    const regName = typeof spec === 'string' ? spec : spec.reg;
    if (typeof regName !== 'string' || !(regName in context)) {
      return;
    }

    let rawValue;
    try {
      rawValue = context[regName];
    } catch (_err) {
      return;
    }

    const label = `${hookName} ${regName}`;
    const size = typeof spec === 'object' && spec !== null && Number.isInteger(spec.size)
      ? spec.size
      : defaultDumpBytes;
    dumpPointer(label, rawValue, size);

    if (typeof spec === 'object' && spec !== null) {
      summarizePointerFields(label, rawValue, spec.summarizeFields || 0);
      summarizeCompressedHeapRefs(label, rawValue, spec.summarizeCompressed || 0);
      dumpCompressedRefTargets(label, rawValue, spec.dumpCompressedTargets || []);
    }
  });
}

function logBacktrace(context) {
  try {
    const frames = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, BACKTRACE_FRAMES)
      .map(DebugSymbol.fromAddress)
      .map((symbol) => `  ${symbol}`)
      .join('\n');
    logLine(`backtrace:\n${frames}`);
  } catch (err) {
    logLine(`backtrace unavailable: ${err}`);
  }
}

function getReturnOffset(returnAddress, moduleBase) {
  if (!returnAddress) {
    return null;
  }

  try {
    return parseInt(returnAddress.sub(moduleBase).toString(), 16);
  } catch (_err) {
    return null;
  }
}

function logCaller(hookName, returnAddress) {
  try {
    const symbol = DebugSymbol.fromAddress(returnAddress);
    logLine(`${hookName} caller: ${returnAddress} ${symbol}`);
  } catch (err) {
    logLine(`${hookName} caller unavailable: ${err}`);
  }
}

function callerOffsetAllowed(returnAddress, moduleBase, allowedOffsets) {
  if (!Array.isArray(allowedOffsets) || allowedOffsets.length === 0 || !returnAddress) {
    return true;
  }

  try {
    return allowedOffsets.some((offset) => returnAddress.equals(moduleBase.add(offset)));
  } catch (_err) {
    return false;
  }
}

function rememberParserRetval(threadId, retval) {
  const key = pointerKey(retval);
  if (threadId < 0 || key === null) {
    return;
  }
  recentParserRetvalsByThread.set(threadId, {
    key,
    at: Date.now(),
  });
}

function getRecentParserRetval(threadId) {
  if (threadId < 0 || !recentParserRetvalsByThread.has(threadId)) {
    return null;
  }

  const entry = recentParserRetvalsByThread.get(threadId);
  if (!entry || (Date.now() - entry.at) > PARSER_RETVAL_TTL_MS) {
    recentParserRetvalsByThread.delete(threadId);
    return null;
  }
  return entry;
}

function startBindTraceFromBuilder(threadId, wrapperPtr, parserPtr) {
  const parserKey = pointerKey(parserPtr);
  const wrapperKey = pointerKey(wrapperPtr);
  if (threadId < 0 || parserKey === null || wrapperKey === null) {
    return false;
  }

  const recentParser = getRecentParserRetval(threadId);
  if (recentParser === null || recentParser.key !== parserKey) {
    return false;
  }

  if (!parserLooksLikePairSuccess(parserPtr)) {
    return false;
  }

  activeBindTraceByThread.set(threadId, {
    parserKey,
    wrapperKey,
    inlineArmed: false,
    startedAt: Date.now(),
  });
  return true;
}

function getActiveBindTrace(threadId) {
  if (threadId < 0 || !activeBindTraceByThread.has(threadId)) {
    return null;
  }
  return activeBindTraceByThread.get(threadId) || null;
}

function enterDispatchScope(threadId) {
  if (threadId < 0) {
    return;
  }
  const depth = activeDispatchScopeByThread.get(threadId) || 0;
  activeDispatchScopeByThread.set(threadId, depth + 1);
}

function leaveDispatchScope(threadId) {
  if (threadId < 0 || !activeDispatchScopeByThread.has(threadId)) {
    return;
  }
  const depth = activeDispatchScopeByThread.get(threadId) || 0;
  if (depth <= 1) {
    activeDispatchScopeByThread.delete(threadId);
    return;
  }
  activeDispatchScopeByThread.set(threadId, depth - 1);
}

function hasActiveDispatchScope(threadId) {
  if (threadId < 0) {
    return false;
  }
  return (activeDispatchScopeByThread.get(threadId) || 0) > 0;
}

function clearActiveBindTrace(threadId) {
  if (threadId < 0) {
    return;
  }
  activeBindTraceByThread.delete(threadId);
  activeDispatchScopeByThread.delete(threadId);
}

function shouldLogHook(hook, threadId, args, context) {
  if (typeof hook.shouldLog === 'function') {
    const decision = hook.shouldLog({
      threadId,
      context,
    }, args);
    if (!decision) {
      return false;
    }
  }

  if (hook.requiresActiveBindTrace) {
    const state = getActiveBindTrace(threadId);
    if (state === null) {
      return false;
    }
  }

  if (hook.requiresInlineArm) {
    const state = getActiveBindTrace(threadId);
    if (state === null || !state.inlineArmed) {
      return false;
    }
    if (context && pointerKey(context.x1) !== state.wrapperKey) {
      return false;
    }
  }

  if (hook.requiresActiveDispatchScope && !hasActiveDispatchScope(threadId)) {
    return false;
  }

  return true;
}

function attachHooks(moduleBase) {
  HOOKS.forEach((hook) => {
    const address = moduleBase.add(hook.offset);
    logLine(`hooking ${hook.name} @ ${address} (+0x${hook.offset.toString(16)})`);
    try {
      Interceptor.attach(address, {
        onEnter(args) {
          this.skipHook = false;
          this.hookName = hook.name;
          this.__copilotThreadId = getThreadId();
          this.__copilotReturnOffset = getReturnOffset(this.returnAddress, moduleBase);

          if (!callerOffsetAllowed(this.returnAddress, moduleBase, hook.allowedCallerOffsets)) {
            this.skipHook = true;
            return;
          }

          if (!shouldLogHook(hook, this.__copilotThreadId, args, this.context)) {
            this.skipHook = true;
            return;
          }

          logLine(`ENTER ${hook.name}`);

          if (hook.logCaller && this.returnAddress) {
            logCaller(hook.name, this.returnAddress);
          }

          const argCount = hook.dumpArgs || 0;
          const dumpBytes = hook.dumpBytes || POINTER_DUMP_BYTES;
          for (let i = 0; i < argCount; i += 1) {
            dumpPointer(`${hook.name} arg${i}`, args[i], dumpBytes);
            summarizePointerFields(`${hook.name} arg${i}`, args[i], hook.summarizeArgs || 0);
            const compressedArgLimit = Array.isArray(hook.summarizeCompressedArgs)
              ? (hook.summarizeCompressedArgs[i] || 0)
              : (hook.summarizeCompressedArgs || 0);
            summarizeCompressedHeapRefs(`${hook.name} arg${i}`, args[i], compressedArgLimit);
            const compressedArgTargets = Array.isArray(hook.dumpCompressedTargets)
              ? (hook.dumpCompressedTargets[i] || [])
              : [];
            dumpCompressedRefTargets(`${hook.name} arg${i}`, args[i], compressedArgTargets);
          }

          dumpContextRegisters(
            hook.name,
            this.context,
            hook.dumpContextRegs || [],
            hook.contextDumpBytes || dumpBytes,
          );

          if (Array.isArray(hook.dumpPostArgs) && hook.dumpPostArgs.length > 0) {
            this.postArgs = {};
            hook.dumpPostArgs.forEach((argIndex) => {
              try {
                this.postArgs[argIndex] = ptr(args[argIndex]);
              } catch (_err) {
                // Ignore non-pointer or unavailable argument captures.
              }
            });
          }

          if (hook.backtrace) {
            logBacktrace(this.context);
          }

          if (typeof hook.onEnter === 'function') {
            hook.onEnter.call(this, {
              threadId: this.__copilotThreadId,
              returnOffset: this.__copilotReturnOffset,
              returnAddress: this.returnAddress,
              context: this.context,
            }, args);
          }
        },
        onLeave(retval) {
          if (this.skipHook) {
            return;
          }

          if (hook.dumpRetval) {
            dumpPointer(`${hook.name} retval`, retval, hook.dumpBytes || POINTER_DUMP_BYTES);
            summarizePointerFields(`${hook.name} retval`, retval, hook.summarizeRetval || 0);
            summarizeCompressedHeapRefs(
              `${hook.name} retval`,
              retval,
              hook.summarizeCompressedRetval || 0,
            );
            dumpCompressedRefTargets(
              `${hook.name} retval`,
              retval,
              hook.dumpCompressedRetvalTargets || [],
            );
          }

          if (this.postArgs !== undefined) {
            const postDumpBytes = hook.postDumpBytes || hook.dumpBytes || POINTER_DUMP_BYTES;
            const postSummarizeArgs = hook.postSummarizeArgs || 0;
            Object.keys(this.postArgs).forEach((key) => {
              const argIndex = Number(key);
              const postArg = this.postArgs[argIndex];
              dumpPointer(`${hook.name} post-arg${argIndex}`, postArg, postDumpBytes);
              summarizePointerFields(`${hook.name} post-arg${argIndex}`, postArg, postSummarizeArgs);
              const compressedPostArgLimit = Array.isArray(hook.postSummarizeCompressedArgs)
                ? (hook.postSummarizeCompressedArgs[argIndex] || 0)
                : (hook.postSummarizeCompressedArgs || 0);
              summarizeCompressedHeapRefs(`${hook.name} post-arg${argIndex}`, postArg, compressedPostArgLimit);
              const compressedPostArgTargets = Array.isArray(hook.postDumpCompressedTargets)
                ? (hook.postDumpCompressedTargets[argIndex] || [])
                : [];
              dumpCompressedRefTargets(`${hook.name} post-arg${argIndex}`, postArg, compressedPostArgTargets);
            });
          }

          if (hook.name === 'sub_32e990') {
            rememberParserRetval(this.__copilotThreadId, retval);
          }

          if (typeof hook.onLeave === 'function') {
            hook.onLeave.call(this, {
              threadId: this.__copilotThreadId,
              returnOffset: this.__copilotReturnOffset,
              returnAddress: this.returnAddress,
              context: this.context,
            }, retval);
          }

          logLine(`LEAVE ${hook.name}`);
        },
      });
    } catch (err) {
      logLine(`failed to hook ${hook.name} @ ${address}: ${err}`);
    }
  });
}

function waitForModule() {
  const module = Process.findModuleByName(TARGET_MODULE);
  if (module !== null) {
    logLine(`found ${TARGET_MODULE} @ ${module.base}`);
    attachHooks(module.base);
    return;
  }

  setTimeout(waitForModule, RETRY_MS);
}

setImmediate(waitForModule);
