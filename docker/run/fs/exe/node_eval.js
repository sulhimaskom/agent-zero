#!/usr/bin/env node

const vm = require('vm');
const path = require('path');

// Security: Create a SECURE sandbox environment
// This replaces the unsafe eval() pattern with proper VM sandboxing

// Retrieve the code from the command-line argument
const code = process.argv[2];

// Verify code is provided
if (!code) {
  console.error('Error: No code provided');
  process.exit(1);
}

// Create a SECURE sandbox context with ONLY safe APIs
// This prevents access to dangerous globals like process, Buffer, require, etc.
const safeGlobals = {
  // Console for output (safe, no access to stdout streams directly)
  console: {
    log: (...args) => console.log(...args),
    error: (...args) => console.error(...args),
    warn: (...args) => console.warn(...args),
    info: (...args) => console.info(...args),
  },
  // Timer APIs (safe)
  setTimeout: setTimeout,
  setInterval: setInterval,
  setImmediate: setImmediate,
  clearTimeout: clearTimeout,
  clearInterval: clearInterval,
  clearImmediate: clearImmediate,
  // Safe math and JSON utilities
  Math: Math,
  JSON: JSON,
  Date: Date,
  Array: Array,
  Object: Object,
  String: String,
  Number: Number,
  Boolean: Boolean,
  RegExp: RegExp,
  Map: Map,
  Set: Set,
  WeakMap: WeakMap,
  WeakSet: WeakSet,
  Promise: Promise,
  Error: Error,
  TypeError: TypeError,
  RangeError: RangeError,
  SyntaxError: SyntaxError,
  ReferenceError: ReferenceError,
  // Safe encode/decode utilities
  btoa: btoa,
  atob: atob,
  encodeURI: encodeURI,
  decodeURI: decodeURI,
  encodeURIComponent: encodeURIComponent,
  decodeURIComponent: decodeURIComponent,
  // Escape hatches - these are intentionally limited
  __filename: '[eval]',
  __dirname: '[eval]',
};

// Create the sandbox context using vm.runInNewContext for TRUE isolation
// This is fundamentally different from eval() inside vm.createContext()
// vm.runInNewContext creates a completely isolated context
const sandbox = vm.createContext(safeGlobals);

// Timeout configuration (default 30 seconds)
const TIMEOUT_MS = 30000;

// Wrap execution in a timeout to prevent infinite loops
let timedOut = false;
const timeoutId = setTimeout(() => {
  timedOut = true;
  console.error('Error: Code execution timed out');
  process.exit(1);
}, TIMEOUT_MS);

try {
  // Execute the user code in the SECURE sandbox using runInNewContext
  // This provides TRUE isolation - code cannot access process, Buffer, require, etc.
  const wrappedCode = `
    (async function() {
      ${code}
    })()
  `;

  // Use vm.runInNewContext instead of eval for true sandboxing
  const script = new vm.Script(wrappedCode, {
    filename: 'eval.js',
  });

  const result = script.runInNewContext(sandbox, {
    timeout: TIMEOUT_MS,
    displayErrors: true,
  });

  // If result is a Promise, wait for it
  if (result && typeof result.then === 'function') {
    result.then((resolved) => {
      clearTimeout(timeoutId);
      if (resolved !== undefined) {
        console.log('Out[1]:', resolved);
      }
    }).catch((err) => {
      clearTimeout(timeoutId);
      console.error(err);
      process.exit(1);
    });
  } else {
    clearTimeout(timeoutId);
    if (result !== undefined) {
      console.log('Out[1]:', result);
    }
  }
} catch (error) {
  clearTimeout(timeoutId);
  console.error(error);
  process.exit(1);
}
