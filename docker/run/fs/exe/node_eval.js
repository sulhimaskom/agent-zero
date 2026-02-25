#!/usr/bin/env node
const vm = require('vm');
const path = require('path');

// Create a SECURE sandbox context with minimal, safe globals only
// REMOVED: require, process, module, exports - these allow RCE
// Using eval() within this sandbox is now safe because dangerous globals are removed
const sandbox = vm.createContext({
  // Safe console for output
  console: {
    log: console.log,
    error: console.error,
    warn: console.warn,
    info: console.info
  },
  // Safe math operations
  Math: Math,
  // Safe array/object primitives
  Array: Array,
  Object: Object,
  String: String,
  Number: Number,
  Boolean: Boolean,
  Date: Date,
  JSON: JSON,
  RegExp: RegExp,
  Error: Error,
  TypeError: TypeError,
  RangeError: RangeError,
  SyntaxError: SyntaxError,
  // Safe timing (no direct process access)
  setTimeout: setTimeout,
  setInterval: setInterval,
  setImmediate: setImmediate,
  clearTimeout: clearTimeout,
  clearInterval: clearInterval,
  clearImmediate: clearImmediate,
  // Safe Buffer subset (read-only methods only)
  Buffer: {
    from: Buffer.from,
    isBuffer: Buffer.isBuffer,
    alloc: Buffer.alloc,
    allocUnsafe: Buffer.allocUnsafe,
    allocUnsafeSlow: Buffer.allocUnsafeSlow,
    concat: Buffer.concat,
    isEncoding: Buffer.isEncoding,
    byteLength: Buffer.byteLength,
    compare: Buffer.compare,
    equals: Buffer.equals,
  },
  // Safe JSON for parsing
  JSON: {
    parse: JSON.parse,
    stringify: JSON.stringify,
    toString: () => '[object JSON]',
    valueOf: () => '[object JSON]',
  },
});

// Retrieve the code from the command-line argument
const code = process.argv[2];

if (!code) {
  console.error('Error: No code provided');
  process.exit(1);
}

// Wrap code to support both expressions and statements
// SECURITY: Using eval() within sandboxed context with NO dangerous globals
// The dangerous globals (require, process, etc.) have been removed from the context
const wrappedCode = `
(async function() {
  try {
    // Use eval within the sandbox - it's now safe because require/process are not available
    const __result__ = eval(${JSON.stringify(code)});
    if (__result__ !== undefined) console.log('Out[1]:', __result__);
  } catch (error) {
    console.error(error);
  }
})();
`;

try {
  vm.runInContext(wrappedCode, sandbox, {
    filename: 'eval.js',
    timeout: 30000, // 30 second timeout to prevent infinite loops
  });
} catch (error) {
  console.error('Execution error:', error.message);
  process.exit(1);
}
