/**
 * The Node entry point to the verifier.
 *
 * `verify.mjs` holds the rules and takes a runtime, so that a browser can supply WebCrypto instead of
 * Node's `crypto`. This module is the one-line consequence: the same rules, with the primitives this
 * machine already has. Everything that runs on a command line imports from here, which keeps the call
 * sites free of runtime plumbing they do not care about.
 *
 * @module verify-node
 */

import { nodeRuntime } from './runtime.mjs';
import { verifyReceipt as verifyWithRuntime } from './verify.mjs';

export * from './verify.mjs';

/**
 * @param {Uint8Array} bytes
 * @param {Record<string, any>} [options]
 * @returns {Promise<Record<string, any>>}
 */
export function verifyReceipt(bytes, options = {}) {
  return verifyWithRuntime(bytes, { runtime: nodeRuntime, ...options });
}
