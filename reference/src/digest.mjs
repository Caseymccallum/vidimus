/**
 * The hashing and encoding primitives a Receipt-format verifier needs, and nothing else.
 *
 * Kept apart from `canonical.mjs` on purpose. Canonicalisation is a *rule* - the same
 * rules must hold in every language - while hashing is a *primitive* that every
 * runtime already has. Mixing them would make it impossible to test the rules without
 * a crypto provider, and impossible to swap the provider without re-reading the rules.
 *
 * This is the only file in `reference/src/` that imports a Node built-in. A browser
 * verifier replaces it with WebCrypto and changes nothing downstream (D-003).
 *
 * @module digest
 */

import { createHash } from 'node:crypto';

import { utf8 } from './encode.mjs';

/** Re-exported from `encode.mjs`, where it is defined once for this module and the capture path alike. */
export { utf8 };


/** @param {Uint8Array} bytes @returns {string} */
export function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

/** @param {string} hex @returns {Uint8Array} */
export function fromHex(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/** @param {Uint8Array} bytes @returns {string} */
export function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

/** @param {string} value @returns {Uint8Array} */
export function fromBase64Url(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

/**
 * SHA-256, as lowercase hex.
 * @param {Uint8Array | string} input
 * @returns {string}
 */
export function sha256(input) {
  const bytes = typeof input === 'string' ? utf8(input) : input;
  return createHash('sha256').update(bytes).digest('hex');
}

/** Length of a SHA-256 digest in hex characters. */
export const SHA256_HEX_LENGTH = 64;

/**
 * @param {unknown} value
 * @returns {value is string}
 */
export function isSha256Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
