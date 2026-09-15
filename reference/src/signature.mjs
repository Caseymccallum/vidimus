/**
 * Ed25519 signing and verification, from raw keys.
 *
 * Raw, not PEM, because a receipt has to carry its own public key in a form that
 * survives JSON and that a JavaScript, Python or Rust verifier can all construct a key
 * from without a parser: 32 bytes, base64url. The two DER prefixes below are the fixed
 * wrapper `node:crypto` wants around them, and they are spelled out rather than hidden
 * so that a reader can reproduce this in any other runtime in a few lines.
 *
 * Ed25519 rather than ECDSA P-256 for the default: deterministic signatures (the same
 * key and message always produce the same bytes, so a fixture can record one), no
 * per-signature nonce to get wrong, and 64-byte signatures that fit in a URL.
 *
 * @module signature
 */

import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { sha256, toBase64Url, fromBase64Url, toHex } from './digest.mjs';

/** PKCS#8 prefix for an Ed25519 private key: the 32-byte seed follows it. */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** SubjectPublicKeyInfo prefix for an Ed25519 public key: the 32-byte key follows it. */
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Raw key length, and therefore signature length, in bytes. */
export const ED25519_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

/**
 * The label a receipt must use for this algorithm. Changing it is a spec change.
 */
export const ED25519_ALG = 'ed25519';

/**
 * @param {Uint8Array} seed Exactly 32 bytes.
 * @returns {import('node:crypto').KeyObject}
 */
export function privateKeyFromSeed(seed) {
  if (seed.length !== ED25519_KEY_BYTES) {
    throw new Error(`an Ed25519 seed is ${ED25519_KEY_BYTES} bytes, not ${seed.length}`);
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * @param {Uint8Array} raw Exactly 32 bytes.
 * @returns {import('node:crypto').KeyObject}
 */
export function publicKeyFromRaw(raw) {
  if (raw.length !== ED25519_KEY_BYTES) {
    throw new Error(`an Ed25519 public key is ${ED25519_KEY_BYTES} bytes, not ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

/**
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {Uint8Array} The 32 raw public key bytes.
 */
export function rawPublicKey(privateKey) {
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return new Uint8Array(spki.subarray(spki.length - ED25519_KEY_BYTES));
}

/**
 * The receipt's `key_id`: the SHA-256 of the raw public key, as lowercase hex. A digest
 * rather than the key itself, so a receipt can be referred to by key without a listing,
 * and so a key directory can be keyed by it.
 *
 * @param {Uint8Array} rawPublicKeyBytes
 * @returns {string}
 */
export function keyId(rawPublicKeyBytes) {
  return sha256(rawPublicKeyBytes);
}

/**
 * A fresh 32-byte seed from the operating system's random source.
 *
 * The one function in this module that is not deterministic, and it lives here rather than in the CLI
 * so that no other module needs to import a random source: the verifier's purity rule is easier to
 * keep when the exceptions are few, named and in one place.
 *
 * @returns {Uint8Array}
 */
export function generateSeed() {
  return new Uint8Array(randomBytes(ED25519_KEY_BYTES));
}

/**
 * @param {Uint8Array} message
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {Uint8Array}
 */
export function signMessage(message, privateKey) {
  return new Uint8Array(sign(null, Buffer.from(message), privateKey));
}

/**
 * Verify, and never throw: a receipt is untrusted input, and a malformed key or
 * signature is an answer ("no"), not an exception the caller might not catch.
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} signatureBytes
 * @param {Uint8Array} rawPublicKeyBytes
 * @returns {boolean}
 */
export function verifyMessage(message, signatureBytes, rawPublicKeyBytes) {
  if (signatureBytes.length !== ED25519_SIGNATURE_BYTES) return false;
  if (rawPublicKeyBytes.length !== ED25519_KEY_BYTES) return false;
  try {
    return verify(
      null,
      Buffer.from(message),
      publicKeyFromRaw(rawPublicKeyBytes),
      Buffer.from(signatureBytes),
    );
  } catch {
    return false;
  }
}

/** Serialise a key or signature for JSON. */
export const encodeBase64Url = toBase64Url;
/** Parse a key or signature from JSON. */
export const decodeBase64Url = fromBase64Url;
/** Hex, for key ids and digests. */
export const toHexString = toHex;
