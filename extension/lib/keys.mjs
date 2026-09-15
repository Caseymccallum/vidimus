/**
 * The sealing key, and WebCrypto's part in making a signature.
 *
 * The key is generated here, exported as PKCS#8 so it can be stored and re-imported, and never leaves
 * the browser: there is no server in this project to send it to. The public half travels inside every
 * receipt, which is what makes a receipt attributable.
 *
 * Written as plain ESM using WebCrypto, which means it runs in a browser *and* in Node - so the test
 * suite can exercise the whole browser sealing path against the reference verifier without opening a
 * browser (`reference/test/extension.test.mjs`).
 *
 * @module keys
 */

import { toBase64Url, toHex } from '../../reference/src/encode.mjs';
import { sha256 } from '../../reference/src/sha256.mjs';

/** The algorithm, named once. Ed25519, the same one the verifier implements. */
const ALGORITHM = { name: 'Ed25519' };

/**
 * @param {Uint8Array} publicRaw
 * @returns {string} The key id: the digest of the raw public key, exactly as a receipt derives it.
 */
export function keyIdOf(publicRaw) {
  return toHex(sha256(publicRaw));
}

/**
 * A new signing key.
 *
 * @param {string | null} [signer] A name to carry in the receipts this key signs. Self-asserted, and
 *   labelled as such wherever it appears.
 * @returns {Promise<{ pkcs8: Uint8Array, publicRaw: Uint8Array, keyId: string, signer: string | null }>}
 */
export async function generateKey(signer = null) {
  const pair = await crypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify']);
  return {
    pkcs8: new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
    publicRaw: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)),
    keyId: keyIdOf(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
    signer,
  };
}

/**
 * The signature object a claim carries, from a key and the message to sign.
 *
 * `key_id` is derived from the public key rather than stored alongside it, for the same reason a
 * receipt's is derived: an asserted identifier can be edited, and a derived one cannot.
 *
 * @param {{ pkcs8: Uint8Array, publicRaw: Uint8Array, signer?: string | null }} key
 * @param {Uint8Array} message
 * @returns {Promise<Record<string, any>>}
 */
export async function signClaim(key, message) {
  const privateKey = await crypto.subtle.importKey('pkcs8', key.pkcs8, ALGORITHM, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign(ALGORITHM, privateKey, message));

  return {
    alg: 'ed25519',
    key_id: keyIdOf(key.publicRaw),
    public_key: toBase64Url(key.publicRaw),
    sig: toBase64Url(signature),
    ...(typeof key.signer === 'string' && key.signer !== '' ? { signer: key.signer } : {}),
  };
}
