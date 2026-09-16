/**
 * The primitives a verifier needs from its runtime, and the Node implementation of them.
 *
 * The verifier's *rules* - the check table, the order of the stages, what a status means, how a level
 * rolls up - are the same everywhere. What differs is how a program computes a digest, reads a
 * container, and checks a signature. Node has `crypto` and `zlib`; a browser has WebCrypto, whose
 * `verify` is asynchronous, and `DecompressionStream`.
 *
 * So they are injected, and that seam is the whole reason the format's rules can be shared by a command
 * line and an extension without either reimplementing the other (D-021).
 *
 * A runtime supplies:
 *
 * ```
 * digest(bytes)                          -> lowercase hex SHA-256
 * readContainer(bytes)                   -> { entries: Map<string, Uint8Array>, order: string[] }
 * keyId(rawPublicKeyBytes)               -> lowercase hex
 * verifySignature(message, sig, rawKey)  -> boolean, or a promise of one
 * ```
 *
 * `digest` may be asynchronous, and in a browser it will be, because the browser can only reach its
 * own SHA-256 through `crypto.subtle`, which returns a promise. Everything downstream awaits, so a
 * synchronous implementation - as here - costs nothing.
 *
 * @module runtime
 */

import { gunzipSync } from 'node:zlib';

import { sha256 } from './digest.mjs';
import { keyId, verifyMessage } from './signature.mjs';
import { readZip } from './zip.mjs';
import { decompress, findMainDocument } from './warc.mjs';
import { findWarcEntry } from './wacz.mjs';

/**
 * The Node runtime: every primitive the platform already has, wrapped so that the verifier does not
 * have to know where it is running.
 *
 * This is the default, so nothing that calls `verifyReceipt` needs to pass anything - and the browser's
 * version lives with the extension, beside the WebCrypto it uses.
 */
export const nodeRuntime = {
  name: 'node',
  digest: (bytes) => sha256(bytes),
  readContainer: (bytes) => readZip(bytes),
  keyId: (rawPublicKey) => keyId(rawPublicKey),
  verifySignature: (message, signature, rawPublicKey) => verifyMessage(message, signature, rawPublicKey),

  /**
   * The document a capture holds, for the checks that need to re-read it - `subject.text` today, and the
   * currency comparison tomorrow.
   *
   * This is the one primitive that reaches into somebody else's format, and it does so through the same
   * strict, narrow reader the producer uses rather than a second one: a verifier that re-derived a
   * document differently from the tool that wrote the claim would report a mismatch that is its own.
   *
   * @param {Uint8Array} captureBytes
   * @param {string | null} url
   * @returns {Promise<import('./warc.mjs').MainDocument>}
   */
  mainDocument: async (captureBytes, url) => {
    const warc = await findWarcEntry(captureBytes, { readContainer: readZip });
    // Node's inflater, spelled the way Node spells it. The record layer below is the same one the
    // browser calls, and it is synchronous because both runtimes have a synchronous SHA-256 of their own.
    const plain = decompress(warc.bytes, (bytes) => new Uint8Array(gunzipSync(bytes)));
    return findMainDocument(plain, url, { digest: (bytes) => sha256(bytes) });
  },
};
