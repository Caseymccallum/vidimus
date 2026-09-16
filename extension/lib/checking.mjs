/**
 * Checking a receipt in a browser.
 *
 * The verifier's rules are shared (`reference/src/verify.mjs`); what a browser has to supply is the
 * primitives. Three of the four are easy:
 *
 * - **the digest** is this project's own SHA-256, which already runs in both runtimes and is pinned
 *   against the platform's by a test;
 * - **the container reader** is `browser-zip.mjs`, which reads stored and deflated entries and declines
 *   anything else by name;
 * - **the key id** is the same digest, which is exactly what a receipt means by a key id.
 *
 * The fourth is the interesting one: **a signature check**, which a browser can only do through
 * `crypto.subtle`, and therefore only asynchronously. That single reality is why the verifier takes a
 * runtime and awaits its answers - and having paid that price, the browser can check a receipt with the
 * same rules the command line uses, rather than with a second implementation that might disagree (D-021).
 *
 * @module checking
 */

import { toHex } from '../../reference/src/encode.mjs';
import { sha256 } from '../../reference/src/sha256.mjs';
import { verifyReceipt } from '../../reference/src/verify.mjs';
import { findMainDocument, isGzipped } from '../../reference/src/warc.mjs';
import { findWarcEntry } from '../../reference/src/wacz.mjs';
import { readZipInBrowser, inflateGzip } from './browser-zip.mjs';

/** The algorithm, named once here as it is named once in the claim's shape. */
const ALGORITHM = { name: 'Ed25519' };

/** The primitives a browser already has, wrapped so the verifier does not have to know where it runs. */
export const browserRuntime = {
  name: 'browser',
  digest: (bytes) => toHex(sha256(bytes)),
  readContainer: (bytes) => readZipInBrowser(bytes),
  keyId: (rawPublicKey) => toHex(sha256(rawPublicKey)),
  verifySignature: async (message, signature, rawPublicKey) => {
    const key = await crypto.subtle.importKey('raw', rawPublicKey, ALGORITHM, false, ['verify']);
    return crypto.subtle.verify(ALGORITHM, key, signature, message);
  },

  /**
   * The document a capture holds, so a browser can check the checks that re-read it.
   *
   * Without this, a browser would report `subject.text: not_checked` while the command line reported a
   * `pass` for the same receipt - two verdicts for one file, which is the thing the shared rules exist to
   * prevent. A browser has `DecompressionStream('gzip')` where Node has `gunzipSync`, and a WARC reader
   * that is pure (D-021).
   *
   * @param {Uint8Array} captureBytes
   * @param {string | null} url
   * @returns {Promise<Record<string, any>>}
   */
  mainDocument: async (captureBytes, url) => {
    const warc = await findWarcEntry(captureBytes, { readContainer: readZipInBrowser });
    // A browser's inflater is asynchronous, so the gzip step happens here and the record layer below
    // stays the synchronous, shared one (D-021).
    const plain = isGzipped(warc.bytes) ? await inflateGzip(warc.bytes) : warc.bytes;
    return findMainDocument(plain, url, { digest: (bytes) => toHex(sha256(bytes)) });
  },
};

/**
 * Verify a receipt in a browser, with the same rules the command line uses.
 *
 * @param {Uint8Array} bytes
 * @param {Record<string, any>} [options] `trustedKeys`, `previousClaimHash` - the same options as ever.
 * @returns {Promise<Record<string, any>>} The same verdict a command line would produce.
 */
export function checkReceipt(bytes, options = {}) {
  return verifyReceipt(bytes, { ...options, runtime: browserRuntime });
}
