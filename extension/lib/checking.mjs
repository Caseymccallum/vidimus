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
import { readDer, oidValue } from '../../reference/src/der.mjs';
import { findMainDocument, isGzipped } from '../../reference/src/warc.mjs';
import { findWarcEntry } from '../../reference/src/wacz.mjs';
import { readZipInBrowser, inflateGzip } from './browser-zip.mjs';

/** The algorithm, named once here as it is named once in the claim's shape. */
const ALGORITHM = { name: 'Ed25519' };

/**
 * The signature algorithms a `SubjectPublicKeyInfo` can name, and the curves a browser needs named.
 *
 * WebCrypto will not take a curve it was not told, and it wants an ECDSA signature as `r || s` of a fixed
 * width where CMS carries a DER `SEQUENCE` of two `INTEGER`s. Both of those are the browser's business,
 * which is why this lives here and not in the shared rules (D-021).
 */
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const CURVES = {
  '1.2.840.10045.3.1.7': { name: 'P-256', bytes: 32 },
  '1.3.132.0.34': { name: 'P-384', bytes: 48 },
  '1.3.132.0.35': { name: 'P-521', bytes: 66 },
};

/** @param {string} hash @returns {string} */
const webCryptoHash = (hash) => `SHA-${hash.replace('sha', '')}`;

/**
 * An ECDSA signature as WebCrypto wants it: two integers of equal, fixed width, left-padded.
 *
 * @param {Uint8Array} der
 * @param {number} width
 * @returns {Uint8Array}
 */
function toP1363(der, width) {
  const sequence = readDer(der);
  if (sequence.tag !== 0x30 || sequence.children.length !== 2) {
    throw new Error('an ECDSA signature is a SEQUENCE of two INTEGERs');
  }
  const out = new Uint8Array(width * 2);
  sequence.children.forEach((integer, index) => {
    const value = integer.value;
    // A DER INTEGER is signed, so a value with its high bit set carries a leading zero that is not part of
    // the number.
    const trimmed = value.length > width && value[0] === 0 ? value.subarray(1) : value;
    if (trimmed.length > width) throw new Error('an ECDSA signature component is wider than its curve');
    out.set(trimmed, index * width + (width - trimmed.length));
  });
  return out;
}

/**
 * Check a signature made with a certificate's key.
 *
 * @param {{ spki: Uint8Array, hash: string, data: Uint8Array, signature: Uint8Array }} input
 * @returns {Promise<boolean>}
 */
async function verifyWithPublicKey(input) {
  const spki = readDer(input.spki);
  const algorithm = oidValue(spki.children[0].children[0]);
  const hash = webCryptoHash(input.hash);

  if (algorithm === RSA_ENCRYPTION) {
    const key = await crypto.subtle.importKey(
      'spki', input.spki, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify'],
    );
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, input.signature, input.data);
  }

  if (algorithm === EC_PUBLIC_KEY) {
    const parameters = spki.children[0].children[1];
    const curve = parameters === undefined ? undefined : CURVES[oidValue(parameters)];
    if (curve === undefined) {
      throw new Error(`this runtime has no named curve for the one this key uses`);
    }
    const key = await crypto.subtle.importKey(
      'spki', input.spki, { name: 'ECDSA', namedCurve: curve.name }, false, ['verify'],
    );
    return crypto.subtle.verify(
      { name: 'ECDSA', hash }, key, toP1363(input.signature, curve.bytes), input.data,
    );
  }

  throw new Error(`this runtime cannot use a ${algorithm} key`);
}

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

  /**
   * A certificate's signature, checked with WebCrypto.
   *
   * The same primitive the command line supplies, and the same token either way: what differs is that a
   * browser needs a curve named and an ECDSA signature reshaped, which is why that work is here rather
   * than in the shared rules.
   */
  verifyWithPublicKey,
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
