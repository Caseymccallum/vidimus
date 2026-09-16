/**
 * The record layer, with Node's primitives supplied.
 *
 * `warc.mjs` is pure: it takes plain bytes and a digest function. This is the one-line wrapper that gives
 * it Node's `gunzipSync` and Node's SHA-256, so a caller on a command line - and every test - keeps the
 * synchronous, one-argument call it has always had.
 *
 * The same two primitives are supplied by the browser, from `extension/lib/checking.mjs`, where they are
 * `DecompressionStream('gzip')` and this project's own SHA-256 (D-021).
 *
 * @module warc-node
 */

import { gunzipSync } from 'node:zlib';

import { sha256 } from './digest.mjs';
import { decompress as decompressWith, findMainDocument as findInPlainWarc } from './warc.mjs';

export {
  WarcError, isGzipped, parseHttpResponse, readWarc, toClaimTimestamp,
} from './warc.mjs';

/**
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function decompress(bytes) {
  return decompressWith(bytes, (compressed) => new Uint8Array(gunzipSync(Buffer.from(compressed))));
}

/**
 * @param {Uint8Array} warcBytes
 * @param {string | null} [url]
 * @returns {import('./warc.mjs').MainDocument}
 */
export function findMainDocument(warcBytes, url = null) {
  return findInPlainWarc(decompress(warcBytes), url, { digest: (bytes) => sha256(bytes) });
}
