/**
 * The two encodings a capture needs, written so that they work in both runtimes.
 *
 * `digest.mjs` has its own, built on Node's `Buffer`. These exist because the capture path runs in a
 * browser, where `Buffer` does not exist, and because a receipt is written in one place and read in
 * another - so the encodings that appear *inside* a receipt have to be reproducible in both.
 *
 * `btoa` is a global in every browser and in Node from version 16 onwards, which makes it the one
 * base64 implementation that honestly belongs in a shared module. Hex needs no such argument.
 *
 * @module encode
 */

/**
 * @param {string} text
 * @returns {Uint8Array} The text as UTF-8 bytes.
 */
export function utf8(text) {
  return new TextEncoder().encode(text);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string} Lowercase hex, two characters per byte.
 */
export function toHex(bytes) {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Standard base64, with padding - which is what a `WARC-Payload-Digest` uses, and what the claim's hex
 * digests deliberately do not.
 *
 * The chunking is not decoration: `String.fromCharCode` takes one argument per byte and a spread of
 * several hundred thousand arguments throws, so a capture of a large page would fail on exactly the
 * pages people most want to keep.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}
