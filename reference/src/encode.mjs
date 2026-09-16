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

/**
 * base64url, without padding: the form the claim uses for public keys and signatures, because they
 * travel in JSON and sometimes in a URL.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
/**
 * base64url, without padding: the form the claim uses for public keys and signatures, because they
 * travel in JSON and sometimes in a URL.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * @param {string} value
 * @returns {Uint8Array}
 */
export function fromBase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/**
 * @param {string} text
 * @returns {Uint8Array} The text as one byte per character, so a byte-for-byte view of a binary
 * file can be searched with string operations. Bytes above 0x7f survive unchanged.
 */
export function latin1(text) {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index) & 0xff;
  return bytes;
}

/**
 * Turn bytes into a string one character per byte.
 *
 * Chunked for the same reason `toBase64` is: `String.fromCharCode` takes one argument per byte, and a
 * spread of several hundred thousand arguments throws - which would fail on exactly the large captures
 * this is for.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function fromLatin1(bytes) {
  let text = '';
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    text += String.fromCharCode.apply(null, bytes.subarray(offset, offset + chunk));
  }
  return text;
}

/**
 * Standard base64, with padding - the form a `WARC-Payload-Digest` uses. `atob` is a global in both
 * runtimes, which is why this can live here beside the url-safe variant.
 *
 * @param {string} value
 * @returns {Uint8Array}
 */
export function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/**
 * True for a 64-character lowercase hex digest, which is the only form the claim admits.
 *
 * @param {unknown} value
 * @returns {value is string}
 */
export function isSha256Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
