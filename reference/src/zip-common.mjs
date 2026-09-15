/**
 * The parts of ZIP handling that both the reader and the writer need, and that must run anywhere.
 *
 * This module exists because of a boundary rather than a preference. A receipt is written by a
 * *browser* (the page you are reading is the capture) and read by a *command line* - so the writer has
 * to run where Node's `zlib` does not exist, while the reader can lean on it. Splitting the two means
 * the writer's dependency list can be inspected and kept empty, and `scripts/check-browser-safe.mjs`
 * keeps it that way (D-018).
 *
 * Nothing here imports a Node built-in, and nothing here will.
 *
 * @module zip-common
 */

/** Raised when a container is not a ZIP either module is willing to handle. */
export class ZipError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'ZipError';
  }
}

/**
 * The signature of each record a ZIP is made of, defined once for both the reader and the writer.
 *
 * One definition rather than two: these are the numbers each side checks, and a reader that agreed
 * with a writer about them only by convention would be a reader that failed to notice a writer bug.
 */
export const LOCAL_HEADER = 0x04034b50;
export const CENTRAL_HEADER = 0x02014b50;
export const END_OF_CENTRAL_DIRECTORY = 0x06054b50;

/** CRC-32 table, built once. The only arithmetic in this module. */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let value = i;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[i] = value >>> 0;
  }
  return table;
})();

/**
 * The CRC-32 every ZIP entry carries, and which `gzip.mjs` also needs for its trailer.
 *
 * @param {Uint8Array} bytes
 * @returns {number}
 */
export function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
