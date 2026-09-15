/**
 * A ZIP reader for a browser: entries that are stored, and nothing else.
 *
 * The command-line reader inflates deflated entries with Node's `zlib`. A browser has
 * `DecompressionStream`, which is asynchronous - and this reader is deliberately kept synchronous,
 * because its whole purpose is to answer now. So it reads what it can, and for anything else it throws
 * an error marked `code: 'unsupported'`, which the verifier reports as `unsupported` rather than `fail`.
 *
 * Every receipt this project writes stores its entries uncompressed, so the limit costs nothing for its
 * own output; it is another tool's container that may need the command line.
 *
 * The header walking is deliberately a reduced copy of `reference/src/zip.mjs`. Two readers for two
 * runtimes, pinned against each other by a test that reads the same fixture with both and compares what
 * they found - the same trade, and the same mitigation, as the two SHA-256s (D-019, D-021).
 *
 * @module store-zip
 */

import { CENTRAL_HEADER, END_OF_CENTRAL_DIRECTORY, LOCAL_HEADER, ZipError, crc32 } from '../../reference/src/zip-common.mjs';

/**
 * An error a runtime raises to say "this is beyond me", rather than "this is wrong".
 *
 * @param {string} message
 * @returns {Error & { code: string }}
 */
function unsupported(message) {
  const error = /** @type {Error & { code: string }} */ (new ZipError(message));
  error.code = 'unsupported';
  return error;
}

/**
 * @param {Uint8Array} bytes
 * @returns {number}
 */
function findEndOfCentralDirectory(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minimum = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (offset >= 0 && view.getUint32(offset, true) === END_OF_CENTRAL_DIRECTORY) return offset;
  }
  throw new ZipError('no end-of-central-directory record: this is not a ZIP');
}

/**
 * Read a stored-only ZIP.
 *
 * @param {Uint8Array} bytes
 * @returns {{ entries: Map<string, Uint8Array>, order: string[] }}
 * @throws {ZipError}
 */
export function readStoredZip(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = findEndOfCentralDirectory(bytes);
  const totalEntries = view.getUint16(eocd + 8, true);
  if (totalEntries === 0xffff) throw unsupported('ZIP64 archives are not supported here');
  if (view.getUint16(eocd + 10, true) !== totalEntries) {
    throw unsupported('multi-disk archives are not supported here');
  }

  const directorySize = view.getUint32(eocd + 12, true);
  const directoryStart = view.getUint32(eocd + 16, true);
  if (directoryStart === 0xffffffff || directorySize === 0xffffffff) {
    throw unsupported('ZIP64 archives are not supported here');
  }

  /** @type {Map<string, Uint8Array>} */
  const entries = new Map();
  /** @type {string[]} */
  const order = [];
  let cursor = directoryStart;

  for (let index = 0; index < totalEntries; index += 1) {
    if (view.getUint32(cursor, true) !== CENTRAL_HEADER) {
      throw new ZipError(`central directory entry ${index} has a bad signature`);
    }
    const method = view.getUint16(cursor + 10, true);
    const crc = view.getUint32(cursor + 16, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const localOffset = view.getUint32(cursor + 42, true);
    const name = new TextDecoder('utf-8').decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    cursor += 46 + nameLength + extraLength + commentLength;

    if (name.endsWith('/')) continue;
    if (method !== 0) {
      throw unsupported(
        `"${name}" is compressed (method ${method}), which this verifier cannot read in a browser: `
        + 'check it with the command line instead',
      );
    }
    if (view.getUint32(localOffset, true) !== LOCAL_HEADER) {
      throw new ZipError(`local header for "${name}" has a bad signature`);
    }

    const dataStart = localOffset + 30
      + view.getUint16(localOffset + 26, true)
      + view.getUint16(localOffset + 28, true);
    const contents = bytes.slice(dataStart, dataStart + compressedSize);
    if (crc32(contents) !== crc) throw new ZipError(`"${name}" failed its CRC-32 check`);

    entries.set(name, contents);
    order.push(name);
  }

  return { entries, order };
}
