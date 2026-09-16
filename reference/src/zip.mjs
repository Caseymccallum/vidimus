/**
 * The smallest ZIP that a conformance suite can honestly use: read and write, no
 * dependencies, byte-for-byte reproducible when writing.
 *
 * A receipt is a ZIP, and a WACZ is a ZIP, so both the fixtures and the verifier need
 * this. It is hand-rolled rather than pulled from npm for one reason that matters to
 * this project specifically: **the reference verifier must run with no install step.**
 * A conformance suite that needs `npm install` first is a conformance suite people
 * skip, and a format whose reference implementation is a dependency tree is a format
 * nobody can check in five years. Sentinel's `scripts/*.mjs` gates are the precedent
 * (D-002).
 *
 * What this supports:
 *  - Reading: STORE (0) and DEFLATE (8), comments, extra fields - anything a real
 *    capture tool emits, because receipts are written by other people's code.
 *  - Writing: STORE only, with a caller-supplied timestamp, so two runs produce
 *    identical bytes and the fixture digest can be a recorded constant.
 *
 * What it is not: a general ZIP library. It does not stream, does not support ZIP64 or
 * encryption, and refuses rather than guesses when it meets them. A verifier that
 * silently mis-reads a container is worse than one that says "unsupported".
 *
 * This module is the **reader** and imports Node's `zlib` to inflate. The **writer** lives in
 * `zip-write.mjs` and imports nothing from Node, because a receipt is written in a browser and read on
 * a command line. Both are re-exported here, so nothing that imported this module has to care (D-018).
 *
 * @module zip
 */

import { inflateRawSync } from 'node:zlib';

import {
  CENTRAL_HEADER, END_OF_CENTRAL_DIRECTORY, LOCAL_HEADER, ZipError, crc32,
} from './zip-common.mjs';

/**
 * Re-exported so that every existing caller keeps working: importing `zip.mjs` still gives you a
 * reader *and* a writer. Importing `zip-write.mjs` instead gives you only the parts that run in a
 * browser, which is what a capturing extension needs (D-018).
 */
export { crc32, ZipError } from './zip-common.mjs';
export { dosDateTime, writeZip } from './zip-write.mjs';

/**
 * Locate the end-of-central-directory record, the only place a ZIP can be read from
 * forwards. Scans back at most 64 KiB + 22 bytes, the largest an EOCD with a comment
 * is allowed to be.
 *
 * @param {Uint8Array} bytes
 * @returns {number} Offset of the EOCD signature.
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
 * @typedef {object} ZipEntryHeader
 * @property {string} name
 * @property {number} method
 * @property {number} flags
 * @property {number} crc
 * @property {number} compressedSize
 * @property {number} uncompressedSize
 * @property {number} localOffset
 */

/**
 * Walk the central directory. Nothing here reads file data: the central directory is
 * the archive's table of contents, and parsing it separately from the bytes it points
 * at keeps "is this a well-formed archive" and "are these the bytes it claims" as two
 * failure modes with two different messages.
 *
 * @param {Uint8Array} bytes
 * @returns {ZipEntryHeader[]}
 */
function readCentralDirectory(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = findEndOfCentralDirectory(bytes);
  const diskEntries = view.getUint16(eocd + 10, true);
  const totalEntries = view.getUint16(eocd + 8, true);
  if (diskEntries !== totalEntries) throw new ZipError('multi-disk archives are not supported');
  if (totalEntries === 0xffff) throw new ZipError('ZIP64 archives are not supported');

  const directorySize = view.getUint32(eocd + 12, true);
  const directoryStart = view.getUint32(eocd + 16, true);
  if (directoryStart === 0xffffffff || directorySize === 0xffffffff) {
    throw new ZipError('ZIP64 archives are not supported');
  }
  const directoryEnd = directoryStart + directorySize;
  if (directoryEnd > bytes.length) {
    throw new ZipError('central directory runs past the end of the file');
  }

  /** @type {ZipEntryHeader[]} */
  const headers = [];
  let cursor = directoryStart;

  for (let index = 0; index < totalEntries; index += 1) {
    if (cursor + 46 > directoryEnd) throw new ZipError('central directory entry is truncated');
    if (view.getUint32(cursor, true) !== CENTRAL_HEADER) {
      throw new ZipError(`central directory entry ${index} has a bad signature`);
    }
    const header = {
      name: new TextDecoder('utf-8').decode(
        bytes.subarray(cursor + 46, cursor + 46 + view.getUint16(cursor + 28, true)),
      ),
      method: view.getUint16(cursor + 10, true),
      flags: view.getUint16(cursor + 8, true),
      crc: view.getUint32(cursor + 16, true),
      compressedSize: view.getUint32(cursor + 20, true),
      uncompressedSize: view.getUint32(cursor + 24, true),
      localOffset: view.getUint32(cursor + 42, true),
    };
    if (
      header.compressedSize === 0xffffffff ||
      header.uncompressedSize === 0xffffffff ||
      header.localOffset === 0xffffffff
    ) {
      throw new ZipError('ZIP64 archives are not supported');
    }
    cursor += 46 + view.getUint16(cursor + 28, true) + view.getUint16(cursor + 30, true)
      + view.getUint16(cursor + 32, true);
    if (!header.name.endsWith('/')) headers.push(header);
  }

  return headers;
}

/**
 * Read a ZIP into its entries, checking every entry as it goes.
 *
 * Each entry is checksummed on the way out and the checksum is *checked*, because a
 * receipt verifier's whole job is to notice that bytes are not what they claim to be.
 * A container that fails its own CRC never reaches the layer above.
 *
 * @param {Uint8Array} bytes
 * @returns {{
 *   entries: Map<string, Uint8Array>,
 *   order: string[],
 *   compressed: Map<string, number>,
 *   crc: Map<string, number>,
 * }}
 * @throws {ZipError}
 */
export function readZip(bytes) {
  const headers = readCentralDirectory(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  /** @type {Map<string, Uint8Array>} */
  const entries = new Map();
  const compressed = new Map();
  const crcs = new Map();
  /** @type {string[]} */
  const order = [];

  for (const header of headers) {
    if ((header.flags & 0x0001) !== 0) {
      throw new ZipError(`"${header.name}" is encrypted, which this reader does not support`);
    }
    if (view.getUint32(header.localOffset, true) !== LOCAL_HEADER) {
      throw new ZipError(`local header for "${header.name}" has a bad signature`);
    }
    // The local header's own name/extra lengths decide where the data starts. An archive
    // may legitimately use different extra fields in the two headers, and assuming they
    // match is a classic way to read four bytes of the wrong thing and then report a
    // digest mismatch as though the content had changed.
    const dataStart = header.localOffset + 30
      + view.getUint16(header.localOffset + 26, true)
      + view.getUint16(header.localOffset + 28, true);
    const dataEnd = dataStart + header.compressedSize;
    if (dataEnd > bytes.length) {
      throw new ZipError(`"${header.name}" runs past the end of the file`);
    }

    const raw = bytes.subarray(dataStart, dataEnd);
    let contents;
    if (header.method === 0) {
      contents = raw.slice();
    } else if (header.method === 8) {
      try {
        contents = new Uint8Array(inflateRawSync(raw));
      } catch (error) {
        throw new ZipError(`"${header.name}" could not be inflated: ${error.message}`);
      }
    } else {
      throw new ZipError(
        `"${header.name}" uses compression method ${header.method}, which is unsupported`,
      );
    }

    if (contents.length !== header.uncompressedSize) {
      throw new ZipError(
        `"${header.name}" declared ${header.uncompressedSize} bytes but holds ${contents.length}`,
      );
    }
    if (crc32(contents) !== header.crc) {
      throw new ZipError(`"${header.name}" failed its CRC-32 check`);
    }

    if (entries.has(header.name)) {
      throw new ZipError(`"${header.name}" appears twice in the archive`);
    }
    entries.set(header.name, contents);
    order.push(header.name);
    compressed.set(header.name, header.compressedSize);
    crcs.set(header.name, header.crc);
  }

  return { entries, order, compressed, crc: crcs };
}
