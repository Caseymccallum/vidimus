/**
 * Reading a container in a browser: entries, stored or deflated.
 *
 * The command line inflates with Node's `zlib`. A browser has `DecompressionStream`, which is
 * asynchronous - and that is why this reader is too, and why the runtime contract allows an asynchronous
 * `readContainer` at all (D-021). Having already paid for one `await` in the verifier, a browser can read
 * any container this format produces, including one written by a tool that compresses properly, rather
 * than only its own stored entries.
 *
 * What it declines to do, it declines *by name*: ZIP64, multi-disk archives, encrypted entries and
 * unknown methods are refused as `unsupported`, so the verifier reports a gap in itself rather than a
 * fault in a receipt. Everything it does read is checked - CRC-32 and the uncompressed length - because a
 * reader that trusts a container it has not checked hands the layer above a lie.
 *
 * The header walking is deliberately a reduced copy of `reference/src/zip.mjs`, and the two are pinned
 * against each other by a test that reads the same containers with both and compares what they found.
 *
 * @module browser-zip
 */

import {
  CENTRAL_HEADER, END_OF_CENTRAL_DIRECTORY, LOCAL_HEADER, ZipError, crc32,
} from '../../reference/src/zip-common.mjs';

/**
 * An error that says "this is beyond me" rather than "this is wrong".
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
 * Read a decompression stream into one buffer, refusing to hold more than `cap` bytes.
 *
 * A browser has no synchronous inflater and no `maxOutputLength`, so the ceiling is enforced while the
 * stream arrives: the reader is cancelled the moment the total passes it, rather than after the allocation
 * a hostile file was asking for. That is the difference between refusing a bomb and surviving one.
 *
 * @param {ReadableStream<Uint8Array>} stream
 * @param {number} cap
 * @param {string} what Named in the refusal, so the message says which entry asked for the memory.
 * @returns {Promise<Uint8Array>}
 */
async function readCapped(stream, cap, what) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > cap) {
      await reader.cancel();
      throw unsupported(`${what} expands past the ${cap} bytes this reader will hold in memory`);
    }
    chunks.push(value);
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Inflate one raw deflate stream, the way a browser can.
 *
 * @param {Uint8Array} bytes
 * @param {string} name
 * @param {number} cap
 * @returns {Promise<Uint8Array>}
 */
async function inflateRaw(bytes, name, cap) {
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return await readCapped(stream, cap, `"${name}"`);
  } catch (error) {
    if (error instanceof ZipError) throw error;
    throw new ZipError(`"${name}" could not be inflated: ${error.message}`);
  }
}

/**
 * Inflate a gzip stream, the way a browser can.
 *
 * A WACZ's WARC is gzipped, so a browser that wants to re-read a captured document - to check a text
 * fingerprint, or to compare a page against a receipt - needs this as well as `inflateRaw`. Node spells
 * the same thing `gunzipSync`; the two are pinned against each other by the same test that pins the
 * container readers.
 *
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>}
 */
export async function inflateGzip(bytes, cap = Infinity) {
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return await readCapped(stream, cap, 'the WARC');
  } catch (error) {
    if (error instanceof ZipError) throw error;
    throw new ZipError(`the WARC could not be decompressed: ${error.message}`);
  }
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
 * Read a container, stored or deflated.
 *
 * @param {Uint8Array} bytes
 * @returns {Promise<{
 *   entries: Map<string, Uint8Array>, order: string[],
 *   compressed: Map<string, number>, crc: Map<string, number>,
 * }>}
 * @throws {ZipError}
 */
export async function readZipInBrowser(bytes, limits = {}) {
  const maxEntryBytes = limits.maxEntryBytes ?? Infinity;
  const maxTotalBytes = limits.maxTotalBytes ?? Infinity;
  const maxEntries = limits.maxEntries ?? Infinity;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = findEndOfCentralDirectory(bytes);
  const totalEntries = view.getUint16(eocd + 8, true);
  if (totalEntries > maxEntries) {
    throw unsupported(
      `this archive lists ${totalEntries} entries, and this reader stops at ${maxEntries}`,
    );
  }
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
  /** @type {Map<string, number>} */
  const compressedSizes = new Map();
  /** @type {Map<string, number>} */
  const crcs = new Map();
  /** @type {string[]} */
  const order = [];
  let cursor = directoryStart;
  let total = 0;

  for (let index = 0; index < totalEntries; index += 1) {
    if (view.getUint32(cursor, true) !== CENTRAL_HEADER) {
      throw new ZipError(`central directory entry ${index} has a bad signature`);
    }
    const flags = view.getUint16(cursor + 8, true);
    const method = view.getUint16(cursor + 10, true);
    const crc = view.getUint32(cursor + 16, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const uncompressedSize = view.getUint32(cursor + 24, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const localOffset = view.getUint32(cursor + 42, true);
    const name = new TextDecoder('utf-8').decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    cursor += 46 + nameLength + extraLength + commentLength;

    if (name.endsWith('/')) continue;
    if ((flags & 0x0001) !== 0) throw unsupported(`"${name}" is encrypted, which is not supported`);
    // Refused before the bytes are touched, exactly as the command line's reader does it.
    if (uncompressedSize > maxEntryBytes) {
      throw unsupported(
        `"${name}" declares ${uncompressedSize} bytes, and this reader inflates at most `
        + `${maxEntryBytes} of one entry`,
      );
    }
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      throw unsupported('ZIP64 archives are not supported here');
    }
    if (view.getUint32(localOffset, true) !== LOCAL_HEADER) {
      throw new ZipError(`local header for "${name}" has a bad signature`);
    }

    const dataStart = localOffset + 30
      + view.getUint16(localOffset + 26, true)
      + view.getUint16(localOffset + 28, true);
    const raw = bytes.slice(dataStart, dataStart + compressedSize);

    let contents;
    if (method === 0) contents = raw;
    else if (method === 8) contents = await inflateRaw(raw, name, maxEntryBytes);
    else throw unsupported(`"${name}" uses compression method ${method}, which is not supported here`);

    if (contents.length !== uncompressedSize) {
      throw new ZipError(`"${name}" declared ${uncompressedSize} bytes but holds ${contents.length}`);
    }
    if (crc32(contents) !== crc) throw new ZipError(`"${name}" failed its CRC-32 check`);

    total += contents.length;
    if (total > maxTotalBytes) {
      throw unsupported(
        `this archive holds more than the ${maxTotalBytes} bytes of uncompressed content this reader `
        + 'will keep in memory at once',
      );
    }

    entries.set(name, contents);
    order.push(name);
    compressedSizes.set(name, compressedSize);
    crcs.set(name, crc);
  }

  return { entries, order, compressed: compressedSizes, crc: crcs };
}
