/**
 * The ZIP writer: stored entries only, from a plan rather than a clock.
 *
 * **Browser-safe on purpose.** This is the module a capturing extension bundles, so it imports nothing
 * from Node - no `zlib`, no `Buffer` - and only uses `TextEncoder`, `DataView` and plain arithmetic,
 * all of which exist in every browser (D-018). `scripts/check-browser-safe.mjs` enforces that, because
 * a stray import here is a build error somebody discovers at the worst moment otherwise.
 *
 * Stored, not deflated, and that is a property of the format rather than a limitation of the writer: a
 * receipt's payloads are digested and signed elsewhere, so a container that compresses them only adds
 * a way for two implementations to disagree about the bytes of `receipt.json` while both being "the
 * same document".
 *
 * `date` is a parameter, not `new Date()`, so writing the same plan twice produces identical bytes.
 * That is what lets the conformance vectors carry a recorded digest of a fixture instead of a recipe
 * for reproducing it.
 *
 * @module zip-write
 */

import {
  CENTRAL_HEADER, END_OF_CENTRAL_DIRECTORY, LOCAL_HEADER, ZipError, crc32,
} from './zip-common.mjs';

/** Bit 11 of the general purpose flags: the file name is UTF-8. */
const FLAG_UTF8_NAMES = 0x0800;

/**
 * A DOS date/time, so a written container carries only the time it was told to carry.
 * @param {Date} date
 * @returns {{ time: number, date: number }}
 */
export function dosDateTime(date) {
  const year = Math.max(1980, date.getUTCFullYear());
  return {
    time: (date.getUTCHours() << 11) | (date.getUTCMinutes() << 5) | (date.getUTCSeconds() >> 1),
    date: ((year - 1980) << 9) | ((date.getUTCMonth() + 1) << 5) | date.getUTCDate(),
  };
}

/**
 * @param {Array<[string, Uint8Array]> | Map<string, Uint8Array>} entries
 * @param {{ date?: Date }} [options]
 * @returns {Uint8Array}
 */
export function writeZip(entries, options = {}) {
  const list = entries instanceof Map ? [...entries] : entries;
  const { time, date } = dosDateTime(options.date ?? new Date(Date.UTC(2026, 0, 1)));
  const encoder = new TextEncoder();

  let localSize = 0;
  let directorySize = 0;
  for (const [name, bytes] of list) {
    const nameLength = encoder.encode(name).length;
    if (nameLength > 0xffff) throw new ZipError(`entry name too long: ${name}`);
    if (bytes.length > 0xffffffff) throw new ZipError(`entry too large: ${name}`);
    localSize += 30 + nameLength + bytes.length;
    directorySize += 46 + nameLength;
  }

  const output = new Uint8Array(localSize + directorySize + 22);
  const view = new DataView(output.buffer);
  let cursor = 0;

  /** @type {Array<{ name: Uint8Array, crc: number, size: number, offset: number }>} */
  const written = [];

  for (const [name, bytes] of list) {
    const nameBytes = encoder.encode(name);
    const offsets = { name: nameBytes, crc: crc32(bytes), size: bytes.length, offset: cursor };

    view.setUint32(cursor, LOCAL_HEADER, true);
    view.setUint16(cursor + 4, 20, true); // version needed: 2.0
    view.setUint16(cursor + 6, FLAG_UTF8_NAMES, true);
    view.setUint16(cursor + 8, 0, true); // stored
    view.setUint16(cursor + 10, time, true);
    view.setUint16(cursor + 12, date, true);
    view.setUint32(cursor + 14, offsets.crc, true);
    view.setUint32(cursor + 18, bytes.length, true);
    view.setUint32(cursor + 22, bytes.length, true);
    view.setUint16(cursor + 26, nameBytes.length, true);
    view.setUint16(cursor + 28, 0, true); // no extra field
    output.set(nameBytes, cursor + 30);
    output.set(bytes, cursor + 30 + nameBytes.length);

    cursor += 30 + nameBytes.length + bytes.length;
    written.push(offsets);
  }

  const directoryStart = cursor;
  for (const entry of written) {
    view.setUint32(cursor, CENTRAL_HEADER, true);
    view.setUint16(cursor + 4, 20, true); // version made by
    view.setUint16(cursor + 6, 20, true); // version needed
    view.setUint16(cursor + 8, FLAG_UTF8_NAMES, true);
    view.setUint16(cursor + 10, 0, true); // stored
    view.setUint16(cursor + 12, time, true);
    view.setUint16(cursor + 14, date, true);
    view.setUint32(cursor + 16, entry.crc, true);
    view.setUint32(cursor + 20, entry.size, true);
    view.setUint32(cursor + 24, entry.size, true);
    view.setUint16(cursor + 28, entry.name.length, true);
    view.setUint16(cursor + 30, 0, true); // no extra field
    view.setUint16(cursor + 32, 0, true); // no comment
    view.setUint16(cursor + 34, 0, true); // first disk
    view.setUint16(cursor + 36, 0, true); // internal attributes
    view.setUint32(cursor + 38, 0, true); // external attributes
    view.setUint32(cursor + 42, entry.offset, true);
    output.set(entry.name, cursor + 46);
    cursor += 46 + entry.name.length;
  }

  view.setUint32(cursor, END_OF_CENTRAL_DIRECTORY, true);
  view.setUint16(cursor + 4, 0, true); // this disk
  view.setUint16(cursor + 6, 0, true); // disk with the central directory
  view.setUint16(cursor + 8, written.length, true);
  view.setUint16(cursor + 10, written.length, true);
  view.setUint32(cursor + 12, cursor - directoryStart, true);
  view.setUint32(cursor + 16, directoryStart, true);
  view.setUint16(cursor + 20, 0, true); // no comment

  return output;
}
