/**
 * The container. A receipt is a ZIP, so every claim the format makes about bytes rests on
 * this reader being exact - and on it being exact about archives written by *other* tools,
 * which is why the DEFLATE test builds one by hand rather than using this project's own
 * writer.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync, gunzipSync } from 'node:zlib';

import { crc32, readZip, writeZip, ZipError, dosDateTime } from '../src/zip.mjs';
import { storeGzip } from '../src/gzip.mjs';

const bytes = (value) => new TextEncoder().encode(value);
const text = (value) => new TextDecoder().decode(value);

/** The offset the EOCD says the central directory starts at. */
function centralDirectoryOffset(archive) {
  return new DataView(archive.buffer, archive.byteOffset, archive.byteLength)
    .getUint32(archive.length - 22 + 16, true);
}

/** Where an entry's data begins, according to the local header. */
function dataOffset(archive) {
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  return 30 + view.getUint16(26, true) + view.getUint16(28, true);
}

test('a written archive reads back with the same entries', () => {
  const archive = writeZip([['a.txt', bytes('first')], ['dir/b.bin', bytes('second')]]);
  const { entries, order } = readZip(archive);
  assert.deepEqual(order, ['a.txt', 'dir/b.bin']);
  assert.equal(text(entries.get('a.txt')), 'first');
  assert.equal(text(entries.get('dir/b.bin')), 'second');
});

test('writing is deterministic: no clock, no ordering surprises', () => {
  const plan = [['one', bytes('1')], ['two', bytes('2')]];
  assert.deepEqual(writeZip(plan), writeZip(plan));
  assert.notDeepEqual(
    writeZip(plan),
    writeZip(plan, { date: new Date(Date.UTC(2027, 5, 5)) }),
    'the timestamp must actually be written',
  );
});

test('an archive that is not an archive is refused, by name', () => {
  let error = null;
  try {
    readZip(bytes('a sentence, not an archive'));
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof ZipError);
  assert.match(error.message, /not a ZIP/);
});

test('a single flipped byte in an entry is caught by the CRC', () => {
  const archive = writeZip([['payload.txt', bytes('the exact bytes that were signed')]]);
  archive[dataOffset(archive) + 4] ^= 0x01;
  assert.throws(() => readZip(archive), /failed its CRC-32 check/);
});

test('the local header decides where data starts, not the central directory', () => {
  // A writer that puts an extra field in the local header only is legal, and reading it
  // with the central directory's lengths is how a verifier reports a digest mismatch for
  // content that never changed.
  const archive = withLocalExtraField(writeZip([['x.txt', bytes('payload')]]), 4);
  assert.equal(text(readZip(archive).entries.get('x.txt')), 'payload');
});

test('a real DEFLATE archive, as other tools write them, reads correctly', () => {
  const archive = deflatedZip('archive/data.warc.gz', bytes('deflate me, I am a record'));
  assert.equal(
    text(readZip(archive).entries.get('archive/data.warc.gz')),
    'deflate me, I am a record',
  );
});

test('an unsupported compression method is refused rather than guessed at', () => {
  const archive = deflatedZip('x.bin', bytes('payload'));
  const central = centralDirectoryOffset(archive);
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  view.setUint16(8, 12, true); // local header: bzip2
  view.setUint16(central + 10, 12, true); // central directory
  assert.throws(() => readZip(archive), /compression method 12/);
});

test('the fixture gzip is byte-identical every time, and decompresses', () => {
  const payload = bytes('WARC/1.0\r\nWARC-Type: response\r\n\r\nHello.');
  const first = storeGzip(payload);
  const second = storeGzip(payload);
  assert.deepEqual(first, second);
  // The OS byte and the mtime are pinned, so a recorded fixture digest does not depend on
  // the machine or the zlib build that produced it. This is the whole reason the writer
  // exists - see D-010.
  assert.equal(first[9], 0xff);
  assert.equal(first[4] | first[5] | first[6] | first[7], 0, 'the mtime is zeroed');
  assert.deepEqual(new Uint8Array(gunzipSync(first)), payload);
});

test('the stored-block gzip wraps payloads larger than one block correctly', () => {
  const payload = bytes('x'.repeat(200_000));
  assert.deepEqual(new Uint8Array(gunzipSync(storeGzip(payload))), payload);
});

test('the stored-block gzip is a real gzip stream, not just its own reader', () => {
  const payload = bytes('round trip through zlib');
  // zlib decodes it, so any other implementation will too.
  assert.deepEqual(new Uint8Array(gunzipSync(storeGzip(payload))), payload);
  assert.equal(storeGzip(payload)[2], 8, 'compression method: deflate');
});

test('CRC-32 matches the reference value for a known input', () => {
  // The check value every CRC-32 implementation reproduces for "123456789".
  assert.equal(crc32(bytes('123456789')), 0xcbf43926);
});

test('DOS timestamps are clamped to the format, not to the calendar', () => {
  assert.deepEqual(
    dosDateTime(new Date(Date.UTC(1970, 0, 1))),
    dosDateTime(new Date(Date.UTC(1980, 0, 1))),
  );
});

/**
 * Build a ZIP the way other tools do: DEFLATE, no extra fields.
 * @param {string} name
 * @param {Uint8Array} contents
 * @returns {Uint8Array}
 */
function deflatedZip(name, contents) {
  const nameBytes = new TextEncoder().encode(name);
  const deflated = new Uint8Array(deflateRawSync(contents));
  const crc = crc32(contents);

  const local = new Uint8Array(30 + nameBytes.length + deflated.length);
  const lv = new DataView(local.buffer);
  lv.setUint32(0, 0x04034b50, true);
  lv.setUint16(4, 20, true);
  lv.setUint16(6, 0x0800, true);
  lv.setUint16(8, 8, true); // deflate
  lv.setUint16(12, 0x0021, true); // 1 January 1980
  lv.setUint32(14, crc, true);
  lv.setUint32(18, deflated.length, true);
  lv.setUint32(22, contents.length, true);
  lv.setUint16(26, nameBytes.length, true);
  local.set(nameBytes, 30);
  local.set(deflated, 30 + nameBytes.length);

  const central = new Uint8Array(46 + nameBytes.length);
  const cv = new DataView(central.buffer);
  cv.setUint32(0, 0x02014b50, true);
  cv.setUint16(4, 20, true);
  cv.setUint16(6, 20, true);
  cv.setUint16(8, 0x0800, true);
  cv.setUint16(10, 8, true);
  cv.setUint16(14, 0x0021, true);
  cv.setUint32(16, crc, true);
  cv.setUint32(20, deflated.length, true);
  cv.setUint32(24, contents.length, true);
  cv.setUint16(28, nameBytes.length, true);
  central.set(nameBytes, 46);

  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, 1, true);
  ev.setUint16(10, 1, true);
  ev.setUint32(12, central.length, true);
  ev.setUint32(16, local.length, true);

  const out = new Uint8Array(local.length + central.length + eocd.length);
  out.set(local, 0);
  out.set(central, local.length);
  out.set(eocd, local.length + central.length);
  return out;
}

/**
 * Add an extra field to the *local* header only, which shifts where the data starts
 * without changing the central directory. Exact on purpose: only the local extra length
 * and the EOCD's central-directory offset move.
 *
 * @param {Uint8Array} archive
 * @param {number} extraBytes
 * @returns {Uint8Array}
 */
function withLocalExtraField(archive, extraBytes) {
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  const start = 30 + view.getUint16(26, true);
  const out = new Uint8Array(archive.length + extraBytes);
  out.set(archive.subarray(0, start), 0);
  out.set(archive.subarray(start), start + extraBytes);

  const outView = new DataView(out.buffer, out.byteOffset, out.byteLength);
  outView.setUint16(28, extraBytes, true);
  outView.setUint32(
    out.length - 22 + 16,
    view.getUint32(archive.length - 22 + 16, true) + extraBytes,
    true,
  );
  return out;
}
