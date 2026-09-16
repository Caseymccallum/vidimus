/**
 * Size limits: a receipt is untrusted input, and both of its layers expand.
 *
 * A `.receipt` is a ZIP, the WACZ inside it is another ZIP, and the WARC inside that is gzipped - so a few
 * kilobytes can ask a verifier for gigabytes. These tests are written against archives built by hand, with
 * sizes declared separately from the bytes, because that is the only way to write the attack down: an
 * archive that says it holds a terabyte, and an archive that says it holds a kilobyte and then does not.
 *
 * The last test is the one that matters most: a limit must reach a verdict as **this verifier's** limit
 * rather than as a fault in somebody's receipt (D-021).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';

import { LIMITS, verifyReceipt } from '../src/verify-node.mjs';
import { readZip } from '../src/zip.mjs';
import { crc32 } from '../src/zip-common.mjs';
import { utf8 } from '../src/encode.mjs';
import { buildReceipt } from '../src/fixtures.mjs';
import { canonicalise } from '../src/canonical.mjs';

/**
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
function join(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * A ZIP with one entry, deflated, whose declared sizes are whatever the caller says.
 *
 * `writeZip` only writes stored entries, which cannot lie about expanding - so the attack needs an archive
 * assembled by hand. The declarations are the whole point of the test.
 *
 * @param {string} name
 * @param {Uint8Array} contents
 * @param {{ uncompressed?: number, compressed?: number }} [declared]
 * @returns {Uint8Array}
 */
function zipAround(name, contents, declared = {}) {
  const nameBytes = utf8(name);
  const deflated = new Uint8Array(deflateRawSync(contents));
  const uncompressed = declared.uncompressed ?? contents.length;
  const compressed = declared.compressed ?? deflated.length;
  const crc = crc32(contents);

  const local = new Uint8Array(30 + nameBytes.length);
  const localView = new DataView(local.buffer);
  localView.setUint32(0, 0x04034b50, true);
  localView.setUint16(4, 20, true);
  localView.setUint16(8, 8, true);
  localView.setUint32(14, crc, true);
  localView.setUint32(18, compressed, true);
  localView.setUint32(22, uncompressed, true);
  localView.setUint16(26, nameBytes.length, true);
  local.set(nameBytes, 30);

  const central = new Uint8Array(46 + nameBytes.length);
  const centralView = new DataView(central.buffer);
  centralView.setUint32(0, 0x02014b50, true);
  centralView.setUint16(4, 20, true);
  centralView.setUint16(6, 20, true);
  centralView.setUint16(10, 8, true);
  centralView.setUint32(16, crc, true);
  centralView.setUint32(20, compressed, true);
  centralView.setUint32(24, uncompressed, true);
  centralView.setUint16(28, nameBytes.length, true);
  central.set(nameBytes, 46);

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, 1, true);
  eocdView.setUint16(10, 1, true);
  eocdView.setUint32(12, central.length, true);
  eocdView.setUint32(16, local.length + deflated.length, true);

  return join([local, deflated, central, eocd]);
}

/** Two megabytes of zeros: a few kilobytes deflated, which is what makes a bomb a bomb. */
const BOMB = new Uint8Array(2 * 1024 * 1024);

test('a declaration larger than the cap is refused before anything is inflated', () => {
  // The honest bomb: it says how large it is, and the answer is no, without a byte being inflated.
  const archive = zipAround('bomb.bin', BOMB, { uncompressed: 1024 * 1024 * 1024 });
  assert.throws(
    () => readZip(archive, { maxEntryBytes: 4096 }),
    (error) => error.code === 'unsupported' && /declares 1073741824 bytes/.test(error.message),
  );
});

test('the inflater stops at the ceiling even when the declaration lies', () => {
  // The dishonest one: it claims a kilobyte and expands to two megabytes. A reader that trusted the
  // declaration would allocate first and notice afterwards, which is why the ceiling is given to the
  // inflater as well.
  const archive = zipAround('bomb.bin', BOMB, { uncompressed: 1024 });
  assert.throws(
    () => readZip(archive, { maxEntryBytes: 4096 }),
    (error) => error.code === 'unsupported' && /expands past/.test(error.message),
  );
});

test('a container that lists more entries than the reader will walk is refused', () => {
  const archive = zipAround('one.bin', utf8('x'));
  assert.throws(
    () => readZip(archive, { maxEntries: 0 }),
    (error) => error.code === 'unsupported' && /stops at 0/.test(error.message),
  );
});

test('the total is capped across entries, not only per entry', () => {
  const archive = zipAround('one.bin', new Uint8Array(1024));
  assert.throws(
    () => readZip(archive, { maxEntryBytes: 4096, maxTotalBytes: 100 }),
    (error) => error.code === 'unsupported' && /in memory at once/.test(error.message),
  );
});

test('no ceiling is the default, so a producer reading its own file is not capped', () => {
  // A producer sealing a capture the user chose is not defending against that user. What happens instead
  // is the ordinary check: the archive lied about its size, and the reader says so after reading it.
  const archive = zipAround('own.bin', BOMB, { uncompressed: 1024 * 1024 * 1024 });
  assert.throws(() => readZip(archive), /declared 1073741824 bytes but holds/);
});

test('a normal receipt is comfortably inside the limits', async () => {
  const verdict = await verifyReceipt(buildReceipt().bytes);
  assert.equal(verdict.verified, true);
  assert.equal(verdict.levels.L0.status, 'pass');
  // The extension will not capture more than 8 MB of page, so the verifier's per-entry ceiling has to be
  // larger than that: a limit that refused every browser receipt would be a bug wearing a cap.
  assert.ok(LIMITS.maxEntryBytes >= 8 * 1024 * 1024);
  assert.ok(LIMITS.maxTotalBytes >= LIMITS.maxEntryBytes);
});

test('a capture that is a bomb is this verifier\'s limit, not a failure', async () => {
  // End to end, through a verdict: the receipt's own container is perfectly fine, and the WACZ inside it
  // declares two gigabytes. The check that reports it must not say the receipt is broken, because it is
  // not: it is larger than this implementation will inflate, and the reason names the number so that a
  // caller who needs more knows what to raise.
  const bomb = zipAround('archive/data.warc.gz', utf8('not really a warc'), {
    uncompressed: 2 ** 31,
  });
  const verdict = await verifyReceipt(buildReceipt({ wacz: bomb }).bytes);
  const check = verdict.checks.find((candidate) => candidate.id === 'capture.wacz.readable');

  assert.equal(check.status, 'unsupported');
  assert.equal(verdict.levels.L0.status, 'unsupported');
  assert.equal(verdict.verified, false);
  assert.equal(verdict.exit_code, 1, 'nothing failed, and nothing was proven either');
  assert.match(check.reason, /declares 2147483648 bytes/);
});
