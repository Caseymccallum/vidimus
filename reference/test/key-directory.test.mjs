/**
 * Key directories: who a key belongs to.
 *
 * The whole point of this file is the difference between two sentences that a receipt cannot tell apart on
 * its own: *this key signed this claim* (checkable, and checked) and *this key is Example Org's* (a
 * statement somebody has to make). A directory is how the person checking makes it.
 *
 * The last test matters as much as the first: a directory that cannot be read must leave key trust exactly
 * where it was, and must not damage a receipt that had nothing to do with the mistake.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  KeyDirectoryError, keyIdOf, lookUpKey, readKeyDirectory, validityAt,
} from '../src/key-directory.mjs';
import { verifyReceipt } from '../src/verify-node.mjs';
import { buildReceipt, signer, stranger } from '../src/fixtures.mjs';
import { toBase64Url } from '../src/digest.mjs';

/** A directory with one entry, for the fixture signer. */
function directoryFor(key, extra = {}) {
  const publicKey = toBase64Url(key.publicKey);
  return {
    kind: 'receipt-key-directory',
    spec_version: '0.1.0',
    name: 'Example Org records',
    keys: [{
      key_id: keyIdOf(publicKey),
      public_key: publicKey,
      name: 'Example Org',
      ...extra,
    }],
  };
}

test('a directory is read, and a key id in it is found', () => {
  const key = signer();
  const directory = readKeyDirectory(directoryFor(key));
  assert.deepEqual(directory.problems, []);
  assert.equal(directory.name, 'Example Org records');

  const entry = lookUpKey(directory, key.keyId);
  assert.equal(entry?.name, 'Example Org');
  assert.equal(entry?.key_id, key.keyId);
});

test('a directory cannot disagree with itself about which key an id names', () => {
  const key = signer();
  const publicKey = toBase64Url(key.publicKey);
  const directory = readKeyDirectory({
    ...directoryFor(key),
    keys: [{ key_id: stranger().keyId, public_key: publicKey, name: 'Somebody Else' }],
  });

  assert.equal(directory.keys.size, 0);
  assert.equal(directory.problems.length, 1);
  assert.match(directory.problems[0], /derives/);
});

test('a directory that says two things about one key is refused, entry by entry', () => {
  const key = signer();
  const publicKey = toBase64Url(key.publicKey);
  const entry = { key_id: keyIdOf(publicKey), public_key: publicKey, name: 'Twice' };
  const directory = readKeyDirectory({ ...directoryFor(key), keys: [entry, { ...entry }] });

  assert.equal(directory.keys.size, 1, 'the first entry is usable');
  assert.match(directory.problems[0], /two things about one key/);
});

test('a file that is not a directory is refused by name', () => {
  assert.throws(() => readKeyDirectory({ keys: [] }), KeyDirectoryError);
  assert.throws(() => readKeyDirectory({ kind: 'something-else', spec_version: '0.1.0', keys: [] }), /kind/);
  assert.throws(() => readKeyDirectory({ kind: 'receipt-key-directory', spec_version: '0.1.0' }), /keys/);
  assert.throws(() => readKeyDirectory('not even an object'), /JSON object/);
});

test('a validity window is compared against the claim, and reported either way', () => {
  const entry = {
    key_id: 'x', public_key: 'x', name: null, email: null, note: null,
    valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z',
  };
  assert.equal(validityAt(entry, '2026-06-01T00:00:00Z'), 'inside');
  assert.equal(validityAt(entry, '2025-12-31T23:59:59Z'), 'outside');
  assert.equal(validityAt(entry, '2027-01-01T00:00:01Z'), 'outside');
  assert.equal(validityAt({ ...entry, valid_from: null, valid_until: null }, '2026-06-01T00:00:00Z'), 'not_stated');
  assert.equal(validityAt(entry, null), 'no_time');
});

test('a directory turns "this key signed it" into "this key is theirs"', async () => {
  const key = signer();
  const bytes = buildReceipt().bytes;

  const without = await verifyReceipt(bytes);
  assert.equal(without.attribution.key_trusted, 'not_checked');
  assert.equal(without.attribution.trusted_by, null);

  const with_ = await verifyReceipt(bytes, { keyDirectory: directoryFor(key) });
  assert.equal(with_.attribution.key_trusted, 'trusted');
  assert.equal(with_.attribution.trusted_by.name, 'Example Org');
  // The claim's own `signer` field is still reported, and still labelled as what it is.
  assert.equal(with_.attribution.signer, 'Fixture Signer <fixture@example.org>');
  assert.ok(with_.summary.some((line) => line.includes('Example Org')));
});

test('a key the directory has never heard of is untrusted, not broken', async () => {
  const verdict = await verifyReceipt(buildReceipt().bytes, { keyDirectory: directoryFor(stranger()) });
  assert.equal(verdict.attribution.key_trusted, 'untrusted');
  assert.equal(verdict.attribution.trusted_by, null);
  assert.equal(verdict.verified, true, 'an unknown key is not a bad receipt');
});

test('a claim outside the directory window is caveated, never failed', async () => {
  const key = signer();
  const verdict = await verifyReceipt(buildReceipt().bytes, {
    keyDirectory: directoryFor(key, { valid_from: '2027-01-01T00:00:00Z' }),
  });

  assert.equal(verdict.attribution.trusted_by.valid_at_claimed_time, 'outside');
  assert.ok(verdict.caveats.some((line) => line.includes('valid from 2027-01-01T00:00:00Z')));
  // Both values are the author's own: the claim's time is self-asserted, so nothing here is a failure.
  assert.equal(verdict.verified, true);
});

test('a directory that cannot be read leaves the receipt exactly as it was', async () => {
  const verdict = await verifyReceipt(buildReceipt().bytes, { keyDirectory: { kind: 'not-a-directory' } });
  assert.equal(verdict.attribution.key_trusted, 'not_checked');
  assert.equal(verdict.verified, true);
  assert.ok(verdict.caveats.some((line) => line.includes('key directory could not be read')));
});
