/**
 * The pure SHA-256, checked against the published vectors, against the awkward input lengths where
 * padding bugs live, and against the runtime's own implementation.
 *
 * That last comparison is the point. Two implementations of one primitive are usually a mistake; here
 * it is the price of having a synchronous digest in a browser, and this file is what stops the price
 * turning into a bug (D-019).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { sha256 } from '../src/sha256.mjs';
import { DEFAULT_HTML, waczBytes, waczEntries } from '../src/fixtures.mjs';
import { sha256 as runtimeSha256, utf8 } from '../src/digest.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const runtimeDigest = (bytes) => createHash('sha256').update(Buffer.from(bytes)).digest('hex');

test('the published vectors', () => {
  assert.equal(
    hex(sha256(utf8(''))),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
  assert.equal(
    hex(sha256(utf8('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
  assert.equal(
    hex(sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  );
});

test('a million characters of the same letter', () => {
  const million = new Uint8Array(1_000_000).fill(0x61);
  assert.equal(
    hex(sha256(million)),
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
  );
});

test('every length around a block boundary agrees with the runtime', () => {
  // 55, 56, 63 and 64 are where the padding needs another block, and where a hand-written
  // implementation that was never tested at those lengths quietly returns the wrong digest.
  for (const length of [0, 1, 3, 31, 32, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000]) {
    const input = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) input[index] = (index * 7 + 13) & 0xff;
    assert.equal(hex(sha256(input)), runtimeDigest(input), `length ${length}`);
  }
});

test('it agrees with the digest the rest of this project uses, on real fixture bytes', () => {
  assert.equal(hex(sha256(utf8(DEFAULT_HTML))), runtimeSha256(utf8(DEFAULT_HTML)));
  assert.equal(hex(sha256(waczBytes(waczEntries({})))), runtimeSha256(waczBytes(waczEntries({}))));
});

test('a digest is always thirty-two bytes, whatever went in', () => {
  for (const input of [new Uint8Array(0), utf8('x'), new Uint8Array(4096)]) {
    assert.equal(sha256(input).length, 32);
  }
});
