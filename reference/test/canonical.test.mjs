/**
 * The canonical form is the foundation everything else stands on, so it is tested against
 * the *rules* rather than against examples of output: each test below names one rule from
 * `docs/RECEIPT-SPEC.md` section 4 and proves the implementation enforces it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalise,
  assertCanonicalBytes,
  isCanonicalFixedPoint,
  CanonicalJsonError,
  MAX_DEPTH,
} from '../src/canonical.mjs';

test('keys are sorted, so insertion order cannot change the bytes', () => {
  const a = { zebra: 1, apple: 2, mango: 3 };
  const b = { mango: 3, apple: 2, zebra: 1 };
  assert.equal(canonicalise(a), '{"apple":2,"mango":3,"zebra":1}');
  assert.equal(canonicalise(a), canonicalise(b));
});

test('there is no whitespace anywhere', () => {
  assert.equal(canonicalise({ a: [1, 2], b: { c: 'd' } }), '{"a":[1,2],"b":{"c":"d"}}');
});

test('non-ASCII is passed through, not escaped', () => {
  assert.equal(canonicalise({ title: 'café — naïve' }), '{"title":"café — naïve"}');
});

test('a float is refused by name, with the path to it', () => {
  let error = null;
  try {
    canonicalise({ capture: { bytes: 12.5 } });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof CanonicalJsonError, 'expected a CanonicalJsonError');
  assert.match(error.message, /non-integer number/);
  assert.match(error.message, /at \.capture\.bytes/);
});

test('negative zero is refused, because it is not the same bytes as zero', () => {
  assert.throws(() => canonicalise({ a: -0 }), /-0 is not representable/);
  assert.equal(canonicalise({ a: 0 }), '{"a":0}');
});

test('integers beyond the safe range are refused rather than rounded', () => {
  assert.throws(() => canonicalise({ a: 2 ** 53 }), /outside the safe range/);
  assert.equal(canonicalise({ a: Number.MAX_SAFE_INTEGER }), `{"a":${Number.MAX_SAFE_INTEGER}}`);
});

test('an unpaired surrogate is refused at the door', () => {
  assert.throws(() => canonicalise({ a: '\ud800' }), /unpaired high surrogate/);
  assert.throws(() => canonicalise({ a: '\udc00' }), /unpaired low surrogate/);
  // A correctly paired surrogate is an ordinary character and must pass.
  assert.equal(canonicalise({ a: '😀' }), '{"a":"😀"}');
});

test('values with no JSON representation are refused', () => {
  assert.throws(() => canonicalise({ a: undefined }), /undefined is not representable/);
  assert.throws(() => canonicalise({ a: () => {} }), /function is not representable/);
  assert.throws(() => canonicalise({ a: 1n }), /bigint is not representable/);
  assert.throws(() => canonicalise({ a: new Date() }), /only plain objects and arrays/);
  assert.throws(() => canonicalise({ a: new Map() }), /only plain objects and arrays/);
});

test('nesting is capped, so a hostile claim cannot exhaust the stack', () => {
  let deep = 0;
  for (let i = 0; i <= MAX_DEPTH + 1; i += 1) deep = { nested: deep };
  assert.throws(() => canonicalise(deep), /nesting deeper than/);
});

test('the canonical form is a fixed point', () => {
  const value = { b: [1, { a: 'x' }], a: null };
  assert.ok(isCanonicalFixedPoint(value));
  assert.equal(canonicalise(JSON.parse(canonicalise(value))), canonicalise(value));
});

test('duplicate keys in the delivered bytes are caught by the byte comparison, not the parser', () => {
  // JSON.parse silently keeps the last of the two; two readers of the raw bytes could
  // disagree about which value was signed, which is exactly the gap this closes.
  const delivered = new TextEncoder().encode('{"url":"https://a.example","url":"https://b.example"}');
  const parsed = JSON.parse(new TextDecoder().decode(delivered));
  assert.equal(parsed.url, 'https://b.example');

  const canonical = canonicalise(parsed);
  const outcome = assertCanonicalBytes(delivered, canonical);
  assert.equal(outcome.ok, false);
  assert.match(outcome.reason, /not in canonical form/);
});

test('bytes that are canonical pass, and a BOM does not', () => {
  const value = { a: 1 };
  const canonical = canonicalise(value);
  const bytes = new TextEncoder().encode(canonical);
  assert.deepEqual(assertCanonicalBytes(bytes, canonical), { ok: true });

  const withBom = new TextEncoder().encode(`\ufeff${canonical}`);
  const outcome = assertCanonicalBytes(withBom, canonical);
  assert.equal(outcome.ok, false);
  assert.match(outcome.reason, /byte order mark/);
});
