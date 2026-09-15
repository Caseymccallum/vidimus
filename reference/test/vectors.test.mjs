/**
 * The conformance vectors as a test: the record on disk must equal what the code produces
 * now, and the fixtures must rebuild to the digests the record names.
 *
 * This is deliberately the same assertion `npm run vectors:check` makes. The script exists
 * so a CI job (or a person without `node --test`) can run it alone; the test exists so
 * `npm test` cannot pass while the vectors are stale. Both run in `npm run verify`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildVectors, compareDocument } from '../src/vectors.mjs';
import { CHECKS, VERIFIER_VERSION } from '../src/verify.mjs';
import { SPEC_VERSION } from '../src/fixtures.mjs';
import { sha256 } from '../src/digest.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const vectorsPath = join(root, 'spec', 'vectors', 'receipt-vectors.json');
const committed = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const { document, fixtures, problems } = await buildVectors();

test('every case still matches the expectation written down in cases.mjs', () => {
  assert.deepEqual(problems, []);
});

test('the recorded vectors are exactly what the implementation produces now', () => {
  const diff = compareDocument(committed, document);
  assert.deepEqual(
    diff,
    [],
    'a recorded answer moved. If the change is intended, re-record with '
    + '`node reference/src/vectors.mjs --write` and say why in the commit.',
  );
});

test('every fixture rebuilds to the digest the record names', () => {
  for (const vector of committed.vectors) {
    const bytes = fixtures.get(vector.fixture.file);
    assert.ok(bytes instanceof Uint8Array, `${vector.id}: fixture was not built`);
    assert.equal(
      sha256(bytes),
      vector.fixture.sha256,
      `${vector.id}: the fixture changed, so its recorded digest is meaningless`,
    );
    assert.equal(bytes.length, vector.fixture.bytes, `${vector.id}: fixture length changed`);
  }
});

test('the record carries the versions it was made with', () => {
  assert.equal(committed.spec_version, SPEC_VERSION);
  assert.equal(committed.verifier_version, VERIFIER_VERSION);
  assert.equal(document.vectors.length, committed.vectors.length);
});

test('the record lists the checks, so a reader can see what a verdict contains', () => {
  assert.deepEqual(
    committed.checks.map((check) => check.id),
    CHECKS.map((check) => check.id),
  );
  // And the recorded verdicts only ever name checks from that list.
  const known = new Set(CHECKS.map((check) => check.id));
  for (const vector of committed.vectors) {
    for (const id of Object.keys(vector.verdict.checks)) {
      assert.ok(known.has(id), `${vector.id} records a check named ${id}, which is not declared`);
    }
  }
});

test('every vector says what it is for', () => {
  for (const vector of committed.vectors) {
    assert.ok(vector.description.length > 10, `${vector.id} has no description`);
    assert.ok(vector.proves.length > 20, `${vector.id} does not say what it proves`);
  }
  const ids = committed.vectors.map((vector) => vector.id);
  assert.equal(new Set(ids).size, ids.length, 'vector ids must be unique');
});

test('the worked examples in the documentation are real ones', () => {
  // A transcript in a README is a claim, and a claim nobody checks goes stale within a month. Each
  // document quotes the claim hash of the `valid-signed` fixture; this asserts that the quoted value
  // is the one the record holds, so a rename or a fixture change cannot leave prose behind.
  const vector = committed.vectors.find((entry) => entry.id === 'valid-signed');
  assert.ok(vector !== undefined, 'the valid-signed vector must exist');
  const short = vector.verdict.claim_hash.slice(0, 8);

  for (const file of ['README.md', 'docs/RECEIPT-SPEC.md']) {
    const text = readFileSync(join(root, file), 'utf8');
    const quoted = [...text.matchAll(/claim ([0-9a-f]{8})…/g)].map((match) => match[1]);
    assert.ok(quoted.length > 0, `${file} shows no worked example`);
    for (const value of quoted) {
      assert.equal(
        value,
        short,
        `${file} quotes claim ${value}…, which no fixture produces (expected ${short}…)`,
      );
    }
  }
});
