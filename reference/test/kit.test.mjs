/**
 * The conformance kit: what somebody else needs in order to check these answers.
 *
 * The vectors have always recorded a fixture's digest - and the fixtures were never shipped, because they
 * are regenerated from a recipe here. That is fine for *this* repository and useless for a second
 * implementation, which cannot check a digest it has no file for: it would have to reimplement
 * `fixtures.mjs` before it could write a line of its own reader. A kit is the missing half.
 *
 * These tests are therefore about a promise to strangers: emit a kit, check it the way they would, and make
 * sure it fails when the fixtures it ships are not the fixtures it describes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildVectors, checkKit, emitKit, kitReadme } from '../src/vectors.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * Run something with a kit in a temporary directory, and clean up whatever happens.
 *
 * @param {(directory: string) => Promise<void>} body
 */
async function withKit(body) {
  const directory = mkdtempSync(join(tmpdir(), 'vidimus-kit-'));
  try {
    await body(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('a kit is emitted, and stands on its own', async () => {
  await withKit(async (directory) => {
    const { document, fixtures, problems } = await buildVectors();
    assert.deepEqual(problems, [], 'the implementation must match its own expectations first');
    assert.equal(emitKit(directory, document, fixtures), 0);

    // What a stranger needs, and nothing that needs this repository: the fixtures, the answers, and a README
    // that says what to do with them.
    assert.deepEqual(readdirSync(directory).sort(), ['README.md', 'fixtures', 'receipt-vectors.json']);
    assert.equal(readdirSync(join(directory, 'fixtures')).length, fixtures.size);

    // The record travels with it byte for byte, so a kit cannot describe answers the repository does not.
    assert.equal(
      readFileSync(join(directory, 'receipt-vectors.json'), 'utf8'),
      readFileSync(join(root, 'spec', 'vectors', 'receipt-vectors.json'), 'utf8'),
    );

    // And checking it takes the path a stranger takes: files from disk, hashed against the kit's record.
    assert.equal(await checkKit(directory), 0);
  });
});

test('a kit whose fixture has been altered fails against its own record', async () => {
  await withKit(async (directory) => {
    const { document, fixtures } = await buildVectors();
    emitKit(directory, document, fixtures);

    // One byte, in the middle of the container: the digest is the only thing that notices, which is exactly
    // what a conformance kit is for.
    const path = join(directory, 'fixtures', 'valid-signed.receipt');
    const bytes = readFileSync(path);
    bytes[40] ^= 0x01;
    writeFileSync(path, bytes);

    assert.equal(await checkKit(directory), 1);
  });
});

test('a kit missing a fixture fails rather than skipping it', async () => {
  await withKit(async (directory) => {
    const { document, fixtures } = await buildVectors();
    emitKit(directory, document, fixtures);
    unlinkSync(join(directory, 'fixtures', 'valid-signed.receipt'));

    // A suite that quietly checks 40 of 41 things is the failure mode this whole project is arranged around.
    assert.equal(await checkKit(directory), 1);
  });
});

test('the kit README says what to do with the files', () => {
  const text = kitReadme({ spec_version: '0.1.0', verifier_version: '0.1.0' }, 41);
  for (const phrase of [
    'check that its SHA-256',
    'field by field',
    'Reasons are deliberately excluded',
    '`options` is what the verdict was produced with',
    'What is not in here',
    'specification 0.1.0',
  ]) {
    assert.ok(text.includes(phrase), `the kit README should mention "${phrase}"`);
  }
});
