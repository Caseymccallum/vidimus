/**
 * Generate, assert and check the conformance vectors.
 *
 *   node reference/src/vectors.mjs --write    # record (or re-record) the vectors
 *   node reference/src/vectors.mjs --check    # prove the implementation still matches
 *
 * `--check` is what runs in CI and in `npm run verify`. It rebuilds every fixture from its
 * recipe in memory and compares the resulting verdict against the committed file, field
 * by field. Two different things therefore have to stay true for it to pass: the fixtures
 * must still hash to their recorded digests, and the verifier must still return the
 * recorded verdicts.
 *
 * The fixtures themselves are not committed (`.gitignore` explains why): the digests in
 * the vectors are the record, and rebuilding them is the point. A recorded digest over a
 * fixture that is generated from a published recipe catches everything a committed blob
 * would, and stays reviewable in a diff.
 *
 * @module vectors
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CASES } from './cases.mjs';
import { CHECKS, LEVELS, VERIFIER_VERSION, verifyReceipt } from './verify-node.mjs';
import { SPEC_VERSION } from './fixtures.mjs';
import { sha256 } from './digest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const vectorsPath = join(root, 'spec', 'vectors', 'receipt-vectors.json');
const fixturesDir = join(root, 'spec', 'fixtures');

/**
 * Compare a verdict against the expectation written in `cases.mjs`.
 * @param {string} id
 * @param {ReturnType<typeof verifyReceipt>} verdict
 * @param {Record<string, any>} expect
 * @returns {string[]}
 */
function expectationProblems(id, verdict, expect) {
  const problems = [];
  const note = (message) => problems.push(`${id}: ${message}`);

  if (verdict.verified !== expect.verified) {
    note(`expected verified=${expect.verified}, got ${verdict.verified}`);
  }
  if (verdict.exit_code !== expect.exit_code) {
    note(`expected exit_code=${expect.exit_code}, got ${verdict.exit_code}`);
  }
  for (const [level, status] of Object.entries(expect.levels ?? {})) {
    if (verdict.levels[level]?.status !== status) {
      note(`expected ${level}=${status}, got ${verdict.levels[level]?.status}`);
    }
  }
  for (const [checkId, status] of Object.entries(expect.checks ?? {})) {
    const found = verdict.checks.find((check) => check.id === checkId);
    if (found === undefined) note(`expected a check named ${checkId}, and there is none`);
    else if (found.status !== status) note(`expected ${checkId}=${status}, got ${found.status}`);
  }
  if (expect.caveats !== undefined && verdict.caveats.length !== expect.caveats) {
    note(`expected ${expect.caveats} caveats, got ${verdict.caveats.length}`);
  }
  return problems;
}

/**
 * The part of a verdict worth recording: statuses, not prose.
 *
 * Reasons are deliberately excluded. A vector that fails when someone improves a
 * sentence teaches people to re-record vectors without reading them, and the moment that
 * habit forms the vectors stop being evidence. That the reasons exist and are specific is
 * asserted by a test instead.
 *
 * @param {ReturnType<typeof verifyReceipt>} verdict
 * @returns {Record<string, any>}
 */
function record(verdict) {
  const checks = {};
  for (const check of verdict.checks) {
    if (check.status !== 'pass') checks[check.id] = check.status;
  }
  return {
    verified: verdict.verified,
    exit_code: verdict.exit_code,
    // The claim hash is recorded, not just printed: it is the derived identity of a receipt, it is
    // what a signature and an anchor commit to, and it is the value the documentation quotes in its
    // worked examples. A test compares those examples against this field, so a transcript in a
    // document cannot quietly go stale.
    claim_hash: verdict.receipt.claim_hash,
    levels: Object.fromEntries(LEVELS.map((level) => [level.id, verdict.levels[level.id].status])),
    attribution: {
      status: verdict.attribution.status,
      key_trusted: verdict.attribution.key_trusted,
    },
    time_bound: verdict.time.bound,
    caveat_count: verdict.caveats.length,
    checks,
  };
}

/**
 * Build every case, assert the written-down expectation, and return the vector document.
 * @returns {{ document: Record<string, any>, fixtures: Map<string, Uint8Array>, problems: string[] }}
 */
export async function buildVectors() {
  const problems = [];
  const fixtures = new Map();
  const seen = new Set();
  const vectors = [];

  for (const testCase of CASES) {
    if (seen.has(testCase.id)) problems.push(`${testCase.id}: duplicate case id`);
    seen.add(testCase.id);

    const bytes = testCase.build();
    const verdict = await verifyReceipt(bytes, testCase.options ?? {});
    problems.push(...expectationProblems(testCase.id, verdict, testCase.expect));

    // A verdict must always describe every check, in the declared order. This is the
    // guardrail on the guardrail: if a check is added to the table and never recorded,
    // the suite says so here rather than silently testing one fewer thing.
    const ids = verdict.checks.map((check) => check.id);
    if (ids.length !== CHECKS.length) {
      problems.push(`${testCase.id}: verdict has ${ids.length} checks, expected ${CHECKS.length}`);
    }
    if (ids.join('|') !== CHECKS.map((check) => check.id).join('|')) {
      problems.push(`${testCase.id}: verdict checks are not the declared list, in order`);
    }

    const file = `${testCase.id}.receipt`;
    fixtures.set(file, bytes);
    vectors.push({
      id: testCase.id,
      description: testCase.description,
      proves: testCase.proves,
      fixture: { file, sha256: sha256(bytes), bytes: bytes.length },
      options: testCase.options ?? {},
      expect: testCase.expect,
      verdict: record(verdict),
    });
  }

  return {
    document: {
      spec_version: SPEC_VERSION,
      verifier_version: VERIFIER_VERSION,
      generations: [
        'node reference/src/vectors.mjs --write',
        'node reference/src/vectors.mjs --check   # what CI runs',
      ],
      checks: CHECKS.map((check) => ({
        id: check.id,
        level: check.level,
        description: check.description,
      })),
      vectors,
    },
    fixtures,
    problems,
  };
}

/**
 * Every difference between a committed document and the one just computed, as paths.
 *
 * A deep-equal would answer "not equal", which is useless when the vectors are the
 * evidence: the point of a failure is to say *which* recorded answer moved, because the
 * next question is always "is the implementation wrong or was the expectation wrong?".
 *
 * @param {unknown} expected
 * @param {unknown} actual
 * @param {string} [path]
 * @returns {string[]}
 */
export function differences(expected, actual, path = '') {
  if (expected === actual) return [];
  if (typeof expected !== typeof actual || expected === null || actual === null) {
    return [`${path || '<document>'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`];
  }
  if (Array.isArray(expected) || Array.isArray(actual)) {
    const left = Array.isArray(expected) ? expected : [];
    const right = Array.isArray(actual) ? actual : [];
    const out = [];
    if (left.length !== right.length) out.push(`${path}: expected ${left.length} entries, got ${right.length}`);
    for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
      out.push(...differences(left[i], right[i], `${path}[${i}]`));
    }
    return out;
  }
  if (typeof expected === 'object') {
    const keys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
    const out = [];
    for (const key of keys) {
      out.push(...differences(
        /** @type {any} */ (expected)[key],
        /** @type {any} */ (actual)[key],
        path ? `${path}.${key}` : key,
      ));
    }
    return out;
  }
  return [`${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`];
}

/**
 * @param {Record<string, any>} committed
 * @param {Record<string, any>} computed
 * @returns {string[]}
 */
export function compareDocument(committed, computed) {
  return differences(committed, computed);
}

/** @param {string} file @param {Uint8Array} bytes */
function writeFixture(file, bytes) {
  mkdirSync(fixturesDir, { recursive: true });
  writeFileSync(join(fixturesDir, file), bytes);
}

/** @returns {void} */
function main() {
  return mainAsync();
}

/** @returns {Promise<void>} */
async function mainAsync() {
  const mode = process.argv[2];
  const { document, fixtures, problems } = await buildVectors();

  if (problems.length > 0) {
    console.error('the implementation does not match the written-down expectations:');
    for (const problem of problems) console.error(`  - ${problem}`);
    console.error('\nFix the implementation, or change the expectation in reference/src/cases.mjs on purpose.');
    process.exitCode = 1;
    return;
  }

  if (mode === '--write') {
    for (const [file, bytes] of fixtures) writeFixture(file, bytes);
    mkdirSync(dirname(vectorsPath), { recursive: true });
    writeFileSync(vectorsPath, `${JSON.stringify(document, null, 2)}\n`);
    console.log(`recorded ${document.vectors.length} vectors and ${fixtures.size} fixtures`);
    console.log(`  ${vectorsPath}`);
    console.log(`  ${fixturesDir}\\*.receipt  (generated, gitignored)`);
    return;
  }

  if (mode === '--check') {
    let committed;
    try {
      committed = JSON.parse(readFileSync(vectorsPath, 'utf8'));
    } catch (error) {
      console.error(`cannot read the recorded vectors: ${error.message}`);
      console.error('run: node reference/src/vectors.mjs --write');
      process.exitCode = 1;
      return;
    }
    const diff = compareDocument(committed, document);
    if (diff.length > 0) {
      console.error(`${diff.length} recorded answer(s) no longer match:`);
      for (const line of diff.slice(0, 40)) console.error(`  - ${line}`);
      if (diff.length > 40) console.error(`  ... and ${diff.length - 40} more`);
      process.exitCode = 1;
      return;
    }
    console.log(`vectors: ${document.vectors.length} of ${document.vectors.length} match the record, fixtures rebuilt and re-hashed`);
    return;
  }

  console.error('usage: node reference/src/vectors.mjs --write | --check');
  process.exitCode = 2;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
