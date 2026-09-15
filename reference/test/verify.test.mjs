/**
 * The properties a verdict must have, checked against every case rather than against
 * examples.
 *
 * These are the rules from `docs/RECEIPT-SPEC.md` section 6 stated as assertions. If one of
 * them is ever relaxed, this file is where the argument has to be made - which is the
 * point: a verifier whose honesty rules live only in prose is a verifier whose honesty
 * rules are opinions.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CASES } from '../src/cases.mjs';
import {
  CHECKS,
  LEVELS,
  verifyReceipt,
  rollUpLevel,
  isSafeEntryName,
  signingMessage,
  signedSubtree,
  validateManifestShape,
} from '../src/verify.mjs';
import { buildReceipt } from '../src/fixtures.mjs';
import { canonicalise } from '../src/canonical.mjs';
import { sha256 } from '../src/digest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const source = (name) => readFileSync(join(here, '..', 'src', name), 'utf8');

/** Every case, built once, with its verdict. */
const built = CASES.map((testCase) => ({
  id: testCase.id,
  bytes: testCase.build(),
  options: testCase.options ?? {},
  verdict: null,
}));
for (const entry of built) entry.verdict = verifyReceipt(entry.bytes, entry.options);

test('every verdict reports every check, exactly once, in the declared order', () => {
  const expected = CHECKS.map((check) => check.id);
  for (const { id, verdict } of built) {
    const actual = verdict.checks.map((check) => check.id);
    assert.deepEqual(actual, expected, `${id} must report the declared checks in order`);
  }
});

test('every check that is not a pass says why', () => {
  for (const { id, verdict } of built) {
    for (const check of verdict.checks) {
      if (check.status === 'pass') continue;
      assert.ok(
        typeof check.reason === 'string' && check.reason.length > 0,
        `${id}: ${check.id} is ${check.status} with no reason`,
      );
    }
  }
});

test('a level passes only when every check in it passes', () => {
  for (const { id, verdict } of built) {
    for (const level of LEVELS) {
      const checks = verdict.checks.filter((check) => check.level === level.id);
      const status = verdict.levels[level.id].status;
      if (status === 'pass') {
        assert.ok(
          checks.every((check) => check.status === 'pass'),
          `${id}: ${level.id} is a pass with a check that is not`,
        );
      }
      if (checks.some((check) => check.status === 'fail')) {
        assert.equal(status, 'fail', `${id}: ${level.id} contains a failure but is not failed`);
      }
    }
  }
});

test('verified means integrity and attribution, and nothing else is folded in', () => {
  for (const { id, verdict } of built) {
    const anyFail = verdict.checks.some((check) => check.status === 'fail');
    const expected = !anyFail
      && verdict.levels.L0.status === 'pass'
      && verdict.levels.L1.status === 'pass';
    assert.equal(verdict.verified, expected, `${id}: verified disagrees with the levels`);
  }
});

test('the exit code has three states and they mean what the CLI says they mean', () => {
  for (const { id, verdict } of built) {
    const anyFail = verdict.checks.some((check) => check.status === 'fail');
    const expected = anyFail ? 2 : (verdict.verified ? 0 : 1);
    assert.equal(verdict.exit_code, expected, `${id}: exit code ${verdict.exit_code}`);
  }
  // All three states must actually occur, or the distinction is untested.
  const seen = new Set(built.map((entry) => entry.verdict.exit_code));
  assert.deepEqual([...seen].sort(), [0, 1, 2], 'every exit code must be exercised');
});

test('a verdict is deterministic: the same bytes give the same answer, twice', () => {
  for (const { id, bytes, options } of built) {
    const first = verifyReceipt(bytes, options);
    const second = verifyReceipt(bytes, options);
    assert.equal(JSON.stringify(first), JSON.stringify(second), `${id} is not reproducible`);
  }
});

test('every check has been seen not passing at least once', () => {
  const nonPass = new Set();
  for (const { verdict } of built) {
    for (const check of verdict.checks) {
      if (check.status !== 'pass') nonPass.add(check.id);
    }
  }
  const never = CHECKS.filter((check) => !nonPass.has(check.id)).map((check) => check.id);
  assert.deepEqual(never, [], 'a check that has never been seen failing is not a check');
});

test('each level reaches a pass somewhere, except the one this verifier cannot check', () => {
  const passes = new Set();
  for (const { verdict } of built) {
    for (const level of LEVELS) {
      if (verdict.levels[level.id].status === 'pass') passes.add(level.id);
    }
  }
  assert.deepEqual([...passes].sort(), ['L0', 'L1', 'L2']);
  // L3 is absent by design: `text-v1` is defined over a rendered document and this verifier
  // has no HTML engine. `docs/CONFORMANCE.md` records it as the known gap, and the day an
  // L3 pass appears here is the day that document is out of date.
});

test('the summary never says a level is verified unless it is', () => {
  for (const { id, verdict } of built) {
    for (const level of LEVELS) {
      const line = verdict.summary.find((text) => text.startsWith(`L${level.id.slice(1)} `));
      assert.ok(line !== undefined, `${id}: no summary line for ${level.id}`);
      if (verdict.levels[level.id].status !== 'pass') {
        assert.ok(
          !/:\s*verified/.test(line),
          `${id}: the summary calls ${level.id} verified when it is ${verdict.levels[level.id].status}`,
        );
      }
    }
  }
});

test('the verifier does not reach outside the bytes it was handed', () => {
  // The same shape of gate Sentinel runs over its source and its bundle: the claim "this
  // checks nothing over the network and reads no clock" is enforced by scanning the code,
  // not by intending it. `digest.mjs` and `signature.mjs` are excluded because they import
  // `node:crypto` on purpose - and nothing else is.
  const forbidden = [
    'fetch(',
    'XMLHttpRequest',
    'readFile',
    'writeFile',
    'node:fs',
    'node:http',
    'node:net',
    'Date.now',
    'new Date(',
    'Math.random',
    'process.env',
  ];
  for (const module of ['verify.mjs', 'canonical.mjs']) {
    const text = source(module);
    for (const pattern of forbidden) {
      assert.ok(
        !text.includes(pattern),
        `${module} mentions "${pattern}": the verifier must stay pure`,
      );
    }
  }
});

test('the check table is its own guardrail', () => {
  const ids = CHECKS.map((check) => check.id);
  assert.equal(new Set(ids).size, ids.length, 'check ids must be unique');
  const levels = new Set(LEVELS.map((level) => level.id));
  for (const check of CHECKS) {
    assert.ok(levels.has(check.level), `${check.id} is in an undeclared level ${check.level}`);
    assert.ok(check.description.length > 0, `${check.id} has no description to render`);
  }
  for (const level of LEVELS) {
    assert.ok(
      CHECKS.some((check) => check.level === level.id),
      `${level.id} has no checks, so it can never mean anything`,
    );
    assert.ok(level.claim.length > 0, `${level.id} has no claim to state`);
  }
});

test('a level rolls up by the rule the spec states, not by majority', () => {
  const state = (statuses) => ({ results: statuses.map((status, index) => ({ id: `c${index}`, status })) });
  const levelOf = (statuses) => rollUpLevel(
    { ...state(statuses), results: state(statuses).results.map((result) => ({ ...result, level: 'L0' })) },
    'L0',
  );

  assert.equal(levelOf(['pass', 'pass']), 'pass');
  assert.equal(levelOf(['pass', 'not_checked']), 'not_checked');
  assert.equal(levelOf(['pass', 'unsupported']), 'unsupported');
  assert.equal(levelOf(['pass', 'fail']), 'fail');
  assert.equal(levelOf(['fail', 'unsupported']), 'fail', 'a failure outranks unsupported');
  assert.equal(levelOf(['not_applicable', 'not_applicable']), 'not_applicable');
  assert.equal(levelOf(['not_applicable', 'not_checked']), 'not_checked');
});

test('entry names are confined to the container they came from', () => {
  const allowed = ['capture.wacz', 'attestations/signature.json', 'a/b/c.txt'];
  const refused = [
    '', '/etc/passwd', 'C:/windows/system32', 'a\\b', 'a//b', 'a/./b', '../x', 'a/../b',
    'trailing/', 'x'.repeat(256),
  ];
  for (const name of allowed) assert.ok(isSafeEntryName(name), `${name} should be allowed`);
  for (const name of refused) assert.ok(!isSafeEntryName(name), `${JSON.stringify(name)} should be refused`);
});

test('the signed subtree excludes the signature, and only a post-hoc anchor', () => {
  // `buildReceipt` defaults to `{"type":"none"}`, which is a statement made at signing time
  // and is therefore covered by the signature.
  const { manifest } = buildReceipt();
  const signed = signedSubtree(manifest);
  assert.equal('signature' in signed, false);
  assert.equal('capture' in signed, true);
  assert.equal('anchor' in signed, true, 'a "none" anchor is signed');

  // A chain link is knowable before the claim hash exists, so it is signed too - otherwise
  // anyone could add one and manufacture an L2 pass.
  const linked = { ...manifest, anchor: { type: 'chain', sequence: 1 } };
  assert.equal('anchor' in signedSubtree(linked), true);

  // An RFC 3161 token is a response to the claim hash and cannot be inside it.
  const stamped = { ...manifest, anchor: { type: 'rfc3161', token: 'MIIB' } };
  assert.equal('anchor' in signedSubtree(stamped), false);

  // An unknown anchor type is signed, so it cannot be bolted on afterwards either.
  const unknown = { ...manifest, anchor: { type: 'clock-radio' } };
  assert.equal('anchor' in signedSubtree(unknown), true);

  // And an unknown *field* is inside the signed subtree, so nothing can be added to a claim
  // without changing the claim hash - the difference between a signed document and a
  // document with a signature attached to one corner of it.
  const withExtra = { ...manifest, notes: { context: 'added later' } };
  assert.notEqual(canonicalise(signedSubtree(withExtra)), canonicalise(signed));
});

test('the signature message format is pinned, because it is wire format', () => {
  const hash = 'ab'.repeat(32);
  assert.deepEqual(
    new TextDecoder().decode(signingMessage('0.1.0', hash)),
    `vidimus/claim/0.1.0:${hash}`,
  );
  // The prefix is looked up per major version rather than interpolated, so that renaming the
  // project again (D-015) cannot silently invalidate every receipt already signed. A version
  // this verifier has no prefix for is a gap, not a guess.
  assert.equal(signingMessage('9.0.0', hash), null);
});

test('shape validation names every problem it finds', () => {
  const good = buildReceipt().manifest;
  assert.deepEqual(validateManifestShape(good), []);

  const bad = {
    ...good,
    capture: { ...good.capture, captured_at: 'yesterday', path: '../escape' },
    subject: { ...good.subject, url: 'not a url' },
  };
  const problems = validateManifestShape(bad);
  assert.ok(problems.some((problem) => problem.includes('capture.path')), problems.join('; '));
  assert.ok(problems.some((problem) => problem.includes('captured_at')), problems.join('; '));
  assert.ok(problems.some((problem) => problem.includes('subject.url')), problems.join('; '));

  const missing = validateManifestShape({ spec_version: '0.1.0' });
  assert.ok(missing.length >= 4, 'a nearly empty manifest should produce many problems');
});
