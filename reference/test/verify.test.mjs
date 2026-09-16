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
} from '../src/verify-node.mjs';
import { buildReceipt } from '../src/fixtures.mjs';
import { canonicalise } from '../src/canonical.mjs';
import { sha256 } from '../src/digest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const source = (name) => readFileSync(join(here, '..', 'src', name), 'utf8');

/**
 * Code without its comments, because prose is allowed to *mention* `fetch`.
 *
 * The same lesson the browser-safety gate records: a sentence documenting a rule must not break the check
 * that enforces it.
 *
 * @param {string} text
 * @returns {string}
 */
function withoutComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/**
 * Every module of the verifier's rules, **reached** from its entry point rather than listed.
 *
 * A list of file names is a promise that decays: five modules joined this verifier while the purity test
 * still named two of them, and a test that says "the verifier is scanned" while scanning a third of it is
 * worse than no test at all. `browser-safety.test.mjs` walks a graph for exactly this reason.
 *
 * @param {string} entry A module name in `reference/src`.
 * @returns {string[]}
 */
function reachableFrom(entry) {
  const seen = [];
  const queue = [entry];
  while (queue.length > 0) {
    const name = queue.shift();
    if (seen.includes(name)) continue;
    seen.push(name);
    const text = withoutComments(source(name));
    for (const match of text.matchAll(/from\s+'(\.[^']+)'/g)) {
      queue.push(match[1].replace(/^\.\//, ''));
    }
  }
  return seen;
}

/** Every case, built once, with its verdict. */
const built = CASES.map((testCase) => ({
  id: testCase.id,
  bytes: testCase.build(),
  options: testCase.options ?? {},
  verdict: null,
}));
for (const entry of built) entry.verdict = await verifyReceipt(entry.bytes, entry.options);

test('every verdict reports every check, exactly once, in the declared order', async () => {
  const expected = CHECKS.map((check) => check.id);
  for (const { id, verdict } of built) {
    const actual = verdict.checks.map((check) => check.id);
    assert.deepEqual(actual, expected, `${id} must report the declared checks in order`);
  }
});

test('every check that is not a pass says why', async () => {
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

test('a level passes only when every check in it passes', async () => {
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

test('verified means integrity and attribution, and nothing else is folded in', async () => {
  for (const { id, verdict } of built) {
    const anyFail = verdict.checks.some((check) => check.status === 'fail');
    const expected = !anyFail
      && verdict.levels.L0.status === 'pass'
      && verdict.levels.L1.status === 'pass';
    assert.equal(verdict.verified, expected, `${id}: verified disagrees with the levels`);
  }
});

test('the exit code has three states and they mean what the CLI says they mean', async () => {
  for (const { id, verdict } of built) {
    const anyFail = verdict.checks.some((check) => check.status === 'fail');
    const expected = anyFail ? 2 : (verdict.verified ? 0 : 1);
    assert.equal(verdict.exit_code, expected, `${id}: exit code ${verdict.exit_code}`);
  }
  // All three states must actually occur, or the distinction is untested.
  const seen = new Set(built.map((entry) => entry.verdict.exit_code));
  assert.deepEqual([...seen].sort(), [0, 1, 2], 'every exit code must be exercised');
});

test('a verdict is deterministic: the same bytes give the same answer, twice', async () => {
  for (const { id, bytes, options } of built) {
    const first = await verifyReceipt(bytes, options);
    const second = await verifyReceipt(bytes, options);
    assert.equal(JSON.stringify(first), JSON.stringify(second), `${id} is not reproducible`);
  }
});

test('every check has been seen not passing at least once', async () => {
  const nonPass = new Set();
  for (const { verdict } of built) {
    for (const check of verdict.checks) {
      if (check.status !== 'pass') nonPass.add(check.id);
    }
  }
  const never = CHECKS.filter((check) => !nonPass.has(check.id)).map((check) => check.id);
  assert.deepEqual(never, [], 'a check that has never been seen failing is not a check');
});

test('each level reaches a pass somewhere', async () => {
  const passes = new Set();
  for (const { verdict } of built) {
    for (const level of LEVELS) {
      if (verdict.levels[level.id].status === 'pass') passes.add(level.id);
    }
  }
  // L3 used to be absent from this list, because `subject.text` was defined over a rendered document and
  // this verifier had no HTML engine. It is defined over bytes now (section 9.2 of the specification), so
  // all four levels reach a pass - and `docs/CONFORMANCE.md` records the change.
  assert.deepEqual([...passes].sort(), ['L0', 'L1', 'L2', 'L3']);
});

test('the summary never says a level is verified unless it is', async () => {
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

test('the verifier does not reach outside the bytes it was handed', async () => {
  // The same shape of gate Sentinel runs over its source and its bundle: the claim "this checks nothing
  // over the network and reads no clock" is enforced by scanning the code, not by intending it.
  //
  // The scan walks the import graph from `verify.mjs` rather than a list of file names, because a list of
  // file names is a promise that decays: five modules have been added to this verifier since the list was
  // written, and every one of them would have been unscanned by a test that still said "the verifier is
  // scanned". `browser-safety.test.mjs` walks a graph for the same reason.
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

  // Exceptions are per module *and* per pattern, with the reason written down, so an exception cannot
  // quietly widen into an unscanned file.
  const allowed = new Map([
    ['claim.mjs', new Map([['new Date(', 'it formats a timestamp the claim already carries, and reads no clock']])],
    ['zip-write.mjs', new Map([['new Date(', 'it is `new Date(Date.UTC(2026, 0, 1))`, a fixed date so that a plan written twice has identical bytes']])],
  ]);

  const modules = reachableFrom('verify.mjs');
  assert.ok(modules.length > 5, 'the graph should have grown past a stub');

  for (const module of modules) {
    const text = withoutComments(source(module));
    for (const pattern of forbidden) {
      const why = allowed.get(module)?.get(pattern);
      if (why !== undefined) continue;
      assert.ok(
        !text.includes(pattern),
        `${module} mentions "${pattern}": the verifier must stay pure`,
      );
    }
  }
});

test('the check table is its own guardrail', async () => {
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

test('a level rolls up by the rule the spec states, not by majority', async () => {
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

test('entry names are confined to the container they came from', async () => {
  const allowed = ['capture.wacz', 'attestations/signature.json', 'a/b/c.txt'];
  const refused = [
    '', '/etc/passwd', 'C:/windows/system32', 'a\\b', 'a//b', 'a/./b', '../x', 'a/../b',
    'trailing/', 'x'.repeat(256),
  ];
  for (const name of allowed) assert.ok(isSafeEntryName(name), `${name} should be allowed`);
  for (const name of refused) assert.ok(!isSafeEntryName(name), `${JSON.stringify(name)} should be refused`);
});

test('the signed subtree excludes the signature, and only a post-hoc anchor', async () => {
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

test('the signature message format is pinned, because it is wire format', async () => {
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

test('shape validation names every problem it finds', async () => {
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
