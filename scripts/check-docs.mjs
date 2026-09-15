/**
 * The numbers in the documentation, checked rather than typed.
 *
 * A README claiming "47 tests" and "34 vectors" is making two claims, and both go stale the first
 * time somebody adds a test. This gate reads the real counts - by running the suite, and by reading
 * the record - and fails if any document disagrees. It is the same principle as the rest of this
 * repository: a number in a document is a claim, and a claim nobody checks is a claim that will be
 * wrong within a month.
 *
 * It re-runs the tests, so `npm run verify` runs them twice. That is one second, and it is the price
 * of the counts being checked at all. `npm test` is still the fast way to run them once.
 *
 * @module check-docs
 */

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { GATE_OPT_OUT } from './gate-exemptions.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** The documents that quote counts at the reader. */
const DOCUMENTS = ['README.md', 'CONTRIBUTING.md', 'docs/ARCHITECTURE.md', 'docs/CONFORMANCE.md',
  'docs/RECEIPT-SPEC.md', 'docs/THREAT-MODEL.md'];

// 1. The test count, from the runner's own TAP summary rather than from a regex over pretty output.
const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap'], { cwd: root, encoding: 'utf8' });
if (run.status !== 0) {
  console.error('check-docs: the test suite does not pass, so there is no count to check.');
  console.error(run.stdout.split('\n').filter((line) => /^not ok/.test(line)).slice(0, 10).join('\n'));
  process.exitCode = 1;
} else {
  const tests = Number((run.stdout.match(/^# tests (\d+)$/m) ?? [])[1]);

  // 2. The other counts, from the record itself.
  const record = JSON.parse(readFileSync(join(root, 'spec', 'vectors', 'receipt-vectors.json'), 'utf8'));
  const actual = {
    tests,
    vectors: record.vectors.length,
    fixtures: record.vectors.length,
    checks: record.checks.length,
  };

  /**
   * Every way a count can be written at a reader: in prose, and in a shields.io badge.
   * The badge form matters because a badge is the easiest place to leave a stale number.
   */
  const PATTERNS = [
    { name: 'tests', prose: /(\d+)\s+tests\b/g, badge: /badge\/tests-(\d+)-/g },
    { name: 'vectors', prose: /(\d+)\s+(?:conformance\s+)?vectors\b/g, badge: /badge\/vectors-(\d+)-/g },
    { name: 'fixtures', prose: /(\d+)\s+fixtures\b/g, badge: null },
    { name: 'checks', prose: /(\d+)\s+checks\b/g, badge: null },
  ];

  const problems = [];
  let checked = 0;

  for (const document of DOCUMENTS) {
    const lines = readFileSync(join(root, document), 'utf8').split(/\r?\n/);
    lines.forEach((line, index) => {
      // "34 of 34 match the record" is a run's output, not a claim about a total, so it is left alone.
      // So is any line that opts out by name - a document explaining a rule has to be able to quote a
      // wrong count while it does so.
      if (/\bof\b/.test(line) && /vectors/.test(line)) return;
      if (GATE_OPT_OUT.test(line)) return;
      for (const pattern of PATTERNS) {
        for (const source of [pattern.prose, pattern.badge]) {
          if (source === null) continue;
          source.lastIndex = 0;
          for (const match of line.matchAll(source)) {
            checked += 1;
            const quoted = Number(match[1]);
            if (quoted !== actual[pattern.name]) {
              problems.push(
                `${document}:${index + 1} says ${quoted} ${pattern.name}, and there are ${actual[pattern.name]}`,
              );
            }
          }
        }
      }
    });
  }

  if (problems.length > 0) {
    console.error('documentation quotes a number the repository does not produce:');
    for (const problem of problems) console.error(`  - ${problem}`);
    console.error('\nUpdate the document, or the count, whichever is wrong.');
    process.exitCode = 1;
  } else if (checked === 0) {
    console.error('no counts were found to check: the documentation has stopped quoting any, which');
    console.error('means this gate is no longer checking anything. Remove it, or put the numbers back.');
    process.exitCode = 1;
  } else {
    const summary = Object.entries(actual).map(([name, value]) => `${value} ${name}`).join(', ');
    console.log(`docs: ${checked} quoted count${checked === 1 ? '' : 's'} agree with reality (${summary})`);
  }
}
