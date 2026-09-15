/**
 * Syntax-check every module in the repository.
 *
 * Sentinel's gates run this shape of check over a built bundle; here it stands in for the
 * `tsc --noEmit` a TypeScript project gets for free. `reference/` is plain ESM with JSDoc
 * types on purpose (D-002) so that the conformance suite runs with no install step, and
 * that trade has to be paid for somewhere: this is where.
 *
 * It is not a type check. It catches the class of mistake that a test suite only finds if
 * it happens to import the file - a stray brace in a module nothing loads yet.
 */

import { readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const searched = ['reference/src', 'reference/test', 'scripts'];

/**
 * @param {string} directory
 * @returns {string[]}
 */
function modulesIn(directory) {
  const found = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) found.push(...modulesIn(path));
    else if (entry.endsWith('.mjs')) found.push(path);
  }
  return found;
}

const files = searched.flatMap((directory) => modulesIn(join(root, directory)));
const failures = [];

for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failures.push(`${relative(root, file)}\n${result.stderr.trim()}`);
  }
}

if (failures.length > 0) {
  console.error(`${failures.length} of ${files.length} modules do not parse:`);
  for (const failure of failures) console.error(`\n${failure}`);
  process.exitCode = 1;
} else {
  console.log(`syntax: ${files.length} modules parse`);
}
