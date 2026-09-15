/**
 * The boundary the extension depends on: a set of modules that must run in a browser, checked by
 * reading them rather than by hoping.
 *
 * A receipt is written in a browser and read on a command line, so the two halves of this project have
 * different runtimes in them. That is the reason for the reader/writer split, the pure SHA-256 and the
 * `btoa`-based encoders - and this file is the reason those decisions stay true, because the day
 * somebody adds `import { gzipSync } from 'node:zlib'` to the capture path, the failure appears in a
 * browser build rather than here.
 *
 * Same shape as Sentinel's `check:local-only`, for the same reason: a promise about what a program does
 * not depend on is only worth anything if something fails when it stops being true.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sourceOf = (name) => readFileSync(join(here, '..', 'src', name), 'utf8');

/** The modules a capturing extension bundles, and everything they import. */
const ENTRY = 'capture.mjs';

/** Relative imports, which is what a module graph is made of here. */
function relativeImports(source) {
  return [...source.matchAll(/from\s+'(\.[^']+)'/g)].map((match) => match[1].replace('./', ''));
}

/**
 * Code without its comments, because prose is allowed to *mention* `Buffer`.
 *
 * The first version of this test scanned the whole file and failed on `encode.mjs`, whose module
 * documentation explains why the capture path cannot use `Buffer` - the sentence that documents the
 * rule broke the check that enforces it. Stripping comments is the fix, and it is the same lesson as
 * the language gate's opt-out: a check has to be able to tell a rule from a description of the rule.
 *
 * @param {string} source
 * @returns {string}
 */
function withoutComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Every module reachable from the entry point, in the order it is reached. */
function reachable(entry) {
  const seen = [];
  const queue = [entry];
  while (queue.length > 0) {
    const name = queue.shift();
    if (seen.includes(name)) continue;
    seen.push(name);
    queue.push(...relativeImports(withoutComments(sourceOf(name))));
  }
  return seen;
}

test('the modules a browser bundles reach nothing in Node', () => {
  const modules = reachable(ENTRY);
  assert.ok(modules.length > 3, 'the entry point should have a graph, not a stub');

  for (const name of modules) {
    const source = withoutComments(sourceOf(name));
    for (const imported of relativeImports(source)) {
      assert.ok(
        !imported.startsWith('node:'),
        `${name} imports ${imported}, which does not exist in a browser`,
      );
    }
    assert.ok(
      !/\bBuffer\b/.test(source),
      `${name} uses Buffer, which does not exist in a browser`,
    );
  }
});

test('the entry point does not quietly acquire a Node dependency', () => {
  // `capture.mjs` is what the extension imports. If it ever reaches `digest.mjs`, `signature.mjs`,
  // `zip.mjs`, `warc.mjs`, `seal.mjs` or `fixtures.mjs`, the split has been undone.
  const modules = reachable(ENTRY);
  const forbidden = ['digest.mjs', 'signature.mjs', 'zip.mjs', 'warc.mjs', 'seal.mjs', 'fixtures.mjs', 'verify.mjs'];
  for (const name of forbidden) {
    assert.ok(!modules.includes(name), `capture.mjs now reaches ${name}, which needs Node`);
  }
});
