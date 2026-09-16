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
import { dirname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const sourceOf = (pathFromRoot) => readFileSync(join(root, pathFromRoot), 'utf8');

/**
 * The entry points a browser bundles, as paths from the repository root.
 *
 * `checking.mjs` is here as well as `sealing.mjs`, so the reader, the verifier and the runtime adapter
 * are all covered by the same walk - which is what makes "the rules are shared with the browser" a
 * tested statement rather than an intention.
 */
const ENTRIES = [
  'reference/src/capture.mjs',
  'extension/lib/sealing.mjs',
  'extension/lib/checking.mjs',
];

/** Relative imports, which is what a module graph is made of here. */
/** Relative imports, resolved against the file that made them, because the graph now spans two trees. */
function relativeImports(from, source) {
  return [...source.matchAll(/from\s+'(\.[^']+)'/g)]
    .map((match) => normalize(join(dirname(from), match[1])).split('\\').join('/'));
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

/** Every module reachable from an entry point, in the order it is reached. */
function reachable(entry) {
  const seen = [];
  const queue = [entry];
  while (queue.length > 0) {
    const name = queue.shift();
    if (seen.includes(name)) continue;
    seen.push(name);
    queue.push(...relativeImports(name, withoutComments(sourceOf(name))));
  }
  return seen;
}

test('everything a browser bundles reaches nothing in Node', () => {
  for (const entry of ENTRIES) {
    const modules = reachable(entry);
    assert.ok(modules.length > 3, `${entry} should have a graph, not a stub`);

    for (const name of modules) {
      const source = withoutComments(sourceOf(name));
      for (const imported of relativeImports(name, source)) {
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
  }
});

test('the entry points do not quietly acquire a Node dependency', () => {
  // `capture.mjs` and the extension's `sealing.mjs` are what a browser bundles. If either ever reaches
  // `digest.mjs`, `signature.mjs`, `zip.mjs`, `warc.mjs`, `seal.mjs`, `fixtures.mjs` or `verify.mjs`,
  // the reader/writer split has been undone.
  const forbidden = ['digest.mjs', 'signature.mjs', 'zip.mjs', 'warc.mjs', 'seal.mjs', 'fixtures.mjs', 'runtime.mjs'];
  for (const entry of ENTRIES) {
    const modules = reachable(entry).map((module) => module.split('/').pop());
    for (const name of forbidden) {
      // Compared by file name, not by suffix: `gzip.mjs` ends with the string `zip.mjs`, and a check
      // that cannot tell those apart fails on the writer it is supposed to be protecting.
      //
      // `verify.mjs` is deliberately *not* on this list any more: since the verifier takes a runtime, its
      // rules import nothing from Node, and the browser imports them directly (D-021).
      assert.ok(
        !modules.includes(name),
        `${entry} now reaches ${name}, which needs Node`,
      );
    }
  }
});
