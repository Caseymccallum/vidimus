/**
 * British English, enforced rather than requested.
 *
 * A spelling convention that lives only in somebody's memory lasts about three pull requests. This
 * is the same shape of gate as Sentinel's `check:local-only`: a claim the documentation makes
 * ("the prose is British English") that the build checks, so no reviewer has to notice.
 *
 * What it scans: prose and code under version control - `*.md`, `*.mjs` and `*.yml`.
 *
 * What it does not scan, and why: `*.json`. That file type holds two things this gate must not
 * touch - npm's `license` field, which is part of a published schema, and the claim's own
 * wire-format field names, which belong to the format rather than to the prose.
 *
 * The exception list below is deliberately in code rather than in a contributor's head. The one
 * entry today is the interesting kind of exception: `normalization` is a *wire-format field name*,
 * spelled the way the Unicode standard spells it ("Normalization Forms"), because the `text-v1`
 * fingerprint is literally defined in terms of NFKC. Everything this project writes itself is
 * British; the names it borrows from another standard keep their own spelling.
 *
 * @module check-language
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { GATE_OPT_OUT } from './gate-exemptions.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Directories that hold no prose of ours. */
const SKIP_DIRECTORIES = new Set(['node_modules', '.git', 'fixtures', 'test-results']);

/**
 * Files this gate must not read, because they have to contain the words it looks for.
 *
 * The first person to run this gate against its own source will see exactly why: the rule table
 * below spells out the American forms on purpose. Exempting the file is honest; teaching the gate
 * to ignore its own syntax would not be.
 */
const SKIP_FILES = new Set(['scripts/check-language.mjs']);

/** Files worth scanning. JSON is excluded on purpose - see the note above. */
const SCANNED = /\.(md|mjs|yml)$/;

/**
 * A line that says so is left alone. The marker is shared with `check-docs.mjs` and defined in
 * `gate-exemptions.mjs`, because the reason is the same for both gates: a document that explains a
 * rule has to be able to quote a violation of it.
 */

/**
 * Lines where an American spelling is somebody else's vocabulary rather than ours.
 *
 * The exception is line-scoped, which is a small hole and a deliberate one: a genuine Americanism
 * sharing a line with an HTML attribute would slip through, and the alternative - teaching this gate
 * to parse markup - would be far more code than the problem is worth. The lines below are one tag
 * each, so the hole is about as small as a hole can be.
 */
const EXEMPT_LINES = [
  { pattern: /align="center"/, why: 'HTML: the attribute value is spelled this way, not by us' },
];

/**
 * American spellings, and what to write instead.
 *
 * The last entry is a rule rather than a word: nearly every American spelling this project could
 * drift into ends in `-ize`. It is listed last so a specific word takes precedence in the message.
 */
const AMERICAN = [
  { pattern: /\bartifacts?\b/g, british: 'artefact, artefacts' },
  { pattern: /\bbehaviors?\b/g, british: 'behaviour, behaviours' },
  { pattern: /\bcolors?\b/g, british: 'colour, colours' },
  { pattern: /\bcenter(ed|ing)?\b/g, british: 'centre, centred' },
  { pattern: /\bfulfill(ed|ing|s)?\b/g, british: 'fulfil, fulfils, fulfilled' },
  { pattern: /\bjudgment\b/g, british: 'judgement (a court judgment keeps its spelling, as a legal term)' },
  { pattern: /\backnowledgment\b/g, british: 'acknowledgement' },
  { pattern: /\bgray\b/g, british: 'grey' },
  { pattern: /\bdefense\b/g, british: 'defence' },
  { pattern: /\boffense\b/g, british: 'offence' },
  { pattern: /\btravel(ed|er)\b/g, british: 'travelled, traveller' },
  { pattern: /\bmodel(ed|ing)\b/g, british: 'modelled, modelling' },
  { pattern: /\bcancel(ed|ing)\b/g, british: 'cancelled, cancelling' },
  { pattern: /\bcatalogs?\b/g, british: 'catalogue, catalogues' },
  { pattern: /\bdialogs?\b/g, british: 'dialogue' },
  { pattern: /\banalogs?\b/g, british: 'analogue' },
  { pattern: /\bfibers?\b/g, british: 'fibre' },
  { pattern: /\bskeptic(al|ism)?\b/g, british: 'sceptic, sceptical' },
  { pattern: /\btoward\b/g, british: 'towards' },
  { pattern: /\benroll(ed|ing|ment)?\b/g, british: 'enrol, enrolled, enrolment' },
  // The `-ize` rule is two patterns instead of one, and both are case-sensitive (`caseSensitive`
  // below), because of camelCase. A single case-insensitive class swallows the capital in
  // `compressedSize` and then finds `iz` - 19 false positives from one flag. Split this way, an
  // ordinary word and a capitalised one are both caught, and an identifier is left alone.
  { pattern: /\b[a-z][a-z]{2,}iz(e|es|ed|ing|ation|ations|er|ers)\b/g, british: '-ise, not -ize', caseSensitive: true },
  { pattern: /\b[A-Z][a-z]{2,}iz(e|es|ed|ing|ation|ations|er|ers)\b/g, british: '-ise, not -ize', caseSensitive: true },
];

/**
 * Words that contain `-ize` without being `-ize` verbs, so the rule above must not touch them, plus
 * the borrowings from other standards described at the top of this file.
 */
const ALLOWED = new Map([
  ['normalization', 'a wire-format field name, spelled as Unicode spells it (Normalization Forms)'],
  ['resize', 'not an -ize verb: re + size'], ['resizes', 'not an -ize verb: re + size'],
  ['resized', 'not an -ize verb: re + size'], ['resizing', 'not an -ize verb: re + size'],
  ['size', 'not an -ize verb'], ['sizes', 'not an -ize verb'],
  ['sized', 'not an -ize verb'], ['sizing', 'not an -ize verb'],
  ['prize', 'not an -ize verb'], ['prizes', 'not an -ize verb'],
  ['seize', 'not an -ize verb'], ['seized', 'not an -ize verb'],
  ['citizen', 'not an -ize verb'], ['citizens', 'not an -ize verb'],
]);

/**
 * @param {string} directory
 * @returns {string[]}
 */
function filesIn(directory) {
  const found = [];
  for (const entry of readdirSync(directory)) {
    if (SKIP_DIRECTORIES.has(entry)) continue;
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) found.push(...filesIn(path));
    else if (SCANNED.test(entry)) found.push(path);
  }
  return found;
}

const findings = [];

for (const file of filesIn(root)) {
  if (SKIP_FILES.has(relative(root, file).split('\\').join('/'))) continue;
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  lines.forEach((line, index) => {
    if (EXEMPT_LINES.some((exemption) => exemption.pattern.test(line))) return;
    if (GATE_OPT_OUT.test(line)) return;
    for (const rule of AMERICAN) {
      // Case-insensitivity is applied here rather than in the table, because the first version of
      // this gate declared its patterns with /g only and therefore missed every Americanism that
      // began a sentence. The mutation test that was meant to prove the gate worked is what found
      // it, which is the entire argument for having one. Rules that must stay case-sensitive say so.
      const pattern = new RegExp(rule.pattern.source, rule.caseSensitive === true ? 'g' : 'gi');
      for (const match of line.matchAll(pattern)) {
        const word = match[0].toLowerCase();
        if (ALLOWED.has(word)) continue;
        findings.push({
          file: relative(root, file),
          line: index + 1,
          word: match[0],
          british: rule.british,
          text: line.trim().slice(0, 90),
        });
      }
    }
  });
}

if (findings.length > 0) {
  console.error(`${findings.length} American spelling${findings.length === 1 ? '' : 's'} in a project that writes British English:`);
  for (const finding of findings) {
    console.error(`\n  ${finding.file}:${finding.line}  "${finding.word}"`);
    console.error(`      write: ${finding.british}`);
    console.error(`      in:    ${finding.text}`);
  }
  console.error('\nIf a word is a wire-format field name or borrowed from another standard, add it to');
  console.error('ALLOWED in scripts/check-language.mjs with the reason, so the exception is visible.');
  process.exitCode = 1;
} else {
  console.log(`language: British English throughout (${filesIn(root).length} files checked)`);
}
