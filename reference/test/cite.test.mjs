/**
 * Citing a receipt.
 *
 * The interesting assertions here are the *absences*. A receipt asserts a URL, a time and the words on a
 * page; it never asserts a title. A citation that quietly invented one would be a plausible falsehood in
 * a bibliography, which is the same failure mode this project refuses inside a signed claim.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CITATION_TYPE, citationFor, indexEntry } from '../src/cite.mjs';

const HASH = 'a'.repeat(64);

test('a citation carries what the receipt asserts, and nothing else', () => {
  const citation = citationFor({
    url: 'https://example.org/a-page-worth-citing',
    capturedAt: '2026-01-01T00:00:00Z',
    claimHash: HASH,
    receiptName: 'page.receipt',
  });

  assert.equal(citation.csl.type, CITATION_TYPE);
  assert.equal(citation.csl.id, HASH);
  assert.equal(citation.csl.URL, 'https://example.org/a-page-worth-citing');
  assert.deepEqual(citation.csl.accessed, { 'date-parts': [[2026, 1, 1]] });
  assert.match(citation.csl.note, /Verified receipt \(page\.receipt\)/);
  // The absence that matters: no title, because the receipt has none to give.
  assert.equal('title' in citation.csl, false);
  assert.equal(citation.caveats.some((line) => line.includes('--title')), true);
});

test('a supplied title is used, and is the citer\'s word rather than ours', () => {
  const citation = citationFor({
    url: 'https://example.org/a-page-worth-citing',
    capturedAt: '2026-01-01T00:00:00Z',
    claimHash: HASH,
    title: 'A page worth citing',
  });

  assert.equal(citation.csl.title, 'A page worth citing');
  assert.equal(citation.caveats.some((line) => line.includes('--title')), false);
  assert.match(citation.text, /^A page worth citing\. https:\/\//);
});

test('a claim with no hash or no time still produces a citation that says so', () => {
  const noHash = citationFor({ url: 'https://example.org/x', capturedAt: '2026-01-01T00:00:00Z' });
  assert.equal('id' in noHash.csl, false);
  assert.equal('note' in noHash.csl, false);
  assert.equal(noHash.trailer, '');
  assert.equal(noHash.caveats.some((line) => line.includes('no identifier')), true);

  const noTime = citationFor({ url: 'https://example.org/x', claimHash: HASH });
  assert.equal('accessed' in noTime.csl, false);
  assert.match(noTime.text, /a time the claim does not state/);
});

test('the text and the trailer are the forms a person and a commit need', () => {
  const citation = citationFor({
    url: 'https://example.org/x',
    capturedAt: '2026-09-15T12:00:00Z',
    claimHash: HASH,
  });
  assert.equal(citation.text, `https://example.org/x (accessed 2026-09-15). Receipt ${HASH}.`);
  assert.equal(citation.trailer, `Receipt: ${HASH}`);
});

test('an index line is a fact per line, not a citation manager', () => {
  const citation = citationFor({
    url: 'https://example.org/x',
    capturedAt: '2026-01-01T00:00:00Z',
    claimHash: HASH,
  });
  const entry = JSON.parse(indexEntry(citation.csl, 'x.receipt'));

  assert.deepEqual(entry, {
    id: HASH,
    url: 'https://example.org/x',
    used: { 'date-parts': [[2026, 1, 1]] },
    title: null,
    receipt: 'x.receipt',
  });
});
