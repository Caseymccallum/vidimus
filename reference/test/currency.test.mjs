/**
 * Currency: the comparison a verifier deliberately does not perform.
 *
 * The test that matters most is the third one: **the bytes changed and the words did not**. That sentence
 * is the reason this module exists, and it is the case a caller would otherwise have to assemble from two
 * booleans - wrongly, in the direction of "the page changed".
 *
 * Nothing here fetches anything. `compareCurrency` is handed facts, which is what makes the network a
 * decision by a caller rather than a side effect of asking a question.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { OUTCOMES, compareCurrency } from '../src/currency.mjs';
import { verifyReceipt } from '../src/verify-node.mjs';
import { DEFAULT_HTML, buildReceipt } from '../src/fixtures.mjs';
import { textDigest } from '../src/text.mjs';
import { sha256 } from '../src/digest.mjs';
import { utf8 } from '../src/encode.mjs';

const CLAIMED = {
  url: 'https://example.org/a-page-worth-citing',
  capturedAt: '2026-01-01T00:00:00Z',
  status: 200,
  document: { sha256: sha256(utf8(DEFAULT_HTML)) },
  textSha256: textDigest(DEFAULT_HTML),
};

/** The same page, byte-identical, looked at again later. */
const SAME = {
  url: CLAIMED.url,
  capturedAt: '2026-09-15T12:00:00Z',
  status: 200,
  documentSha256: CLAIMED.document.sha256,
  documentBytes: utf8(DEFAULT_HTML).length,
  textSha256: CLAIMED.textSha256,
};

test('the same bytes and the same words is unchanged', () => {
  const report = compareCurrency(CLAIMED, SAME);
  assert.equal(report.outcome, 'unchanged');
  assert.equal(report.meaning, OUTCOMES.unchanged);
  assert.deepEqual(report.differences, []);
  assert.deepEqual(report.caveats, []);
});

test('different bytes with the same words is the case worth a report of its own', () => {
  // A rotation nonce, a footer timestamp, an attribute reordering: the markup moved, the meaning did not.
  const report = compareCurrency(
    CLAIMED,
    { ...SAME, documentSha256: sha256(utf8('the same page with a new nonce')) },
  );
  assert.equal(report.outcome, 'words_unchanged');
  assert.equal(report.meaning, 'the bytes changed and the words did not');
  assert.deepEqual(report.differences, ['document_sha256']);
});

test('different words is changed, even when the bytes are the same length', () => {
  const report = compareCurrency(
    CLAIMED,
    {
      ...SAME,
      documentSha256: sha256(utf8('a different page, coincidentally the same size')),
      textSha256: textDigest('<p>A page worth citing</p><p>Claims were made HERE.</p>'),
    },
  );
  assert.equal(report.outcome, 'changed');
  assert.deepEqual(report.differences, ['document_sha256', 'text_sha256']);
});

test('a page that answers with an error is gone, not changed', () => {
  // Saying "the words changed" about a 404 would be the most misleading answer this module could give: the
  // words did not change, the page is not there.
  const report = compareCurrency(CLAIMED, { ...SAME, status: 404, textSha256: null });
  assert.equal(report.outcome, 'gone');
  assert.equal(report.caveats.some((line) => line.includes('404')), true);
});

test('a claim with no fingerprint says so, and compares what it can', () => {
  const report = compareCurrency(
    { ...CLAIMED, textSha256: null },
    { ...SAME, documentSha256: sha256(utf8('something else entirely')) },
  );
  assert.equal(report.outcome, 'words_unchanged', 'only the bytes were comparable');
  assert.equal(report.caveats.some((line) => line.includes('no text fingerprint')), true);
});

test('a page that could not be reached is reported, not thrown', () => {
  const report = compareCurrency(CLAIMED, null, 'the page could not be fetched: getaddrinfo ENOTFOUND');
  assert.equal(report.outcome, 'not_compared');
  assert.equal(report.meaning, OUTCOMES.not_compared);
  assert.equal(report.now.document_sha256, null);
  assert.equal(report.caveats.some((line) => line.includes('ENOTFOUND')), true);
});

test('a changed status is recorded even when the bytes did not move', () => {
  // `outcome` is about content, and `differences` carries everything that was observed. A 301 that serves
  // identical bytes is an `unchanged` page that redirected: both facts are in the report, and neither
  // hides the other.
  const report = compareCurrency(CLAIMED, { ...SAME, status: 301 });
  assert.equal(report.outcome, 'unchanged');
  assert.deepEqual(report.differences, ['status']);
});

test('the same facts produce the same report', () => {
  assert.equal(
    JSON.stringify(compareCurrency(CLAIMED, SAME)),
    JSON.stringify(compareCurrency(CLAIMED, SAME)),
  );
});

test('a verdict reports what the claim asserts, so a caller need not parse the claim itself', async () => {
  // `check` is built on this: the verdict carries the URL, the document digest and the fingerprint, so the
  // command that compares a receipt with a page does not need its own JSON parser for `receipt.json`.
  const built = buildReceipt({
    manifestPatch: (manifest) => {
      manifest.subject.text = { normalization: 'text-v1', sha256: textDigest(DEFAULT_HTML) };
    },
  });
  const verdict = await verifyReceipt(built.bytes);

  assert.equal(verdict.subject.url, 'https://example.org/a-page-worth-citing');
  assert.equal(verdict.subject.captured_at, '2026-01-01T00:00:00Z');
  assert.equal(verdict.subject.status, 200);
  assert.equal(verdict.subject.document_sha256, sha256(utf8(DEFAULT_HTML)));
  assert.equal(verdict.subject.document_bytes, utf8(DEFAULT_HTML).length);
  assert.equal(verdict.subject.text_sha256, textDigest(DEFAULT_HTML));
});
