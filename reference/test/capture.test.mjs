/**
 * The capture core: what a browser will hand over, turned into a WACZ.
 *
 * The first test is the one that matters. It builds a capture the way the extension will, seals it the
 * way the CLI does, and checks the result with the verifier - so the three halves of this project are
 * shown to agree about what a capture is, rather than each being tested against its own idea of one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CaptureError, buildCapture, buildWarcRecord } from '../src/capture.mjs';
import { findCaptureWarc, sealFromCapture } from '../src/seal.mjs';
import { findMainDocument } from '../src/warc.mjs';
import { verifyReceipt } from '../src/verify-node.mjs';
import { signer } from '../src/fixtures.mjs';
import { sha256 } from '../src/digest.mjs';

const text = (bytes) => Buffer.from(bytes).toString('utf8');
const latin1 = (bytes) => Buffer.from(bytes).toString('latin1');

/** What a content script and a background worker can honestly supply. */
const FACTS = {
  url: 'https://example.org/captured',
  status: 200,
  statusText: 'OK',
  headers: [['content-type', 'text/html; charset=utf-8'], ['cache-control', 'no-store']],
  html: '<!doctype html><html><head><title>Captured</title></head><body><p>What the page said.</p></body></html>',
  capturedAt: '2026-03-04T05:06:07Z',
};

/** @param {Record<string, any>} [overrides] */
function capture(overrides = {}) {
  return buildCapture({ ...FACTS, ...overrides });
}

test('a capture made the way a browser will make it seals into a receipt that verifies', async () => {
  const made = capture();
  const sealed = sealFromCapture({
    capture: made.wacz,
    key: { privateKey: signer().privateKey, signer: 'Test Signer' },
  });

  assert.equal(
    sealed.manifest.subject.document.sha256,
    made.document.sha256,
    'the digest the capture computed must be the digest the sealer derives from the capture',
  );
  assert.equal(sealed.manifest.subject.document.bytes, made.document.bytes);
  assert.equal(sealed.manifest.subject.status, 200);
  assert.equal(sealed.manifest.subject.content_type, 'text/html; charset=utf-8');

  const verdict = await verifyReceipt(sealed.bytes);
  assert.equal(verdict.verified, true);
  assert.equal(verdict.levels.L0.status, 'pass');
  assert.equal(verdict.levels.L1.status, 'pass');
});

test('the reader gets back exactly what the writer put in', async () => {
  const made = capture();
  const document = findMainDocument(findCaptureWarc(made.wacz), FACTS.url);

  assert.equal(text(document.body), FACTS.html);
  assert.equal(sha256(document.body), made.document.sha256);
  assert.equal(document.status, 200);
  assert.equal(document.contentType, 'text/html; charset=utf-8');
  assert.equal(document.capturedAt, FACTS.capturedAt);
  assert.equal(document.url, FACTS.url);
});

test('a length that described the wire is never passed off as describing the capture', async () => {
  // The page's own Content-Length describes bytes that no longer exist, because the body is now the
  // rendered document. Leaving it in would make the record claim a length it does not have, and the
  // reader - which trusts that field - would refuse the capture it had just been handed.
  const made = capture({ headers: [['content-length', '999999'], ['content-type', 'text/html']] });
  const record = latin1(made.record);

  assert.ok(!record.includes('999999'), 'the observed length must not survive into the record');
  assert.equal(findMainDocument(findCaptureWarc(made.wacz), FACTS.url).status, 200);
});

test('the same facts produce the same bytes, twice', async () => {
  // Which is only true because the record identifier is derived from the content rather than drawn at
  // random, and because the writer takes its timestamps from the capture rather than from a clock.
  assert.deepEqual(capture().wacz, capture().wacz);
  assert.deepEqual(capture().record, capture().record);
});

test('a redirect is recorded as where the document came from', async () => {
  const made = capture({ finalUrl: 'https://example.org/after-the-redirect' });
  const warc = findCaptureWarc(made.wacz);
  assert.equal(findMainDocument(warc, 'https://example.org/after-the-redirect').url,
    'https://example.org/after-the-redirect');
  assert.match(text(warc), /WARC-Target-URI: https:\/\/example\.org\/after-the-redirect/);
});

test('headers can arrive in any of the shapes a browser offers them', async () => {
  const common = { url: FACTS.url, status: 200, capturedAt: FACTS.capturedAt, body: FACTS.html };
  const asObject = buildWarcRecord({ ...common, headers: { 'Content-Type': 'text/html' } });
  const asMap = buildWarcRecord({ ...common, headers: new Map([['Content-Type', 'text/html']]) });
  const asPairs = buildWarcRecord({ ...common, headers: [['Content-Type', 'text/html']] });

  assert.deepEqual(asObject, asMap);
  assert.deepEqual(asObject, asPairs);
  assert.match(latin1(asObject), /Content-Type: text\/html/);
});

test('a page of three hundred thousand characters is captured without falling over', async () => {
  // The base64 in the record's own digest is why this test exists: a naive `String.fromCharCode(...)`
  // throws on a payload this size, on exactly the pages people most want to keep.
  const html = `<!doctype html><p>${'wide '.repeat(60_000)}</p>`;
  const made = capture({ html });
  assert.equal(made.document.bytes, Buffer.byteLength(html, 'utf8'));
  assert.equal(text(findMainDocument(findCaptureWarc(made.wacz), FACTS.url).body), html);
});

test('facts that do not add up to a capture are refused, each by name', async () => {
  const refusals = [
    [{ url: 'not a url' }, /not absolute/],
    [{ url: 'ftp://example.org/file' }, /http or https/],
    [{ status: 99 }, /between 100 and 599/],
    [{ status: 600 }, /between 100 and 599/],
    [{ status: 200.5 }, /between 100 and 599/],
    [{ capturedAt: '2026-03-04' }, /UTC to the second/],
    [{ capturedAt: '2026-03-04T05:06:07.123Z' }, /UTC to the second/],
    [{ capturedAt: '2026-03-04T05:06:07+01:00' }, /UTC to the second/],
    [{ html: '' }, /capture of nothing/],
    [{ html: '   \n  ' }, /capture of nothing/],
  ];

  for (const [overrides, expected] of refusals) {
    let error = null;
    try {
      capture(overrides);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof CaptureError, `${JSON.stringify(overrides)} should be refused`);
    assert.match(error.message, expected, `${JSON.stringify(overrides)}: ${error?.message}`);
  }
});

test('the record it writes is one the reader would accept on its own', async () => {
  // The payload digest this module writes is the one `warc.mjs` checks, so this assertion is the
  // writer and the reader agreeing about a value that neither would notice disagreeing about
  // otherwise: a wrong one would simply make every capture look corrupt.
  const record = buildWarcRecord({ ...FACTS });
  const digestLine = latin1(record).match(/WARC-Payload-Digest: (sha256:[A-Za-z0-9+/=]+)/);
  assert.ok(digestLine !== null, 'the record must state its own payload digest');
  findMainDocument(record, FACTS.url);
});
