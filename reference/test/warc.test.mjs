/**
 * The WARC reader: the one part of this project that reads somebody else's format, and therefore the
 * part where a wrong answer becomes a false claim rather than a missed check.
 *
 * The most valuable test here is the first one. It compares what the reader finds against what the
 * fixture *knows* it wrote - a parser tested only against itself proves nothing.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  WarcError, decompress, findMainDocument, isGzipped, parseHttpResponse, readWarc, toClaimTimestamp,
} from '../src/warc.mjs';
import { DEFAULT_HTML, DEFAULT_URL, warcRecord } from '../src/fixtures.mjs';
import { sha256, utf8 } from '../src/digest.mjs';
import { storeGzip } from '../src/gzip.mjs';

const bytes = (value) => new TextEncoder().encode(value);
const text = (value) => Buffer.from(value).toString('utf8');

/** A digest computed with Node's own crypto, so the check does not go through this project's helper. */
const base64Digest = (value) => createHash('sha256').update(Buffer.from(value, 'utf8')).digest('base64');

/** A WARC record with whatever headers a test needs. */
function warcWith(headers, payloadText) {
  return bytes(`WARC/1.0\r\n${headers.join('\r\n')}\r\n\r\n${payloadText}`);
}

/** A minimal HTTP response block. */
function httpResponse(body, { declaredLength = null, contentType = 'text/html' } = {}) {
  const length = declaredLength === null ? utf8(body).length : declaredLength;
  return `HTTP/1.1 200 OK\r\nContent-Type: ${contentType}\r\nContent-Length: ${length}\r\n\r\n${body}`;
}

/** @param {string} url @param {string} html */
function responseRecord(url, html) {
  return warcWith([
    'WARC-Type: response',
    `WARC-Target-URI: ${url}`,
    'WARC-Date: 2026-01-01T00:00:00Z',
    'Content-Type: application/http; msgtype=response',
  ], httpResponse(html));
}

test('the document it finds is the one the capture actually holds', () => {
  const record = warcRecord({ url: DEFAULT_URL, capturedAt: '2026-01-01T00:00:00Z', html: DEFAULT_HTML });
  const document = findMainDocument(storeGzip(record), DEFAULT_URL);

  assert.equal(text(document.body), DEFAULT_HTML);
  assert.equal(sha256(document.body), sha256(utf8(DEFAULT_HTML)));
  assert.equal(document.status, 200);
  assert.equal(document.contentType, 'text/html; charset=utf-8');
  assert.equal(document.capturedAt, '2026-01-01T00:00:00Z');
  assert.equal(document.url, DEFAULT_URL);
});

test('a two-page capture yields the page that was asked for', () => {
  const capture = new Uint8Array([
    ...storeGzip(responseRecord('https://example.org/first', '<p>first</p>')),
    ...storeGzip(responseRecord('https://example.org/second', '<p>second</p>')),
  ]);

  assert.equal(text(findMainDocument(capture, 'https://example.org/second').body), '<p>second</p>');
  assert.equal(text(findMainDocument(capture, 'https://example.org/first').body), '<p>first</p>');
  // With no URL, the first response is used, which is what a single-page capture holds.
  assert.equal(text(findMainDocument(capture).body), '<p>first</p>');
});

test('a capture holding no such page is refused, and says which pages it does hold', () => {
  const capture = storeGzip(responseRecord('https://example.org/only', '<p>only</p>'));
  let error = null;
  try {
    findMainDocument(capture, 'https://example.org/absent');
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof WarcError);
  assert.match(error.message, /no response for https:\/\/example\.org\/absent/);
  assert.match(error.message, /https:\/\/example\.org\/only/);
});

test('a file that is not a WARC is refused by name', () => {
  assert.throws(() => readWarc(bytes('this is a sentence, not a capture')), /contains no WARC records/);
});

test('a record with no HTTP block is refused rather than half-read', () => {
  const record = warcWith(
    ['WARC-Type: response', 'WARC-Target-URI: https://example.org/x'],
    'not http at all',
  );
  assert.throws(() => findMainDocument(record), /no HTTP header block/);
});

test('a truncated record is refused instead of hashed as a partial document', () => {
  const record = warcWith(
    ['WARC-Type: response', 'WARC-Target-URI: https://example.org/x'],
    httpResponse('<p>short</p>', { declaredLength: 4000 }),
  );
  assert.throws(() => findMainDocument(record), /appears to be truncated/);
});

test('a body is cut to the length the response declares', () => {
  // Records may carry padding or a trailing block. Treating that as the document would make the
  // digest depend on the crawler's filler rather than on what the page said.
  const padded = warcWith(
    ['WARC-Type: response', 'WARC-Target-URI: https://example.org/x'],
    `${httpResponse('<p>real</p>')}\r\nPADDING-PADDING-PADDING`,
  );
  assert.equal(text(findMainDocument(padded).body), '<p>real</p>');
});

test('an uncompressed WARC reads exactly like a compressed one', () => {
  const record = responseRecord(DEFAULT_URL, DEFAULT_HTML);
  assert.equal(isGzipped(record), false);
  assert.deepEqual(decompress(record), record);
  assert.equal(text(findMainDocument(record).body), DEFAULT_HTML);
});

test('a gzip stream that will not inflate is an error', () => {
  // A gzip header followed by nonsense: zlib refuses rather than returning nothing.
  assert.throws(
    () => decompress(new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
    WarcError,
  );
  assert.throws(() => decompress(new Uint8Array([0x1f, 0x8b, 0x08, 0x00])), WarcError);
});

test('two bytes of gzip magic are not enough to be a stream', () => {
  // `isGzipped` refuses anything shorter than a minimal stream, so two bytes are passed through
  // untouched and refused by the record reader instead. Two ways to refuse, and neither of them
  // guesses at what the caller meant.
  const stub = new Uint8Array([0x1f, 0x8b]);
  assert.deepEqual(decompress(stub), stub);
  assert.throws(() => findMainDocument(stub), /contains no WARC records/);
});

test('a stream cut short is refused by whichever layer notices', () => {
  // zlib refuses a truncated gzip stream, so a capture cut mid-stream is refused before any record is
  // read. This was measured rather than assumed: the assumption that zlib would quietly return what it
  // had was wrong, and the test that encoded it failed.
  const whole = storeGzip(responseRecord(DEFAULT_URL, DEFAULT_HTML));
  assert.throws(
    () => findMainDocument(whole.subarray(0, whole.length - 40)),
    /could not be decompressed/,
  );

  // The other shape of partial capture: a perfectly valid stream holding a record that was itself cut
  // short before it was compressed. The record layer refuses it, because its declared length is longer
  // than the bytes that survived.
  const cutRecord = responseRecord(DEFAULT_URL, DEFAULT_HTML).subarray(0, 200);
  assert.throws(() => findMainDocument(storeGzip(cutRecord)), /no HTTP header block|appears to be truncated/);
});

test('a record that disagrees with its own payload digest is refused', () => {
  const payload = httpResponse('<p>body</p>');
  const record = warcWith([
    'WARC-Type: response',
    'WARC-Target-URI: https://example.org/x',
    `WARC-Payload-Digest: sha256:${base64Digest('something else entirely')}`,
  ], payload);

  assert.throws(() => findMainDocument(record), /Either the capture is corrupt/);
});

test('a record that agrees with its own payload digest is accepted', () => {
  const payload = httpResponse('<p>body</p>');
  const record = warcWith([
    'WARC-Type: response',
    'WARC-Target-URI: https://example.org/x',
    `WARC-Payload-Digest: sha256:${base64Digest(payload)}`,
  ], payload);

  assert.equal(text(findMainDocument(record).body), '<p>body</p>');
});

test('a digest in an algorithm this reader does not know is left alone', () => {
  const payload = httpResponse('<p>body</p>');
  const record = warcWith([
    'WARC-Type: response',
    'WARC-Target-URI: https://example.org/x',
    'WARC-Payload-Digest: sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed',
  ], payload);

  assert.equal(text(findMainDocument(record).body), '<p>body</p>');
});

test('a WARC date becomes the one timestamp form the claim admits', () => {
  assert.equal(toClaimTimestamp('2026-01-01T00:00:00Z'), '2026-01-01T00:00:00Z');
  assert.equal(toClaimTimestamp('2026-01-01T00:00:00.123456Z'), '2026-01-01T00:00:00Z');
  assert.equal(toClaimTimestamp('2026-01-01T00:00:00+01:00'), null);
  assert.equal(toClaimTimestamp('yesterday'), null);
  assert.equal(toClaimTimestamp(null), null);
});

test('an HTTP status line is required, and other statuses are read as they are', () => {
  assert.equal(parseHttpResponse(utf8('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')).status, 404);
  assert.throws(() => parseHttpResponse(utf8('NOT-HTTP\r\n\r\n')), /HTTP status line/);
});
