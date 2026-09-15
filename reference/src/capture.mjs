/**
 * Turning what a browser knows into a capture.
 *
 * This is the module the extension will call: it takes facts a page can supply and produces a WACZ
 * that `seal.mjs` will turn into a receipt. It is here, in the reference implementation, rather than
 * in the extension, because *making* a capture is a format concern (D-018) - an extension that
 * re-implemented it would be a second source of truth for what a receipt contains, which is the
 * failure this repository exists to avoid.
 *
 * ## What the capture holds, and why it is not the wire bytes
 *
 * The body of the record this module writes is **the document as the browser rendered it**, not the
 * bytes the server sent. That is not a shortcut, it is the honest answer available under Manifest V3:
 *
 * - `webRequest` can observe a request's headers and status, but not its body.
 * - Reading the body would mean either re-fetching the URL (a second request, which answers with
 *   something else - a login wall, a rotated ad, a rate limit) or driving `chrome.debugger`, which
 *   asks the user to hand over a great deal more than a receipt needs.
 *
 * So the capture is the rendered document, and it is labelled as such rather than presented as
 * something it is not. The observed status and the observed response headers are recorded beside it,
 * because those *were* observed; the handful of headers that describe a wire representation that no
 * longer applies - `Content-Length`, `Transfer-Encoding`, `Content-Encoding` - are dropped, because
 * leaving them in would describe these bytes as something they are not.
 *
 * Nothing here touches a browser, the network or the filesystem: the caller supplies the facts, and
 * this turns them into bytes. Everything it cannot check, it refuses to invent.
 *
 * @module capture
 */

import { canonicalise } from './canonical.mjs';
import { toBase64, toHex, utf8 } from './encode.mjs';
import { storeGzip } from './gzip.mjs';
import { sha256 } from './sha256.mjs';
import { writeZip } from './zip-write.mjs';

/** Thrown when the facts handed over do not add up to a capture. */
export class CaptureError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'CaptureError';
  }
}

/**
 * Headers that describe how the body travelled, which cannot describe a rendered document.
 *
 * Dropping them is the difference between a capture that says "this is the document as rendered" and
 * one that says "this is the response body" while holding something else. The second is a lie, and a
 * verifier that trusted it would refuse the receipt for the wrong reason.
 */
const REPRESENTATION_HEADERS = new Set(['content-length', 'content-encoding', 'transfer-encoding']);

/**
 * Normalise headers from whatever shape a browser gave them.
 *
 * @param {Record<string, string> | Array<[string, string]> | Iterable<[string, string]> | undefined} headers
 * @returns {Array<[string, string]>}
 */
function normaliseHeaders(headers) {
  if (headers === undefined || headers === null) return [];

  // The array check has to come first, and that is not a style choice: `Array.prototype.entries`
  // exists, so a plain array of pairs would otherwise be taken apart into index/value pairs and every
  // header would be silently dropped by the filter below. The tests that compare the three shapes
  // against each other are what caught it.
  let entries;
  if (Array.isArray(headers)) entries = headers;
  else if (typeof headers.entries === 'function') entries = [...headers.entries()];
  else entries = Object.entries(headers);

  return entries
    .filter(([name, value]) => typeof name === 'string' && typeof value === 'string')
    .filter(([name]) => !REPRESENTATION_HEADERS.has(name.toLowerCase()));
}

/**
 * A record identifier derived from the record's own content.
 *
 * The WARC specification requires a globally unique `WARC-Record-ID`, and the obvious implementation
 * is a random UUID. That is rejected here because it would make two captures of the same page produce
 * different bytes, and this project relies on "same inputs, same bytes" for its tests and for its
 * ability to explain a fixture's digest. Deriving the identifier from the record's content keeps the
 * uniqueness in practice and the reproducibility in fact.
 *
 * @param {string[]} parts
 * @returns {string}
 */
function derivedRecordId(parts) {
  const digest = sha256(utf8(parts.join('\u0000')));
  const hex = toHex(digest).slice(0, 32);
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
function concat(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

/**
 * The HTTP block: the status line that was observed, the headers that were observed, and the document
 * as the body.
 *
 * The `Content-Length` here is the *captured* body's length, which is why the observed one was dropped
 * on the way in. A reader of the record therefore sees a response whose body is the rendered document
 * and whose length matches it, rather than a response claiming a length it does not have.
 *
 * @param {{ status: number, statusText: string, headers: Array<[string, string]>, body: string }} input
 * @returns {Uint8Array}
 */
function buildHttpBlock({ status, statusText, headers, body }) {
  const bodyBytes = utf8(body);
  const lines = [`HTTP/1.1 ${status}${statusText === '' ? '' : ` ${statusText}`}`];
  for (const [name, value] of headers) lines.push(`${name}: ${value}`);
  lines.push(`Content-Length: ${bodyBytes.length}`);
  return concat([utf8(`${lines.join('\r\n')}\r\n\r\n`), bodyBytes]);
}

/**
 * One WARC response record, holding one document.
 *
 * @param {{
 *   url: string, status: number, statusText?: string,
 *   headers?: Record<string, string> | Array<[string, string]> | Iterable<[string, string]>,
 *   capturedAt: string, body: string,
 * }} input
 * @returns {Uint8Array}
 */
export function buildWarcRecord(input) {
  const headers = normaliseHeaders(input.headers);
  const payload = buildHttpBlock({
    status: input.status,
    statusText: input.statusText ?? '',
    headers,
    body: input.body,
  });
  const payloadDigest = toBase64(sha256(payload));

  const recordHeaders = [
    'WARC-Type: response',
    `WARC-Target-URI: ${input.url}`,
    `WARC-Date: ${input.capturedAt}`,
    `WARC-Record-ID: ${derivedRecordId([input.url, input.capturedAt, payloadDigest])}`,
    `WARC-Payload-Digest: sha256:${payloadDigest}`,
    'Content-Type: application/http; msgtype=response',
    `Content-Length: ${payload.length}`,
  ];

  return concat([utf8(`WARC/1.0\r\n${recordHeaders.join('\r\n')}\r\n\r\n`), payload]);
}

/**
 * A whole capture: one WARC record, gzipped, inside a WACZ that advertises it.
 *
 * The shape is the one `seal.mjs` and `warc.mjs` already read, which is the point of this module living
 * in the reference implementation rather than in the extension: there is one definition of what a
 * capture is, and both halves of the project use it (D-018).
 *
 * @param {{
 *   url: string, finalUrl?: string, status: number, statusText?: string,
 *   headers?: Record<string, string> | Array<[string, string]> | Iterable<[string, string]>,
 *   html: string, capturedAt: string,
 * }} input
 * @returns {{ wacz: Uint8Array, record: Uint8Array, document: { sha256: string, bytes: number } }}
 * @throws {CaptureError}
 */
export function buildCapture(input) {
  let parsed;
  try {
    parsed = new URL(input.url);
  } catch {
    throw new CaptureError(`the URL is not absolute: ${input.url}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new CaptureError(`a receipt is for an http or https page: ${input.url}`);
  }
  if (!Number.isInteger(input.status) || input.status < 100 || input.status > 599) {
    throw new CaptureError(`the status must be a whole number between 100 and 599: ${input.status}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(input.capturedAt)) {
    throw new CaptureError(
      `capturedAt must be UTC to the second, such as 2026-01-01T00:00:00Z: ${input.capturedAt}`,
    );
  }
  if (typeof input.html !== 'string' || input.html.trim() === '') {
    throw new CaptureError('there is no document to capture: a capture of nothing is not a capture');
  }

  const finalUrl = input.finalUrl ?? input.url;
  const record = buildWarcRecord({
    url: finalUrl,
    status: input.status,
    statusText: input.statusText ?? '',
    headers: input.headers,
    capturedAt: input.capturedAt,
    body: input.html,
  });

  const warc = storeGzip(record);
  const warcPath = 'archive/data.warc.gz';
  const dataPackage = canonicalise({
    profile: 'data-package',
    wacz_version: '1.1.1',
    resources: [{
      name: warcPath.split('/').pop(),
      path: warcPath,
      hash: `sha256:${toHex(sha256(warc))}`,
      bytes: warc.length,
    }],
  });
  const pages = canonicalise({ ts: input.capturedAt, url: finalUrl });

  const wacz = writeZip([
    ['datapackage.json', utf8(dataPackage)],
    [warcPath, warc],
    ['pages/pages.jsonl', utf8(`${pages}\n`)],
  ], { date: new Date(input.capturedAt) });

  const html = utf8(input.html);
  return {
    wacz,
    record,
    document: { sha256: toHex(sha256(html)), bytes: html.length },
  };
}
