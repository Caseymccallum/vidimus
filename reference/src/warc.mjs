/**
 * The smallest WARC reader that can answer one question: what was the main document?
 *
 * **Why this exists at all**, given that the verifier refuses to parse WARC (§9 of the
 * specification). A producer and a verifier have opposite duties, and the asymmetry is the argument:
 *
 * - A **verifier** that half-parses a WARC and gets it wrong reports a change that did not happen.
 *   That is bad, so the verifier declines and says `not_checked`.
 * - A **producer** that half-parses and gets it wrong writes a claim that is *false* - a receipt
 *   asserting a document digest that describes something else. There is no honest way to decline,
 *   because the claim requires the field. So the producer reads the capture correctly or stops.
 *
 * Hence the shape of this module: **strict, narrow, and pure.**
 *
 * - Strict: anything it does not recognise is an error, never a guess. It never invents a document.
 * - Narrow: it finds the response record for one URL and parses its embedded HTTP response. It does
 *   not deduplicate records, follow `WARC-Concurrent-To`, handle revisit records, or reconstruct a
 *   site. It cannot grow into a crawler without being rewritten, which is the point (D-016).
 * - Pure: bytes in, a parsed record out. No file access, no clock, no network.
 *
 * It also checks the record's own `WARC-Payload-Digest` when the capture states one, because a
 * capture that disagrees with itself about its own bytes is not something to seal a claim over.
 *
 * It is **pure and runtime-free**: the digest and the inflater are passed in. That is what lets the same
 * record layer run in a command line (Node's `zlib`, Node's SHA-256) and in a browser
 * (`DecompressionStream('gzip')`, WebCrypto) - which matters because the verifier re-reads a capture's
 * document to check a text fingerprint (section 4.5 of the specification), and a browser that could not
 * read a WARC would have to report that check as `not_checked` while the command line reported a `pass`.
 *
 * @module warc
 */

import { fromBase64, fromLatin1, latin1 } from './encode.mjs';

/** Thrown for anything this reader will not guess at. */
export class WarcError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'WarcError';
  }
}

/** Every WARC record begins with this, which is how records are told apart without an index. */
const RECORD_MAGIC = 'WARC/1.0';

/**
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function isGzipped(bytes) {
  return bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

/**
 * Inflate a WARC file if it needs it.
 *
 * `gunzipSync` walks *concatenated* members, which is what a WACZ contains: each record is gzipped
 * on its own so that a CDXJ index can seek to it. That was verified against both zlib's own output
 * and this project's stored-block writer before this module was written, because the alternative -
 * hunting for `1f 8b` boundaries by hand - is the sort of code that works until it meets a payload
 * that contains the magic bytes.
 *
 * A stream that will not inflate is an error here, and that includes a stream cut short: zlib refuses a
 * truncated gzip stream with "unexpected end of file" rather than quietly returning what it had, which
 * is worth stating because the opposite is a common assumption. The record layer refuses the other
 * shape of partial capture - a *valid* stream holding a record whose declared length is longer than
 * the bytes that survived - so a capture cut short is refused at one layer or the other, and never
 * half-read.
 *
 * The inflater comes from the caller, because the two runtimes spell this differently and neither
 * spelling belongs in a format. A runtime that supplies none is told so by name rather than being
 * handed an unreadable stream.
 *
 * @param {Uint8Array} bytes
 * @param {(bytes: Uint8Array) => Uint8Array} [inflate]
 * @returns {Uint8Array}
 */
export function decompress(bytes, inflate) {
  if (!isGzipped(bytes)) return bytes;
  if (typeof inflate !== 'function') {
    throw new WarcError(
      'this capture holds a gzipped WARC and the runtime supplied no inflater for it',
    );
  }
  try {
    return inflate(bytes);
  } catch (error) {
    throw new WarcError(`the capture's WARC file could not be decompressed: ${error.message}`);
  }
}

/**
 * @typedef {object} WarcRecord
 * @property {string} type
 * @property {string | null} targetUri
 * @property {string | null} date
 * @property {string | null} contentType
 * @property {Map<string, string>} headers
 * @property {Uint8Array} payload
 */

/**
 * Split a decompressed WARC into records.
 *
 * Splitting on the record magic rather than on `Content-Length` is deliberate: the length field is
 * optional in practice, writers disagree about what it counts, and a reader that trusts it is a
 * reader that silently mis-slices. The magic is unambiguous in a decompressed stream.
 *
 * @param {Uint8Array} bytes
 * @returns {WarcRecord[]}
 */
export function readWarc(bytes) {
  // latin1 is a byte-for-byte view of the buffer, so string searching stays exact and payloads
  // containing arbitrary binary survive the round trip.
  const text = fromLatin1(bytes);
  const starts = [];
  let found = text.indexOf(RECORD_MAGIC);
  while (found !== -1) {
    starts.push(found);
    found = text.indexOf(RECORD_MAGIC, found + RECORD_MAGIC.length);
  }
  if (starts.length === 0) {
    throw new WarcError('the file contains no WARC records: it does not begin with "WARC/1.0"');
  }

  /** @type {WarcRecord[]} */
  const records = [];
  starts.forEach((start, position) => {
    const end = position + 1 < starts.length ? starts[position + 1] : text.length;
    const slice = text.slice(start, end);
    const headerEnd = slice.indexOf('\r\n\r\n');
    if (headerEnd === -1) {
      throw new WarcError(`WARC record ${position + 1} has no blank line after its headers`);
    }

    /** @type {Map<string, string>} */
    const headers = new Map();
    for (const line of slice.slice(RECORD_MAGIC.length, headerEnd).split('\r\n')) {
      if (line.trim() === '') continue;
      const colon = line.indexOf(':');
      if (colon === -1) {
        throw new WarcError(`WARC record ${position + 1} has an unparsable header: ${line}`);
      }
      const name = line.slice(0, colon).trim().toLowerCase();
      if (!headers.has(name)) headers.set(name, line.slice(colon + 1).trim());
    }

    records.push({
      type: headers.get('warc-type') ?? '',
      targetUri: headers.get('warc-target-uri') ?? null,
      date: headers.get('warc-date') ?? null,
      contentType: headers.get('content-type') ?? null,
      headers,
      payload: latin1(slice.slice(headerEnd + 4)),
    });
  });

  return records;
}

/**
 * Normalise a WARC date to the one form the claim admits: UTC, to the second.
 *
 * Crawlers write `2026-01-01T00:00:00Z` and sometimes `2026-01-01T00:00:00.123456Z`. The claim
 * admits only the first, so the fraction is dropped - deliberately, and only here, where the value
 * has been read from the capture rather than typed by a person.
 *
 * @param {string | null} value
 * @returns {string | null} Null when it is not a timestamp this reader will vouch for.
 */
export function toClaimTimestamp(value) {
  if (typeof value !== 'string') return null;
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z$/.exec(value.trim());
  return match === null ? null : `${match[1]}Z`;
}

/**
 * @typedef {object} HttpResponse
 * @property {number} status
 * @property {string | null} contentType
 * @property {Map<string, string>} headers
 * @property {Uint8Array} body
 */

/**
 * Parse the HTTP response embedded in a `response` record's payload.
 *
 * When the response states a `Content-Length`, the body is cut to it: a record may carry padding, or
 * a trailing block, and treating that as part of the document would make the document digest depend
 * on the crawler's filler. When the stated length is *longer* than the record, the record was
 * truncated and this refuses rather than hashing a partial document.
 *
 * @param {Uint8Array} payload
 * @returns {HttpResponse}
 */
export function parseHttpResponse(payload) {
  const text = fromLatin1(payload);
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    throw new WarcError('the response record has no HTTP header block, so it holds no document');
  }

  const lines = text.slice(0, headerEnd).split('\r\n');
  const statusLine = /^HTTP\/\d(?:\.\d)? (\d{3})(?: .*)?$/.exec(lines[0]);
  if (statusLine === null) {
    throw new WarcError(
      `the response record does not begin with an HTTP status line: "${lines[0].slice(0, 60)}"`,
    );
  }

  /** @type {Map<string, string>} */
  const headers = new Map();
  for (const line of lines.slice(1)) {
    if (line.trim() === '') continue;
    const colon = line.indexOf(':');
    if (colon === -1) throw new WarcError(`the response has an unparsable header: ${line}`);
    const name = line.slice(0, colon).trim().toLowerCase();
    if (!headers.has(name)) headers.set(name, line.slice(colon + 1).trim());
  }

  let body = latin1(text.slice(headerEnd + 4));
  const declared = headers.get('content-length');
  if (declared !== undefined) {
    if (!/^\d+$/.test(declared)) {
      throw new WarcError(`the response states a Content-Length of "${declared}", which is not a number`);
    }
    const length = Number(declared);
    if (length > body.length) {
      throw new WarcError(
        `the response declares ${length} bytes of body and the record holds ${body.length}: the record appears to be truncated`,
      );
    }
    body = body.subarray(0, length);
  }

  return {
    status: Number(statusLine[1]),
    contentType: headers.get('content-type') ?? null,
    headers,
    body,
  };
}

/**
 * @typedef {object} MainDocument
 * @property {string | null} url
 * @property {number} status
 * @property {string | null} contentType
 * @property {Uint8Array} body
 * @property {string | null} capturedAt
 */

/**
 * Find the response record for a page, and return the document it holds.
 *
 * **The bytes must already be inflated**, and the digest must be synchronous. Both are deliberate: the
 * platform's decompressor is a platform's business (Node has `gunzipSync`, a browser has an asynchronous
 * `DecompressionStream`), while the digest used here is this project's own SHA-256, which exists in both
 * runtimes and is pinned against each platform's by a test. Keeping this function synchronous is what lets
 * the producer read a capture without turning every one of its callers asynchronous.
 *
 * With no URL, the first response record is used, which is what a single-page capture holds. With a
 * URL, the record whose `WARC-Target-URI` matches it is used - and if there is none, this refuses and
 * lists the URLs it did find, because "no record for your page" is a fact the caller needs, not a
 * reason to fall back to a different page.
 *
 * @param {Uint8Array} warcBytes Plain (inflated) WARC bytes.
 * @param {string | null} [url]
 * @param {{ digest?: ((bytes: Uint8Array) => string) | null }} [runtime] A digest for the record's own
 * stated `WARC-Payload-Digest`. Without one, a record that states a hash is refused by name rather than
 * passed on unchecked.
 * @returns {MainDocument}
 * @throws {WarcError}
 */
export function findMainDocument(warcBytes, url = null, runtime = {}) {
  const records = readWarc(warcBytes);
  const responses = records.filter((record) => record.type === 'response');
  if (responses.length === 0) {
    throw new WarcError(
      `the capture holds ${records.length} WARC record${records.length === 1 ? '' : 's'}`
      + ' and none of them is an HTTP response',
    );
  }

  let chosen = responses[0];
  if (typeof url === 'string' && url !== '') {
    const match = responses.find((record) => record.targetUri === url);
    if (match === undefined) {
      const seen = [...new Set(responses.map((record) => record.targetUri ?? '(no WARC-Target-URI)'))];
      throw new WarcError(
        `the capture holds no response for ${url}. It holds responses for: ${seen.join(', ')}`,
      );
    }
    chosen = match;
  }

  checkPayloadDigest(chosen, runtime.digest ?? null);
  const response = parseHttpResponse(chosen.payload);
  return {
    url: chosen.targetUri,
    status: response.status,
    contentType: response.contentType,
    body: response.body,
    capturedAt: toClaimTimestamp(chosen.date),
  };
}

/**
 * Compare a record's stated `WARC-Payload-Digest` with the payload it describes.
 *
 * A capture that disagrees with itself about its own bytes is not something to seal a claim over, so
 * a mismatch stops the seal. The message names both digests and admits the other possibility - that
 * this reader's understanding of the field differs from the writing tool's - because that is a real
 * possibility and the reader should not pretend otherwise.
 *
 * A digest in any algorithm other than SHA-256 is left alone: this reader does not know the
 * conventions of an algorithm it has not implemented, and guessing would be worse than silence. A
 * SHA-256 digest with no digest function to check it against is a *named* refusal rather than a silent
 * skip, because skipping it would make "this capture is self-consistent" a claim this reader never
 * established.
 *
 * @param {WarcRecord} record
 * @param {((bytes: Uint8Array) => string) | null} digest
 */
function checkPayloadDigest(record, digest) {
  const stated = record.headers.get('warc-payload-digest');
  if (stated === undefined) return;
  const match = /^sha256:([A-Za-z0-9+/=_-]+)$/.exec(stated);
  if (match === null) return;
  if (digest === null) {
    throw new WarcError(
      'the capture states a WARC-Payload-Digest and no digest function was supplied to check it with',
    );
  }

  const actual = digest(record.payload);
  const statedHex = [...fromBase64(match[1])].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  if (statedHex !== actual) {
    throw new WarcError(
      `the capture states ${stated} for this record's payload, and the payload hashes to `
      + `sha256:${actual}. Either the capture is corrupt, or the tool that wrote it computes `
      + 'WARC-Payload-Digest differently from this reader. Nothing was written.',
    );
  }
}
