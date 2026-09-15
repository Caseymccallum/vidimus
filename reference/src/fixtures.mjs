/**
 * Fixture construction: the deterministic inputs the conformance vectors are recorded
 * against.
 *
 * Everything here is a pure function of its arguments and the two fixed seeds below. No
 * clock, no randomness, no environment. That is what makes a *recorded* digest in
 * `spec/vectors/receipt-vectors.json` meaningful: if a fixture changes, the recorded
 * value stops matching and `npm run verify` says so, instead of the suite quietly
 * testing something else.
 *
 * The fixtures are deliberately not real captures. A real capture of a real page is not
 * reproducible, and a test that depends on one fails on a Tuesday when a site changes its
 * footer. What these reproduce is the *structure* - a claim, a container, a WACZ with
 * hashed resources, a signature - which is the part the spec constrains.
 *
 * @module fixtures
 */

import { writeZip } from './zip.mjs';
import { canonicalise } from './canonical.mjs';
import { sha256, toBase64Url, utf8, fromHex } from './digest.mjs';
import { privateKeyFromSeed, rawPublicKey, keyId, signMessage } from './signature.mjs';
import { signingMessage, signedSubtree, SPEC_VERSION } from './verify.mjs';
import { storeGzip } from './gzip.mjs';

/**
 * Re-exported so that everything which builds a fixture, a case or a vector can keep asking this
 * module for the version, while there remains exactly one place that defines it (`verify.mjs`).
 */
export { SPEC_VERSION };

/** Fixed, so a written container is byte-identical between runs. */
export const FIXTURE_DATE = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));

/**
 * The signer's seed. Published on purpose: these are fixtures, and a private key in a
 * repository is a private key nobody should ever trust for anything. The verdict for
 * every signed vector carries this key's id, which is how a reader confirms the check ran
 * against the key it claims to.
 */
export const SIGNER_SEED = fromHex(
  '7f2c1f6f9d3af0c61cbe2f1a4d5e6b708192a3b4c5d6e7f8091a2b3c4d5e6f70',
);

/** A second seed, for the vectors that need the wrong key to do the signing. */
export const STRANGER_SEED = fromHex(
  '0f1e2d3c4b5a69788796a5b4c3d2e1f00a1b2c3d4e5f60718293a4b5c6d7e8f9',
);

/** The HTML the fixtures capture, unless one passes its own. */
export const DEFAULT_HTML = '<!doctype html><html><head><title>A page worth citing</title></head>'
  + '<body><h1>A page worth citing</h1><p>Claims were made here.</p></body></html>';

/** The URL the fixtures cite, unless one passes its own. */
export const DEFAULT_URL = 'https://example.org/a-page-worth-citing';

/**
 * @param {Uint8Array} seed
 * @returns {{ privateKey: import('node:crypto').KeyObject, publicKey: Uint8Array, keyId: string }}
 */
function keyFrom(seed) {
  const privateKey = privateKeyFromSeed(seed);
  const publicKey = rawPublicKey(privateKey);
  return { privateKey, publicKey, keyId: keyId(publicKey) };
}

/** The key every signed fixture uses. */
export function signer() {
  return keyFrom(SIGNER_SEED);
}

/** The key that signs the vectors where the named key must not be the signing key. */
export function stranger() {
  return keyFrom(STRANGER_SEED);
}

/**
 * A minimal WARC response record.
 *
 * Valid enough to be recognisable, stable enough to be reproducible. The receipt layer
 * never parses it - see D-010 on why the fixture's gzip is stored-deflate.
 *
 * @param {{ url: string, capturedAt: string, html: string }} input
 * @returns {Uint8Array}
 */
export function warcRecord({ url, capturedAt, html }) {
  const body = utf8(html);
  return utf8([
    'WARC/1.0',
    'WARC-Type: response',
    `WARC-Target-URI: ${url}`,
    `WARC-Date: ${capturedAt}`,
    'Content-Type: application/http; msgtype=response',
    '',
    'HTTP/1.1 200 OK',
    'Content-Type: text/html; charset=utf-8',
    'Cache-Control: no-store',
    `Content-Length: ${body.length}`,
    '',
    html,
    '',
  ].join('\r\n'));
}

/**
 * The entries of a fixture WACZ: a datapackage that advertises the records it holds, and
 * those records.
 *
 * @param {{ url?: string, capturedAt?: string, html?: string }} [input]
 * @returns {Array<[string, Uint8Array]>}
 */
export function waczEntries(input = {}) {
  const url = input.url ?? DEFAULT_URL;
  const capturedAt = input.capturedAt ?? '2026-01-01T00:00:00Z';
  const html = input.html ?? DEFAULT_HTML;
  const path = 'archive/data.warc.gz';
  const record = storeGzip(warcRecord({ url, capturedAt, html }));
  const dataPackage = canonicalise({
    profile: 'data-package',
    wacz_version: '1.1.1',
    resources: [{ name: 'data.warc.gz', path, hash: `sha256:${sha256(record)}`, bytes: record.length }],
  });
  return [
    ['datapackage.json', utf8(dataPackage)],
    [path, record],
    ['pages/pages.jsonl', utf8(`${canonicalise({ ts: capturedAt, url })}\n`)],
  ];
}

/**
 * @param {Array<[string, Uint8Array]>} entries
 * @returns {Uint8Array}
 */
export function waczBytes(entries) {
  return writeZip(entries, { date: FIXTURE_DATE });
}

/**
 * Build a whole `.receipt` container.
 *
 * The order of operations mirrors what a real tool must do, and the order is the point:
 * the claim hash is computed over the manifest *without* its signature and anchor, the
 * signature covers the domain-separated hash, and only then is `receipt.json` serialised
 * in canonical form. Doing it in another order is the most likely way for a new
 * implementation to produce receipts that verify nowhere, which is why the spec states it
 * as a numbered sequence rather than leaving it to the reader.
 *
 * @param {{
 *   url?: string,
 *   capturedAt?: string,
 *   html?: string,
 *   wacz?: Uint8Array,
 *   anchor?: Record<string, any>,
 *   signed?: boolean,
 *   signWith?: import('node:crypto').KeyObject,
 *   publicKeyOverride?: string,
 *   manifestPatch?: (manifest: Record<string, any>) => void,
 *   serialise?: (manifest: Record<string, any>) => Uint8Array,
 *   extraEntries?: Array<[string, Uint8Array]>,
 * }} [input]
 * @returns {{ bytes: Uint8Array, manifest: Record<string, any>, claimHash: string, wacz: Uint8Array }}
 */
export function buildReceipt(input = {}) {
  const url = input.url ?? DEFAULT_URL;
  const capturedAt = input.capturedAt ?? '2026-01-01T00:00:00Z';
  const html = input.html ?? DEFAULT_HTML;
  const wacz = input.wacz ?? waczBytes(waczEntries({ url, capturedAt, html }));

  const manifest = {
    spec_version: SPEC_VERSION,
    canonical_form: 'canonical-json-v1',
    capture: {
      path: 'capture.wacz',
      media_type: 'application/wacz',
      sha256: sha256(wacz),
      bytes: wacz.length,
      captured_at: capturedAt,
    },
    subject: {
      url,
      final_url: url,
      status: 200,
      content_type: 'text/html; charset=utf-8',
      document: { sha256: sha256(utf8(html)), bytes: utf8(html).length },
    },
    tool: { name: 'vidimus-fixture', version: SPEC_VERSION },
    signature: null,
    anchor: input.anchor ?? { type: 'none' },
  };
  if (input.manifestPatch !== undefined) input.manifestPatch(manifest);

  // Computed the way the spec says, and after `manifestPatch` so a vector that changes a
  // field gets a claim hash that commits to the change: a tampered claim must fail on the
  // signature, not accidentally on the hash.
  const claimHash = sha256(canonicalise(signedSubtree(manifest)));

  if (input.signed !== false) {
    const keyObject = input.signWith ?? signer().privateKey;
    manifest.signature = {
      alg: 'ed25519',
      key_id: keyId(rawPublicKey(keyObject)),
      public_key: input.publicKeyOverride ?? toBase64Url(rawPublicKey(keyObject)),
      sig: toBase64Url(signMessage(signingMessage(SPEC_VERSION, claimHash), keyObject)),
      signer: 'Fixture Signer <fixture@example.org>',
    };
  }

  const serialise = input.serialise ?? canonicalJson;
  return {
    bytes: writeZip([
      ['receipt.json', serialise(manifest)],
      ['capture.wacz', wacz],
      ...(input.extraEntries ?? []),
    ], { date: FIXTURE_DATE }),
    manifest,
    claimHash,
    wacz,
  };
}

/**
 * `receipt.json` as the spec requires it: canonical form, UTF-8, no trailing newline.
 *
 * @param {Record<string, any>} manifest
 * @returns {Uint8Array}
 */
export function canonicalJson(manifest) {
  return utf8(canonicalise(manifest));
}

/**
 * What a tool produces when it reaches for `JSON.stringify` and stops there: pretty
 * printed, keys in insertion order. The bytes are still *readable* - which is exactly why
 * the canonical-form check cannot be about readability.
 *
 * @param {Record<string, any>} manifest
 * @returns {Uint8Array}
 */
export function prettyJson(manifest) {
  const visible = { ...manifest };
  if (visible.signature === null) delete visible.signature;
  return utf8(JSON.stringify(visible, null, 2));
}
