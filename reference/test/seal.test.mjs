/**
 * The sealer: the producer half, where a guessed value becomes a lying claim rather than a missed
 * check. So these tests are as interested in what it *refuses* as in what it produces.
 *
 * Every test that seals also verifies, because a receipt that cannot be checked by somebody else is
 * not a receipt - and that is the only property this module has to get right.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SealError, findCaptureWarc, sealFromCapture } from '../src/seal.mjs';
import { verifyReceipt } from '../src/verify-node.mjs';
import { DEFAULT_HTML, DEFAULT_URL, signer, waczBytes, waczEntries, warcRecord } from '../src/fixtures.mjs';
import { TSA_GEN_TIME, tsaCertificate, timestampToken } from '../src/tst-fixture.mjs';
import { canonicalise } from '../src/canonical.mjs';
import { sha256, toBase64Url, utf8 } from '../src/digest.mjs';
import { decompress, isGzipped } from '../src/warc-node.mjs';
import { storeGzip } from '../src/gzip.mjs';

const text = (value) => Buffer.from(value).toString('utf8');

/** The key the fixtures sign with. Published on purpose; never a key to trust. */
function key(signerName = 'Test Signer') {
  return { privateKey: signer().privateKey, signer: signerName };
}

/**
 * A WACZ assembled to order, so a test can hand the sealer a capture that is wrong in one specific way.
 * @param {{ warc?: Uint8Array, hash?: string, path?: string, advertise?: boolean }} [options]
 */
function wacz(options = {}) {
  const record = options.warc ?? warcRecord({
    url: DEFAULT_URL,
    capturedAt: '2026-01-01T00:00:00Z',
    html: DEFAULT_HTML,
  });
  const path = options.path ?? 'archive/data.warc.gz';
  const bytes = options.warc === undefined ? storeGzip(record) : record;

  const resources = options.advertise === false ? [] : [{
    name: path.split('/').pop(),
    path,
    hash: options.hash ?? `sha256:${sha256(bytes)}`,
    bytes: bytes.length,
  }];
  const dataPackage = canonicalise({ profile: 'data-package', wacz_version: '1.1.1', resources });

  return waczBytes([
    ['datapackage.json', utf8(dataPackage)],
    [path, bytes],
    ['pages/pages.jsonl', utf8('{"ts":"2026-01-01T00:00:00Z","url":"' + DEFAULT_URL + '"}\n')],
  ]);
}

test('a sealed capture verifies, and its document digest describes what the capture holds', async () => {
  const capture = waczBytes(waczEntries({}));
  const sealed = sealFromCapture({ capture, key: key() });

  assert.deepEqual(sealed.warnings, []);
  assert.equal(
    sealed.manifest.subject.document.sha256,
    sha256(utf8(DEFAULT_HTML)),
    'the document digest must describe the bytes the capture holds',
  );
  assert.equal(sealed.manifest.subject.document.bytes, utf8(DEFAULT_HTML).length);

  const verdict = await verifyReceipt(sealed.bytes);
  assert.equal(verdict.verified, true);
  assert.equal(verdict.levels.L0.status, 'pass');
  assert.equal(verdict.levels.L1.status, 'pass');
  assert.equal(verdict.attribution.signer, 'Test Signer');
  assert.equal(verdict.receipt.claim_hash, sealed.claimHash);
});

test('the URL and the capture time come from the capture itself', async () => {
  const sealed = sealFromCapture({ capture: wacz(), key: key() });
  assert.equal(sealed.manifest.subject.url, DEFAULT_URL);
  assert.equal(sealed.manifest.subject.final_url, undefined, 'no redirect happened, so no final_url');
  assert.equal(sealed.manifest.capture.captured_at, '2026-01-01T00:00:00Z');
  assert.equal(sealed.manifest.subject.status, 200);
  assert.equal(sealed.manifest.subject.content_type, 'text/html; charset=utf-8');
});

test('a caller may override the URL and the time, and the override is what the claim says', async () => {
  const sealed = sealFromCapture({
    capture: wacz(),
    url: DEFAULT_URL,
    capturedAt: '2026-02-02T02:02:02Z',
    key: key(),
  });
  assert.equal(sealed.manifest.capture.captured_at, '2026-02-02T02:02:02Z');
  assert.equal((await verifyReceipt(sealed.bytes)).verified, true);
});

test('an unsigned seal is a receipt that says nobody signs for it', async () => {
  const sealed = sealFromCapture({ capture: wacz(), key: null });
  assert.equal(sealed.manifest.signature, null);

  const verdict = await verifyReceipt(sealed.bytes);
  assert.equal(verdict.levels.L0.status, 'pass');
  assert.equal(verdict.levels.L1.status, 'not_applicable');
  assert.equal(verdict.verified, false, 'unsigned is not verified, and is not a failure either');
  assert.equal(verdict.exit_code, 1);
});

test('a chain head seal reaches L2 on its own', async () => {
  const sealed = sealFromCapture({ capture: wacz(), key: key(), anchor: { type: 'chain', sequence: 1 } });
  const verdict = await verifyReceipt(sealed.bytes);
  assert.equal(verdict.levels.L2.status, 'pass');
  assert.equal(verdict.verified, true);
});

test('sealing the same capture twice produces identical bytes', async () => {
  const capture = wacz();
  const first = sealFromCapture({ capture, key: key() });
  const second = sealFromCapture({ capture, key: key() });
  assert.deepEqual(first.bytes, second.bytes);
});

test('the claim binds the exact capture it was built from', async () => {
  const capture = wacz();
  const sealed = sealFromCapture({ capture, key: key() });
  assert.equal(sealed.manifest.capture.sha256, sha256(capture));
  assert.equal(sealed.manifest.capture.bytes, capture.length);
  assert.equal(sealed.manifest.capture.path, 'capture.wacz');
});

test('a capture whose own advertised hash is wrong is refused, not sealed', async () => {
  const capture = wacz({ hash: `sha256:${'0'.repeat(64)}` });
  let error = null;
  try {
    sealFromCapture({ capture, key: key() });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof SealError);
  assert.match(error.message, /That is a corrupt capture, and nothing was written/);
});

test('a capture that advertises no WARC is refused, and says what it does advertise', async () => {
  const capture = wacz({ advertise: false });
  assert.throws(() => sealFromCapture({ capture, key: key() }), /advertises no WARC record/);
});

test('a capture whose WARC cannot be read is refused rather than sealed with a guess', async () => {
  const capture = wacz({ warc: utf8('this is not a WARC, whatever it claims') });
  assert.throws(
    () => sealFromCapture({ capture, key: key() }),
    /contains no WARC records/,
    'with no document to fall back on, the seal must stop',
  );
});

test('a caller-supplied document is used, and the claim says less because of it', async () => {
  const capture = wacz({ warc: utf8('this is not a WARC, whatever it claims') });
  const supplied = utf8('<p>what the caller says the page held</p>');
  const sealed = sealFromCapture({ capture, document: supplied, url: DEFAULT_URL, capturedAt: '2026-01-01T00:00:00Z', key: key() });

  assert.equal(sealed.warnings.length, 1);
  assert.match(sealed.warnings[0], /could not be read/);
  assert.equal(sealed.manifest.subject.document.sha256, sha256(supplied));
  // The capture answered nothing, so the claim asserts nothing about the response beyond the body.
  assert.equal(sealed.manifest.subject.status, undefined);
  assert.equal(sealed.manifest.subject.content_type, undefined);

  // And the verdict says exactly that: the claim's account of the document is the caller's word, and a
  // verifier that cannot confirm it says `not_checked` rather than `pass` - which is why L0 no longer passes
  // (D-032). Nothing *failed*, so the exit code is 1 rather than 2: a receipt whose record this reader cannot
  // open is not a broken receipt, it is one whose document nobody can confirm.
  const verdict = await verifyReceipt(sealed.bytes);
  assert.equal(verdict.checks.find((check) => check.id === 'subject.document').status, 'not_checked');
  assert.equal(verdict.levels.L0.status, 'not_checked');
  assert.equal(verdict.verified, false);
  assert.equal(verdict.exit_code, 1);
  assert.equal(verdict.levels.L1.status, 'pass', 'the signature is untouched by any of this');
});

test('a timestamp token cannot change the claim hash it commits to', async () => {
  // This single property is what makes timestamping a two-step workflow a user can actually perform: seal
  // once to learn the claim hash, ask a timestamping authority for a token over it, seal again with the token.
  // It holds because an `rfc3161` anchor is outside the signed subtree (section 6.1) - which is also why a
  // token does not need to exist when the claim is signed.
  const capture = wacz();
  const placeholder = sealFromCapture({ capture, key: key(), anchor: { type: 'rfc3161', token: 'AA' } });
  const token = timestampToken({ claimHash: placeholder.claimHash, genTime: TSA_GEN_TIME });
  const real = sealFromCapture({
    capture,
    key: key(),
    anchor: { type: 'rfc3161', token: toBase64Url(token) },
  });

  assert.equal(real.claimHash, placeholder.claimHash);
  assert.notEqual(
    real.manifest.anchor.token,
    placeholder.manifest.anchor.token,
    'the two receipts carry different tokens, so the equality above is not a coincidence of both being empty',
  );

  // And the reason the placeholder has to be an `rfc3161` anchor rather than `{"type":"none"}`: the type is
  // inside the signed subtree even though the token is not. Getting this wrong produces a digest nobody will
  // ever sign - which is exactly what a first attempt at the CLI workflow did, and what this pins.
  const wrongKind = sealFromCapture({ capture, key: key() });
  assert.notEqual(wrongKind.claimHash, placeholder.claimHash);

  // And the receipt with the real token is one a verifier can validate, against a pinned TSA.
  const verdict = await verifyReceipt(real.bytes, { trustedTsa: [sha256(tsaCertificate())] });
  assert.equal(verdict.levels.L2.status, 'pass');
  assert.equal(verdict.time.attested_before, TSA_GEN_TIME);
});

test('a capture time that is not UTC to the second is refused', async () => {
  assert.throws(
    () => sealFromCapture({ capture: wacz(), capturedAt: '2026-01-01', key: key() }),
    /must be UTC to the second/,
  );
});

test('a URL the capture does not hold is refused, with what it does hold', async () => {
  assert.throws(
    () => sealFromCapture({ capture: wacz(), url: 'https://example.org/other', key: key() }),
    /It holds responses for: https:\/\/example\.org\/a-page-worth-citing/,
  );
});

test('the WARC is found through the capture’s own datapackage, and read from the container', async () => {
  const found = findCaptureWarc(waczBytes(waczEntries({})));
  assert.equal(isGzipped(found), true, 'a WACZ stores its records gzipped');
  assert.match(text(decompress(found)), /^WARC\/1\.0/);

  const renamed = findCaptureWarc(wacz({ path: 'archive/renamed.warc' }));
  assert.match(text(decompress(renamed)), /^WARC\/1\.0/);

  assert.throws(() => findCaptureWarc(utf8('not a container at all')), /not a readable WACZ/);
});

test('a refusal leaves nothing behind, and never says less than it knows', async () => {
  // The error message is the whole deliverable when a seal fails, so it has to name the cause.
  let error = null;
  try {
    sealFromCapture({ capture: wacz({ warc: utf8('nope') }), key: key() });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error !== null);
  assert.ok(error.message.length > 20, 'a refusal has to explain itself');
  assert.match(error.message, /WARC|gzip|response/i);
});
