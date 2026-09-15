/**
 * The extension: the browser producer, and the permissions it asks for.
 *
 * The sealing path runs here in Node, with Node's WebCrypto, and its output is checked with the
 * reference verifier. That is the whole argument for keeping the browser logic in plain ESM: a browser
 * is not needed to know that the browser producer works, only to use it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateKey, keyIdOf } from '../../extension/lib/keys.mjs';
import { sealPage } from '../../extension/lib/sealing.mjs';
import { HOST_PERMISSIONS, PERMISSIONS, REASONS } from '../../extension/permissions.mjs';
import { verifyReceipt } from '../src/verify.mjs';
import { sha256 } from '../src/digest.mjs';

/** What a popup can gather: the tab's URL, the observed response, and the rendered document. */
const FACTS = {
  url: 'https://example.org/a-page-worth-citing',
  finalUrl: 'https://example.org/a-page-worth-citing',
  status: 200,
  statusText: 'OK',
  contentType: 'text/html; charset=utf-8',
  headers: [['content-type', 'text/html; charset=utf-8'], ['cache-control', 'no-store']],
  html: '<!doctype html><html><head><title>Sealed from a browser</title></head><body><p>Hello.</p></body></html>',
  capturedAt: '2026-04-05T06:07:08Z',
};

test('the browser path seals a receipt the reference verifier accepts', async () => {
  const key = await generateKey('Browser Test Signer');
  const sealed = await sealPage({ facts: FACTS, key });

  const verdict = verifyReceipt(sealed.bytes);
  assert.equal(verdict.verified, true);
  assert.equal(verdict.levels.L0.status, 'pass');
  assert.equal(verdict.levels.L1.status, 'pass');
  assert.equal(verdict.attribution.signer, 'Browser Test Signer');
  assert.equal(verdict.attribution.key_id, key.keyId);
  assert.equal(verdict.receipt.claim_hash, sealed.claimHash);
  assert.equal(sealed.manifest.subject.document.sha256, sha256(new TextEncoder().encode(FACTS.html)));
  assert.equal(sealed.manifest.subject.status, 200);
  assert.equal(sealed.manifest.subject.content_type, 'text/html; charset=utf-8');
});

test('an unsigned page is a receipt that says nobody signs for it', async () => {
  const sealed = await sealPage({ facts: FACTS, key: null });
  const verdict = verifyReceipt(sealed.bytes);
  assert.equal(verdict.levels.L0.status, 'pass');
  assert.equal(verdict.levels.L1.status, 'not_applicable');
  assert.equal(verdict.verified, false);
  assert.equal(verdict.exit_code, 1);
});

test('the same page and the same key produce the same receipt, twice', async () => {
  // Which requires WebCrypto's Ed25519 to be deterministic, as Ed25519 is, and the container writer to
  // take its timestamps from the capture. Both are properties worth having and neither is obvious.
  const key = await generateKey('Browser Test Signer');
  const first = await sealPage({ facts: FACTS, key });
  const second = await sealPage({ facts: FACTS, key });
  assert.deepEqual(first.bytes, second.bytes);
});

test('the key id is derived from the key, never asserted', async () => {
  const key = await generateKey();
  assert.equal(key.keyId, keyIdOf(key.publicRaw));
  assert.equal(key.publicRaw.length, 32);
  assert.equal(key.keyId.length, 64);
});

test('every permission the extension asks for says why', () => {
  const asked = [...PERMISSIONS, ...HOST_PERMISSIONS];
  for (const permission of asked) {
    assert.ok(
      typeof REASONS[permission] === 'string' && REASONS[permission].length > 20,
      `${permission} is asked for without a reason written down`,
    );
  }
});

test('the permission list changes only on purpose', () => {
  // A speed bump rather than a proof: adding a permission means editing this test as well, so the
  // question "why does it need that?" is asked in the diff rather than after somebody installs it.
  assert.deepEqual(PERMISSIONS, ['storage', 'scripting', 'webRequest']);
  assert.deepEqual(HOST_PERMISSIONS, ['<all_urls>']);
  for (const permission of Object.keys(REASONS)) {
    assert.ok(
      PERMISSIONS.includes(permission) || HOST_PERMISSIONS.includes(permission),
      `${permission} has a reason but is not asked for`,
    );
  }
});
