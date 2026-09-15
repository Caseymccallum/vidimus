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
import { checkReceipt } from '../../extension/lib/checking.mjs';
import { readStoredZip } from '../../extension/lib/store-zip.mjs';
import { HOST_PERMISSIONS, PERMISSIONS, REASONS } from '../../extension/permissions.mjs';
import { verifyReceipt } from '../src/verify-node.mjs';
import { sha256 } from '../src/digest.mjs';
import { readZip, writeZip } from '../src/zip.mjs';
import { toHex, utf8 } from '../src/encode.mjs';

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

  const verdict = await verifyReceipt(sealed.bytes);
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
  const verdict = await verifyReceipt(sealed.bytes);
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

test('every permission the extension asks for says why', async () => {
  const asked = [...PERMISSIONS, ...HOST_PERMISSIONS];
  for (const permission of asked) {
    assert.ok(
      typeof REASONS[permission] === 'string' && REASONS[permission].length > 20,
      `${permission} is asked for without a reason written down`,
    );
  }
});

test('the permission list changes only on purpose', async () => {
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

test('the browser runtime checks a receipt the browser sealed', async () => {
  const key = await generateKey('Browser Test Signer');
  const sealed = await sealPage({ facts: FACTS, key });
  const verdict = await checkReceipt(sealed.bytes);

  assert.equal(verdict.verified, true);
  assert.equal(verdict.levels.L0.status, 'pass');
  assert.equal(verdict.levels.L1.status, 'pass');
  assert.equal(verdict.attribution.key_id, key.keyId);
  assert.equal(verdict.receipt.claim_hash, sealed.claimHash);
});

test('the browser and the command line reach the same verdict, word for word', async () => {
  // The strongest form this test can take: not "both pass" but "the two verdicts are identical",
  // including every reason. Two runtimes that agree on a verdict can still disagree about why; two that
  // produce the same JSON cannot.
  const sealed = await sealPage({ facts: FACTS, key: await generateKey('Both') });
  const inBrowser = await checkReceipt(sealed.bytes);
  const onCommandLine = await verifyReceipt(sealed.bytes);
  assert.equal(JSON.stringify(inBrowser), JSON.stringify(onCommandLine));
});

test('a receipt that has been tampered with fails in the browser too', async () => {
  const sealed = await sealPage({ facts: FACTS, key: await generateKey('Browser Test Signer') });
  const damaged = sealed.bytes.slice();
  // Somewhere in the middle of the container, past the headers.
  damaged[Math.floor(damaged.length / 2)] ^= 0x01;

  const verdict = await checkReceipt(damaged);
  assert.equal(verdict.verified, false);
  assert.ok(verdict.checks.some((check) => check.status === 'fail'));
});

test('the store-only reader finds exactly what the command-line reader finds', () => {
  // Two readers for two runtimes, pinned against each other the way the two SHA-256s are: if they ever
  // disagree about a container, one of them is wrong and this says so.
  const container = writeZip([
    ['receipt.json', utf8('{"a":1}')],
    ['capture.wacz', utf8('some capture bytes')],
  ]);

  const viaCommandLine = readZip(container);
  const inBrowser = readStoredZip(container);

  assert.deepEqual(inBrowser.order, viaCommandLine.order);
  for (const [name, contents] of inBrowser.entries) {
    assert.equal(toHex(contents), toHex(viaCommandLine.entries.get(name)));
  }
});

test('a container this verifier cannot read is unsupported, not failed', async () => {
  // A receipt whose entry claims to be deflated: perfectly legal ZIP, and beyond a synchronous browser
  // reader. The distinction matters - `fail` would be accusing the receipt of something.
  const container = writeZip([['receipt.json', utf8('{"a":1}')]]);
  const view = new DataView(container.buffer, container.byteOffset, container.byteLength);
  view.setUint16(8, 8, true); // local header: method 8, deflate
  view.setUint16(view.getUint32(container.length - 22 + 16, true) + 10, 8, true); // central directory

  const verdict = await checkReceipt(container);
  const readable = verdict.checks.find((check) => check.id === 'container.readable');
  assert.equal(readable.status, 'unsupported');
  assert.equal(verdict.levels.L0.status, 'unsupported');
  assert.equal(verdict.verified, false);
});
