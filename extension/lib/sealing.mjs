/**
 * Sealing a page, in a browser.
 *
 * This is the browser half of the producer, and it differs from `seal.mjs` in exactly two ways - both
 * because of where it runs:
 *
 * 1. the capture comes from `capture.mjs`, built out of what the page and the browser could observe,
 *    rather than out of a WARC read from disk;
 * 2. the signature comes from WebCrypto, which is asynchronous.
 *
 * Everything else - what a claim contains, how it is canonicalised, what the signature covers - comes
 * from `claim.mjs`, which is why there is no chance of the two producers disagreeing about the format.
 * The claim-building step is shared; the differences are the two above and nothing else.
 *
 * Written as plain ESM so that the test suite can run this exact path in Node, with Node's WebCrypto,
 * and verify the result with the reference verifier. A browser is not required to know that the browser
 * producer works - only to *use* it.
 *
 * @module sealing
 */

import { buildCapture } from '../../reference/src/capture.mjs';
import { draftClaim, finishClaim } from '../../reference/src/claim.mjs';
import { signClaim } from './keys.mjs';

/**
 * @typedef {object} PageFacts
 * @property {string} url The address being cited.
 * @property {string | null} [finalUrl] Where the document actually came from, when that differs.
 * @property {number | null} [status] The observed status, or null when it was not observed.
 * @property {string | null} [contentType]
 * @property {string | null} [statusText]
 * @property {Array<[string, string]>} [headers] Observed response headers.
 * @property {string} html The rendered document.
 * @property {string} capturedAt UTC to the second.
 */

/**
 * Seal a page into a receipt.
 *
 * @param {{
 *   facts: PageFacts,
 *   key?: { pkcs8: Uint8Array, publicRaw: Uint8Array, signer?: string | null } | null,
 *   anchor?: Record<string, any>,
 * }} input
 * @returns {Promise<{
 *   bytes: Uint8Array, manifest: Record<string, any>, claimHash: string,
 *   capture: Uint8Array, document: { sha256: string, bytes: number },
 * }>}
 */
export async function sealPage(input) {
  const facts = input.facts;
  const capture = buildCapture({
    url: facts.url,
    finalUrl: facts.finalUrl ?? undefined,
    status: facts.status ?? undefined,
    statusText: facts.statusText ?? undefined,
    headers: facts.headers,
    html: facts.html,
    capturedAt: facts.capturedAt,
  });

  const draft = draftClaim({
    capture: capture.wacz,
    url: facts.url,
    finalUrl: facts.finalUrl ?? null,
    status: facts.status ?? null,
    contentType: facts.contentType ?? null,
    capturedAt: facts.capturedAt,
    document: capture.document,
    anchor: input.anchor,
  });

  const signature = input.key === undefined || input.key === null
    ? null
    : await signClaim(input.key, draft.message);

  const finished = finishClaim(draft, signature);
  return {
    bytes: finished.bytes,
    manifest: finished.manifest,
    claimHash: finished.claimHash,
    capture: capture.wacz,
    document: capture.document,
  };
}
