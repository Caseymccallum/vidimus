/**
 * The claim: what a receipt asserts, and the bytes a signature covers.
 *
 * This module is the single definition of the claim's shape, and it is the seam that lets the project
 * have two producers without having two formats. `seal.mjs` (Node, Ed25519 from `node:crypto`) and the
 * browser extension (WebCrypto) both call `draftClaim` and `finishClaim`; only the signing step differs,
 * and that is exactly the difference that should exist (D-020).
 *
 * It is browser-safe: no `node:` imports, no `Buffer`, and no dependency on the verifier. The pure
 * pieces of the format that used to live in `verify.mjs` - the specification version, the
 * domain-separated message, and the rule for what is inside the signed subtree - are here instead,
 * because a producer needs them and the verifier does not own them.
 *
 * The two call sequence is deliberate, and it is what makes an asynchronous signer possible:
 *
 * ```js
 * const draft = draftClaim({ ... });           // manifest with signature: null, plus the claim hash
 * const signature = await signSomehow(draft.message);
 * const { bytes } = finishClaim(draft.manifest, signature);
 * ```
 *
 * @module claim
 */

import { canonicalise } from './canonical.mjs';
import { toHex, utf8 } from './encode.mjs';
import { sha256 } from './sha256.mjs';
import { writeZip } from './zip-write.mjs';

/**
 * The specification version a producer writes into a new claim.
 *
 * One constant, in one module, because a fixture, a sealer, a browser and a verifier that disagree
 * about the format version produce receipts that verify nowhere for a reason nobody can see.
 */
export const SPEC_VERSION = '0.1.0';

/** The only signature algorithm this version of the format defines. */
export const ED25519_ALG = 'ed25519';

/** The domain-separation prefix for signature messages, per major specification version. */
const SIGNING_PREFIX_BY_MAJOR = new Map([[0, 'vidimus/claim/']]);

/**
 * The message a signature covers: `vidimus/claim/<spec_version>:<claim_hash>`.
 *
 * Frozen, and looked up rather than interpolated, for one reason: this string is inside every signature
 * ever produced, so editing it silently invalidates every receipt already in the world. A future rename
 * adds an entry for a *new* major version and leaves this one alone (D-013, D-015).
 *
 * @param {string} specVersion
 * @param {string} claimHash
 * @returns {Uint8Array | null} Null when there is no prefix for that major version.
 */
export function signingMessage(specVersion, claimHash) {
  const major = Number.parseInt(String(specVersion).split('.')[0], 10);
  const prefix = SIGNING_PREFIX_BY_MAJOR.get(major);
  if (prefix === undefined) return null;
  return utf8(`${prefix}${specVersion}:${claimHash}`);
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The part of a manifest the signature covers: everything except `signature`, and except an `rfc3161`
 * anchor.
 *
 * `signature` is excluded because a signature cannot cover itself. The anchor rule is the interesting
 * one: **an anchor that could have existed when the claim was signed is signed; one that cannot be is
 * not.** A chain link knows its `sequence` and `prev_claim_hash` before the claim hash exists, and
 * `{"type":"none"}` is a statement made at signing time, so both are inside the signed subtree. An RFC
 * 3161 token is a *response* to a digest, so it cannot be inside the thing it commits to - and does not
 * need to be, because it independently commits to the claim hash (D-011, D-012).
 *
 * @param {Record<string, any>} manifest
 * @returns {Record<string, any>}
 */
export function signedSubtree(manifest) {
  const rest = { ...manifest };
  delete rest.signature;
  if (isObject(rest.anchor) && rest.anchor.type === 'rfc3161') delete rest.anchor;
  return rest;
}

/**
 * The claim hash: SHA-256 over the canonical form of the signed subtree, as lowercase hex.
 *
 * Computed and never stored (D-004).
 *
 * @param {Record<string, any>} manifest
 * @returns {string}
 */
export function claimHashOf(manifest) {
  return toHex(sha256(utf8(canonicalise(signedSubtree(manifest)))));
}

/**
 * Build a claim up to the point of signing.
 *
 * Everything except the signature is decided here, which is the point: `seal.mjs` and the browser
 * extension both call this, so they cannot disagree about what a claim contains. The caller supplies
 * the document digest rather than this module deriving it, because deriving it means reading the
 * capture, and reading the capture is a separate job with a separate failure mode (D-016).
 *
 * The optional fields follow the same rule as everywhere else in this project: a field is present only
 * when its value is known. `status` and `content_type` are absent rather than guessed, because a
 * guessed value inside a signature is a falsehood and an absent one is a fact about what was observed.
 *
 * @param {{
 *   capture: Uint8Array,
 *   url: string,
 *   finalUrl?: string | null,
 *   status?: number | null,
 *   contentType?: string | null,
 *   capturedAt: string,
 *   document: { sha256: string, bytes: number },
 *   anchor?: Record<string, any>,
 *   tool?: { name: string, version: string },
 * }} input
 * @returns {{ manifest: Record<string, any>, claimHash: string, message: Uint8Array, capture: Uint8Array }}
 */
export function draftClaim(input) {
  const manifest = {
    spec_version: SPEC_VERSION,
    canonical_form: 'canonical-json-v1',
    capture: {
      path: 'capture.wacz',
      media_type: 'application/wacz',
      sha256: toHex(sha256(input.capture)),
      bytes: input.capture.length,
      captured_at: input.capturedAt,
    },
    subject: {
      url: input.url,
      ...(typeof input.finalUrl === 'string' && input.finalUrl !== input.url
        ? { final_url: input.finalUrl }
        : {}),
      ...(Number.isInteger(input.status) ? { status: input.status } : {}),
      ...(typeof input.contentType === 'string' && input.contentType !== ''
        ? { content_type: input.contentType }
        : {}),
      document: { sha256: input.document.sha256, bytes: input.document.bytes },
    },
    tool: input.tool ?? { name: 'vidimus', version: SPEC_VERSION },
    signature: null,
    anchor: input.anchor ?? { type: 'none' },
  };

  const claimHash = claimHashOf(manifest);
  const message = signingMessage(manifest.spec_version, claimHash);
  if (message === null) {
    // A build error rather than a caller error: this module writes the version itself, so a version it
    // cannot sign for is a mistake in this file.
    throw new Error(`this build has no signing prefix for ${manifest.spec_version}`);
  }

  return { manifest, claimHash, message, capture: input.capture };
}

/**
 * Add the signature and write the container.
 *
 * The claim hash is recomputed from the finished manifest rather than carried over, so that a
 * signature which somehow changed the signed subtree would be caught here instead of producing a
 * receipt that verifies nowhere. The tests assert the two hashes are equal, which is the property that
 * makes a signature still valid after the signature field is added.
 *
 * @param {{ manifest: Record<string, any>, capture: Uint8Array }} draft
 * @param {Record<string, any> | null} signature
 * @returns {{ bytes: Uint8Array, manifest: Record<string, any>, claimHash: string }}
 */
export function finishClaim(draft, signature) {
  const manifest = { ...draft.manifest, signature: signature ?? null };
  const claimHash = claimHashOf(manifest);
  const bytes = writeZip(
    [['receipt.json', utf8(canonicalise(manifest))], ['capture.wacz', draft.capture]],
    { date: new Date(manifest.capture.captured_at) },
  );
  return { bytes, manifest, claimHash };
}
