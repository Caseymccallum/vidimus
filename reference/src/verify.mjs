/**
 * The Receipt-format verifier, as implemented by Vidimus.
 *
 * The whole design in one sentence: **verification is a list of named checks, each of
 * which reports one of five statuses, and a level is `pass` only when every check in it
 * is `pass`.** Nothing is inferred from a check that did not run.
 *
 * That rule exists because the failure mode of a verification tool is not being forged
 * - it is *being believed when it checked nothing*. A verifier that reads a broken
 * capture, cannot find the signer's key, and still prints "verified" is worse than no
 * verifier at all, because the user now has a receipt with a green tick and no reason
 * to look again. Sentinel's `measured: null` rule is the same idea applied to scores
 * (D-006 there, D-005 here).
 *
 * The five statuses:
 *
 * | status | means |
 * | --- | --- |
 * | `pass` | the check ran and the answer is yes |
 * | `fail` | the check ran and the answer is no |
 * | `not_checked` | the check could not run here, for a reason that is stated |
 * | `unsupported` | the receipt asks for something this verifier does not implement |
 * | `not_applicable` | the receipt does not contain the thing being checked |
 *
 * This module is pure with respect to the outside world: it is handed bytes and
 * options, it reads no clock, opens no file, and makes no network request. Level 3
 * ("is the page still the same?") is therefore *declared* here and performed by the
 * caller, never silently by this code - see `docs/THREAT-MODEL.md` section 5.
 *
 * @module verify
 */

import { canonicalise, assertCanonicalBytes, CanonicalJsonError } from './canonical.mjs';
import { fromBase64Url, isSha256Hex, utf8 } from './encode.mjs';
import {
  ED25519_ALG, SPEC_VERSION, claimHashOf, signedSubtree, signingMessage,
} from './claim.mjs';

/**
 * Re-exported from `claim.mjs`, where they live because a producer needs them and the verifier does not
 * own them. Every caller of this module keeps working; the definitions moved, the names did not.
 */
export { SPEC_VERSION, signedSubtree, signingMessage };

/** The specification version this verifier implements. */
export const VERIFIER_VERSION = '0.1.0';

/** Spec versions whose major number this verifier understands. */
export const SUPPORTED_MAJOR = 0;

/**
 * Every check a verdict can contain, with the level it belongs to.
 *
 * This table is the contract. `docs/RECEIPT-SPEC.md` section 6 renders it, the tests
 * assert against it, and `verifyReceipt` refuses to emit a result for an id that is not
 * in it - so a check cannot be quietly dropped from the list and from the docs while
 * still appearing in a verdict.
 */
export const CHECKS = [
  { id: 'container.readable', level: 'L0', description: 'the file is a ZIP that reads' },
  { id: 'manifest.present', level: 'L0', description: 'receipt.json is present' },
  { id: 'manifest.parseable', level: 'L0', description: 'receipt.json is valid JSON' },
  { id: 'manifest.spec_version', level: 'L0', description: 'spec_version is understood' },
  { id: 'manifest.canonical', level: 'L0', description: 'receipt.json is in canonical form' },
  { id: 'manifest.shape', level: 'L0', description: 'required fields are present and typed' },
  { id: 'claim.digest', level: 'L0', description: 'the signed subtree digests deterministically' },
  { id: 'capture.present', level: 'L0', description: 'the capture named by the receipt exists' },
  { id: 'capture.bytes', level: 'L0', description: 'the capture is the declared length' },
  { id: 'capture.digest', level: 'L0', description: 'the capture hashes to the declared digest' },
  { id: 'capture.media_type', level: 'L0', description: 'the capture is a container this verifier reads' },
  { id: 'capture.wacz.readable', level: 'L0', description: 'the capture is a readable WACZ' },
  { id: 'capture.wacz.resources', level: 'L0', description: 'every WACZ resource matches its hash' },
  { id: 'signature.present', level: 'L1', description: 'the claim carries a signature' },
  { id: 'signature.alg', level: 'L1', description: 'the signature algorithm is supported' },
  { id: 'signature.key_id', level: 'L1', description: 'key_id is the digest of public_key' },
  { id: 'signature.verify', level: 'L1', description: 'the signature verifies' },
  { id: 'anchor.present', level: 'L2', description: 'the claim carries a time anchor' },
  { id: 'anchor.verified', level: 'L2', description: 'the time anchor verifies' },
  { id: 'subject.text', level: 'L3', description: 'the text fingerprint matches its definition' },
];

/**
 * The capture profiles this verifier interprets.
 *
 * An unrecognised one is reported and caveated, never judged: the bytes of a capture are checkable
 * whatever it holds, and what it holds is not something a verifier can work out for itself. See section
 * 4.4 of the specification, which also explains why this is not a check.
 */
export const KNOWN_CAPTURE_PROFILES = new Set(['document-v1']);

/** Levels, in order, with what each one is allowed to mean. */
export const LEVELS = [
  { id: 'L0', name: 'integrity', claim: 'these are the bytes this receipt names' },
  { id: 'L1', name: 'attribution', claim: 'the named key signed this claim' },
  { id: 'L2', name: 'time', claim: 'a third party attested the claim existed at a time' },
  { id: 'L3', name: 'currency', claim: 'the page still matches, as of now' },
];

/** Field name for the claim digest. Kept in one place so the spec can cite it. */
export const CLAIM_HASH_FIELD = 'claim_hash';

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Verify a receipt from its bytes.
 *
 * Stage order is deliberate: the claim is checked before anything that depends on a key,
 * a third party or a network, so a verdict can never be more confident than the bytes it
 * was handed justify. Level 3 (whether the page *still* matches) is not performed here
 * at all - it needs the network, and this module does not have one.
 *
 * @param {Uint8Array} bytes The whole `.receipt` container.
 * @param {{
 *   trustedKeys?: string[],
 *   previousClaimHash?: string,
 * }} [options]
 * @returns {{
 *   verifier: { name: string, version: string },
 *   receipt: { spec_version: string | null, claim_hash: string | null, entries: string[] },
 *   capture: { profile: string | null, profile_known: boolean | null },
 *   verified: boolean,
 *   exit_code: 0 | 1 | 2,
 *   levels: Record<string, { status: string, name: string, claim: string }>,
 *   checks: Array<{ id: string, level: string, status: string, reason?: string }>,
 *   attribution: { status: string, key_id: string | null, signer: string | null, key_trusted: string },
 *   time: { claimed: string | null, bound: string, anchor_type: string, attested_before: string | null },
 *   caveats: string[],
 *   summary: string[],
 * }}
 */
export async function verifyReceipt(bytes, options = {}) {
  const runtime = options.runtime;
  if (runtime === undefined) {
    // Named error rather than a silent default, because there is no *silent* default that works in both
    // runtimes: importing the Node primitives here would make this module unimportable in a browser, and
    // guessing would be exactly the sort of convenience that hides a mistake. `verify-node.mjs` is the
    // one-line wrapper that supplies them on a command line.
    throw new Error(
      'verifyReceipt needs a runtime: import the Node one from verify-node.mjs, or pass your own',
    );
  }

  const state = newState();

  const shapeOk = await verifyContainer(bytes, state, runtime);
  if (shapeOk) await verifyCapture(state, runtime);
  recordGaps(state, 'L0', gapReason(state, 'L0'));

  if (state.manifest === null) {
    const reason = gapReason(state, 'L0');
    recordGaps(state, 'L1', reason);
    recordGaps(state, 'L2', reason);
    recordGaps(state, 'L3', reason);
  } else {
    await verifySignature(state, options, runtime);
    recordGaps(state, 'L1', gapReason(state, 'L1'));
    verifyAnchor(state, options);
    recordGaps(state, 'L2', gapReason(state, 'L2'));
    verifyText(state);
    recordGaps(state, 'L3', gapReason(state, 'L3'));
  }

  // Deterministic order, so two verdicts can be compared with a diff rather than read.
  const order = new Map(CHECKS.map((check, index) => [check.id, index]));
  state.results.sort((left, right) => order.get(left.id) - order.get(right.id));

  if (state.results.length !== CHECKS.length) {
    const missing = CHECKS.filter((check) => !state.results.some((r) => r.id === check.id));
    throw new Error(`every check must appear exactly once in a verdict; missing: ${missing.map((c) => c.id).join(', ')}`);
  }

  const manifest = state.manifest;
  if (manifest !== null) {
    const claimedEntries = new Set(['receipt.json', manifest.capture?.path].filter(Boolean));
    const strays = state.entryNames.filter(
      (name) => !claimedEntries.has(name) && !name.startsWith('attestations/'),
    );
    if (strays.length > 0) {
      state.caveats.push(
        `entries that are neither the claim nor its capture nor an attestation: ${strays.join(', ')}`,
      );
    }
    if (typeof manifest.subject?.url === 'string' && manifest.subject.url.startsWith('http:')) {
      state.caveats.push('the page was served over plain HTTP, so this records what a network could alter');
    }

    const declaredProfile = manifest.capture?.profile;
    if (typeof declaredProfile === 'string' && !KNOWN_CAPTURE_PROFILES.has(declaredProfile)) {
      state.caveats.push(
        `the capture declares profile "${declaredProfile}", which this verifier does not interpret: `
        + 'the bytes are checked, and what kind of capture this is, is not',
      );
    }
  }

  const statuses = Object.fromEntries(LEVELS.map((level) => [level.id, rollUpLevel(state, level.id)]));
  const anyFail = state.results.some((result) => result.status === 'fail');
  const verified = !anyFail && statuses.L0 === 'pass' && statuses.L1 === 'pass';
  const signature = isObject(manifest?.signature) ? manifest.signature : null;
  const signatureCheck = state.results.find((result) => result.id === 'signature.verify');
  const anchored = state.results.find((result) => result.id === 'anchor.verified')?.status === 'pass';

  return {
    verifier: { name: 'vidimus', version: VERIFIER_VERSION },
    receipt: {
      spec_version: typeof manifest?.spec_version === 'string' ? manifest.spec_version : null,
      claim_hash: state.claimHash,
      entries: state.entryNames.slice(),
    },
    capture: {
      // Reported, never judged. What kind of capture this is cannot be worked out from its bytes, so a
      // reader is told what the claim says and whether this verifier interprets it (specification 4.4).
      profile: typeof manifest?.capture?.profile === 'string' ? manifest.capture.profile : null,
      profile_known: typeof manifest?.capture?.profile === 'string'
        ? KNOWN_CAPTURE_PROFILES.has(manifest.capture.profile)
        : null,
    },
    verified,
    exit_code: anyFail ? 2 : (verified ? 0 : 1),
    levels: Object.fromEntries(LEVELS.map((level) => [level.id, {
      status: statuses[level.id],
      name: level.name,
      claim: level.claim,
    }])),
    checks: state.results,
    attribution: {
      status: signatureCheck?.status === 'pass'
        ? 'valid'
        : (signatureCheck?.status === 'fail' ? 'invalid' : 'none'),
      key_id: state.keyId ?? (typeof signature?.key_id === 'string' ? signature.key_id : null),
      signer: typeof signature?.signer === 'string' ? signature.signer : null,
      key_trusted: state.trust,
    },
    time: {
      claimed: state.time.claimed,
      bound: anchored ? 'anchored' : 'claimed_only',
      anchor_type: typeof manifest?.anchor?.type === 'string' ? manifest.anchor.type : 'none',
      // Always null in v0.1: no anchor implementation here produces a time, and inventing
      // one from the claim would be exactly the conflation this field exists to prevent.
      attested_before: null,
    },
    caveats: state.caveats,
    summary: summarise(state, statuses),
  };
}

/**
 * The process exit code for a verdict: `0` verified, `2` something failed, `1` nothing
 * failed and the receipt is simply not verified here.
 *
 * Three states rather than two, because "this receipt is broken" and "I could not check
 * this receipt" must not share an exit code in a script. A pipeline that treats them the
 * same will eventually assert a fact it never established.
 *
 * @param {{ exit_code: number }} verdict
 * @returns {number}
 */
export function exitCode(verdict) {
  return verdict.exit_code;
}


/**
 * A timestamp is either a whole-second UTC instant (`2026-09-15T12:00:00Z`) or absent.
 * Milliseconds are refused rather than truncated, because a field that is silently
 * rounded is a field two implementations will disagree about.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isUtcSecondTimestamp(value) {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
    && !Number.isNaN(Date.parse(value));
}

/**
 * Entry names inside a receipt are relative, forward-slashed, and confined to the
 * archive.
 *
 * This is not paranoia about ZIP: it is about *the CLI*, which resolves `capture.path`
 * against a directory to find the capture. A receipt is a file people are encouraged to
 * send each other, so an entry name is untrusted input to a filesystem call, and the
 * rule belongs in the verifier rather than in every consumer of it.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isSafeEntryName(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) return false;
  if (value.startsWith('/') || value.includes('\\')) return false;
  // A colon is a drive letter or an NTFS alternate data stream on Windows, and there is no
  // reason for a receipt to contain one. Refusing it here is cheaper than discovering that
  // `path.join(directory, capture.path)` ignored the directory.
  if (value.includes(':')) return false;
  if (value.includes('//')) return false;
  return !value.split('/').some((segment) => segment === '' || segment === '.' || segment === '..');
}

/**
 * Structural validation, kept separate from cryptographic validation so a malformed
 * receipt and a forged one produce different sentences in the verdict.
 *
 * @param {Record<string, any>} manifest
 * @returns {string[]} One human-readable problem per issue, empty when the shape is fine.
 */
export function validateManifestShape(manifest) {
  const problems = [];
  const requireHex = (value, label) => {
    if (!isSha256Hex(value)) problems.push(`${label} must be 64 lowercase hex characters`);
  };
  const requireInteger = (value, label) => {
    if (!Number.isInteger(value) || value < 0) problems.push(`${label} must be a non-negative integer`);
  };

  if (typeof manifest.spec_version !== 'string' || !/^\d+\.\d+\.\d+$/.test(manifest.spec_version)) {
    problems.push('spec_version must be a semantic version such as "0.1.0"');
  }
  if (manifest.canonical_form !== 'canonical-json-v1') {
    problems.push('canonical_form must be "canonical-json-v1"');
  }

  if (!isObject(manifest.capture)) {
    problems.push('capture must be an object');
  } else {
    if (!isSafeEntryName(manifest.capture.path)) {
      problems.push('capture.path must be a relative entry name inside the receipt');
    }
    if (typeof manifest.capture.media_type !== 'string' || manifest.capture.media_type === '') {
      problems.push('capture.media_type must be a non-empty string');
    }
    requireHex(manifest.capture.sha256, 'capture.sha256');
    requireInteger(manifest.capture.bytes, 'capture.bytes');
    if (!isUtcSecondTimestamp(manifest.capture.captured_at)) {
      problems.push('capture.captured_at must be a UTC timestamp to the second, e.g. "2026-09-15T12:00:00Z"');
    }
  }

  if (!isObject(manifest.subject)) {
    problems.push('subject must be an object');
  } else {
    let url = null;
    try {
      url = new URL(manifest.subject.url);
    } catch {
      problems.push('subject.url must be an absolute URL');
    }
    if (url !== null && url.protocol !== 'http:' && url.protocol !== 'https:') {
      problems.push('subject.url must be an http or https URL');
    }
    if (manifest.subject.final_url !== undefined) {
      try {
        new URL(manifest.subject.final_url);
      } catch {
        problems.push('subject.final_url must be an absolute URL when present');
      }
    }
    if (manifest.subject.status !== undefined && !Number.isInteger(manifest.subject.status)) {
      problems.push('subject.status must be an integer when present');
    }
    if (!isObject(manifest.subject.document)) {
      problems.push('subject.document must be an object');
    } else {
      requireHex(manifest.subject.document.sha256, 'subject.document.sha256');
      requireInteger(manifest.subject.document.bytes, 'subject.document.bytes');
    }
    if (manifest.subject.text !== undefined) {
      if (!isObject(manifest.subject.text)) {
        problems.push('subject.text must be an object when present');
      } else if (manifest.subject.text.normalization !== 'text-v1') {
        problems.push('subject.text.normalization must be "text-v1"');
      } else {
        requireHex(manifest.subject.text.sha256, 'subject.text.sha256');
      }
    }
  }

  if (!isObject(manifest.tool) || typeof manifest.tool.name !== 'string'
      || typeof manifest.tool.version !== 'string') {
    problems.push('tool must be an object with a name and a version');
  }
  if (manifest.signature !== null && manifest.signature !== undefined
      && !isObject(manifest.signature)) {
    problems.push('signature must be an object or null');
  }
  if (!isObject(manifest.anchor) || typeof manifest.anchor.type !== 'string') {
    problems.push('anchor must be an object with a type');
  }
  return problems;
}

/**
 * @typedef {object} VerificationState
 * @property {Array<{ id: string, level: string, status: string, reason?: string }>} results
 * @property {string[]} caveats Non-fatal observations a reader needs to interpret the verdict.
 * @property {Map<string, Uint8Array>} entries Entries of the receipt container.
 * @property {string[]} entryNames In the order the archive lists them.
 * @property {Record<string, any> | null} manifest
 * @property {string | null} claimHash Computed, never stored - see D-004.
 * @property {string | null} keyId
 * @property {'trusted' | 'untrusted' | 'not_checked'} trust
 * @property {{ claimed: string | null, bound: 'claimed_only' | 'anchored', authority: string | null }} time
 */

/**
 * @param {any} state
 * @returns {VerificationState}
 */
function newState() {
  return {
    results: [],
    caveats: [],
    entries: new Map(),
    entryNames: [],
    manifest: null,
    claimHash: null,
    keyId: null,
    trust: 'not_checked',
    time: { claimed: null, bound: 'claimed_only', authority: null },
  };
}

/**
 * Record one check. An id that is not in `CHECKS` is a programming error, not a verdict,
 * so it throws rather than producing a result nobody documented.
 *
 * @param {VerificationState} state
 * @param {string} id
 * @param {'pass' | 'fail' | 'not_checked' | 'unsupported' | 'not_applicable'} status
 * @param {string} [reason]
 */
function record(state, id, status, reason) {
  const known = CHECKS.find((check) => check.id === id);
  if (known === undefined) throw new Error(`unknown check id: ${id}`);
  state.results.push({ id, level: known.level, status, ...(reason ? { reason } : {}) });
}

/**
 * The container and the claim: everything that can be decided before a key or a clock
 * enters the picture.
 *
 * Returns false when a later stage cannot be reached honestly, so the caller marks the
 * remaining checks `not_checked` with a reason instead of leaving them out. A verdict
 * that simply omits checks looks identical to one where they passed, which is the one
 * outcome this file exists to prevent.
 *
 * @param {Uint8Array} bytes
 * @param {VerificationState} state
 * @returns {boolean} Whether the claim is intact enough to keep going.
 */
async function verifyContainer(bytes, state, runtime) {
  let archive;
  try {
    archive = await runtime.readContainer(bytes);
  } catch (error) {
    // A runtime is allowed to declare a limit rather than a verdict. An error carrying
    // `code: 'unsupported'` means this verifier cannot read *this kind* of container, which is a gap in
    // the verifier rather than a fault in the receipt - and reporting that as a failure would be a lie
    // in the safer direction, which is still a lie (D-021).
    const unsupported = /** @type {any} */ (error).code === 'unsupported';
    record(state, 'container.readable', unsupported ? 'unsupported' : 'fail',
      error.message ?? String(error));
    return false;
  }
  record(state, 'container.readable', 'pass');
  state.entries = archive.entries;
  state.entryNames = archive.order;

  const raw = archive.entries.get('receipt.json');
  if (raw === undefined) {
    record(state, 'manifest.present', 'fail', 'receipt.json is not present in the container');
    return false;
  }
  record(state, 'manifest.present', 'pass');

  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch (error) {
    record(state, 'manifest.parseable', 'fail', `receipt.json is not valid UTF-8 JSON: ${error.message}`);
    return false;
  }
  if (!isObject(manifest)) {
    record(state, 'manifest.parseable', 'fail', 'receipt.json must be a JSON object');
    return false;
  }
  record(state, 'manifest.parseable', 'pass');
  state.manifest = manifest;
  if (isObject(manifest.capture) && typeof manifest.capture.captured_at === 'string') {
    state.time.claimed = manifest.capture.captured_at;
  }

  const version = manifest.spec_version;
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) {
    record(state, 'manifest.spec_version', 'fail', 'spec_version is missing or is not a semantic version');
    return false;
  }
  if (Number(version.split('.')[0]) !== SUPPORTED_MAJOR) {
    record(
      state,
      'manifest.spec_version',
      'fail',
      `this verifier implements ${SUPPORTED_MAJOR}.x and cannot check a ${version} receipt`,
    );
    return false;
  }
  record(state, 'manifest.spec_version', 'pass', undefined);

  let wholeCanonical = null;
  try {
    wholeCanonical = canonicalise(manifest);
  } catch (error) {
    record(state, 'manifest.canonical', 'fail', error instanceof CanonicalJsonError
      ? `${error.message}`
      : String(error));
  }
  if (wholeCanonical !== null) {
    const canonicalBytes = assertCanonicalBytes(raw, wholeCanonical);
    record(state, 'manifest.canonical', canonicalBytes.ok ? 'pass' : 'fail',
      canonicalBytes.ok ? undefined : canonicalBytes.reason);
  } else {
    record(state, 'claim.digest', 'not_checked', 'the claim could not be canonicalised');
    return false;
  }

  const signed = signedSubtree(manifest);
  let once;
  try {
    once = canonicalise(signed);
  } catch (error) {
    record(state, 'claim.digest', 'fail', `the signed subtree is not representable: ${error.message}`);
    return false;
  }
  const fixed = canonicalise(JSON.parse(once)) === once;
  record(state, 'claim.digest', fixed ? 'pass' : 'fail',
    fixed ? undefined : 'canonicalisation is not a fixed point for this claim');
  state.claimHash = claimHashOf(manifest);

  const problems = validateManifestShape(manifest);
  record(state, 'manifest.shape', problems.length === 0 ? 'pass' : 'fail',
    problems.length === 0 ? undefined : problems.join('; '));
  return problems.length === 0;
}

/**
 * The capture: is the file the receipt names present, is it the length and the digest it
 * claims, and is it the kind of container this verifier reads?
 *
 * The WACZ's own resource hashes are checked because they are the part of the capture
 * that is *self-describing*: without them, a digest over the container says only "you
 * have the same file I have", never "the file contains the records it says it does".
 * A verifier that skipped this could pass a WACZ whose inner WARC had been swapped for
 * a different one of exactly the same length, provided the receipt was re-signed - and
 * the point of the inner hashes is that no re-signing is needed to notice.
 *
 * This is not a full WACZ validator. It checks what the receipt layer depends on and
 * says so in `docs/RECEIPT-SPEC.md` section 7 rather than implying more.
 *
 * @param {VerificationState} state
 * @returns {boolean}
 */
async function verifyCapture(state, runtime) {
  const manifest = /** @type {Record<string, any>} */ (state.manifest);
  const capture = manifest.capture;

  const captureBytes = state.entries.get(capture.path);
  if (captureBytes === undefined) {
    record(state, 'capture.present', 'fail', `the container has no entry named "${capture.path}"`);
    return false;
  }
  record(state, 'capture.present', 'pass');

  record(state, 'capture.bytes', captureBytes.length === capture.bytes ? 'pass' : 'fail',
    captureBytes.length === capture.bytes
      ? undefined
      : `the capture is ${captureBytes.length} bytes, and the receipt says ${capture.bytes}`);

  const actualDigest = await runtime.digest(captureBytes);
  record(state, 'capture.digest', actualDigest === capture.sha256 ? 'pass' : 'fail',
    actualDigest === capture.sha256
      ? undefined
      : `the capture hashes to ${actualDigest}, and the receipt says ${capture.sha256}`);

  if (capture.media_type !== 'application/wacz') {
    record(state, 'capture.media_type', 'unsupported',
      `this verifier reads application/wacz captures; this one claims ${capture.media_type}`);
    return false;
  }
  record(state, 'capture.media_type', 'pass');

  let inner;
  try {
    inner = await runtime.readContainer(captureBytes);
  } catch (error) {
    record(state, 'capture.wacz.readable', 'fail', `the capture is not a readable WACZ: ${error.message}`);
    return false;
  }
  record(state, 'capture.wacz.readable', 'pass');

  const dataPackageRaw = inner.entries.get('datapackage.json');
  if (dataPackageRaw === undefined) {
    record(state, 'capture.wacz.resources', 'fail',
      'the capture has no datapackage.json, so it advertises no resource hashes to check');
    return false;
  }

  let dataPackage;
  try {
    dataPackage = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(dataPackageRaw));
  } catch (error) {
    record(state, 'capture.wacz.resources', 'fail',
      `the capture's datapackage.json is not valid JSON: ${error.message}`);
    return false;
  }

  const resources = Array.isArray(dataPackage?.resources) ? dataPackage.resources : [];
  if (resources.length === 0) {
    record(state, 'capture.wacz.resources', 'fail',
      'the capture advertises no resources, which binds nothing');
    return false;
  }

  for (const resource of resources) {
    const where = typeof resource?.path === 'string' ? resource.path : JSON.stringify(resource);
    if (!isSafeEntryName(resource?.path)) {
      record(state, 'capture.wacz.resources', 'fail',
        `resource "${where}" has a path that is not a plain entry name`);
      return false;
    }
    const advertised = typeof resource.hash === 'string' ? resource.hash : '';
    if (!/^sha256:[0-9a-f]{64}$/.test(advertised)) {
      record(state, 'capture.wacz.resources', 'fail',
        `resource "${where}" advertises no usable sha256 hash`);
      return false;
    }
    const contents = inner.entries.get(resource.path);
    if (contents === undefined) {
      record(state, 'capture.wacz.resources', 'fail',
        `resource "${where}" is advertised but is not in the capture`);
      return false;
    }
    const actual = `sha256:${await runtime.digest(contents)}`;
    if (actual !== advertised) {
      record(state, 'capture.wacz.resources', 'fail',
        `resource "${where}" hashes to ${actual}, and the capture advertises ${advertised}`);
      return false;
    }
    if (resource.bytes !== undefined && resource.bytes !== contents.length) {
      record(state, 'capture.wacz.resources', 'fail',
        `resource "${where}" is ${contents.length} bytes and the capture advertises ${resource.bytes}`);
      return false;
    }
  }

  record(state, 'capture.wacz.resources', 'pass',
    `${resources.length} resource${resources.length === 1 ? '' : 's'} match their advertised digests`);
  return true;
}

/**
 * Level 1: attribution.
 *
 * What this level means when it passes is narrow, and the narrowness is the point: *the
 * holder of the key with this id signed this claim hash*. It does not mean the signer is
 * honest, that the key belongs to the person named in `signer`, or that the claim is
 * true. Key trust is answered by `key_trusted` in the verdict and by the caller's key
 * directory, never by this function (D-007).
 *
 * An unsigned receipt is not a failure. `not_applicable` is the honest status: there is
 * nothing here to verify, and the verdict says so instead of printing a tick.
 *
 * @param {VerificationState} state
 * @param {{ trustedKeys?: string[] }} options
 */
async function verifySignature(state, options, runtime) {
  const manifest = /** @type {Record<string, any>} */ (state.manifest);
  const signature = manifest.signature;

  if (signature === null || signature === undefined) {
    record(state, 'signature.present', 'not_applicable', 'the claim is unsigned');
    return;
  }
  const hasFields = typeof signature.alg === 'string'
    && typeof signature.key_id === 'string'
    && typeof signature.public_key === 'string'
    && typeof signature.sig === 'string';
  if (!hasFields) {
    record(state, 'signature.present', 'fail',
      'signature must carry alg, key_id, public_key and sig');
    return;
  }
  record(state, 'signature.present', 'pass');

  if (signature.alg !== ED25519_ALG) {
    record(state, 'signature.alg', 'unsupported',
      `this verifier implements ${ED25519_ALG}; the claim is signed with ${signature.alg}`);
    return;
  }
  record(state, 'signature.alg', 'pass');

  let rawPublicKey;
  let signatureBytes;
  try {
    rawPublicKey = fromBase64Url(signature.public_key);
    signatureBytes = fromBase64Url(signature.sig);
  } catch (error) {
    record(state, 'signature.key_id', 'fail',
      `public_key or sig is not valid base64url: ${error.message}`);
    return;
  }

  const computedKeyId = await runtime.keyId(rawPublicKey);
  if (computedKeyId !== signature.key_id) {
    record(state, 'signature.key_id', 'fail',
      `key_id is ${signature.key_id}, and the public key hashes to ${computedKeyId}`);
    return;
  }
  record(state, 'signature.key_id', 'pass');
  state.keyId = computedKeyId;

  const claimed = state.claimHash;
  if (claimed === null) {
    record(state, 'signature.verify', 'not_checked', 'the claim hash could not be computed');
    return;
  }
  const message = signingMessage(manifest.spec_version, claimed);
  if (message === null) {
    record(state, 'signature.verify', 'not_checked',
      `no signing prefix is defined for specification version ${manifest.spec_version}`);
    return;
  }
  const ok = await runtime.verifySignature(message, signatureBytes, rawPublicKey);
  record(state, 'signature.verify', ok ? 'pass' : 'fail',
    ok ? undefined : 'the signature does not verify against the public key it names');

  const trustedKeys = Array.isArray(options.trustedKeys) ? options.trustedKeys : null;
  state.trust = trustedKeys === null
    ? 'not_checked'
    : (trustedKeys.includes(computedKeyId) ? 'trusted' : 'untrusted');
}

/**
 * Level 2: time.
 *
 * A receipt with no anchor is not wrong, it is *unwitnessed*: the capture time is the
 * author's own statement, and the level is reported `not_checked` so that "captured on
 * the 15th" never reads as "proven to have been captured on the 15th".
 *
 * `rfc3161` is specified but deliberately reported `unsupported` by this implementation.
 * A CMS/RFC 3161 token parser is real work, and a half-implementation that answers
 * `pass` for tokens it did not fully check would be worse than an honest refusal.
 * `docs/CONFORMANCE.md` records it as the first thing a v0.2 implementer should pick up.
 *
 * @param {VerificationState} state
 * @param {{ previousClaimHash?: string }} options
 */
function verifyAnchor(state, options) {
  const manifest = /** @type {Record<string, any>} */ (state.manifest);
  const anchor = manifest.anchor;

  if (anchor === null || anchor === undefined || anchor.type === 'none') {
    record(state, 'anchor.present', 'not_applicable', 'the claim carries no anchor');
    record(state, 'anchor.verified', 'not_checked',
      'the capture time is self-asserted: no third party attested it');
    state.caveats.push('captured_at is a claim, not an attestation: there is no anchor');
    return;
  }

  if (anchor.type === 'chain') {
    record(state, 'anchor.present', 'pass');

    // A chain anchor is a statement the author makes *at signing time*: "this receipt sits
    // at position N of my archive". That statement is only worth anything if the signature
    // over it holds, so a broken signature cannot leave an L2 pass standing. Without this
    // rule, adding `{"type":"chain","sequence":1}` to any receipt - signed or not - would
    // read as "a third party attested this existed at a time" in the summary, which is the
    // single most misleading thing this format could say (D-012).
    const signatureCheck = state.results.find((result) => result.id === 'signature.verify');
    if (signatureCheck?.status !== 'pass') {
      record(state, 'anchor.verified', 'not_checked',
        'a chain anchor commits to a position at signing time, and this claim is not validly signed');
      return;
    }

    if (!Number.isInteger(anchor.sequence) || anchor.sequence < 1) {
      record(state, 'anchor.verified', 'fail', 'a chain anchor needs a sequence of 1 or more');
      return;
    }
    if (anchor.sequence === 1) {
      if (anchor.prev_claim_hash !== undefined) {
        record(state, 'anchor.verified', 'fail', 'sequence 1 is the head of a chain: it has no predecessor');
        return;
      }
      // Nothing to follow, so there is nothing to check - and it is still a `pass`, because
      // "this is the first receipt in an archive" is a complete and checkable statement,
      // unlike "the link matches" which needs the neighbour in hand.
      record(state, 'anchor.verified', 'pass', 'this is the head of the chain: there is no link to follow');
      return;
    }
    if (!isSha256Hex(anchor.prev_claim_hash)) {
      record(state, 'anchor.verified', 'fail',
        `sequence ${anchor.sequence} must name the previous claim hash`);
      return;
    }

    if (typeof options.previousClaimHash !== 'string') {
      record(state, 'anchor.verified', 'not_checked',
        'the previous receipt in the chain was not supplied, so the link was not followed');
      state.caveats.push(
        'chain anchor: ordering is only as good as the archive you hold, and it attests '
        + 'nothing about time to anyone outside that archive',
      );
      return;
    }
    const linked = anchor.prev_claim_hash === options.previousClaimHash;
    record(state, 'anchor.verified', linked ? 'pass' : 'fail',
      linked ? undefined : 'the chain link does not match the previous receipt supplied');
    return;
  }

  if (anchor.type === 'rfc3161') {
    record(state, 'anchor.present', 'pass');
    record(state, 'anchor.verified', 'unsupported',
      'this verifier does not implement RFC 3161 token validation, so the anchor was not checked');
    state.caveats.push('an RFC 3161 anchor is present but unverified by this implementation');
    return;
  }

  record(state, 'anchor.present', 'unsupported',
    `this verifier does not know the anchor type "${anchor.type}"`);
  record(state, 'anchor.verified', 'unsupported', `anchor type "${anchor.type}" is not implemented`);
}

/**
 * Level 3: the text fingerprint, which this verifier structurally cannot check.
 *
 * `text-v1` is defined over a rendered document - the same deterministic DOM walk Shelf
 * performs when it indexes a page - and the reference verifier has no HTML engine and no
 * layout. So it validates the *declaration* and reports `not_checked` with that reason
 * rather than pretending. The extension is the reference implementation for this check
 * because it already has the engine (D-009).
 *
 * @param {VerificationState} state
 */
function verifyText(state) {
  const manifest = /** @type {Record<string, any>} */ (state.manifest);
  const text = manifest.subject?.text;
  if (text === undefined) {
    record(state, 'subject.text', 'not_applicable', 'the claim carries no text fingerprint');
    return;
  }
  record(state, 'subject.text', 'not_checked',
    'text-v1 is defined over a rendered document, and this verifier has no HTML engine');
  state.caveats.push('a text fingerprint is declared but was not checked by this verifier');
}

/**
 * Fill in every check of a level that never ran, with a reason taken from the check that
 * stopped the stage.
 *
 * A verdict must contain **every** check, always. Omitting the ones that did not run is
 * how a verification report lies: a reader scanning for problems sees nothing, and
 * concludes there were none, when in fact nothing was examined. `verifyReceipt` asserts
 * that the result count equals `CHECKS.length` before it returns, so a check that is
 * added to the table and forgotten in the code fails a test rather than silently
 * disappearing from every verdict.
 *
 * @param {VerificationState} state
 * @param {string} level
 * @param {string} reason
 */
function recordGaps(state, level, reason) {
  const existing = state.results.filter((result) => result.level === level);
  // If everything the stage did decide was "this does not apply here", then the checks it
  // never reached do not apply either. Reporting them as `not_checked` would suggest an
  // attempt was made and blocked, which is a different and more alarming statement than
  // "there is no signature to check".
  const status = existing.length > 0 && existing.every((result) => result.status === 'not_applicable')
    ? 'not_applicable'
    : 'not_checked';
  for (const check of CHECKS) {
    if (check.level !== level) continue;
    if (state.results.some((result) => result.id === check.id)) continue;
    record(state, check.id, status, reason);
  }
}

/**
 * Why a stage stopped, phrased from the results themselves so the gap names its cause.
 *
 * @param {VerificationState} state
 * @param {string} level
 * @returns {string}
 */
function gapReason(state, level) {
  const blocking = state.results.find(
    (result) => result.level === level && (result.status === 'fail' || result.status === 'unsupported'),
  );
  if (blocking !== undefined) return `not checked: ${blocking.reason ?? blocking.id}`;
  if (state.results.some((result) => result.level === level && result.status === 'pass')) {
    return 'the check was not reached';
  }
  return 'nothing in this level applies to this receipt';
}

/**
 * A level is `pass` only when every check in it is `pass`.
 *
 * No exceptions, no "pass with warnings", because the moment one is allowed the level
 * stops meaning anything a reader can rely on. `unsupported` and `not_checked` both
 * leave a level short of `pass`, which is the whole point: this verifier would rather
 * say "I did not check that" than let a green tick stand for work it did not do.
 *
 * @param {VerificationState} state
 * @param {string} level
 * @returns {'pass' | 'fail' | 'not_checked' | 'unsupported' | 'not_applicable'}
 */
export function rollUpLevel(state, level) {
  const statuses = state.results.filter((result) => result.level === level).map((r) => r.status);
  if (statuses.length === 0) return 'not_checked';
  if (statuses.includes('fail')) return 'fail';
  if (statuses.every((status) => status === 'pass')) return 'pass';
  if (statuses.includes('unsupported')) return 'unsupported';
  if (statuses.every((status) => status === 'not_applicable')) return 'not_applicable';
  return 'not_checked';
}

/** How each status reads in the one-line summary. */
const STATUS_WORDS = {
  pass: 'verified',
  fail: 'FAILED',
  not_checked: 'not checked',
  unsupported: 'unsupported here',
  not_applicable: 'not applicable',
};

/**
 * The verdict as sentences, because the JSON is for programs and this is what a person
 * actually reads. Deliberately plain: no "success", no tick, and an explicit statement of
 * what was *not* examined.
 *
 * @param {VerificationState} state
 * @param {Record<string, string>} levels
 * @returns {string[]}
 */
export function summarise(state, levels) {
  const manifest = state.manifest ?? {};
  const signature = isObject(manifest.signature) ? manifest.signature : null;
  const lines = [
    `receipt ${manifest.spec_version ?? '?'} · claim ${state.claimHash ?? 'not computed'}`,
    `subject ${manifest.subject?.url ?? '?'}${manifest.capture?.captured_at
      ? ` · captured ${manifest.capture.captured_at} (${levels.L2 === 'pass' ? 'attested' : 'self-asserted'})`
      : ''}`,
  ];
  for (const level of LEVELS) {
    lines.push(`L${level.id.slice(1)} ${level.name}: ${STATUS_WORDS[levels[level.id]]} — ${level.claim}`);
  }
  lines.push(signature !== null
    ? `signed by key ${state.keyId ?? signature.key_id}${signature.signer ? ` (${signature.signer})` : ''}`
    : 'unsigned: this claim is attributed to nobody');
  if (state.trust === 'untrusted') lines.push('the signing key is not in the keys you trust');
  if (state.caveats.length > 0) lines.push(`${state.caveats.length} caveat${state.caveats.length === 1 ? '' : 's'}`);
  return lines;
}
