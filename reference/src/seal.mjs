/**
 * Sealing: turning a capture into a receipt.
 *
 * This is the producer half of the project, and everything here is in service of one property: **a
 * receipt must be checkable by somebody who does not trust the person who wrote it.** So the claim is
 * built in the order section 6.5 of the specification gives, and every value this module cannot read
 * for itself stops the seal rather than being guessed at.
 *
 * The document digest is the case in point. `subject.document` is required by the claim, and this
 * module derives it from the capture's own WARC record rather than from anything the person sealing
 * supplies (D-016). A caller *may* override it with `document`, which exists for captures whose WARC
 * this reader cannot parse; when that happens the caller is told in `warnings` that the digest came
 * from somewhere other than the capture, and the CLI prints it.
 *
 * Pure: bytes in, bytes out. The filesystem, the key file and the clock belong to the CLI.
 *
 * @module seal
 */

import { sha256, utf8, toBase64Url } from './digest.mjs';
import { readZip } from './zip.mjs';
import { findMainDocument } from './warc-node.mjs';
import { warcEntryOf } from './wacz.mjs';
import { textDigest } from './text.mjs';
import { ED25519_ALG, draftClaim, finishClaim } from './claim.mjs';
import { rawPublicKey, keyId, signMessage } from './signature.mjs';

/** Thrown when the capture cannot be sealed honestly. */
export class SealError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'SealError';
  }
}

/**
 * A WACZ advertises its records in `datapackage.json`, and finding the WARC among them now lives in
 * `wacz.mjs`, where the browser's reader can reach it too.
 */

/**
 * Find the WARC inside a WACZ, and check it against the hash the capture advertises for it.
 *
 * The hash check is not redundant with the receipt's own `capture.sha256`: that digest covers the
 * whole container, and this one covers the file being *read*. A capture whose text was corrupted in
 * transit can still be a valid ZIP; what it cannot be is a thing to build a claim from.
 *
 * @param {Uint8Array} waczBytes
 * @returns {Uint8Array}
 * @throws {SealError}
 */
export function findCaptureWarc(waczBytes) {
  let archive;
  try {
    archive = readZip(waczBytes);
  } catch (error) {
    throw new SealError(`the capture is not a readable WACZ: ${error.message}`);
  }

  // The lookup itself lives in `wacz.mjs`, because the browser's verifier needs the same one and a
  // second copy of "where is the WARC" is a second answer to a question with one right answer.
  let entry;
  try {
    entry = warcEntryOf(archive);
  } catch (error) {
    throw new SealError(error.message);
  }

  if (entry.advertised !== null && /^sha256:[0-9a-f]{64}$/.test(entry.advertised)) {
    const actual = `sha256:${sha256(entry.bytes)}`;
    if (actual !== entry.advertised) {
      throw new SealError(
        `the capture advertises ${entry.advertised} for "${entry.path}" and it hashes to ${actual}. `
        + 'That is a corrupt capture, and nothing was written.',
      );
    }
  }

  return entry.bytes;
}

/**
 * Build a signed receipt from a capture.
 *
 * The order of operations is section 6.5 of the specification, and it is not an implementation
 * detail: the claim hash is taken over the manifest *without* its signature and anchor, the signature
 * covers the domain-separated hash, and only then is `receipt.json` serialised in canonical form.
 *
 * @param {{
 *   capture: Uint8Array,
 *   url?: string | null,
 *   document?: Uint8Array | null,
 *   capturedAt?: string | null,
 *   anchor?: Record<string, any>,
 *   key?: { privateKey: import('node:crypto').KeyObject, signer?: string | null } | null,
 * }} input
 * @returns {{ bytes: Uint8Array, manifest: Record<string, any>, claimHash: string, warnings: string[] }}
 * @throws {SealError}
 */
export function sealFromCapture(input) {
  const capture = input.capture;
  const warnings = [];
  const warc = findCaptureWarc(capture);

  // Read the capture's own account of the document first: it answers the URL and the capture time as
  // well as the digest, and reading it once keeps those three answers consistent with each other.
  let fromCapture = null;
  try {
    fromCapture = findMainDocument(warc, input.url ?? null);
  } catch (error) {
    if (input.document === undefined || input.document === null) throw error;
    warnings.push(
      `the capture's WARC could not be read (${error.message}), so the document came from the caller`,
    );
  }

  const url = input.url ?? fromCapture?.url ?? null;
  if (url === null) {
    throw new SealError('the capture does not say which URL it is for, and neither did the caller: pass --url');
  }

  const body = input.document ?? fromCapture?.body ?? null;
  if (body === null) throw new SealError('no document was found in the capture');
  if (input.document !== undefined && input.document !== null && fromCapture !== null) {
    warnings.push(
      'the document was supplied by the caller rather than read from the capture, so subject.document '
      + 'describes what the caller handed over',
    );
  }

  const capturedAt = input.capturedAt ?? fromCapture?.capturedAt ?? null;
  if (capturedAt === null) {
    throw new SealError(
      "the capture's WARC records no date and the caller gave none: pass --captured-at, rather than "
      + 'letting this machine\'s clock date the claim',
    );
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(capturedAt)) {
    throw new SealError(
      `captured-at must be UTC to the second, such as 2026-01-01T00:00:00Z; received "${capturedAt}"`,
    );
  }

  // The claim is built by `claim.mjs`, which is the module the browser producer uses too: one definition
  // of what a claim contains, so the two producers cannot drift apart (D-020).
  const draft = draftClaim({
    capture,
    url,
    finalUrl: fromCapture === null ? null : fromCapture.url,
    status: fromCapture === null ? null : fromCapture.status,
    contentType: fromCapture === null ? null : fromCapture.contentType,
    capturedAt,
    document: { sha256: sha256(body), bytes: body.length },
    // The words, from the same bytes. Always: the fingerprint is derived, costs nothing to recompute, and
    // is what makes "the bytes changed but the words did not" answerable later (section 4.5).
    text: { sha256: textDigest(body) },
    captureProfile: input.captureProfile ?? null,
    anchor: input.anchor ?? { type: 'none' },
  });

  let signature = null;
  if (input.key !== undefined && input.key !== null) {
    const { privateKey } = input.key;
    const publicKey = rawPublicKey(privateKey);
    /** @type {Record<string, any>} */
    const made = {
      alg: ED25519_ALG,
      key_id: keyId(publicKey),
      public_key: toBase64Url(publicKey),
      sig: toBase64Url(signMessage(draft.message, privateKey)),
    };
    if (typeof input.key.signer === 'string' && input.key.signer !== '') {
      made.signer = input.key.signer;
    }
    signature = made;
  }

  const finished = finishClaim(draft, signature);
  return {
    bytes: finished.bytes,
    manifest: finished.manifest,
    claimHash: finished.claimHash,
    warnings,
  };
}
