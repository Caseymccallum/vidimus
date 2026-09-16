/**
 * The conformance cases: one fixture each, and the verdict each one must produce.
 *
 * Two rules make this file worth trusting.
 *
 * 1. **The expectation is written down before the generator runs.** `expect` is asserted
 *    by `vectors.mjs`, so a case whose verdict drifts fails the run rather than quietly
 *    recording the new answer. If the implementation is wrong, the expectation catches
 *    it; if the expectation is wrong, you have to change it on purpose and the diff shows
 *    you did.
 * 2. **Every case says what it proves.** A vector with no claim attached is a snapshot,
 *    and a snapshot of a bug is indistinguishable from a snapshot of a feature.
 *
 * The case that matters most is `claim-not-canonical`: the bytes are readable, the
 * signature still verifies, and the receipt is *still rejected*, because a receipt that
 * was re-serialised after signing is no longer the document that was signed. Its
 * expectation records `signature.verify: pass` next to `manifest.canonical: fail` so that
 * no reader can mistake which check did the work.
 *
 * @module cases
 */

import { canonicalJson, buildReceipt, prettyJson, signer, stranger } from './fixtures.mjs';
import { sha256, toBase64Url, utf8 } from './digest.mjs';
import { FIXTURE_DATE, waczBytes, waczEntries, DEFAULT_HTML, SPEC_VERSION } from './fixtures.mjs';
import { writeZip } from './zip.mjs';
import { signMessage } from './signature.mjs';
import { signingMessage } from './verify.mjs';

/** The same page, one word uppercased: same byte length, different content. */
const HTML_EDITED = '<!doctype html><html><head><title>A page worth citing</title></head>'
  + '<body><h1>A page worth citing</h1><p>Claims were made HERE.</p></body></html>';

/** A fixed digest to link a chain to, so the fixture does not depend on another fixture. */
const EARLIER_CLAIM = sha256(utf8('an earlier receipt in the same archive'));

/**
 * Assemble a container by hand, so a case can put a claim and a capture together that a
 * tool would never have produced. This is how the tampering vectors are built - with the
 * same writer the honest fixtures use, so the only difference between them is the
 * tampering.
 *
 * @param {Record<string, any>} manifest
 * @param {Uint8Array | null} wacz
 * @param {(manifest: Record<string, any>) => Uint8Array} [serialise]
 * @returns {Uint8Array}
 */
function containerOf(manifest, wacz, serialise = canonicalJson) {
  return writeZip([
    ['receipt.json', serialise(manifest)],
    ...(wacz === null ? [] : [['capture.wacz', wacz]]),
  ], { date: FIXTURE_DATE });
}


/**
 * @typedef {object} Case
 * @property {string} id
 * @property {string} description
 * @property {string} proves
 * @property {() => Uint8Array} build
 * @property {{ previousClaimHash?: string, trustedKeys?: string[] }} [options]
 * @property {{
 *   verified: boolean,
 *   exit_code: number,
 *   levels: Record<string, string>,
 *   checks: Record<string, string>,
 * }} expect
 */

/** @type {Case[]} */
export const CASES = [
  {
    id: 'valid-signed',
    description: 'a signed receipt for one page, with no anchor',
    proves: 'the happy path verifies integrity and attribution, and reports time and currency as unchecked rather than as passes',
    build: () => buildReceipt().bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'container.readable': 'pass',
        'capture.wacz.resources': 'pass',
        'signature.verify': 'pass',
        'anchor.verified': 'not_checked',
        'subject.text': 'not_applicable',
      },
    },
  },
  {
    id: 'valid-signed-trusted',
    description: 'the same receipt, checked against a key list that contains the signer',
    proves: 'key trust is reported separately: L1 says the signature is valid, and only a caller-supplied key list can say the key is one you meant to trust',
    build: () => buildReceipt().bytes,
    options: { trustedKeys: [signer().keyId] },
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: { 'signature.verify': 'pass' },
    },
  },
  {
    id: 'valid-unsigned',
    description: 'a receipt whose claim carries no signature',
    proves: 'an unsigned receipt is not reported as a failure and not reported as verified: attribution is not_applicable, and the exit code distinguishes it from a broken receipt',
    build: () => buildReceipt({ signed: false }).bytes,
    expect: {
      verified: false,
      exit_code: 1,
      levels: { L0: 'pass', L1: 'not_applicable', L2: 'not_checked', L3: 'not_applicable' },
      checks: { 'signature.present': 'not_applicable', 'signature.verify': 'not_applicable' },
    },
  },
  {
    id: 'valid-signed-trusted-wrong',
    description: 'a valid signature from a key the caller does not list',
    proves: 'an untrusted key does not make a receipt invalid, and does not make it trusted either',
    build: () => buildReceipt().bytes,
    options: { trustedKeys: [stranger().keyId] },
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: { 'signature.verify': 'pass' },
    },
  },
  {
    id: 'valid-http-page',
    description: 'a capture of a page served over plain HTTP',
    proves: 'an insecure page is still worth recording, so it verifies and is caveated rather than failed',
    build: () => buildReceipt({ url: 'http://example.org/plain' }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {},
    },
  },
  {
    id: 'valid-with-text',
    description: 'a receipt that declares a text fingerprint',
    proves: 'this verifier says it did not check the fingerprint instead of implying it did',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        manifest.subject.text = { normalization: 'text-v1', sha256: sha256(utf8('A page worth citing')) };
      },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_checked' },
      checks: { 'subject.text': 'not_checked' },
    },
  },
  {
    id: 'valid-signed-with-notes',
    description: 'a receipt carrying an extra field the spec does not define',
    proves: 'an unknown top-level field is inside the signed subtree: it cannot be added, removed or edited without the signature failing',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        manifest.notes = { context: 'cited in a literature review', reviewer: 'A. Reader' };
      },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: { 'claim.digest': 'pass', 'signature.verify': 'pass' },
    },
  },
  {
    id: 'capture-digest-mismatch',
    description: 'the capture swapped for a different one of exactly the same length',
    proves: 'the digest check does work nothing else does: the length matches, the replacement capture is internally consistent, and only capture.digest notices',
    build: () => {
      const original = buildReceipt();
      const substitute = waczBytes(waczEntries({ html: HTML_EDITED }));
      return containerOf(original.manifest, substitute);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'capture.bytes': 'pass',
        'capture.digest': 'fail',
        'capture.wacz.readable': 'pass',
        'capture.wacz.resources': 'pass',
        'signature.verify': 'pass',
      },
    },
  },
  {
    id: 'capture-resource-mismatch',
    description: 'a WACZ whose record does not match the hash its own datapackage advertises',
    proves: 'the inner resource hashes catch content the outer container digest cannot see, and the receipts binds them because it was signed over exactly these bytes',
    build: () => {
      const honest = waczEntries({ html: DEFAULT_HTML });
      const edited = waczEntries({ html: HTML_EDITED });
      // The datapackage keeps describing the honest record; the record itself is the
      // edited one, and the two are the same length.
      const wacz = waczBytes([honest[0], edited[1], honest[2]]);
      return buildReceipt({ wacz, html: DEFAULT_HTML }).bytes;
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'capture.digest': 'pass',
        'capture.wacz.readable': 'pass',
        'capture.wacz.resources': 'fail',
      },
    },
  },
  {
    id: 'claim-edited-after-signing',
    description: 'the cited URL changed after the receipt was signed',
    proves: 'the signature covers the claim, not the file: editing a signed field leaves bytes that are canonical and a signature that means nothing',
    build: () => {
      const original = buildReceipt();
      const edited = {
        ...original.manifest,
        subject: { ...original.manifest.subject, url: 'https://example.org/a-different-page' },
      };
      return containerOf(edited, original.wacz);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'fail', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'manifest.canonical': 'pass',
        'claim.digest': 'pass',
        'capture.digest': 'pass',
        'signature.verify': 'fail',
      },
    },
  },
  {
    id: 'claim-not-canonical',
    description: 'a receipt serialised with JSON.stringify instead of canonical form',
    proves: 'the signature still verifies and the receipt is still rejected, because the bytes that were signed are not the bytes that were delivered',
    build: () => buildReceipt({ serialise: prettyJson }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'manifest.parseable': 'pass',
        'manifest.canonical': 'fail',
        'claim.digest': 'pass',
        'signature.verify': 'pass',
      },
    },
  },
  {
    id: 'claim-contains-a-float',
    description: 'a claim with a fractional byte count',
    proves: 'canonical-json-v1 admits integers only, so a float is a named failure rather than a rounding difference between two implementations',
    build: () => {
      // Built by hand rather than with `buildReceipt`, because a conforming tool could not
      // have produced this: canonicalising the claim throws before a signature is possible.
      // The unsigned manifest is the honest form of an impossible receipt.
      const original = buildReceipt();
      const floaty = {
        ...original.manifest,
        subject: {
          ...original.manifest.subject,
          document: { ...original.manifest.subject.document, bytes: 1.5 },
        },
      };
      delete floaty.signature;
      return containerOf(floaty, original.wacz, prettyJson);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'not_applicable', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'manifest.canonical': 'fail',
        'claim.digest': 'not_checked',
        'capture.digest': 'not_checked',
      },
    },
  },
  {
    id: 'container-not-a-zip',
    description: 'a file that is not a receipt at all',
    proves: 'an unreadable container fails at L0 and every later level says so, instead of reporting nothing and looking clean',
    build: () => utf8('this is not a receipt, it is a sentence'),
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'not_checked', L2: 'not_checked', L3: 'not_checked' },
      checks: {
        'container.readable': 'fail',
        'signature.present': 'not_checked',
        'anchor.verified': 'not_checked',
      },
    },
  },
  {
    id: 'capture-missing',
    description: 'a container that holds the claim but not the capture',
    proves: 'a claim without its bytes verifies nothing: the capture checks are not_checked with a reason, never silently absent',
    build: () => {
      const original = buildReceipt();
      return containerOf(original.manifest, null);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'capture.present': 'fail',
        'capture.digest': 'not_checked',
        'signature.verify': 'pass',
      },
    },
  },
  {
    id: 'capture-path-escapes',
    description: 'a claim that points its capture entry outside the container',
    proves: 'an entry name is untrusted input to a filesystem call, so it is refused at the shape check and never resolved',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        manifest.capture.path = '../../outside.wacz';
      },
    }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'manifest.shape': 'fail',
        'capture.present': 'not_checked',
      },
    },
  },
  {
    id: 'spec-version-unknown',
    description: 'a receipt from a future version of the specification',
    proves: 'a version this verifier does not implement is a failure rather than a soft "unknown": nobody can honestly verify a claim they cannot read',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        manifest.spec_version = '9.0.0';
      },
    }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'not_checked', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'manifest.spec_version': 'fail',
        'manifest.canonical': 'not_checked',
        'signature.verify': 'not_checked',
      },
    },
  },
  {
    id: 'signature-from-another-claim',
    description: 'a signature lifted from a different receipt',
    proves: 'the carried key is well formed, its id matches, the signature is a real Ed25519 signature - and it still fails, because it was made over another claim',
    build: () => {
      const original = buildReceipt();
      const lifted = toBase64Url(
        signMessage(signingMessage(SPEC_VERSION, sha256(utf8('an entirely different claim'))), stranger().privateKey),
      );
      const edited = {
        ...original.manifest,
        signature: { ...original.manifest.signature, sig: lifted },
      };
      return containerOf(edited, original.wacz);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'fail', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'signature.key_id': 'pass',
        'signature.verify': 'fail',
      },
    },
  },
  {
    id: 'signature-shape-broken',
    description: 'a signature object with no key in it',
    proves: 'a malformed signature is a failure, not a gap - reporting "not checked" for something that is present and wrong would understate it',
    build: () => buildReceipt({
      signed: false,
      manifestPatch: (manifest) => {
        manifest.signature = { alg: 'ed25519' };
      },
    }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'fail', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'signature.present': 'fail',
        'signature.verify': 'not_checked',
      },
    },
  },
  {
    id: 'anchor-chain-head',
    description: 'the first receipt in a chain',
    proves: 'a chain head has no link to follow, and saying so is a pass rather than a gap',
    build: () => buildReceipt({ anchor: { type: 'chain', sequence: 1 } }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'pass', L3: 'not_applicable' },
      checks: { 'anchor.verified': 'pass' },
    },
  },
  {
    id: 'anchor-chain-linked',
    description: 'a receipt that links to the previous one in its archive',
    proves: 'the link is only followed when the neighbour is supplied, and then it is actually compared',
    build: () => buildReceipt({
      anchor: { type: 'chain', sequence: 2, prev_claim_hash: EARLIER_CLAIM },
    }).bytes,
    options: { previousClaimHash: EARLIER_CLAIM },
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'pass', L3: 'not_applicable' },
      checks: { 'anchor.verified': 'pass' },
    },
  },
  {
    id: 'anchor-chain-unlinked',
    description: 'a receipt whose chain link does not match the neighbour supplied',
    proves: 'a broken chain link is a failure: the claim is intact and the archive it claims to belong to is not',
    build: () => buildReceipt({
      anchor: { type: 'chain', sequence: 2, prev_claim_hash: EARLIER_CLAIM },
    }).bytes,
    options: { previousClaimHash: sha256(utf8('some other receipt entirely')) },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'pass', L2: 'fail', L3: 'not_applicable' },
      checks: { 'anchor.verified': 'fail' },
    },
  },
  {
    id: 'anchor-chain-unfollowed',
    description: 'a chain receipt verified without its neighbour',
    proves: 'an unfollowed link is not_checked, not a pass: the receipt stays verified on integrity and attribution, and the summary says why the ordering is unproven',
    build: () => buildReceipt({
      anchor: { type: 'chain', sequence: 2, prev_claim_hash: EARLIER_CLAIM },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: { 'anchor.verified': 'not_checked' },
    },
  },
  {
    id: 'anchor-chain-head-with-predecessor',
    description: 'a chain head that names a predecessor',
    proves: 'a receipt cannot be both the start of a chain and a link in one',
    build: () => buildReceipt({
      anchor: { type: 'chain', sequence: 1, prev_claim_hash: EARLIER_CLAIM },
    }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'pass', L2: 'fail', L3: 'not_applicable' },
      checks: { 'anchor.verified': 'fail' },
    },
  },
  {
    id: 'anchor-rfc3161-unimplemented',
    description: 'a receipt carrying an RFC 3161 timestamp token',
    proves: 'an anchor this implementation cannot validate is reported unsupported and caveated, and never counts as time established',
    build: () => buildReceipt({
      anchor: { type: 'rfc3161', token: 'MIIBogYJKoZIhvcNAQcCoIIBkzCCAY8CAQMxCzAJBgUrDgMCGgUAMIIB' },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'unsupported', L3: 'not_applicable' },
      checks: { 'anchor.present': 'pass', 'anchor.verified': 'unsupported' },
    },
  },
  {
    id: 'anchor-unknown-type',
    description: 'a receipt with an anchor type that does not exist',
    proves: 'an unknown anchor is unsupported rather than a failure: this verifier does not know whether it is broken, and says so',
    build: () => buildReceipt({ anchor: { type: 'clock-radio' } }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'unsupported', L3: 'not_applicable' },
      checks: { 'anchor.present': 'unsupported', 'anchor.verified': 'unsupported' },
    },
  },
  {
    id: 'container-with-stray-entry',
    description: 'a receipt with an extra file that no rule covers',
    proves: 'content outside the claim and the capture is reported as a caveat rather than ignored, because nothing signs it',
    build: () => buildReceipt({
      extraEntries: [['notes/readme.txt', utf8('not covered by any digest in this receipt')]],
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {},
    },
  },
  {
    id: 'manifest-missing',
    description: 'a container with a capture but no claim',
    proves: 'a container without a claim is not a receipt: the missing file is a failure and every later check says it never ran',
    build: () => {
      const original = buildReceipt();
      return writeZip([['capture.wacz', original.wacz]], { date: FIXTURE_DATE });
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'not_checked', L2: 'not_checked', L3: 'not_checked' },
      checks: { 'manifest.present': 'fail' },
    },
  },
  {
    id: 'manifest-not-json',
    description: 'a receipt.json that is not JSON',
    proves: 'unparseable bytes are a failure at the container level, not an empty verdict',
    build: () => writeZip(
      [['receipt.json', utf8('this is not JSON, it is a hope')]],
      { date: FIXTURE_DATE },
    ),
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'not_checked', L2: 'not_checked', L3: 'not_checked' },
      checks: { 'manifest.parseable': 'fail' },
    },
  },
  {
    id: 'capture-length-wrong',
    description: 'a claim that understates the size of its own capture',
    proves: 'the declared length is checked separately from the digest, so a claim that is wrong about its bytes says so precisely',
    build: () => buildReceipt({
      // Signed as it stands, so the only thing wrong with the receipt is the claim's own
      // arithmetic: a tool that computed the length wrongly, not a claim edited later.
      manifestPatch: (manifest) => {
        manifest.capture.bytes = 1;
      },
    }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'capture.bytes': 'fail',
        'capture.digest': 'pass',
        'capture.wacz.resources': 'pass',
      },
    },
  },
  {
    id: 'capture-media-type-unknown',
    description: 'a claim whose capture is a container this verifier does not read',
    proves: 'an unreadable kind of capture is unsupported rather than failed, and the receipt is still not verified',
    build: () => buildReceipt({
      // Signed as it stands: this is a claim about a capture type this verifier does not
      // read, not a claim somebody tampered with.
      manifestPatch: (manifest) => {
        manifest.capture.media_type = 'application/wacz2';
      },
    }).bytes,
    expect: {
      verified: false,
      exit_code: 1,
      levels: { L0: 'unsupported', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'capture.media_type': 'unsupported',
        'capture.wacz.readable': 'not_checked',
      },
    },
  },
  {
    id: 'capture-not-a-wacz',
    description: 'a capture that is not a container at all, correctly hashed',
    proves: 'the digest being right is not the same as the capture being readable, and the two failures are reported separately',
    build: () => buildReceipt({ wacz: utf8('I am a file that claims to be an archive') }).bytes,
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'fail', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'capture.digest': 'pass',
        'capture.wacz.readable': 'fail',
        'capture.wacz.resources': 'not_checked',
      },
    },
  },
  {
    id: 'signature-key-id-mismatch',
    description: 'a receipt whose key id does not match the key it carries',
    proves: 'key ids are derived, not asserted: a mismatch is caught before the signature itself is even examined',
    build: () => {
      const original = buildReceipt();
      const edited = {
        ...original.manifest,
        signature: { ...original.manifest.signature, key_id: '0'.repeat(64) },
      };
      return containerOf(edited, original.wacz);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'fail', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'signature.key_id': 'fail',
        'signature.verify': 'not_checked',
      },
    },
  },
  {
    id: 'signature-algorithm-unsupported',
    description: 'a receipt signed with an algorithm this verifier does not implement',
    proves: 'an unimplemented algorithm leaves the receipt unverified with no failure recorded, which is why the exit codes have three values and not two',
    build: () => {
      const original = buildReceipt();
      const edited = {
        ...original.manifest,
        signature: { ...original.manifest.signature, alg: 'ecdsa-p256-sha256' },
      };
      return containerOf(edited, original.wacz);
    },
    expect: {
      verified: false,
      exit_code: 1,
      levels: { L0: 'pass', L1: 'unsupported', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'signature.alg': 'unsupported',
        'signature.verify': 'not_checked',
      },
    },
  },
  {
    id: 'anchor-bolted-on',
    description: 'a chain anchor added to a receipt after it was signed',
    proves: 'the obvious implementation of "exclude the anchor from the signature" would let anyone add one and manufacture an L2 pass; signing every anchor that could have existed at signing time makes it break the signature instead',
    build: () => {
      const original = buildReceipt();
      const edited = {
        ...original.manifest,
        anchor: { type: 'chain', sequence: 1 },
      };
      return containerOf(edited, original.wacz);
    },
    expect: {
      verified: false,
      exit_code: 2,
      levels: { L0: 'pass', L1: 'fail', L2: 'not_checked', L3: 'not_applicable' },
      checks: {
        'manifest.canonical': 'pass',
        'signature.verify': 'fail',
        'anchor.present': 'pass',
        'anchor.verified': 'not_checked',
      },
    },
  },
  {
    id: 'capture-profile-declared',
    description: 'a capture that says what kind of capture it is',
    proves: 'the profile is reported rather than judged: verification is unchanged, and a reader is told which kind of capture they are holding',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        manifest.capture.profile = 'document-v1';
      },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {},
    },
  },
  {
    id: 'capture-profile-unrecognised',
    description: 'a capture whose declared kind this verifier does not interpret',
    proves: 'an unknown profile is neither a pass nor a failure: the bytes are checked, the meaning is caveated, and the receipt stays verified on integrity and attribution',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        // A profile from a future version, deliberately not one this verifier knows. (This case used to
        // name `wire-v1`, which was unrecognised when it was written and became recognised later - so it
        // silently stopped testing what it said it tested. The vectors caught it, which is their job.)
        manifest.capture.profile = 'capture-from-the-future-v9';
      },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {},
      caveats: 2,
    },
  },
  {
    id: 'capture-profile-wire',
    description: 'a capture that declares itself the bytes a server sent',
    proves: 'a *recognised* profile is reported without a caveat, so the caveat above means "unknown" rather than "declared"',
    build: () => buildReceipt({
      manifestPatch: (manifest) => {
        manifest.capture.profile = 'wire-v1';
      },
    }).bytes,
    expect: {
      verified: true,
      exit_code: 0,
      levels: { L0: 'pass', L1: 'pass', L2: 'not_checked', L3: 'not_applicable' },
      checks: {},
      caveats: 1,
    },
  },
];
