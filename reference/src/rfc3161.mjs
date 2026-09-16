/**
 * An RFC 3161 timestamp token: read it, then do the four things the specification requires.
 *
 * Section 8.3 of the specification lists what a conforming implementation **MUST** do before it reports a
 * `pass`, written down before any implementation existed so that a half-implementation could not answer
 * "yes" too early. This module is that list, in code:
 *
 * 1. **parse the CMS `SignedData` and validate the signature to a TSA the verifier is willing to trust.**
 *    Trust here is a certificate the *caller* pinned (`trustedTsa`), compared byte for byte. That is the
 *    narrowest honest form of "a TSA the verifier is willing to trust": an anchor, not a chain - and
 *    `docs/CONFORMANCE.md` names what that leaves out.
 * 2. **check `messageImprint` against the claim hash**, under the same hash algorithm.
 * 3. **check `genTime`** against the signing certificate's validity window.
 * 4. **report the attested instant** as `attested_before`, which is a bound and not a capture time.
 *
 * Plus the two things CMS requires for the signature to mean anything: `contentType` must name the TSTInfo
 * and `messageDigest` must be the digest of the encapsulated content. Without those, a token could carry a
 * perfectly good signature over attributes that describe nothing.
 *
 * **What this module will not do**: guess. A token it cannot read, an algorithm it does not implement, or
 * a TSA it was not given are all reported as *this verifier's* limits (`unsupported`) or as an untrusted
 * signer (`not_checked`) - never as a fault in the receipt. A token it *can* read and that breaks a rule is
 * a `fail`, with the rule named (D-021).
 *
 * @module rfc3161
 */

import { readDer, oidValue, integerValue, timeValue, octetString, concat } from './der.mjs';
import { EKU_TIME_STAMPING, readCertificate } from './x509.mjs';
import { fromBase64Url, toHex, utf8 } from './encode.mjs';

/** `id-signedData`, `id-ct-TSTInfo`, `id-ct-contentType` and `id-ct-messageDigest`. */
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/** The digest OID this implementation computes: SHA-256, for the imprint and for the content binding. */
const OID_DIGEST_SHA256 = '2.16.840.1.101.3.4.2.1';

const SIGNATURE_ALGORITHMS = {
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};

/**
 * What the parse produced, before any of it is judged.
 *
 * @typedef {object} ParsedToken
 * @property {import('./x509.mjs').Certificate[]} certificates
 * @property {import('./x509.mjs').Certificate | null} signer
 * @property {Uint8Array} signedBytes The `signedAttrs` re-encoded as a `SET OF`, which is what is signed.
 * @property {Uint8Array} signature
 * @property {string} signatureAlgorithm OID.
 * @property {string} digestAlgorithm OID.
 * @property {Map<string, import('./der.mjs').DerElement[]>} attributes
 * @property {Uint8Array} content The encapsulated `TSTInfo` bytes.
 * @property {Uint8Array} contentDigest A digest of `content`, computed by the caller's runtime.
 * @property {string} imprintAlgorithm OID.
 * @property {Uint8Array} imprint
 * @property {string} genTime
 * @property {string} policy
 * @property {string} serialNumber
 */

/** Thrown when a token cannot be read, with the reason phrased as this reader's limit. */
export class TokenError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'TokenError';
  }
}

/**
 * @param {unknown} value
 * @param {string} where
 * @returns {import('./der.mjs').DerElement}
 */
function need(value, where) {
  if (value === undefined) throw new TokenError(`the token has no ${where}`);
  return value;
}

/**
 * The `AlgorithmIdentifier` OID, refusing a parameter form this code cannot interpret.
 *
 * @param {import('./der.mjs').DerElement} algorithm
 * @returns {string}
 */
function algorithmOf(algorithm) {
  const [oid] = algorithm.children;
  return oidValue(need(oid, 'algorithm identifier'));
}

/**
 * Read a token into the facts the four steps need.
 *
 * @param {Uint8Array} bytes DER.
 * @param {(bytes: Uint8Array) => string} digestOf A synchronous hex SHA-256, which both runtimes have.
 * @returns {ParsedToken}
 * @throws {TokenError}
 */
export function parseToken(bytes, digestOf) {
  let outer;
  try {
    outer = readDer(bytes);
  } catch (error) {
    // A DER reader's refusal is still an answer about the token, so it is said in the token's terms.
    throw new TokenError(`the token could not be read: ${error.message}`);
  }
  const [contentType, wrapped] = outer.children;
  if (contentType === undefined || oidValue(contentType) !== OID_SIGNED_DATA) {
    throw new TokenError(
      `a timestamp token wraps CMS signedData, and this one wraps `
      + `${contentType === undefined ? 'nothing' : oidValue(contentType)}`,
    );
  }
  const signedData = need(wrapped?.children[0], 'signedData');
  const encapsulated = signedData.children[2];
  if (encapsulated === undefined) throw new TokenError('the signedData has no encapsulated content');

  const [eContentType, eContent] = encapsulated.children;
  if (eContentType === undefined || oidValue(eContentType) !== OID_TST_INFO) {
    throw new TokenError('the encapsulated content is not a TSTInfo, so this is not a timestamp token');
  }
  const content = need(eContent?.children[0], 'TSTInfo content').value;

  /** @type {import('./x509.mjs').Certificate[]} */
  const certificates = [];
  let signerInfos = null;
  for (const child of signedData.children.slice(3)) {
    if (child.tag === 0xa0) {
      for (const entry of child.children) certificates.push(readCertificate(entry.whole));
    } else if (child.tag === 0x31) {
      signerInfos = child;
    }
  }
  if (signerInfos === null) throw new TokenError('the token carries no signer information');
  if (signerInfos.children.length !== 1) {
    throw new TokenError(
      `this reader verifies a token with one signer, and this one has ${signerInfos.children.length}`,
    );
  }

  const signerInfo = signerInfos.children[0];
  const parts = signerInfo.children;
  const sid = parts[1];
  if (sid === undefined) throw new TokenError('the signer information names no signer');
  if (sid.tag !== 0x30) {
    throw new TokenError(
      'this reader matches a signer by issuer and serial number, and this token names it another way',
    );
  }
  const [sidIssuer, sidSerial] = sid.children;
  const serial = [...sidSerial.value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const signer = certificates.find(
    (candidate) => candidate.serialNumber === serial
      && sameBytes(candidate.issuer, sidIssuer.whole),
  ) ?? null;
  if (signer === null) {
    throw new TokenError(
      'the signer named by the token is not among the certificates it carries, so its key is not here',
    );
  }

  let signedAttrs = null;
  let signatureAlgorithm = null;
  let signature = null;
  for (const child of parts.slice(3)) {
    if (child.tag === 0xa0) signedAttrs = child;
    else if (signatureAlgorithm === null && child.tag === 0x30) signatureAlgorithm = child;
    else if (child.tag === 0x04) signature = child;
  }
  if (signedAttrs === null) {
    throw new TokenError('the token has no signed attributes, which is where its content binding lives');
  }
  if (signatureAlgorithm === null || signature === null) {
    throw new TokenError('the token has no signature');
  }

  /** @type {Map<string, import('./der.mjs').DerElement[]>} */
  const attributes = new Map();
  for (const attribute of signedAttrs.children) {
    const [id, values] = attribute.children;
    if (id === undefined || values === undefined) continue;
    attributes.set(oidValue(id), values.children);
  }

  const tst = readDer(content);
  const [version, policy, messageImprint, serialNumber, genTime] = tst.children;
  if (version === undefined || integerValue(version) !== 1) {
    throw new TokenError('this reader knows version 1 of the TSTInfo structure');
  }
  const [imprintAlgorithm, imprint] = need(messageImprint, 'message imprint').children;

  return {
    certificates,
    signer,
    // `signedAttrs` is `[0] IMPLICIT SET OF`: the same bytes with the tag rewritten are what is signed.
    signedBytes: concat([new Uint8Array([0x31]), signedAttrs.whole.subarray(1)]),
    signature: signature.value,
    signatureAlgorithm: algorithmOf(signatureAlgorithm),
    digestAlgorithm: algorithmOf(need(parts[2], 'digest algorithm')),
    attributes,
    content,
    contentDigest: digestOf(content),
    imprintAlgorithm: algorithmOf(need(imprintAlgorithm, 'imprint algorithm')),
    imprint: need(imprint, 'imprint value').value,
    genTime: timeValue(need(genTime, 'genTime')),
    policy: oidValue(need(policy, 'policy')),
    serialNumber: integerValue(need(serialNumber, 'serial number')).toString(),
  };
}

/**
 * The `text` of a token's base64url field, as the claim carries it.
 *
 * @param {unknown} value
 * @returns {Uint8Array}
 * @throws {TokenError}
 */
export function tokenBytes(value) {
  if (typeof value !== 'string' || value === '') {
    throw new TokenError('the anchor carries no token');
  }
  try {
    return fromBase64Url(value);
  } catch (error) {
    throw new TokenError(`the token is not base64url: ${error.message}`);
  }
}

/**
 * What a token verification concluded.
 *
 * @typedef {object} TokenVerdict
 * @property {'verified'|'invalid'|'unreadable'|'untrusted_signer'} outcome
 * @property {string} detail One sentence, phrased for a person reading a verdict.
 * @property {string | null} genTime
 * @property {string | null} authority What the signing certificate calls itself, or its fingerprint.
 * @property {string | null} fingerprint SHA-256 of the signing certificate.
 * @property {string | null} policy The TSA's policy OID, reported and not judged.
 */

/** @param {import('./x509.mjs').Certificate} signer */
const describe = (signer) => signer.subjectName ?? `certificate ${signer.fingerprint.slice(0, 16)}…`;

/** The shape a verdict takes when the reader never got far enough to learn anything about the signer. */
const noIdentity = { genTime: null, authority: null, fingerprint: null, policy: null };

/**
 * The four steps of section 8.3 of the specification, in order.
 *
 * Order is deliberate and load-bearing. Trust comes first, because every later check is only meaningful for
 * a certificate the caller asked us to believe; then the certificate's own fitness; then what the token
 * *says* (imprint, attributes); then the signature, which is what makes any of it the TSA's statement
 * rather than a stranger's.
 *
 * @param {{
 *   token: Uint8Array,
 *   claimHash: string,
 *   trustedTsa: Array<Uint8Array | string>,
 *   digestOf: (bytes: Uint8Array) => string,
 *   runtime: { verifyWithPublicKey: (input: {
 *     spki: Uint8Array, hash: string, data: Uint8Array, signature: Uint8Array,
 *   }) => boolean | Promise<boolean> },
 * }} input
 * @returns {Promise<TokenVerdict>}
 */
export async function verifyToken(input) {
  let parsed;
  try {
    parsed = parseToken(input.token, input.digestOf);
  } catch (error) {
    // A token this reader cannot read is this reader's limit, not a fault in the receipt (D-021).
    return { outcome: 'unreadable', detail: error.message, ...noIdentity };
  }

  const { signer } = parsed;
  const identity = {
    genTime: parsed.genTime,
    authority: describe(signer),
    fingerprint: signer.fingerprint,
    policy: parsed.policy,
  };

  // 1. Trust, which is the caller's configuration and nothing else. A pin may be the certificate itself or
  // its SHA-256 fingerprint, because the two are the same statement and a fingerprint is what a caller
  // usually has.
  const matches = (pinned) => (typeof pinned === 'string'
    ? pinned.toLowerCase() === signer.fingerprint
    : sameBytes(pinned, signer.der));
  if (!input.trustedTsa.some(matches)) {
    return {
      outcome: 'untrusted_signer',
      detail: `the token is signed by ${describe(signer)} (${signer.fingerprint}), which is not a TSA `
        + 'certificate the caller pinned, so nothing about it was checked against a trust you stated',
      ...identity,
    };
  }

  // The pinning says "believe these bytes"; RFC 3161 still says what those bytes must be for.
  if (!signer.extendedKeyUsage.includes(EKU_TIME_STAMPING)) {
    return {
      outcome: 'invalid',
      detail: 'RFC 3161 requires a TSA certificate to carry the timeStamping extended key usage, and '
        + `${describe(signer)} does not`,
      ...identity,
    };
  }
  if (!signer.keyUsagePermitsSigning) {
    return {
      outcome: 'invalid',
      detail: `the key usage of ${describe(signer)} permits neither signing nor non-repudiation`,
      ...identity,
    };
  }

  // 3, taken early because it is a fact about the certificate rather than about the signature.
  if (parsed.genTime < signer.notBefore || parsed.genTime > signer.notAfter) {
    return {
      outcome: 'invalid',
      detail: `the token says ${parsed.genTime} and the certificate that made it was valid from `
        + `${signer.notBefore} to ${signer.notAfter}`,
      ...identity,
    };
  }

  return finishTokenCheck(input, parsed, identity);
}

/**
 * The rest of the four steps: the algorithms this verifier has, the two CMS bindings, the imprint, and the
 * signature itself.
 *
 * @param {object} input As `verifyToken` received it.
 * @param {ParsedToken} parsed
 * @param {Record<string, any>} identity
 * @returns {Promise<TokenVerdict>}
 */
async function finishTokenCheck(input, parsed, identity) {
  const hash = SIGNATURE_ALGORITHMS[parsed.signatureAlgorithm];
  if (hash === undefined) {
    return {
      outcome: 'unreadable',
      detail: 'this verifier checks RSA PKCS#1 v1.5 and ECDSA with SHA-256, SHA-384 and SHA-512; this '
        + `token is signed with ${parsed.signatureAlgorithm}`,
      ...noIdentity,
    };
  }
  if (parsed.digestAlgorithm !== OID_DIGEST_SHA256) {
    return {
      outcome: 'unreadable',
      detail: 'this verifier compares the content digest in SHA-256, and this token uses '
        + `${parsed.digestAlgorithm} for it`,
      ...noIdentity,
    };
  }

  const contentType = parsed.attributes.get(OID_ATTR_CONTENT_TYPE)?.[0];
  if (contentType === undefined || oidValue(contentType) !== OID_TST_INFO) {
    return {
      outcome: 'invalid',
      detail: 'the signed attributes do not name the TSTInfo content type, so the signature does not cover '
        + 'what the token carries',
      ...identity,
    };
  }
  const messageDigest = parsed.attributes.get(OID_ATTR_MESSAGE_DIGEST)?.[0];
  if (messageDigest === undefined || toHex(messageDigest.value) !== parsed.contentDigest) {
    return {
      outcome: 'invalid',
      detail: 'the signed attributes do not carry the digest of the content they sign',
      ...identity,
    };
  }

  if (parsed.imprintAlgorithm !== OID_DIGEST_SHA256) {
    return {
      outcome: 'unreadable',
      detail: `this token's imprint is computed with ${parsed.imprintAlgorithm}, and a claim hash is `
        + 'SHA-256',
      ...noIdentity,
    };
  }
  const imprint = toHex(parsed.imprint);
  if (imprint !== input.claimHash) {
    return {
      outcome: 'invalid',
      detail: `the token commits to ${imprint} and this claim hashes to ${input.claimHash}`,
      ...identity,
    };
  }

  let verified = false;
  try {
    verified = await input.runtime.verifyWithPublicKey({
      spki: parsed.signer.spki,
      hash,
      data: parsed.signedBytes,
      signature: parsed.signature,
    });
  } catch (error) {
    return {
      outcome: 'unreadable',
      detail: `the token's signature could not be checked here: ${error.message}`,
      ...noIdentity,
    };
  }
  if (verified !== true) {
    return {
      outcome: 'invalid',
      detail: "the token's signature does not verify against the certificate that made it "
        + `(${identity.authority})`,
      ...identity,
    };
  }

  return {
    outcome: 'verified',
    detail: `${identity.authority} attests that this claim existed no later than ${parsed.genTime}`,
    ...identity,
  };
}

/** @param {Uint8Array} left @param {Uint8Array} right */
export function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/** Re-exported so a caller needing bytes does not have to reach into two modules for one job. */
export { utf8, octetString, toHex };
