/**
 * A certificate, read only as far as a timestamp token needs.
 *
 * RFC 3161 asks a verifier for four things, and one of them is trust in the TSA - which in this
 * implementation is a certificate the caller pinned. So what this module has to answer is narrow:
 *
 * - which certificate signed the token, and is it **exactly** the one the caller pinned (byte equality)?
 * - was it **valid at the instant it stamped** (`notBefore` ≤ `genTime` ≤ `notAfter`)?
 * - is it **a timestamping certificate** - the extended key usage RFC 3161 requires?
 * - and what does it call itself, so a verdict can report an authority rather than a hex string?
 *
 * It deliberately does **not** build a chain, check a revocation list, or validate the certificate's own
 * signature. A pinned certificate is a trust anchor: the caller chose those exact bytes, so nothing about
 * them needs proving again - and claiming chain validation this code does not perform would be the kind of
 * overstatement the rest of the project exists to avoid. `docs/CONFORMANCE.md` records the limit.
 *
 * @module x509
 */

import { toHex } from './encode.mjs';
import { sha256 } from './sha256.mjs';
import { readDer, integerBytes, integerValue, oidValue, timeValue } from './der.mjs';

/** Thrown when a certificate cannot be read as one. */
export class X509Error extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'X509Error';
  }
}

/** `id-kp-timeStamping`, the extended key usage RFC 3161 requires a TSA certificate to carry. */
export const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';

/** `id-ce-extKeyUsage`, `id-ce-keyUsage`, and the common name attribute. */
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_KEY_USAGE = '2.5.29.15';
const OID_COMMON_NAME = '2.5.4.3';

/**
 * @typedef {object} Certificate
 * @property {Uint8Array} der The whole certificate, which is what a caller pins.
 * @property {string} fingerprint SHA-256 of those bytes, lowercase hex.
 * @property {number} version `1`, `2` or `3`.
 * @property {string} serialNumber Hex, because a serial number is an identifier, not arithmetic.
 * @property {string} signatureAlgorithm An OID, as dotted decimal.
 * @property {Uint8Array} issuer The issuer field exactly as encoded, for comparison.
 * @property {Uint8Array} subject Likewise.
 * @property {string | null} subjectName The common name, or null when the subject has none.
 * @property {string} notBefore Whole-second UTC.
 * @property {string} notAfter Whole-second UTC.
 * @property {string} publicKeyAlgorithm An OID: how the key in `spki` is used.
 * @property {Uint8Array} spki The `SubjectPublicKeyInfo`, DER, in the form both runtimes import.
 * @property {string[]} extendedKeyUsage OIDs, empty when the certificate states none.
 * @property {boolean} keyUsagePermitsSigning True when `keyUsage` is absent, or permits signing.
 */

/**
 * The common name out of an X.501 name, or null.
 *
 * `Name ::= RDNSequence ::= SEQUENCE OF SET OF AttributeTypeAndValue`, and the common name is the
 * attribute with OID 2.5.4.3. A name this reader cannot walk is a name it reports as absent rather than as
 * a guess: the fingerprint is the identity that matters, and this is only here so a verdict can say
 * something a person recognises.
 *
 * @param {import('./der.mjs').DerElement} name
 * @returns {string | null}
 */
function commonNameOf(name) {
  try {
    for (const rdn of name.children) {
      for (const attribute of rdn.children) {
        const [type, value] = attribute.children;
        if (type === undefined || value === undefined) continue;
        if (oidValue(type) !== OID_COMMON_NAME) continue;
        return new TextDecoder('utf-8', { fatal: true }).decode(value.value);
      }
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Read the extensions this module cares about: the two key usages.
 *
 * `keyUsage` is a BIT STRING, and the bits that matter are `digitalSignature` (bit 0) and
 * `nonRepudiation` (bit 1) - a certificate that forbids both may not sign a token. The byte is read as a
 * whole rather than bit by bit because DER numbers the bits from the most significant end of the first
 * byte, so `0x80` is bit 0.
 *
 * @param {import('./der.mjs').DerElement} extensions The `[3] EXPLICIT` wrapper.
 * @returns {Map<string, any>}
 */
function readExtensions(extensions) {
  const found = new Map();
  const list = extensions.children[0];
  if (list === undefined) return found;

  for (const extension of list.children) {
    const [id, maybeCritical, maybeValue] = extension.children;
    if (id === undefined) continue;
    const value = maybeValue ?? maybeCritical;
    if (value === undefined || value.tag !== 0x04) continue;
    const oid = oidValue(id);

    if (oid === OID_EXT_KEY_USAGE) {
      const inner = readDer(value.value);
      found.set(oid, inner.children.map((usage) => oidValue(usage)));
    }
    if (oid === OID_KEY_USAGE) {
      const inner = readDer(value.value);
      // A BIT STRING's first content byte says how many trailing bits are unused; the bits themselves are
      // the next byte, numbered from the most significant end.
      const bits = inner.value[1] ?? 0;
      found.set(oid, [(bits & 0x80) !== 0 || (bits & 0x40) !== 0]);
    }
  }
  return found;
}

/**
 * Read a certificate.
 *
 * @param {Uint8Array} der
 * @returns {Certificate}
 * @throws {X509Error}
 */
export function readCertificate(der) {
  try {
    const certificate = readDer(der);
    if (certificate.tag !== 0x30 || certificate.children.length !== 3) {
      throw new X509Error('a certificate is a SEQUENCE of three elements');
    }
    const [tbs, signatureAlgorithm, signatureValue] = certificate.children;
    if (signatureValue.tag !== 0x03) throw new X509Error('the certificate signature must be a BIT STRING');

    let index = 0;
    let version = 1;
    if (tbs.children[index]?.tag === 0xa0) {
      version = integerValue(tbs.children[index].children[0]) + 1;
      index += 1;
    }
    const serial = integerBytes(tbs.children[index]);
    index += 1;
    const sigAlg = tbs.children[index];
    index += 1;
    const issuer = tbs.children[index];
    index += 1;
    const validity = tbs.children[index];
    index += 1;
    const subject = tbs.children[index];
    index += 1;
    const spki = tbs.children[index];

    if (sigAlg === undefined || issuer === undefined || subject === undefined) {
      throw new X509Error('a certificate needs a signature algorithm, an issuer and a subject');
    }
    if (validity === undefined || validity.children.length !== 2) {
      throw new X509Error('a certificate needs a validity of two times');
    }
    if (spki === undefined || spki.children.length !== 2) {
      throw new X509Error('a certificate needs a subject public key');
    }

    const extensions = tbs.children.find((child) => child.tag === 0xa3);
    const usage = extensions === undefined ? new Map() : readExtensions(extensions);

    return {
      der,
      fingerprint: toHex(sha256(der)),
      version,
      serialNumber: [...serial].map((byte) => byte.toString(16).padStart(2, '0')).join(''),
      signatureAlgorithm: oidValue(sigAlg.children[0]),
      issuer: issuer.whole,
      subject: subject.whole,
      subjectName: commonNameOf(subject),
      notBefore: timeValue(validity.children[0]),
      notAfter: timeValue(validity.children[1]),
      publicKeyAlgorithm: oidValue(spki.children[0].children[0]),
      spki: spki.whole,
      extendedKeyUsage: usage.get(OID_EXT_KEY_USAGE) ?? [],
      keyUsagePermitsSigning: usage.get(OID_KEY_USAGE) === undefined
        || (usage.get(OID_KEY_USAGE)[0] ?? true),
    };
  } catch (error) {
    if (error instanceof X509Error) throw error;
    throw new X509Error(`the certificate could not be read: ${error.message}`);
  }
}
