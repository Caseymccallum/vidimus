/**
 * A deterministic TSA and its tokens, for the conformance vectors.
 *
 * The vectors need a timestamp token, and a fixture has to be a deterministic function of committed bytes.
 * RSA PKCS#1 v1.5 signing is deterministic, so a token minted here is byte-identical on every run and every
 * machine - which is what lets `spec/vectors/receipt-vectors.json` record its digest and mean something
 * (D-014).
 *
 * **The key below is published on purpose and is worthless.** It exists so that these fixtures can be
 * rebuilt by anybody; it is not, and must never be, a key anybody trusts. The same is true of the
 * certificate, whose common name says so. A private key in a repository is a private key nobody should
 * ever use for anything.
 *
 * Node-only, and only ever called by a fixture or a test: it signs and it exports a public key, which is
 * `node:crypto`'s business. The *verifier* never touches this module - it reads tokens with `rfc3161.mjs`,
 * which has no Node in it at all.
 *
 * @module tst-fixture
 */

import { createPrivateKey, createPublicKey, sign } from 'node:crypto';

import {
  bitString, boolean, concat, context, element, generalizedTime, integer, nullValue,
  objectIdentifier, octetString, sequence, setOf, utcTime,
} from './der.mjs';
import { latin1 } from './encode.mjs';
import { sha256, fromHex } from './digest.mjs';
import { readCertificate } from './x509.mjs';

/** The published RSA key. See the module comment: worthless, and meant to be. */
const TSA_JWK = {
  kty: 'RSA',
  n: 'vQxXLuir33D5z5IsP0zkj3FhdM-YCxcY065xTDUtX-nh4S8Fve3dPGX5ucyRI0wQDZuleDEIDiC0s-5xTtTcBOknRm5te6_2crkuSOk9PpLwCrOlfHYl5N2zz30bbzCHzT9mxT6Np1kVSpNdlM4tKxgx7rHR0SeobkcDgNGsk2A2DfSpgbrm0C6LIGGQgbrdhKYdh-wpErMKNzUrAo5Vn-PJ5UA46BwhNHpAfOR2QLdD4u9RtDkXenn7C9UkvsXs9zFULj3i_ArPhHdSvgpLMA_zFfrFNGPy8gBNKaJgJayeFaXNg7Z_JhJQvi0IM7dXaBsI_ebWhXMZRIidi9Hf5w',
  e: 'AQAB',
  d: 'HJPn_gRYLv_SE6nCHJOQHYsDM3hKQKruKtm88Ms9H7moVrUYBh0WC5JSzN56tj5CUvxLaD7pO9F_349U-5i75dYlBMWesUrpU3Bg6c6wXmwx8zwy8PyfP9iv3NbJteY9MS67Z2fMXBbgXBSo2dzNAS24JqAk2pxHHtyHUAriLqjiZ-oEJJKxVtQWefhq1D6Zvie9H3pzqvsF38Vq_c6_1gs9hq2PyF4gTu3muksU9GiLSMOzGWCKwbOyC0y9paeivCXqAcGbuKLZ2v3Gze3KkxZKPXKHoyq2Prrq5_aEbcETt1EhV9XIm0Ud-wVzfK5S3BLi57AE5ayMUlEbFGhEKQ',
  p: '_s20d28HGakaMWJlrGywczOw9H_hfi2fJFeMGamb3jRrnaqybWemgKv4XQbPxS5VT_ycqDqC5DMZ33X6XSrPeORqXf29F-qbYO7IIXcjoLfSp4KBxQK2g6YdM5DHIuVJYSobrVve6YlDukcyh639yrI3vK53Esfgmh7B8zACDbM',
  q: 've-XnKYtYeBEGHfN7Rv0bO6zST-pOE7FyVNQanBkGHZEyZktyUgGzmyYK_bSe33-oWjRIMc3UibUrhMBOzqgHGB883V7GJUuJYnIDl_SUQocjA3vlGwEERI7sKMGy8D7WQYvVN7q4C-wwvVM-J_uiL8lMQISmFzQihTdjLt9Uv0',
  dp: 'XzQu9N0oMv9LCR6xzJ4Dw9eRi5logIO9TY_kigYkdf7yIsQPzO8IeFVJBEEySoOIXs2NHxJVq7woM6VaOYtwX8RAtgPDrnb7PVmar15bkoZ8kBgkMp9T4JalnInAzhoLs-FO3BRSksG165kEmUt6Y0z5pGcvmHXURuGtKBdM_R8',
  dq: 'PfNoADAznTkI_PIWuL_leaJh2AJrr3ICESibkhwWieQJi7fqtzxG_A1vlOdsv9rYssz9aTORV7pSpHSOckMs9hSCrOYkwF_oLVZDamzWrJgft47UFhUlPmw0C-kgzlSjpuXdilErSvRDM1PPR0jjBLdT6ihC6G9dlaw4ly6QMgE',
  qi: '4h3f3OlLlCPzomsZ9Qe6EHoUH-lcUlg75xOlA4Vu8gpSQzMcTomjnK41rd5tzlwkfvsU3CmboWLpnX6Kks4tmYhH3gLoJwQQ-To_kLycBF7al1uM0KYW1RqUZzuAIdVE40f9FJcGcA_bi9CpzE8DvDtXfKY7PEycOe6wUIXV8nY',
};

/** OIDs this fixture writes, named once so a typo cannot become a second algorithm. */
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA256_RSA = '1.2.840.113549.1.1.11';
const OID_COMMON_NAME = '2.5.4.3';
const OID_KEY_USAGE = '2.5.29.15';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/** A policy OID that says "these tokens are fixtures and attest nothing about anything real". */
export const TSA_POLICY = '1.3.6.1.4.1.99999.1.1';

/** The instant the fixture tokens stamp, and the window the fixture certificates are valid in. */
export const TSA_GEN_TIME = '2026-01-01T00:00:00Z';
export const TSA_NOT_BEFORE = '2020-01-01T00:00:00Z';
export const TSA_NOT_AFTER = '2035-01-01T00:00:00Z';

/** @returns {import('node:crypto').KeyObject} */
function tsaPrivateKey() {
  return createPrivateKey({ key: TSA_JWK, format: 'jwk' });
}

/**
 * An X.501 name with one common name in it.
 *
 * `Name ::= RDNSequence ::= SEQUENCE OF SET OF AttributeTypeAndValue`, and a common name is a
 * `PrintableString` - which is what a real certificate writes for one, so the fixture does too.
 *
 * @param {string} commonName
 * @returns {Uint8Array}
 */
function encodedName(commonName) {
  return sequence(
    setOf(sequence(objectIdentifier(OID_COMMON_NAME), element(0x13, [latin1(commonName)]))),
  );
}

/**
 * A self-signed timestamping certificate.
 *
 * Self-signed is the honest shape for a fixture: it is signed by its own key, which is the key the fixture
 * published, and it is worthless for exactly the same reason.
 *
 * @param {{
 *   commonName?: string, notBefore?: string, notAfter?: string, serial?: number,
 *   withTimeStampingEku?: boolean,
 * }} [input]
 * @returns {Uint8Array} DER.
 */
export function tsaCertificate(input = {}) {
  const commonName = input.commonName ?? 'Vidimus Test TSA (not a real authority)';
  const spki = new Uint8Array(
    createPublicKey(tsaPrivateKey()).export({ format: 'der', type: 'spki' }),
  );

  const extensions = [];
  if (input.withTimeStampingEku !== false) {
    extensions.push(sequence(
      objectIdentifier(OID_EXT_KEY_USAGE),
      boolean(true),
      octetString(sequence(objectIdentifier(OID_TIME_STAMPING))),
    ));
  }
  extensions.push(sequence(
    objectIdentifier(OID_KEY_USAGE),
    boolean(true),
    // digitalSignature and nonRepudiation, numbered from the high end of the first byte.
    octetString(bitString(new Uint8Array([0xc0]))),
  ));

  const tbs = sequence(
    context(0, true, integer(2)),
    integer(input.serial ?? 0x5a17c0de),
    sequence(objectIdentifier(OID_SHA256_RSA), nullValue()),
    encodedName(commonName),
    sequence(utcTime(input.notBefore ?? TSA_NOT_BEFORE), utcTime(input.notAfter ?? TSA_NOT_AFTER)),
    encodedName(commonName),
    spki,
    context(3, true, sequence(...extensions)),
  );

  return sequence(
    tbs,
    sequence(objectIdentifier(OID_SHA256_RSA), nullValue()),
    bitString(sign('sha256', tbs, tsaPrivateKey())),
  );
}

/**
 * The `TSTInfo` a token encapsulates: what was stamped, when, by which policy.
 *
 * @param {{ imprint: string, genTime: string, policy?: string, serialNumber?: number }} input
 * @returns {Uint8Array}
 */
function tstInfo(input) {
  return sequence(
    integer(1),
    objectIdentifier(input.policy ?? TSA_POLICY),
    sequence(
      sequence(objectIdentifier(OID_SHA256), nullValue()),
      octetString(fromHex(input.imprint)),
    ),
    integer(input.serialNumber ?? 1),
    generalizedTime(input.genTime),
  );
}

/**
 * Mint a timestamp token.
 *
 * `imprint` is separate from `claimHash` so that a vector can build the token a TSA would *not* have made -
 * one that commits to different bytes - which is the only way to show that the imprint check does something.
 *
 * @param {{
 *   claimHash?: string, imprint?: string, genTime?: string, policy?: string,
 *   certificate?: Uint8Array, content?: Uint8Array,
 * }} input
 * @returns {Uint8Array} DER.
 */
export function timestampToken(input) {
  const certificate = input.certificate ?? tsaCertificate();
  const cert = readCertificate(certificate);
  const content = input.content ?? tstInfo({
    imprint: input.imprint ?? input.claimHash ?? '00'.repeat(32),
    genTime: input.genTime ?? TSA_GEN_TIME,
    policy: input.policy,
  });

  const signedAttrs = context(
    0,
    true,
    sequence(objectIdentifier(OID_ATTR_CONTENT_TYPE), setOf(objectIdentifier(OID_TST_INFO))),
    sequence(objectIdentifier(OID_ATTR_MESSAGE_DIGEST), setOf(octetString(fromHex(sha256(content))))),
  );
  // What is signed is the attributes as a `SET OF`, which is the same bytes under the universal tag.
  const signedBytes = concat([new Uint8Array([0x31]), signedAttrs.subarray(1)]);
  const signature = sign('sha256', signedBytes, tsaPrivateKey());

  const signerInfo = sequence(
    integer(1),
    sequence(cert.issuer, integer(fromHex(cert.serialNumber))),
    sequence(objectIdentifier(OID_SHA256), nullValue()),
    signedAttrs,
    sequence(objectIdentifier(OID_SHA256_RSA), nullValue()),
    octetString(signature),
  );

  const signedData = sequence(
    integer(3),
    setOf(sequence(objectIdentifier(OID_SHA256), nullValue())),
    sequence(objectIdentifier(OID_TST_INFO), context(0, true, octetString(content))),
    context(0, true, certificate),
    setOf(signerInfo),
  );

  return sequence(objectIdentifier(OID_SIGNED_DATA), context(0, true, signedData));
}
