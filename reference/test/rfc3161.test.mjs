/**
 * RFC 3161 anchors: the reader, the certificate, and the four steps of section 8.3.
 *
 * The reader tests come first because everything else rests on them, and because a DER reader that accepts
 * something it should not is the failure mode that matters: a token arrives inside a receipt, and a receipt
 * is untrusted input. Each refusal here is a shape a real token never has.
 *
 * Then the four steps in order, one test each, plus the CMS bindings that make a signature mean anything.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';

import {
  DerError, boolean, concat, context, generalizedTime, integer, integerValue, nullValue,
  objectIdentifier, octetString, oidValue, readDer, sequence, timeValue, utcTime,
} from '../src/der.mjs';
import { X509Error, readCertificate } from '../src/x509.mjs';
import { TokenError, parseToken, tokenBytes, verifyToken } from '../src/rfc3161.mjs';
import { TSA_GEN_TIME, tsaCertificate, timestampToken } from '../src/tst-fixture.mjs';
import { toHex, utf8 } from '../src/encode.mjs';
import { sha256 } from '../src/digest.mjs';

/** The synchronous digest the token layer takes, exactly as the verifier supplies it. */
const digestOf = (bytes) => sha256(bytes);

/** The runtime primitive, implemented the way Node implements it. */
const runtime = {
  verifyWithPublicKey: ({ spki, hash, data, signature }) => verify(
    hash, data, createPublicKey({ key: spki, format: 'der', type: 'spki' }), signature,
  ),
};

const CLAIM_HASH = sha256(utf8('a claim worth stamping'));

test('DER round-trips what the fixture writes', () => {
  const encoded = sequence(
    integer(1),
    objectIdentifier('1.2.840.113549.1.9.16.1.4'),
    generalizedTime('2026-01-01T00:00:00Z'),
    utcTime('2026-01-01T00:00:00Z'),
    boolean(true),
    nullValue(),
    context(0, true, octetString(utf8('x'))),
  );
  const parsed = readDer(encoded);
  assert.equal(parsed.tag, 0x30);
  assert.equal(parsed.children.length, 7);
  assert.equal(integerValue(parsed.children[0]), 1);
  assert.equal(oidValue(parsed.children[1]), '1.2.840.113549.1.9.16.1.4');
  assert.equal(timeValue(parsed.children[2]), '2026-01-01T00:00:00Z');
  assert.equal(timeValue(parsed.children[3]), '2026-01-01T00:00:00Z');
  // The two-digit year resolves by the RFC 5280 rule, which is why a 2050 certificate is another story.
  assert.equal(timeValue(readDer(utcTime('1999-12-31T23:59:59Z'))), '1999-12-31T23:59:59Z');
  assert.equal(parsed.children[4].tag, 0x01);
  assert.equal(parsed.children[5].tag, 0x05);
  assert.equal(parsed.children[6].tag, 0xa0);
  assert.equal(parsed.children[6].children[0].tag, 0x04);
});

test('DER refuses the shapes a token never has', () => {
  // Indefinite length is BER, not DER.
  assert.throws(() => readDer(new Uint8Array([0x30, 0x80, 0x00, 0x00])), /indefinite/);
  // A length longer than the bytes that follow.
  assert.throws(() => readDer(new Uint8Array([0x30, 0x10, 0x02, 0x01, 0x00])), /truncated/);
  // Bytes after the structure.
  assert.throws(
    () => readDer(concat([sequence(integer(1)), new Uint8Array([0x00])])),
    /follow the structure/,
  );
  // A multi-byte tag number.
  assert.throws(() => readDer(new Uint8Array([0x3f, 0x81, 0x00, 0x00])), /multi-byte/);
  // A length field of absurd width, and nothing at all.
  assert.throws(() => readDer(new Uint8Array([0x30, 0x85, 1, 2, 3, 4, 5])), /four bytes/);
  assert.throws(() => readDer(new Uint8Array([])), DerError);
});

test('DER refuses an integer it cannot hold exactly', () => {
  const huge = concat([new Uint8Array([0x02, 0x09]), new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])]);
  assert.throws(() => integerValue(readDer(huge)), /exactly/);
});

test('a certificate is read as far as a token needs', () => {
  const certificate = readCertificate(tsaCertificate());
  assert.equal(certificate.version, 3);
  assert.equal(certificate.subjectName, 'Vidimus Test TSA (not a real authority)');
  assert.equal(certificate.notBefore, '2020-01-01T00:00:00Z');
  assert.equal(certificate.notAfter, '2035-01-01T00:00:00Z');
  assert.deepEqual(certificate.extendedKeyUsage, ['1.3.6.1.5.5.7.3.8']);
  assert.equal(certificate.keyUsagePermitsSigning, true);
  assert.equal(certificate.publicKeyAlgorithm, '1.2.840.113549.1.1.1');
  assert.equal(certificate.fingerprint.length, 64);
  // Self-signed, so the two names are the same bytes.
  assert.deepEqual([...certificate.issuer], [...certificate.subject]);

  // A certificate with no timestamping usage says so rather than being assumed to have one.
  assert.deepEqual(readCertificate(tsaCertificate({ withTimeStampingEku: false })).extendedKeyUsage, []);
  assert.throws(() => readCertificate(utf8('not a certificate')), X509Error);
});

test('a token is read into the facts the four steps need', () => {
  const certificate = tsaCertificate();
  const token = timestampToken({ claimHash: CLAIM_HASH, genTime: TSA_GEN_TIME, certificate });
  const parsed = parseToken(token, digestOf);

  assert.equal(toHex(parsed.imprint), CLAIM_HASH);
  assert.equal(parsed.genTime, TSA_GEN_TIME);
  assert.equal(parsed.policy, '1.3.6.1.4.1.99999.1.1');
  assert.equal(parsed.signer.fingerprint, readCertificate(certificate).fingerprint);
  assert.equal(parsed.certificates.length, 1);
  // The signed attributes are re-encoded as a `SET OF`, which is what a CMS signature hangs on.
  assert.equal(parsed.signedBytes[0], 0x31);
  assert.equal(parsed.contentDigest, sha256(parsed.content));
  assert.equal(parsed.attributes.size, 2);
});

test('a token that is not a token is refused by name', () => {
  assert.throws(() => parseToken(utf8('not DER at all'), digestOf), TokenError);
  assert.throws(() => parseToken(timestampToken({}).subarray(0, 40), digestOf), TokenError);
  assert.throws(() => tokenBytes(''), TokenError);
  assert.throws(() => tokenBytes(42), TokenError);
});

test('the four steps, and the outcomes they produce', async () => {
  const certificate = tsaCertificate();
  const token = timestampToken({ claimHash: CLAIM_HASH, genTime: TSA_GEN_TIME, certificate });
  const base = { token, claimHash: CLAIM_HASH, trustedTsa: [certificate], digestOf, runtime };

  const verified = await verifyToken(base);
  assert.equal(verified.outcome, 'verified');
  assert.equal(verified.genTime, TSA_GEN_TIME);
  assert.equal(verified.authority, 'Vidimus Test TSA (not a real authority)');
  assert.match(verified.detail, /no later than 2026-01-01T00:00:00Z/);

  // Step 1: a certificate the caller did not pin. Not a failure, and not a pass either.
  const other = await verifyToken({
    ...base, trustedTsa: [tsaCertificate({ commonName: 'Some Other TSA' })],
  });
  assert.equal(other.outcome, 'untrusted_signer');
  assert.equal(other.authority, 'Vidimus Test TSA (not a real authority)');

  // Step 2: the imprint.
  const imprint = await verifyToken({ ...base, claimHash: sha256(utf8('a different claim')) });
  assert.equal(imprint.outcome, 'invalid');
  assert.match(imprint.detail, /commits to/);

  // Step 3: the certificate must have been valid when it stamped.
  const late = timestampToken({
    claimHash: CLAIM_HASH, genTime: '2040-01-01T00:00:00Z', certificate,
  });
  const expired = await verifyToken({ ...base, token: late });
  assert.equal(expired.outcome, 'invalid');
  assert.match(expired.detail, /valid from 2020/);

  // And the certificate must be a timestamping one: a pinned certificate is not a licence to skip RFC 3161.
  const noEku = tsaCertificate({ withTimeStampingEku: false });
  const unfit = await verifyToken({
    ...base,
    trustedTsa: [noEku],
    token: timestampToken({ claimHash: CLAIM_HASH, genTime: TSA_GEN_TIME, certificate: noEku }),
  });
  assert.equal(unfit.outcome, 'invalid');
  assert.match(unfit.detail, /timeStamping/);
});

test('a tampered token is a failure, never a shrug', async () => {
  const certificate = tsaCertificate();
  const token = timestampToken({ claimHash: CLAIM_HASH, genTime: TSA_GEN_TIME, certificate });
  const base = { claimHash: CLAIM_HASH, trustedTsa: [certificate], digestOf, runtime };

  // The untouched token is the control: if this stopped verifying, the mutation test would prove nothing.
  assert.equal((await verifyToken({ ...base, token })).outcome, 'verified');

  // One byte of the imprint inside the encapsulated TSTInfo. The token still *says* it commits to the claim;
  // what catches this is the digest binding in the signed attributes, which is why that check exists.
  const mutated = token.slice();
  let imprintAt = -1;
  for (let index = 0; index < token.length - 32; index += 1) {
    if (Buffer.from(token.subarray(index, index + 32)).toString('hex') === CLAIM_HASH) {
      imprintAt = index;
      break;
    }
  }
  assert.ok(imprintAt > 0, 'the imprint should be findable inside the token');
  mutated[imprintAt] ^= 0x01;

  const outcome = await verifyToken({ ...base, token: mutated });
  assert.equal(outcome.outcome, 'invalid');
  assert.match(outcome.detail, /digest of the content/);
});

test('a token this verifier cannot read is its own limit, not the receipt\'s fault', async () => {
  const certificate = tsaCertificate();
  // Signed with a hash this implementation does not compare content digests under: the token is well
  // formed and the answer is "I cannot check this", never "this is broken".
  const outcome = await verifyToken({
    token: timestampToken({ claimHash: CLAIM_HASH, genTime: TSA_GEN_TIME, certificate }),
    claimHash: CLAIM_HASH,
    trustedTsa: [certificate],
    digestOf,
    runtime: {},
  });
  assert.equal(outcome.outcome, 'unreadable');
  assert.match(outcome.detail, /could not be checked here/);
});
