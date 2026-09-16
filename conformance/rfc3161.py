#!/usr/bin/env python3
"""An RFC 3161 timestamp token: read it, then do the four things the specification requires.

Section 8.3 of `docs/RECEIPT-SPEC.md` lists what a conforming implementation **MUST** do before it reports a
`pass`, written down before any implementation existed so that a half-implementation could not answer "yes"
too early. This module is that list:

1. parse the CMS `SignedData` and validate the signature against a TSA the caller pinned;
2. check `messageImprint` against the claim hash, under the same hash algorithm;
3. check `genTime` against the signing certificate's validity window;
4. report the attested instant, which is a bound and not a capture time.

Plus the two things CMS requires for the signature to mean anything: the signed attributes must name the
`TSTInfo` content type, and must carry the digest of the content they sign. Without those, a token could
carry a perfectly good signature over attributes that describe nothing.

**What this module will not do: guess.** A token it cannot read, an algorithm it does not implement, or a
signer nobody pinned are all reported as *this verifier's* limit or as an untrusted signer - never as a fault
in the receipt. A token it can read that breaks a rule *is* a fault, and is named.

It was written from RFC 3161, RFC 5652 and the specification. The reference implementation's `rfc3161.mjs` was
read for the *order* of the checks and for nothing else - and the order matters, because a token signed by a
stranger with a broken imprint is `not_checked` rather than `fail`: trust first, then rules.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from base64 import urlsafe_b64decode
from der import (
    CONTEXT_0, GENERALIZED_TIME, INTEGER, NULL, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, SET, UTC_TIME,
    DerError, children, elements, expect, integer, object_identifier, read, time_value,
)
from x509 import OID_TIME_STAMPING, CertificateError, read_certificate


class TokenError(Exception):
    """A token this reader will not guess about, phrased as this reader's limit."""


# The identifiers a token is built from.
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

# The digest this implementation computes: SHA-256, for the imprint and for the content binding.
OID_DIGEST_SHA256 = "2.16.840.1.101.3.4.2.1"

# The signature algorithms this implementation verifies. Anything else is `unsupported`, by name, rather than
# a guess - and ECDSA is left out rather than half-implemented, because a signature scheme verified wrongly
# is worse than one reported as not implemented.
SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}

# The DER `DigestInfo` prefixes for RSA PKCS#1 v1.5, from RFC 8017 section 9.2. They exist because the
# signature is over a structure that names its own hash, and a verifier that compared a bare digest would
# accept a signature made under a different one.
DIGEST_INFO = {
    "sha256": "3031300d060960864801650304020105000420",
    "sha384": "3041300d060960864801650304020205000430",
    "sha512": "3051300d060960864801650304020305000440",
}


def rsa_verify(public_key: tuple[int, int], message: bytes, signature: bytes, hash_name: str) -> bool:
    """Whether `signature` is RSA PKCS#1 v1.5 over `message`, from RFC 8017 section 8.2.2.

    The verification is `signature^e mod n`, padded and compared with the encoded digest: the modular
    exponentiation *is* the whole check, which is why a second implementation of it is worth having. The
    comparison is constant-time out of habit rather than necessity - there is no secret here - and the
    padding length is derived rather than assumed, so a short modulus is refused rather than mis-padded.
    """
    modulus, exponent = public_key
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False

    recovered = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
    digest_info = bytes.fromhex(DIGEST_INFO[hash_name]) + hashlib.new(hash_name, message).digest()
    padding = size - len(digest_info) - 3
    if padding < 8:
        return False

    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    return hmac.compare_digest(recovered, expected)


def decode_token(value: str) -> bytes:
    """The token's DER, from the base64url the claim carries (section 8.3)."""
    if not isinstance(value, str) or value == "":
        raise TokenError("the anchor carries no token")
    try:
        return urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        raise TokenError("the anchor's token is not base64url") from None


def matches_pin(entry, certificate: dict) -> bool:
    """Whether a caller's pin names this certificate: its DER, or its SHA-256 fingerprint (section 8.3)."""
    if not isinstance(entry, str):
        return False
    if re.fullmatch(r"[0-9a-fA-F]{64}", entry):
        return entry.lower() == certificate["fingerprint"]
    try:
        if bytes.fromhex(entry) == certificate["der"]:
            return True
    except ValueError:
        pass
    try:
        return urlsafe_b64decode(entry + "=" * (-len(entry) % 4)) == certificate["der"]
    except Exception:
        return False


def parse_token(token: bytes) -> dict:
    """The parts of a timestamp token this verifier judges, or a refusal naming what it could not read."""
    tag, body, end = read(token)
    if tag != SEQUENCE or end != len(token):
        raise TokenError("a token must be one DER SEQUENCE")

    outer = children(body)
    content_type = object_identifier(expect(outer, 0, OBJECT_IDENTIFIER, "content type"))
    if content_type != OID_SIGNED_DATA:
        raise TokenError("the token's content type is %s, not signedData" % content_type)

    wrapper = children(expect(outer, 1, CONTEXT_0, "signed data"))
    signed = children(expect(wrapper, 0, SEQUENCE, "signed data"))

    # version, digestAlgorithms, encapContentInfo, [0] certificates (optional), signerInfos.
    encapsulated = children(expect(signed, 2, SEQUENCE, "encapsulated content"))
    if object_identifier(expect(encapsulated, 0, OBJECT_IDENTIFIER, "content type")) != OID_TST_INFO:
        raise TokenError("the token does not encapsulate a TSTInfo")

    inside = children(expect(encapsulated, 1, CONTEXT_0, "encapsulated content"))
    content = expect(inside, 0, OCTET_STRING, "TSTInfo")

    position = 3
    certificates = []
    if position < len(signed) and signed[position][0] == CONTEXT_0:
        # `[0] IMPLICIT SET OF Certificate`: the element's own bytes are what a fingerprint hashes.
        certificates = [
            read_certificate(full) for _, _, full in elements(signed[position][1])
        ]
        position += 1
    if not certificates:
        raise TokenError("the token carries no certificate to check its signature against")

    signers = children(expect(signed, position, SET, "signer infos"))
    if len(signers) != 1:
        raise TokenError("the token has %d signers, and this reader reads one" % len(signers))

    return {**parse_signer(signers[0][1], certificates), "content": content}


def parse_tst_info(content: bytes) -> dict:
    """The `TSTInfo`: what was stamped, when, under which policy."""
    info = children(expect(children(content), 0, SEQUENCE, "TSTInfo"))
    # version, policy, messageImprint, serialNumber, genTime - and genTime is found by its tag rather than
    # by position, because a token may carry optional fields this reader has no business interpreting.
    policy = object_identifier(expect(info, 1, OBJECT_IDENTIFIER, "policy"))

    imprint = children(expect(info, 2, SEQUENCE, "message imprint"))
    imprint_algorithm = object_identifier(
        expect(children(expect(imprint, 0, SEQUENCE, "imprint algorithm")), 0, OBJECT_IDENTIFIER, "imprint")
    )

    gen_time = None
    for tag, value in info:
        if tag in (UTC_TIME, GENERALIZED_TIME):
            gen_time = time_value(tag, value)
    if gen_time is None:
        raise TokenError("the TSTInfo carries no genTime")

    return {
        "policy": policy,
        "imprint_algorithm": imprint_algorithm,
        "imprint": expect(imprint, 1, OCTET_STRING, "imprint"),
        "gen_time": gen_time,
    }


def verify_token(token: bytes, claim_hash: str, pinned: list) -> tuple[str, str]:
    """Judge a token: `(outcome, detail)`, with the outcome one of `verified`, `invalid`, `untrusted_signer`
    or `unreadable`.

    The order is the reference implementation's, and it is the interesting part of this function. **Trust
    comes first**: a token signed by somebody nobody pinned is `not_checked` whatever else is wrong with it,
    because "this token is broken" and "this token is not yours to judge" are different sentences. Then the
    rules - the extended key usage, the validity window, the two CMS bindings, the imprint, the signature -
    each naming itself when it fails, because section 8.3 promises a `fail` *with the rule named*.
    """
    try:
        parsed = {**parse_token(token)}
        parsed.update(parse_tst_info(parsed["content"]))
    except (DerError, CertificateError, TokenError) as error:
        # A token this reader cannot read is this reader's limit, not a fault in the receipt.
        return ("unreadable", str(error))

    signer = parsed["signer"]
    if not any(matches_pin(entry, signer) for entry in pinned):
        return (
            "untrusted_signer",
            "the token is signed by %s, and no pinned certificate has that fingerprint" % signer["fingerprint"],
        )

    # The pinning says "believe these bytes"; RFC 3161 still says what those bytes must be for.
    if OID_TIME_STAMPING not in signer["extended_key_usage"]:
        return ("invalid", "the pinned certificate has no timeStamping extended key usage")
    if not signer["key_usage_permits_signing"]:
        return ("invalid", "the pinned certificate's key usage does not permit signing")

    # Taken before the signature, because it is a fact about the certificate rather than about the token.
    if not signer["not_before"] <= parsed["gen_time"] <= signer["not_after"]:
        return (
            "invalid",
            "genTime %s falls outside the signing certificate's validity (%s to %s)"
            % (parsed["gen_time"], signer["not_before"], signer["not_after"]),
        )

    hash_name = SIGNATURE_ALGORITHMS.get(parsed["signature_algorithm"])
    if hash_name is None:
        return ("unreadable", "signature algorithm %s is not implemented here" % parsed["signature_algorithm"])
    if parsed["digest_algorithm"] != OID_DIGEST_SHA256:
        return ("unreadable", "digest algorithm %s is not implemented here" % parsed["digest_algorithm"])

    # The two CMS bindings, without which a signature over the attributes describes nothing.
    if parsed["content_type"] != OID_TST_INFO:
        return (
            "invalid",
            "the signed attributes name %s rather than a TSTInfo" % (parsed["content_type"] or "nothing"),
        )
    content_digest = hashlib.sha256(parsed["content"]).hexdigest()
    if parsed["message_digest"] != content_digest:
        return (
            "invalid",
            "the signed attributes carry %s and the content hashes to %s"
            % (parsed["message_digest"] or "nothing", content_digest),
        )

    if parsed["imprint_algorithm"] != OID_DIGEST_SHA256:
        return ("unreadable", "imprint algorithm %s is not implemented here" % parsed["imprint_algorithm"])
    if parsed["imprint"].hex() != claim_hash:
        return (
            "invalid",
            "the token's messageImprint is %s and the claim hash is %s"
            % (parsed["imprint"].hex(), claim_hash),
        )

    if not rsa_verify(signer["public_key"], parsed["signed_bytes"], parsed["signature"], hash_name):
        return ("invalid", "the token's signature does not verify over its signed attributes")

    return (
        "verified",
        "attested %s, within the validity of %s, under policy %s"
        % (parsed["gen_time"], signer["fingerprint"], parsed["policy"]),
    )


def parse_signer(signer_info: bytes, certificates: list[dict]) -> dict:
    """The one `SignerInfo` a token should have: who signed, over what bytes, with which algorithms."""
    info = elements(signer_info)
    # version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature.
    sid = children(expect([(tag, value) for tag, value, _ in info], 1, SEQUENCE, "signer identifier"))
    serial = integer(expect(sid, 1, INTEGER, "signer serial number"))
    signer = next((certificate for certificate in certificates if certificate["serial"] == serial), None)
    if signer is None:
        raise TokenError("the token's signer names serial %d, and no certificate it carries has it" % serial)

    if info[3][0] != CONTEXT_0:
        raise TokenError("the token's signer carries no signed attributes, which a token requires")
    signed_attrs_value = info[3][1]
    signed_attrs_full = info[3][2]

    digest_algorithm = object_identifier(
        expect(children(expect([(tag, value) for tag, value, _ in info], 2, SEQUENCE, "digest algorithm")),
               0, OBJECT_IDENTIFIER, "digest")
    )
    signature_algorithm = object_identifier(
        expect(children(expect([(tag, value) for tag, value, _ in info], 4, SEQUENCE, "signature algorithm")),
               0, OBJECT_IDENTIFIER, "algorithm")
    )
    signature = expect([(tag, value) for tag, value, _ in info], 5, OCTET_STRING, "signature")

    attributes: dict[str, list[bytes]] = {}
    for _, attribute in children(signed_attrs_value):
        parts = children(attribute)
        oid = object_identifier(expect(parts, 0, OBJECT_IDENTIFIER, "attribute identifier"))
        attributes[oid] = [value for _, value in children(expect(parts, 1, SET, "attribute values"))]

    content_type = attributes.get(OID_ATTR_CONTENT_TYPE)
    message_digest = attributes.get(OID_ATTR_MESSAGE_DIGEST)

    return {
        "signer": signer,
        "digest_algorithm": digest_algorithm,
        "signature_algorithm": signature_algorithm,
        "signature": signature,
        # What is signed is the attributes **re-tagged** as a `SET OF`: the same bytes after the tag that
        # identifies them, length octets included. This is the one CMS detail that catches every first
        # implementation, and getting it wrong is how this reader refused a perfectly good token: taking the
        # `[0]` element's *value* drops the length octets, so the re-tagged bytes come out shorter.
        "signed_bytes": bytes([SET]) + signed_attrs_full[1:],
        "content_type": object_identifier(content_type[0]) if content_type else None,
        "message_digest": message_digest[0].hex() if message_digest else None,
    }
