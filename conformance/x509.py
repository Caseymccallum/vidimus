#!/usr/bin/env python3
"""The four things this project needs from an X.509 certificate, and nothing else.

A timestamp token carries its signing certificate, and section 8.3 says what a verifier must do with it: pin
it (the caller's business), require the `timeStamping` extended key usage, require a key usage that permits
signing, and compare `genTime` with the validity window. That is four fields, so this is a four-field reader.

**It does not check the certificate's own signature, and that is deliberate rather than an omission.** Section
8.3 makes trust a *pin*: "a caller pins a certificate by supplying its DER or its SHA-256 fingerprint". A pin
is an anchor, not a chain - `docs/CONFORMANCE.md` says no chain building to a root, no revocation checking -
so a self-signed fixture certificate and a certificate from a real authority are treated the same way, which
is exactly what a pinned trust anchor means.
"""

from __future__ import annotations

import hashlib

from der import (
    BIT_STRING, CONTEXT_0, CONTEXT_3, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE,
    DerError, children, expect, integer, object_identifier, read, time_value,
)


class CertificateError(DerError):
    """A certificate this reader will not guess about."""


# The extensions section 8.3 and RFC 5280 name.
OID_EXTENDED_KEY_USAGE = "2.5.29.37"
OID_KEY_USAGE = "2.5.29.15"
OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"


def read_certificate(certificate: bytes) -> dict:
    """The fields this project reads, from the certificate's own DER.

    `certificate` is the complete element - the one whose bytes are hashed for a fingerprint, so that a pin
    supplied as a fingerprint compares against exactly what the token carried.
    """
    tag, body, end = read(certificate)
    if tag != SEQUENCE:
        raise CertificateError("a certificate must be a SEQUENCE")
    if end != len(certificate):
        raise CertificateError("a certificate has %d trailing bytes" % (len(certificate) - end))

    outer = children(body)
    if len(outer) < 3:
        raise CertificateError("a certificate needs a body, an algorithm and a signature")
    tbs = expect(outer, 0, SEQUENCE, "certificate body")

    fields = children(tbs)
    offset = 0
    if fields and fields[0][0] == CONTEXT_0:
        offset = 1  # `[0] EXPLICIT INTEGER` is the v3 version marker.
    serial = integer(expect(fields, offset + 0, INTEGER, "serial number"))
    validity = expect(fields, offset + 3, SEQUENCE, "validity")
    extensions = _extensions(fields, offset + 6)

    times = children(validity)
    if len(times) != 2:
        raise CertificateError("a validity window needs exactly two times")

    return {
        "der": certificate,
        "fingerprint": hashlib.sha256(certificate).hexdigest(),
        "serial": serial,
        "not_before": time_value(times[0][0], times[0][1]),
        "not_after": time_value(times[1][0], times[1][1]),
        "extended_key_usage": extensions["extended_key_usage"],
        "key_usage_permits_signing": extensions["key_usage_permits_signing"],
        "public_key": _public_key(fields, offset + 5),
    }


def _extensions(fields: list[tuple[int, bytes]], index: int) -> dict:
    """The two extensions this project reads, from the `[3] EXPLICIT` block when there is one."""
    result = {
        "extended_key_usage": [],
        # A certificate with no key usage extension is not restricted by it, which is what RFC 5280 says.
        "key_usage_permits_signing": True,
    }
    if index >= len(fields) or fields[index][0] != CONTEXT_3:
        return result

    sequence = children(expect(children(fields[index][1]), 0, SEQUENCE, "extension list"))
    for _, extension in sequence:
        parts = children(extension)
        oid = object_identifier(expect(parts, 0, OBJECT_IDENTIFIER, "extension identifier"))
        value = expect(parts, len(parts) - 1, OCTET_STRING, "extension value")

        if oid == OID_EXTENDED_KEY_USAGE:
            inner = children(expect(children(value), 0, SEQUENCE, "extended key usage"))
            result["extended_key_usage"] = [
                object_identifier(expect(inner, position, OBJECT_IDENTIFIER, "key purpose"))
                for position in range(len(inner))
            ]
        elif oid == OID_KEY_USAGE:
            # The extension value is the DER of a BIT STRING; bit 0 is the high bit of its first byte:
            # `digitalSignature`.
            unused, bits = _bit_string_element(value)
            result["key_usage_permits_signing"] = bool(bits) and bool(bits[0] & 0x80)

    return result


def _bit_string_element(value: bytes) -> tuple[int, bytes]:
    """A BIT STRING that is still DER-encoded inside an extension value."""
    tag, body, _ = read(value)
    if tag != BIT_STRING:
        raise CertificateError("an extension that must hold a BIT STRING holds tag 0x%02x" % tag)
    return body[0], body[1:]


def _public_key(fields: list[tuple[int, bytes]], index: int) -> tuple[int, int]:
    """An RSA public key as `(n, e)`. Anything else is refused by name, not guessed at."""
    spki = children(expect(fields, index, SEQUENCE, "subject public key info"))
    algorithm = object_identifier(expect(children(expect(spki, 0, SEQUENCE, "key algorithm")), 0,
                                      OBJECT_IDENTIFIER, "key algorithm identifier"))
    if algorithm != "1.2.840.113549.1.1.1":
        raise CertificateError("the signing key is %s, and this reader implements RSA only" % algorithm)

    # `spki[1]` is a BIT STRING, so what comes back is already its content: one unused-bits byte and then
    # the key. Reading it as DER again is the mistake that made this function refuse a perfectly good token.
    bits = expect(spki, 1, BIT_STRING, "public key")
    parts = children(expect(children(bits[1:]), 0, SEQUENCE, "RSA public key"))
    return integer(expect(parts, 0, INTEGER, "modulus")), integer(expect(parts, 1, INTEGER, "exponent"))
