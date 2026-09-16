#!/usr/bin/env python3
"""Enough DER to read a timestamp token, and no more.

Everything here is from X.690 as it is used by CMS, X.509 and RFC 3161: tags, definite lengths, the four
primitive types those structures actually contain (OID, INTEGER, OCTET STRING, BIT STRING) and the two time
spellings a certificate uses. The writer for the reference implementation's fixtures is `reference/src/der.mjs`;
this is a reader, written from the encoding rules rather than from that file.

Three things it refuses rather than guessing at, because a lenient reader of DER is how one parser ends up
disagreeing with another about the same bytes:

* **indefinite lengths** (`0x80`), which are BER rather than DER - a CMS structure may not use them;
* **a length that runs past the end of its parent**, which is how a truncated token would otherwise read as
  a shorter one;
* **trailing bytes** after a structure that is supposed to fill its element.

The tag is returned as a single integer: `0x30` for a SEQUENCE, `0xa0` for `[0]` constructed. That is enough
for CMS, whose context-specific tags never exceed 30 in these structures.
"""

from __future__ import annotations


class DerError(Exception):
    """Bytes this reader will not guess about."""


# The tags this reader meets, named.
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
SEQUENCE = 0x30
SET = 0x31
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18

# Context-specific, constructed: `[0]` through `[3]`, the only ones these structures use.
CONTEXT_0 = 0xA0
CONTEXT_1 = 0xA1
CONTEXT_2 = 0xA2
CONTEXT_3 = 0xA3


def read(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """One element: its tag, the bytes of its value, and where the next element starts."""
    if offset >= len(data):
        raise DerError("the structure ends where an element was expected")

    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise DerError("a multi-byte tag number is not used by any structure this reader reads")
    offset += 1

    if offset >= len(data):
        raise DerError("an element declares no length")
    first = data[offset]
    offset += 1
    if first == 0x80:
        raise DerError("an indefinite length is BER, not DER")
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count > 4:
            raise DerError("a length of more than four bytes is not a length this reader will believe")
        if offset + count > len(data):
            raise DerError("a length runs past the end of the structure")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count

    if offset + length > len(data):
        raise DerError("an element runs past the end of the structure")
    return tag, data[offset:offset + length], offset + length


def children(value: bytes) -> list[tuple[int, bytes]]:
    """The elements of a constructed value, in order, with no bytes left over."""
    elements = []
    offset = 0
    while offset < len(value):
        tag, element, offset = read(value, offset)
        elements.append((tag, element))
    return elements


def elements(value: bytes) -> list[tuple[int, bytes, bytes]]:
    """Each element of a constructed value as `(tag, value, the element's own bytes)`.

    The whole element is what a certificate fingerprint hashes and what a re-tagged `SET OF` needs, so a
    caller that only got the value back would have to re-encode it - and re-encoding DER is how two readers
    come to disagree about the same bytes.
    """
    found = []
    offset = 0
    while offset < len(value):
        tag, body, next_offset = read(value, offset)
        found.append((tag, body, value[offset:next_offset]))
        offset = next_offset
    return found


def expect(elements: list[tuple[int, bytes]], index: int, tag: int, what: str) -> bytes:
    """The value of the element at `index`, or a refusal naming which tag was wanted."""
    if index >= len(elements):
        raise DerError("the structure has no %s" % what)
    actual, value = elements[index]
    if actual != tag:
        raise DerError("expected %s (0x%02x) and found tag 0x%02x" % (what, tag, actual))
    return value


def object_identifier(value: bytes) -> str:
    """A dotted OID. The first byte carries the first two arcs, which is why the arithmetic is odd."""
    if not value:
        raise DerError("an object identifier with no bytes")
    first = value[0]
    arcs = [first // 40, first % 40]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(current)
            current = 0
    return ".".join(str(arc) for arc in arcs)


def integer(value: bytes) -> int:
    """A signed two's-complement integer, which is what DER INTEGERs are."""
    if not value:
        raise DerError("an integer with no bytes")
    return int.from_bytes(value, "big", signed=True)


def bit_string(value: bytes) -> tuple[int, bytes]:
    """A bit string as (unused bits, bytes)."""
    if not value:
        raise DerError("a bit string with no bytes")
    if value[0] > 7:
        raise DerError("a bit string claims %d unused bits" % value[0])
    return value[0], value[1:]


def time_value(tag: int, value: bytes) -> str:
    """A certificate or token time, normalised to the one form the claim admits: `YYYY-MM-DDTHH:MM:SSZ`.

    UTCTime carries two digits of year, with the window X.690 defines: 50 through 99 are 1950 to 1999, and
    00 through 49 are 2000 to 2049. Both spellings end in `Z` here, because a local time with an offset is a
    thing a receipt never admits and a token should not.
    """
    text = value.decode("ascii", "replace").strip()
    if not text.endswith("Z"):
        raise DerError('the time "%s" is not UTC' % text)
    digits = text[:-1]
    if tag == UTC_TIME:
        if len(digits) != 12 or not digits.isdigit():
            raise DerError('the UTCTime "%s" is not YYMMDDHHMMSSZ' % text)
        year = int(digits[:2])
        year += 1900 if year >= 50 else 2000
        rest = digits[2:]
    elif tag == GENERALIZED_TIME:
        if len(digits) < 14 or not digits[:14].isdigit():
            raise DerError('the GeneralizedTime "%s" is not YYYYMMDDHHMMSS[.f]Z' % text)
        year = int(digits[:4])
        rest = digits[4:14]
    else:
        raise DerError("tag 0x%02x is not a time" % tag)

    return "%04d-%s-%sT%s:%s:%sZ" % (
        year, rest[0:2], rest[2:4], rest[4:6], rest[6:8], rest[8:10],
    )
