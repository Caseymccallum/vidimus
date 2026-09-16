#!/usr/bin/env python3
"""Ed25519 verification, written from RFC 8032 and from nothing else.

The reference implementation uses `node:crypto` and WebCrypto, and this file exists so that the second
implementation does not: a signature scheme checked by the same library in two languages is one check, not
two. Python's standard library has no Ed25519 at all, so this is the RFC's own arithmetic - the field modulo
2^255-19, the twisted Edwards curve, point decompression, and the verification equation.

It verifies; it does not sign, and it has no key generation. The second implementation only ever checks.

Three details that a "works on my test vector" implementation usually gets wrong, and which are stated in
RFC 8032 rather than left to the reader:

* **`S` must be less than `L`.** The group order is ~2^252, and an `S` above it has a second, equivalent
  encoding - the malleability that turns one valid signature into two different byte strings.
* **The point must be on the curve, and must decode.** A `y` with no matching `x` is rejected, not guessed.
* **The sign bit is the lowest bit of `x`**, not the highest of `y` - section 5.1.2, and the one place where
  a vendored implementation written from memory tends to be subtly wrong.

Verified against `node:crypto` and against every signed fixture in the conformance kit; see
`conformance/README.md`.
"""

from __future__ import annotations

import hashlib

# The field, the group order, and the curve constant.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def inverse(value: int) -> int:
    """`value^-1 mod P`, by Fermat: P is prime, so `value^(P-2)` is the inverse."""
    return pow(value, P - 2, P)


D = -121665 * inverse(121666) % P

# sqrt(-1): 2 is a non-residue, so 2^((P-1)/4) is a square root of -1.
SQRT_M1 = pow(2, (P - 1) // 4, P)


def recover_x(y: int, sign: int) -> int | None:
    """The `x` that goes with a `y` on the curve, or None when there is none.

    `x^2 = (y^2 - 1) / (d*y^2 + 1)`; the candidate square root is raised to `(P+3)/8`, and multiplied by
    sqrt(-1) when that was not the root. RFC 8032 section 5.1.3.
    """
    xx = (y * y - 1) * inverse(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        return None
    # The encoding's sign bit is the low bit of x, so the recovered x is made to match it.
    if (x & 1) != sign:
        x = P - x
    return x


def is_on_curve(point) -> bool:
    """`-x^2 + y^2 = 1 + d*x^2*y^2`, in extended coordinates (`x = X/Z`, `y = Y/Z`)."""
    x, y, z, _ = point
    return (-x * x + y * y - z * z - D * x * x * y * y) % P == 0


def add(left, right):
    """Point addition on the twisted Edwards curve, in extended coordinates."""
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def multiply(point, scalar: int):
    """`scalar * point`, by double-and-add. Iterative, so a large scalar cannot exhaust the stack."""
    result = (0, 1, 1, 0)  # the neutral element
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        scalar >>= 1
    return result


def encode(point) -> bytes:
    """The 32-byte encoding: `y`, with `x`'s low bit in the top bit of the last byte."""
    x, y, z, _ = point
    z_inverted = inverse(z)
    x = x * z_inverted % P
    y = y * z_inverted % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode(encoded: bytes):
    """A curve point from its encoding, or None when the bytes are not one."""
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    # Section 5.1.3: a `y` of P or above is not a canonical encoding, so it is not a point.
    if y >= P:
        return None
    x = recover_x(y, sign)
    if x is None:
        return None
    point = (x, y, 1, x * y % P)
    return point if is_on_curve(point) else None


def base_point():
    """The generator: `y = 4/5`, with the even `x`."""
    y = 4 * inverse(5) % P
    x = recover_x(y, 0)
    return (x, y, 1, x * y % P)


BASE_POINT = base_point()


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` is a valid Ed25519 signature over `message` by `public_key`.

    The check is `[S]B = R + [k]A`, with `k = SHA-512(R || A || message) mod L` - and *not* the cofactored
    variant, which accepts a small class of signatures the RFC refuses. A receipt is checked against a
    library that uses the strict rule (`node:crypto`, WebCrypto), so the strict rule is what this implements.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False

    point_a = decode(public_key)
    point_r = decode(signature[:32])
    if point_a is None or point_r is None:
        return False

    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= L:
        # Not a canonical signature: the same value reduced modulo L would also verify, and two byte strings
        # that both verify is exactly the malleability the range check exists to prevent.
        return False

    digest = hashlib.sha512(signature[:32] + public_key + message).digest()
    challenge = int.from_bytes(digest, "little") % L

    return encode(multiply(BASE_POINT, scalar_s)) == encode(add(point_r, multiply(point_a, challenge)))
