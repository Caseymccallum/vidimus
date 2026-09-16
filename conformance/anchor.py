#!/usr/bin/env python3
"""Section 8's time anchors, as far as a claim alone can decide them.

An anchor is evidence, produced by something other than the author, that the claim hash existed at some time.
Three types are defined in 0.1 (section 8): `none`, `chain` and `rfc3161`. This module decides **one** of the
two anchor checks - `anchor.present` - because that one is decidable from the claim's own bytes, and the
specification states it completely:

    none        not_applicable   section 8.1: an admission, not a defect
    chain       pass             section 8.2
    rfc3161     pass             section 8.3
    anything    unsupported      the type is not one this implementation knows

`anchor.verified` is **not here**, and the omission is deliberate rather than pending: it is the check that
needs a CMS `SignedData`, an X.509 certificate, a signature algorithm and a certificate the caller pins
(section 8.3), and a half-implementation that answered "yes" too early is exactly what section 8.3 was
written to prevent. `conformance/README.md` names it as the largest remaining slice.
"""

from __future__ import annotations

import re

import rfc3161

# The anchor types 0.1 defines. A type outside this list is `unsupported`, never a failure: a receipt from a
# future minor version is not a broken receipt.
ANCHOR_TYPES = ("none", "chain", "rfc3161")

# A chain link names a claim hash, which is a lowercase hex SHA-256 and nothing else.
CLAIM_HASH = re.compile(r"^[0-9a-f]{64}$")


def anchor_statuses(
    manifest: dict,
    options: dict | None = None,
    claim_hash: str | None = None,
    signature_verified: str | None = None,
) -> dict:
    """Both anchor checks, as this implementation sees them (sections 7.4, 8.1, 8.2 and 8.3).

    Note the asymmetry section 8.1 requires, which looks like an inconsistency until the reason is read: an
    anchorless claim reports `anchor.present: not_applicable` and `anchor.verified: not_checked`. The first
    says "there is nothing here to have a type"; the second says "there was nothing to verify, and the receipt
    does not have a verified time".

    `signature_verified` is the status of `signature.verify`, and it matters: a chain anchor is a statement
    the author makes *at signing time*, so a broken signature cannot leave an anchor pass standing (D-012).
    `claim_hash` is what an RFC 3161 token's imprint is compared against.
    """
    options = options or {}
    anchor = manifest.get("anchor")

    if anchor is None or (isinstance(anchor, dict) and anchor.get("type") == "none"):
        return {"anchor.present": "not_applicable", "anchor.verified": "not_checked"}

    if not isinstance(anchor, dict) or not isinstance(anchor.get("type"), str):
        # An anchor whose type is missing, null or not a string is a type this verifier does not know.
        return {"anchor.present": "unsupported", "anchor.verified": "unsupported"}

    kind = anchor["type"]

    if kind == "chain":
        return {"anchor.present": "pass", "anchor.verified": _verify_chain(anchor, options, signature_verified)}

    if kind == "rfc3161":
        return {"anchor.present": "pass", "anchor.verified": _verify_token(anchor, options, claim_hash)}

    return {"anchor.present": "unsupported", "anchor.verified": "unsupported"}


def _verify_chain(anchor: dict, options: dict, signature_verified: str | None) -> str:
    """Section 8.2, in the order the specification lists it."""
    if signature_verified != "pass":
        return "not_checked"

    sequence = anchor.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        return "fail"

    if sequence == 1:
        # A head that names a predecessor is not a head: "sequence 1" and "this follows something" are
        # statements that cannot both be true.
        return "fail" if anchor.get("prev_claim_hash") is not None else "pass"

    previous = anchor.get("prev_claim_hash")
    if not isinstance(previous, str) or CLAIM_HASH.match(previous) is None:
        return "fail"
    if not isinstance(options.get("previousClaimHash"), str):
        # The neighbour is the caller's to supply, and without it there is nothing to compare against.
        return "not_checked"

    return "pass" if previous == options["previousClaimHash"] else "fail"


def _verify_token(anchor: dict, options: dict, claim_hash: str | None) -> str:
    """Section 8.3, with the four outcomes mapped to the statuses a verdict carries."""
    pinned = options.get("trustedTsa")
    pinned = pinned if isinstance(pinned, list) else []
    if not pinned:
        # The token is present and well formed for all this verifier knows; what is missing is a trust
        # anchor, which is the caller's to supply. A gap in the caller is not a fault in the receipt.
        return "unsupported"

    if claim_hash is None:
        # Nothing to compare the imprint with, because the claim hash could not be derived.
        return "not_checked"

    try:
        token = rfc3161.decode_token(anchor.get("token"))
    except rfc3161.TokenError:
        return "unsupported"

    outcome, _ = rfc3161.verify_token(token, claim_hash, pinned)
    return {
        "verified": "pass",
        "invalid": "fail",
        # A signer nobody pinned is not a fault in the receipt and not a pass: this verifier simply has no
        # reason to believe a certificate the caller never named.
        "untrusted_signer": "not_checked",
    }.get(outcome, "unsupported")
