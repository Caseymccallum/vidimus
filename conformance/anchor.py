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

# The anchor types 0.1 defines. A type outside this list is `unsupported`, never a failure: a receipt from a
# future minor version is not a broken receipt.
ANCHOR_TYPES = ("none", "chain", "rfc3161")


def anchor_statuses(manifest: dict) -> dict:
    """`anchor.present`, as this implementation sees it (sections 7.4, 8.1 and 8.3).

    Note the asymmetry section 8.1 requires, which looks like an inconsistency until you read the reason: an
    anchorless claim reports `anchor.present: not_applicable` and `anchor.verified: not_checked`. The first
    says "there is nothing here to have a type"; the second says "there was nothing to verify, and the receipt
    does not have a verified time" - which must not be reported as a pass or as a failure.
    """
    anchor = manifest.get("anchor")

    if not isinstance(anchor, dict) or not isinstance(anchor.get("type"), str):
        # `anchor` is a required field and its type must be one this implementation knows, so a claim without
        # one is a failure of this check rather than a gap in this implementation.
        return {"anchor.present": "fail"}

    if anchor["type"] == "none":
        return {"anchor.present": "not_applicable"}

    if anchor["type"] not in ANCHOR_TYPES:
        return {"anchor.present": "unsupported"}

    return {"anchor.present": "pass"}
