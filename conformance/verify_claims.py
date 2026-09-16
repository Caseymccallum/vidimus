#!/usr/bin/env python3
"""A second implementation of the claim-hash derivation, in Python.

The conformance vectors record, for every fixture, the SHA-256 of the claim's *signed subtree* - the
`claim_hash`. That value is the foundation of the format: a signature commits to it, an RFC 3161 token
commits to it, and an index is searched by it. It is also derived entirely by `canonical-json-v1`, which is
the part of this specification most likely to differ between two languages, for reasons the specification
itself names: keys sort by UTF-16 code unit, integers have a range, strings have an escaping rule.

So this is the first slice of a second implementation, and it deliberately covers one layer completely
rather than all of them partially:

  * read each fixture from the conformance kit (`node reference/src/vectors.mjs --emit <dir>`);
  * check the fixture against the digest the kit records for it;
  * read `receipt.json` out of the container, as the bytes that were delivered;
  * re-derive the canonical form of the signed subtree, and the claim hash from it;
  * compare both with what the kit says, and report every disagreement.

It implements **no cryptography at all**, which is not a compromise: the signature is excluded from the
signed subtree, so deriving the claim hash needs no key and no library. Ed25519, the container's own
resource hashes and the rest of the check table are the next slice, and until they exist this file must not
be called a conforming implementation. `conformance/README.md` says the same thing.

Written from the specification (`docs/RECEIPT-SPEC.md` sections 5, 5.1, 5.2 and 6.1), not from
`reference/src/canonical.mjs`. Where the two disagree, the disagreement is the finding - and the findings
are recorded in `conformance/README.md` rather than quietly worked around.

    python conformance/verify_claims.py <kit-directory>
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from base64 import urlsafe_b64decode
from pathlib import Path

import ed25519

# Section 6.4: the message a signature covers, looked up by major version rather than built from a constant,
# because this string is inside every signature ever produced (D-013, D-015).
SIGNING_PREFIXES = {0: "vidimus/claim/"}

# Section 5, rule 5: an integer outside this range has no single safe spelling in the languages this format
# is meant to be read in, so it is refused rather than rounded.
MAX_SAFE_INTEGER = 2**53 - 1

# Section 5, rule 4: the five controls with short forms. Everything else below U+0020 is escaped as \u00XX.
SHORT_ESCAPES = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class NotCanonical(Exception):
    """The value has no `canonical-json-v1` spelling. The message says which rule refused it."""


def utf16_code_units(text: str) -> list[int]:
    """The UTF-16 code units of a string.

    Section 5, rule 2 sorts keys by these, which is *not* the same as sorting by code point. A character
    above the BMP becomes a surrogate pair whose first unit is in D800-DBFF, so it sorts *before* a
    character in E000-FFFF - the opposite of code-point order. Python compares lists element-wise, so a
    list of units is a key that sorts by exactly this rule.
    """
    units: list[int] = []
    for character in text:
        point = ord(character)
        if point >= 0x10000:
            point -= 0x10000
            units.append(0xD800 + (point >> 10))
            units.append(0xDC00 + (point & 0x3FF))
        else:
            units.append(point)
    return units


def quote(text: str) -> str:
    """A string, in canonical form. Section 5, rule 4."""
    pieces = ['"']
    for character in text:
        if character == '"':
            pieces.append('\\"')
        elif character == "\\":
            pieces.append("\\\\")
        elif character in SHORT_ESCAPES:
            pieces.append(SHORT_ESCAPES[character])
        elif ord(character) < 0x20:
            pieces.append("\\u%04x" % ord(character))
        elif 0xD800 <= ord(character) <= 0xDFFF:
            # Rule 7: an unpaired surrogate has no UTF-8 encoding two implementations will agree on. A
            # *paired* one cannot appear here, because Python strings hold code points, not pairs.
            raise NotCanonical(
                "unpaired surrogate U+%04X in a string: it has no UTF-8 encoding" % ord(character)
            )
        else:
            # Everything else is itself, including non-ASCII and DEL. Rule 4 escapes only `"`, `\\` and C0.
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def number(value: int | float, where: str) -> str:
    """An integer, in canonical form. Section 5, rule 5."""
    if isinstance(value, bool):
        # `bool` is an `int` in Python, and `true` is not `1` in JSON. Rule 6 refuses values with no JSON
        # representation; a boolean is one and is handled by the caller, so reaching here is a bug.
        raise NotCanonical(f"a boolean reached the number path at {where}")
    if isinstance(value, float):
        raise NotCanonical(
            "non-integer number: canonical-json-v1 admits integers only (at %s)" % where
        )
    if abs(value) > MAX_SAFE_INTEGER:
        raise NotCanonical(
            "integer outside [-(2^53-1), 2^53-1]: it has no spelling two languages agree on (at %s)" % where
        )
    return str(value)


def canonicalise(value, where: str = "", depth: int = 0) -> str:
    """`canonical-json-v1`, for a value Python's `json` produces.

    `where` is the path the error message names, in the form section 5.1 shows: `.subject.document.bytes`.
    """
    if depth > 64:
        # A SHOULD in the specification; a refusal rather than a stack overflow, which is the point of it.
        raise NotCanonical("nested deeper than 64 levels, which this implementation refuses")

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return number(value, where or "the value")
    if isinstance(value, str):
        return quote(value)
    if isinstance(value, list):
        items = (
            canonicalise(item, "%s[%d]" % (where, index), depth + 1)
            for index, item in enumerate(value)
        )
        return "[" + ",".join(items) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=utf16_code_units)
        members = (
            "%s:%s" % (quote(key), canonicalise(value[key], "%s.%s" % (where, key), depth + 1))
            for key in keys
        )
        return "{" + ",".join(members) + "}"

    # Rule 6. Python's `json` cannot produce any of these, so this is a guard rather than a branch.
    raise NotCanonical("no JSON representation for %s" % type(value).__name__)


def signed_subtree(manifest: dict) -> dict:
    """The part of a claim a signature covers (section 6.1).

    Everything except `signature`, and except an `anchor` whose type is `rfc3161`. An anchor that could have
    existed when the claim was signed *is* signed; one that could not be is not. That is the whole rule, and
    the subtle half of it: the anchor's `type` is signed even when its token is not.
    """
    signed = {key: value for key, value in manifest.items() if key != "signature"}
    anchor = signed.get("anchor")
    if isinstance(anchor, dict) and anchor.get("type") == "rfc3161":
        del signed["anchor"]
    return signed


def claim_hash(manifest: dict) -> str:
    """Section 6.2: SHA-256 of the canonical form of the signed subtree, as UTF-8."""
    canonical = canonicalise(signed_subtree(manifest))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def receipt_json_bytes(fixture: Path) -> bytes:
    """The bytes of `receipt.json`, exactly as delivered.

    Deliberately not decoded here: section 5.2 compares the *bytes* a verifier received against the
    canonical form of the value it parsed, and a comparison of two decoded strings would miss the very
    things that rule exists to catch.
    """
    with zipfile.ZipFile(fixture) as archive:
        return archive.read("receipt.json")


def parse_manifest(raw: bytes) -> dict:
    """Parse the claim, refusing the extensions Python's `json` would otherwise accept."""
    text = raw.decode("utf-8")

    def refuse(constant: str):
        raise NotCanonical("`%s` is not a JSON value, and is not canonical here" % constant)

    return json.loads(text, parse_constant=refuse)


def from_base64url(value: str) -> bytes:
    """The bytes of a base64url field, without padding, as the claim carries them."""
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


# Section 7.4's signature checks, in the order a verdict lists them.
SIGNATURE_CHECKS = ("signature.present", "signature.alg", "signature.key_id", "signature.verify")


def signature_statuses(manifest: dict, derived_hash: str) -> dict:
    """The signature checks, as this implementation sees them (sections 6.3 and 7.4).

    Every check in the family comes back, including the ones a stopped stage never reached - section 7.2: a
    verdict contains every check, and one that never ran is `not_checked`, never a pass. Filling those in is
    not decoration: a comparison that only produced the statuses it happened to reach would report agreement
    on a vector where three recorded statuses were never looked at.
    """
    signature = manifest.get("signature")

    # A claim with no signature is not a failure: everything in the family is `not_applicable`, exactly as
    # the reference reports it.
    if signature is None:
        return dict.fromkeys(SIGNATURE_CHECKS, "not_applicable")

    def stopped(statuses: dict) -> dict:
        """This stage stopped: everything it did not reach is `not_checked`."""
        return {**dict.fromkeys(SIGNATURE_CHECKS, "not_checked"), **statuses}

    # `signature.present` is about the signature carrying the fields the format requires, not merely being an
    # object. Getting that wrong is what this implementation did first, and the kit caught it.
    required = ("alg", "key_id", "public_key", "sig")
    if not isinstance(signature, dict) or not all(
        isinstance(signature.get(field), str) for field in required
    ):
        return stopped({"signature.present": "fail"})

    statuses = {"signature.present": "pass"}

    if signature["alg"] != "ed25519":
        return stopped({**statuses, "signature.alg": "unsupported"})
    statuses["signature.alg"] = "pass"

    public_key = from_base64url(signature["public_key"])
    if hashlib.sha256(public_key).hexdigest() != signature["key_id"]:
        # A key id is derived, never asserted: one that does not match its own public key is a failure, not a
        # reason to check the signature against the key it names.
        return stopped({**statuses, "signature.key_id": "fail"})
    statuses["signature.key_id"] = "pass"

    prefix = SIGNING_PREFIXES.get(int(manifest["spec_version"].split(".")[0]))
    if prefix is None:
        return stopped({**statuses, "signature.verify": "not_checked"})

    message = ("%s%s:%s" % (prefix, manifest["spec_version"], derived_hash)).encode("ascii")
    verified = ed25519.verify(public_key, message, from_base64url(signature["sig"]))
    return {**statuses, "signature.verify": "pass" if verified else "fail"}


def refuses_minus_zero(raw: bytes) -> bool:
    """Whether the delivered bytes contain a `-0` number.

    Rule 5 refuses `-0`, and a parser that maps `-0` and `0` to the same value cannot see it *after* parsing.
    JavaScript does not: `JSON.parse('-0')` keeps the sign, and the reference implementation refuses it there.
    Python's `json` hands out `0`, so this implementation enforces the rule on the raw bytes instead - a scan
    that tracks string state, so that the two characters `-0` inside a string are not mistaken for a number.

    That difference between two standard libraries is the sort of thing a second implementation exists to
    find, and `conformance/README.md` records it.
    """
    text = raw.decode("utf-8", errors="replace")
    in_string = False
    escaped = False

    for index, character in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            in_string = True
            continue

        if character == "-" and text[index + 1:index + 2] == "0":
            following = text[index + 2:index + 3]
            # `-0.5` and `-0e3` are floats, which rule 5 refuses for a different reason. This check is about
            # the integer `-0` alone.
            if following == "" or following not in "0123456789.eE":
                return True

    return False


def check_vector(kit: Path, vector: dict) -> tuple[list[str], str]:
    """What this implementation can say about one vector: (disagreements, outcome).

    The outcome is one of `agreed` (derived the same claim hash as the record), `refused` (this claim has no
    canonical form, and the record says the same), or `skipped` (the fixture is not a container, holds no
    claim, or the claim stops at a gate before anything is derived - all of which the record also says).
    `skipped` is *not* a pass: it is named and listed, because "no disagreement" must never be mistakable for
    "checked".

    The stage order is the first thing a second implementation has to learn. `docs/RECEIPT-SPEC.md` section 7
    states the *principle* - a claim is checked before anything that depends on a key, a third party or a
    network - and the kit records where the reference verifier stopped: a claim that does not parse, or that
    declares a specification version this implementation does not read, never reaches the canonical form at
    all, and the record says so (`manifest.parseable: fail`, `manifest.canonical: not_checked`).
    """
    fixture = kit / "fixtures" / vector["fixture"]["file"]
    checks = vector["verdict"]["checks"]

    # The recorded answers. A check that is *absent* from the record passed - the convention the kit's own
    # README states, so that prose and green ticks do not travel with it.
    expected_hash = vector["verdict"]["claim_hash"]

    raw_fixture = fixture.read_bytes()
    actual_digest = hashlib.sha256(raw_fixture).hexdigest()
    if actual_digest != vector["fixture"]["sha256"]:
        return (
            ["the fixture hashes to %s and the kit says %s" % (actual_digest, vector["fixture"]["sha256"])],
            "agreed",
        )

    try:
        delivered = receipt_json_bytes(fixture)
    except (zipfile.BadZipFile, KeyError) as error:
        if not isinstance(error, KeyError) and checks.get("container.readable", "pass") != "fail":
            return (["this fixture is not a container, and the kit records no container.readable failure"], "skipped")
        return ([], "skipped")

    try:
        manifest = parse_manifest(delivered)
    except (NotCanonical, UnicodeDecodeError, json.JSONDecodeError) as error:
        if checks.get("manifest.parseable", "pass") == "fail":
            return ([], "skipped")
        return (["the claim could not be parsed: %s" % error], "skipped")

    if not isinstance(manifest, dict):
        return (["the claim is not a JSON object, and the kit records no failure for that"], "skipped")

    # Gate one: the specification version. A major this implementation does not read stops here, which is why
    # the record for that vector has no claim hash and `manifest.canonical: not_checked`.
    version = manifest.get("spec_version")
    if not isinstance(version, str) or not re.match(r"^\d+\.\d+\.\d+$", version):
        if checks.get("manifest.spec_version", "pass") == "fail":
            return ([], "skipped")
        return (["spec_version is missing or not a semantic version, and the kit records no failure"], "skipped")
    if version.split(".")[0] != "0":
        if checks.get("manifest.spec_version", "pass") == "fail":
            return ([], "skipped")
        return (["this implementation reads 0.x and the claim is %s" % version], "skipped")

    # Gate two: the canonical form, and the claim hash derived from it. `-0` is checked on the raw bytes,
    # because parsing has already lost it (see `refuses_minus_zero`).
    if refuses_minus_zero(delivered):
        if expected_hash is not None:
            return (["this claim contains `-0`, and the kit records a claim hash"], "refused")
        if checks.get("manifest.canonical", "pass") != "fail":
            return (["this claim contains `-0`, and the kit records no failure"], "refused")
        return ([], "refused")

    try:
        derived = claim_hash(manifest)
    except NotCanonical as error:
        if expected_hash is not None:
            return (["this claim has no canonical form (%s), and the kit records a claim hash" % error], "refused")
        if checks.get("manifest.canonical", "pass") != "fail":
            return (["this claim has no canonical form (%s), and the kit records no failure" % error], "refused")
        # Refused, and the record agrees that it should be. That is a corroboration, not a pass by silence.
        return ([], "refused")

    problems: list[str] = []
    if expected_hash is None:
        problems.append("the kit records no claim hash, and this claim canonicalises fine")
    elif derived != expected_hash:
        problems.append("claim hash: derived %s, kit says %s" % (derived, expected_hash))

    # The signature, whose message is the claim hash this implementation just derived - which is what makes
    # this an Ed25519 check rather than a library call with a known-good input.
    for check_id, status in signature_statuses(manifest, derived).items():
        recorded = checks.get(check_id, "pass")
        if status != recorded:
            problems.append(
                "%s: this implementation says %s, and the kit says %s" % (check_id, status, recorded)
            )

    expected_canonical = checks.get("manifest.canonical", "pass")
    try:
        whole = canonicalise(manifest).encode("utf-8")
    except NotCanonical as error:
        if expected_canonical != "fail":
            problems.append("this claim cannot be canonicalised (%s), and the kit records no failure" % error)
    else:
        actual_canonical = "pass" if whole == delivered else "fail"
        if actual_canonical != expected_canonical:
            problems.append(
                "manifest.canonical: this implementation says %s, and the kit says %s"
                % (actual_canonical, expected_canonical)
            )

    return (problems, "agreed")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python conformance/verify_claims.py <kit-directory>", file=sys.stderr)
        return 2

    kit = Path(argv[1])
    record = json.loads((kit / "receipt-vectors.json").read_text(encoding="utf-8"))

    agreed = 0
    failures = 0
    refused = 0
    skipped: list[str] = []
    for vector in record["vectors"]:
        problems, outcome = check_vector(kit, vector)
        if problems:
            failures += 1
            print("%s:" % vector["id"])
            for problem in problems:
                print("  - %s" % problem)
        elif outcome == "refused":
            refused += 1
        elif outcome == "skipped":
            skipped.append(vector["id"])
        else:
            agreed += 1

    total = len(record["vectors"])
    print("\nclaim hashes: %d of %d fixtures agree" % (agreed, total))
    print("%d refused, and the record says the same (a corroborated refusal, not a pass by silence)" % refused)
    if skipped:
        print("%d not reached by this implementation, and named so that silence is not mistaken for a pass:" % len(skipped))
        for name in skipped:
            print("  - %s" % name)
    print("%d disagree" % failures)
    print(
        "specification %s, vectors recorded by verifier %s"
        % (record["spec_version"], record["verifier_version"])
    )
    print(
        "this implementation covers the canonical form, the claim hash and the signature family"
    )
    print("(6 of the 21 checks); see conformance/README.md")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
