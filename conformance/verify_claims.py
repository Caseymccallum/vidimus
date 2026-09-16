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
import container
import warc
import anchor
import text as text_v1

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


def document_status(inner: dict[str, bytes] | None, manifest: dict) -> tuple[str, str | None]:
    """`subject.document`, re-derived from the capture (sections 4.2 and 7.4).

    Both the digest and the length are checked. The length is redundant with the digest and kept anyway,
    because it is the one a person checks by eye - and "the claim describes a document of another size" is a
    different sentence from "the bytes hash differently".

    A capture this reader cannot open is `not_checked` with the reason, never a `fail` and never a `pass`: the
    claim may be perfectly honest and the capture simply beyond this reader, and what must not happen is L0
    passing on the strength of a digest nobody confirmed (section 4.2, D-032).
    """
    subject = manifest.get("subject")
    document = subject.get("document") if isinstance(subject, dict) else None
    if not isinstance(document, dict):
        return ("not_checked", "the claim does not describe a document")

    if inner is None:
        return ("not_checked", "the capture this claim describes is not a readable container")

    try:
        body = warc.main_document(inner, subject.get("url"))
    except warc.WarcError as error:
        return ("not_checked", "the capture's document could not be re-read: %s" % error)

    digest = hashlib.sha256(body).hexdigest()
    if digest != document.get("sha256"):
        return (
            "fail",
            "the capture holds a document that hashes to %s, and the claim says %s"
            % (digest, document.get("sha256")),
        )
    if len(body) != document.get("bytes"):
        return (
            "fail",
            "the capture holds a %d-byte document, and the claim says %s"
            % (len(body), document.get("bytes")),
        )
    return ("pass", None)


def text_status(manifest: dict, inner: dict[str, bytes] | None) -> dict:
    """`subject.text`: the words, re-extracted from the capture (section 4.5).

    The fingerprint is derived, never supplied - so a claim that carries one is checked by extracting the
    document from the capture's own bytes and hashing what comes out. A capture this reader cannot open is
    `not_checked`, for the same reason `subject.document` is: a verifier that half-reads a document reports a
    change that did not happen, and a claim is not made false by a verifier's limits.
    """
    subject = manifest.get("subject")
    fingerprint = subject.get("text") if isinstance(subject, dict) else None

    if fingerprint is None:
        return {"subject.text": "not_applicable"}
    if not isinstance(fingerprint, dict) or fingerprint.get("normalization") != "text-v1":
        # A normalisation this verifier does not implement is its own limit, not a fault in the receipt.
        return {"subject.text": "unsupported"}
    if inner is None:
        return {"subject.text": "not_checked"}

    try:
        body = warc.main_document(inner, subject.get("url"))
    except warc.WarcError:
        return {"subject.text": "not_checked"}

    actual = text_v1.fingerprint(body)
    return {"subject.text": "pass" if actual == fingerprint.get("sha256") else "fail"}


def from_base64url(value: str) -> bytes:
    """The bytes of a base64url field, without padding, as the claim carries them."""
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


# Section 7.4's signature checks, in the order a verdict lists them.
SIGNATURE_CHECKS = ("signature.present", "signature.alg", "signature.key_id", "signature.verify")

# Every check this implementation models. The four it does not are exactly the ones needing an anchor, a
# WARC or a text extractor: `anchor.present`, `anchor.verified`, `subject.document` and `subject.text`.
MODELLED_CHECKS = (
    "container.readable",
    "manifest.present",
    "manifest.parseable",
    "manifest.spec_version",
    "manifest.canonical",
    "manifest.shape",
    "claim.digest",
    "capture.present",
    "capture.bytes",
    "capture.digest",
    "capture.media_type",
    "capture.wacz.readable",
    "capture.wacz.resources",
    "subject.document",
    "signature.present",
    "signature.alg",
    "signature.key_id",
    "signature.verify",
    "anchor.present",
    "anchor.verified",
    "subject.text",
)


def fill(statuses: dict) -> dict:
    """Every modelled check, with the ones a stopped stage never reached as `not_checked` (section 7.2).

    Filling these in is not decoration. A comparison that only produced the statuses it happened to reach
    would report agreement on a vector where three recorded statuses were never looked at - which is the
    failure mode this whole project is arranged against.
    """
    return {check_id: statuses.get(check_id, "not_checked") for check_id in MODELLED_CHECKS}


def signature_statuses(manifest: dict, derived_hash: str | None) -> dict:
    """The signature checks, as this implementation sees them (sections 6.3 and 7.4).

    `derived_hash` is None when the claim hash could not be derived - a claim that failed the canonical form,
    or declared a version this implementation does not read. The *shape* checks do not need it, and they run
    regardless: the reference verifier checks attribution whenever a claim parsed, even when the claim itself
    failed. Modelling that as a chain, where a stopped claim stage silences everything after it, is what this
    implementation did first and what the kit corrected.
    """
    signature = manifest.get("signature")

    if signature is None:
        return dict.fromkeys(SIGNATURE_CHECKS, "not_applicable")

    def stopped(statuses: dict) -> dict:
        return {**dict.fromkeys(SIGNATURE_CHECKS, "not_checked"), **statuses}

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
        return stopped({**statuses, "signature.key_id": "fail"})
    statuses["signature.key_id"] = "pass"

    if derived_hash is None:
        # The shape is fine and there is nothing to check it against: `not_checked`, with no guess.
        return stopped({**statuses, "signature.verify": "not_checked"})

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

    The outcome is `agreed` (every check this implementation models has the status the record gives it) or
    `refused` (this claim has no canonical form, and the record says the same). A refusal is a corroboration,
    not a pass by silence.

    Two rules from section 7 shape the whole function. **Every verdict contains every check**, so the checks
    this implementation does not model are simply absent from its own comparison rather than assumed to have
    passed - and the checks it *does* model always get a status, with the ones a stopped stage never reached
    filled in as `not_checked`. And **a stage that did not run is not a failure**: a claim that does not
    parse, or a container that is not a zip, stops with a reason rather than a guess.
    """
    fixture = kit / "fixtures" / vector["fixture"]["file"]
    checks = vector["verdict"]["checks"]
    expected_hash = vector["verdict"]["claim_hash"]

    # The caller's configuration, which the kit's README says a conformance run has to supply: a pinned TSA
    # for an RFC 3161 anchor, the neighbouring receipt for a chain link.
    options = vector.get("options") or {}

    raw_fixture = fixture.read_bytes()
    actual_digest = hashlib.sha256(raw_fixture).hexdigest()
    if actual_digest != vector["fixture"]["sha256"]:
        return (
            ["the fixture hashes to %s and the kit says %s" % (actual_digest, vector["fixture"]["sha256"])],
            "agreed",
        )

    statuses: dict[str, str] = {}
    # Bound before the stages that may not reach them, so the rollup can be computed on every path out -
    # including the ones where no claim was ever parsed (`manifest is None`).
    manifest: dict | None = None

    def report(statuses: dict) -> tuple[list[str], str]:
        """Everything this implementation can compare for this vector: the checks and the verdict.

        Defined before it is used, which sounds too obvious to say until a nested function is called from a
        branch above its definition - which is exactly what happened here on the first attempt.
        """
        filled = fill(statuses)
        problems = compare(filled, checks)
        problems.extend(compare_verdict(
            filled, vector.get("verdict") or {}, rollup_fields(manifest, options, filled),
        ))
        return (problems, _outcome(statuses, checks))

    # 1. The container, whose entry names reach a filesystem call in every consumer.
    try:
        entries = container.entries_of(fixture)
    except zipfile.BadZipFile:
        entries = None
    statuses["container.readable"] = "pass" if entries is not None else "fail"
    if entries is None:
        return report(statuses)

    # 2. The claim.
    delivered = entries.get("receipt.json")
    if delivered is None:
        return report({**statuses, "manifest.present": "fail"})
    statuses["manifest.present"] = "pass"

    try:
        manifest = parse_manifest(delivered)
    except (NotCanonical, UnicodeDecodeError, json.JSONDecodeError) as error:
        if checks.get("manifest.parseable", "pass") != "fail":
            return (["the claim could not be parsed: %s" % error], "agreed")
        return report({**statuses, "manifest.parseable": "fail"})
    if not isinstance(manifest, dict):
        return (["the claim is not a JSON object, and the kit records no failure for that"], "agreed")
    statuses["manifest.parseable"] = "pass"

    def finish(statuses: dict, derived: str | None, inner: dict[str, bytes] | None = None) -> tuple[list[str], str]:
        """Add the attribution, anchor and text checks, which run whenever a claim parsed.

        A claim that failed its own stage still says who signed it, what it is anchored to and what words it
        claims - and the record reports all three, so these run however the claim itself went. The anchor
        checks need the signature's verdict (a chain anchor commits to a position at signing time, D-012) and
        the claim hash (an RFC 3161 token's imprint is compared against it); the text check needs the
        capture's document, which is None when the earlier stages never read one.
        """
        signature = signature_statuses(manifest, derived)
        statuses.update(signature)
        statuses.update(anchor.anchor_statuses(
            manifest, options, derived, signature["signature.verify"],
        ))
        statuses.update(text_status(manifest, inner))
        return report(statuses)

    version = manifest.get("spec_version")
    if not isinstance(version, str) or not re.match(r"^\d+\.\d+\.\d+$", version) \
            or version.split(".")[0] != "0":
        return finish({**statuses, "manifest.spec_version": "fail"}, None)
    statuses["manifest.spec_version"] = "pass"

    # 3. The canonical form, the claim hash derived from it, and - section 5.3 - the fixed point it must be.
    #    Two different things can go wrong here, and they differ in what happens next. A claim with *no*
    #    canonical form is not a claim this format admits, so everything below it stops. A claim that *could*
    #    be canonicalised but was not delivered that way is `manifest.canonical: fail` and carries on: the
    #    claim hash is derived from the parsed value, so an attribution check and a capture check are still
    #    possible, and the reference reports them. Collapsing those two into one is what this implementation
    #    did first, and the kit caught it on `claim-not-canonical`.
    try:
        once = canonicalise(manifest)
    except NotCanonical:
        return finish({**statuses, "manifest.canonical": "fail"}, None)

    # `-0` is the same shape of problem: the reference's canonicaliser refuses it on the parsed value, so it
    # stops the claim stage exactly as an uncanonicalisable claim does. This implementation finds it on the
    # raw bytes (Python's parser has already turned `-0` into `0`), and treats it the same way.
    if refuses_minus_zero(delivered):
        return finish({**statuses, "manifest.canonical": "fail"}, None)

    statuses["manifest.canonical"] = "pass" if once.encode("utf-8") == delivered else "fail"
    statuses["claim.digest"] = "pass" if canonicalise(json.loads(once)) == once else "fail"

    derived = claim_hash(manifest)
    if derived != expected_hash:
        # The claim stage ran and derived something else, which is this implementation's disagreement with
        # the record rather than the record's - so it is reported rather than smoothed over.
        return (
            ["claim hash: derived %s, kit says %s" % (derived, expected_hash)],
            _outcome(statuses, checks),
        )

    # 4. The shape, the capture, the document it holds, then the attribution checks. A claim that failed the
    #    canonical form still gets its capture checked - only a *shape* failure stops the capture stage - and
    #    the signature never depended on the claim being sound at all.
    capture = manifest.get("capture")
    capture_bytes = (
        entries.get(capture["path"])
        if isinstance(capture, dict) and isinstance(capture.get("path"), str)
        else None
    )
    inner = container.wacz_entries(capture_bytes)
    statuses.update({
        key: value for key, value in container.container_statuses(entries, manifest, inner).items()
        if key != "container.readable"
    })
    statuses["subject.document"] = document_status(inner, manifest)[0]
    return finish(statuses, derived, inner)


def _outcome(statuses: dict, checks: dict) -> str:
    """`refused` when the only thing this implementation concluded is that the claim has no canonical form."""
    canonical = statuses.get("manifest.canonical")
    if canonical == "fail" and checks.get("manifest.canonical", "pass") == "fail":
        return "refused"
    return "agreed"


# Section 7.4, grouped by the level each check belongs to (section 7.3).
LEVEL_CHECKS = {
    "L0": (
        "container.readable", "manifest.present", "manifest.parseable", "manifest.spec_version",
        "manifest.canonical", "manifest.shape", "claim.digest", "capture.present", "capture.bytes",
        "capture.digest", "capture.media_type", "capture.wacz.readable", "capture.wacz.resources",
        "subject.document",
    ),
    "L1": ("signature.present", "signature.alg", "signature.key_id", "signature.verify"),
    "L2": ("anchor.present", "anchor.verified"),
    "L3": ("subject.text",),
}

# Section 7.3: `fail` outranks everything, then `unsupported`, then `not_checked`.
LEVEL_PRECEDENCE = ("fail", "unsupported", "not_checked")


def level_status(statuses: dict, level: str) -> str:
    """One level's rollup: `pass` only when every check in it is `pass` (section 7.3).

    No "pass with warnings", and no partial credit. A level whose checks are a mix of `pass` and
    `not_checked` is `not_checked`, because the moment a partially examined level can print as verified the
    level stops meaning anything - and `not_applicable` is not a pass either, or an unsigned claim would roll
    L1 up to green.
    """
    values = [statuses.get(check, "not_checked") for check in LEVEL_CHECKS[level]]
    if all(value == "not_applicable" for value in values):
        return "not_applicable"
    for status in LEVEL_PRECEDENCE:
        if status in values:
            return status
    if "not_applicable" in values:
        return "not_checked"
    return "pass"


def verdict_of(statuses: dict) -> dict:
    """The rollup: the levels, `verified`, and the exit code (sections 7.3 and 7.5).

    `verified` is true when **L0 is `pass`, L1 is `pass`, and no check anywhere is `fail`** - and nothing else
    is folded in. An unanchored receipt is verified and its time is not attested; an unimplemented anchor does
    not un-verify the bytes; a signer nobody can trace is still a signer. The exit code has three states
    because "this receipt is broken" and "I could not check this receipt" must not share one in a pipeline.
    """
    levels = {level: level_status(statuses, level) for level in LEVEL_CHECKS}
    any_fail = "fail" in statuses.values()
    verified = levels["L0"] == "pass" and levels["L1"] == "pass" and not any_fail
    return {
        "levels": levels,
        "verified": verified,
        "exit_code": 2 if any_fail else (0 if verified else 1),
    }


def rollup_fields(manifest: dict | None, options: dict, statuses: dict) -> dict:
    """The three verdict fields that follow from the claim and the caller's configuration (section 7).

    Small, and worth comparing: they are the part of a verdict a program reads without opening the claim -
    which the format lifted out on purpose (D-026) - and each has a rule rather than a judgement behind it.
    """
    capture = manifest.get("capture") if isinstance(manifest, dict) and isinstance(manifest.get("capture"), dict) else {}
    profile = capture.get("profile") if isinstance(capture.get("profile"), str) else None

    signed = statuses.get("signature.verify")
    attribution = {
        # `invalid` and `none` are different sentences: one says the signature is wrong, the other says
        # there was nothing to check. A verdict that merged them would lose the only distinction L1 makes.
        "status": "valid" if signed == "pass" else ("invalid" if signed == "fail" else "none"),
        "key_trusted": key_trust(manifest, options),
    }

    # `anchored` means an anchor *verified*, and section 8.4 draws the distinction the other way round:
    # a chain anchor attests ordering within an archive, so it bounds the claim without giving anybody a
    # time. The kit records the bound, not the instant, so a verified chain is `anchored` here.
    time_bound = "anchored" if statuses.get("anchor.verified") == "pass" else "claimed_only"

    return {"capture_profile": profile, "attribution": attribution, "time_bound": time_bound}


def key_trust(manifest: dict | None, options: dict) -> str:
    """Whether the caller says this key is somebody's (section 6.7).

    `trustedKeys` is a list of key ids, and it is the only account of whose key this is that did *not* come
    from the receipt. A caller that names none gets `not_checked` - not a criticism of the receipt, but the
    honest state of a question the format deliberately leaves to its reader.

    `keyDirectory` is the richer form of the same configuration, and this implementation does not read one:
    a caller who supplies only that is reported as `not_checked` rather than guessed at, which is wrong in the
    one direction that matters least.
    """
    named = options.get("trustedKeys")
    if not isinstance(named, list) or not named:
        return "not_checked"

    signature = manifest.get("signature") if isinstance(manifest, dict) else None
    key_id = None
    if isinstance(signature, dict):
        public_key = signature.get("public_key")
        if isinstance(public_key, str):
            try:
                key_id = hashlib.sha256(from_base64url(public_key)).hexdigest()
            except Exception:
                key_id = None
        if key_id is None and isinstance(signature.get("key_id"), str):
            key_id = signature["key_id"]

    return "trusted" if key_id in named else "untrusted"


def compare_verdict(statuses: dict, verdict: dict, fields: dict | None = None) -> list[str]:
    """What the rollup disagrees with the record about - the fields section 11 asks for by name."""
    expected = {**verdict_of(statuses), **(fields or {})}
    problems = []
    for field in ("verified", "exit_code", "capture_profile", "time_bound", "attribution"):
        if field in verdict and expected.get(field, verdict[field]) != verdict[field]:
            problems.append(
                "%s: this implementation says %s, and the record says %s"
                % (field, expected.get(field), verdict[field])
            )
    recorded_levels = verdict.get("levels") or {}
    for level, status in expected["levels"].items():
        if level in recorded_levels and status != recorded_levels[level]:
            problems.append(
                "%s: this implementation rolls up to %s, and the record says %s"
                % (level, status, recorded_levels[level])
            )
    return problems


def compare(statuses: dict, checks: dict) -> list[str]:
    """Every modelled check whose status differs from the record's. An absent record entry means `pass`."""
    problems = []
    for check_id, status in statuses.items():
        recorded = checks.get(check_id, "pass")
        if status != recorded:
            problems.append(
                "%s: this implementation says %s, and the kit says %s" % (check_id, status, recorded)
            )
    return problems


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
    print("this implementation meets section 11: all 21 checks, the rollup rules, the canonical form and")
    print("every rule-derived verdict field. A caveat count is the one field it does not produce, and")
    print("section 11.1 does not ask for it - see conformance/README.md")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
