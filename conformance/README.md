# A second implementation

`docs/CONFORMANCE.md` has said since the first draft that the biggest single gap is a second
implementation: *"the vectors pin one implementation's answers, which is agreement rather than
corroboration."* This directory is the beginning of that, and it is deliberately not a copy of anything in
`reference/`.

## What is here

| File | What it is |
| --- | --- |
| `verify_claims.py` | The canonical form, the claim hash and the signature family, in Python, written from the specification (`docs/RECEIPT-SPEC.md` sections 5, 5.1, 5.2, 6.1, 6.3 and 6.4) rather than from `reference/`. No dependencies beyond the standard library. |
| `ed25519.py` | Ed25519 verification, written from RFC 8032. Python's standard library has none, and checking a signature with the same library in two languages would be one check rather than two. |

It covers **6 of the 21 checks**: `manifest.canonical`, the `spec_version` gate, the claim hash, and
`signature.present`, `signature.alg`, `signature.key_id` and `signature.verify`. It applies the stage order
the specification's section 6.5 implies, reads the signing message by looking the prefix up per major
version (section 6.4), and fills in the checks a stopped stage never reached with `not_checked`, because a
verdict contains every check (section 7.2).

```bash
node reference/src/vectors.mjs --emit ./kit        # the fixtures and the answers
python conformance/verify_claims.py ./kit          # exit 0 when nothing disagrees
```

## The result

```
claim hashes: 39 of 45 fixtures agree
2 refused, and the record says the same (a corroborated refusal, not a pass by silence)
4 not reached by this implementation, and named so that silence is not mistaken for a pass:
  - container-not-a-zip, spec-version-unknown, manifest-missing, manifest-not-json
0 disagree
```

Two independent implementations of `canonical-json-v1` and of the signing rules, written from the same
document in two languages, derive the same claim hash for every claim that reaches one, and reach the same
verdict about the signature — including, for every signed fixture, verifying the Ed25519 signature over
`vidimus/claim/<version>:<claim_hash>` with arithmetic in one language and a platform library in the other.

The four "not reached" fixtures are not containers or hold no parseable claim: the kit records the same thing
(`container.readable: fail`, `manifest.parseable: fail`, `spec_version: fail`), so this is agreement rather
than omission — but it is listed by name, because a conformance report that says "no disagreement" without
saying what it never looked at is the failure mode this project is arranged against.

## What writing it found

Four things that only showed up when somebody implemented the format somewhere else. The first three are now
fixed in the specification, and two have vectors of their own.

1. **`-0` cannot be refused after parsing in Python.** Rule 5 forbids `-0`. JavaScript keeps the sign
   through `JSON.parse`, so the reference rejects it there; Python's `json` returns `0`, and the sign is gone
   before any check can see it. An implementation in that position must read the **raw bytes** — which is
   what this one does, with a scan that tracks string state so that the characters `-0` inside a string are
   not mistaken for a number. The specification now says so.
2. **The escaping rule did not state the case of its hex digits** — and, worse, **no fixture contained a
   control character at all**, so a whole rule was unexercised. Both implementations now agree on it byte for
   byte, and `claim-contains-a-control-character` pins it.
3. **The stage order is stated as a principle, not as gates.** Section 7 says a claim is checked before
   anything that depends on a key, a third party or a network; what an implementer needs is narrower — an
   unknown `spec_version` stops *before* the canonical comparison, and a claim that does not parse records
   `manifest.parseable: fail` with everything after it `not_checked`. The kit records what the reference did,
   so it is discoverable, which is what the vectors are for.
4. **`signature.present` means the signature *carries the required fields*, not that it is an object.** The
   first version of this file treated a `signature` object as a pass and got three statuses wrong on
   `signature-shape-broken`. The kit caught it on the first run, which is the whole argument for recording
   statuses rather than prose: an implementer can disagree with every sentence in the specification and still
   be told, precisely, which check they got wrong.

## What this is not

**It is not a conforming implementation, and it must not be listed as one.** Section 11 requires every check
in section 7.4: this implements 6 of the 21. The container's own resource hashes, the anchors, the text
fingerprint, the document digest and the rest are not written yet, and several of them depend on reading a
WACZ and a WARC rather than a claim.

The next slice is **L0's container checks** — `capture.present`, `capture.bytes`, `capture.digest`,
`capture.media_type` and `capture.wacz.readable` — which need a ZIP reader (the standard library has one) and
the WACZ lookup, and would take the count to 11 of 21.
