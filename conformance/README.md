# A second implementation

`docs/CONFORMANCE.md` has said since the first draft that the biggest single gap is a second
implementation: *"the vectors pin one implementation's answers, which is agreement rather than
corroboration."* This directory is the beginning of that, and it is deliberately not a copy of anything in
`reference/`.

## What is here

`verify_claims.py` — a Python implementation of the **canonical form and the claim hash**, working from the
specification (`docs/RECEIPT-SPEC.md` sections 5, 5.1, 5.2 and 6.1) rather than from
`reference/src/canonical.mjs`. It covers one layer completely instead of all of them partially:

1. read each fixture from a conformance kit (`node reference/src/vectors.mjs --emit <dir>`);
2. check the fixture against the digest the kit records for it;
3. read `receipt.json` out of the container, as the bytes that were delivered;
4. apply the gates the specification's stage order implies;
5. re-derive the canonical form of the signed subtree, and the claim hash from it;
6. compare both with what the kit says, and report every disagreement.

It implements **no cryptography at all**, which is not a shortcut: the signature is excluded from the signed
subtree, so deriving the claim hash needs no key and no library. It has no dependencies beyond Python's
standard library.

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

Two independent implementations of `canonical-json-v1`, written from the same document in two languages,
derive the same claim hash for all 39 claims that reach it — and agree that the other six cannot be reached
or must be refused. The four "not reached" are fixtures that are not containers or hold no parseable claim:
the kit records the same thing (`container.readable: fail`, `manifest.parseable: fail`, and a
`spec_version` gate), so this is agreement rather than omission — but it is listed by name, because a
conformance report that says "no disagreement" without saying what it never looked at is the failure mode
this project is arranged against.

## What writing it found

Three things the specification said, or did not say, that only showed up when somebody implemented it
somewhere else. All three are now fixed in the specification, and the first two have vectors.

1. **`-0` cannot be refused after parsing in Python.** Rule 5 forbids `-0`. JavaScript keeps the sign
   through `JSON.parse`, so the reference implementation rejects it there; Python's `json` returns `0`, and
   the sign is gone before any check can see it. An implementation in that position must read the **raw
   bytes** — which is what this one does, with a scan that tracks string state so that the characters `-0`
   inside a string are not mistaken for a number. The specification now says so.
2. **The escaping rule did not state the case of its hex digits.** Rule 4 escapes `"`, `\` and the C0
   controls, using short forms for five of them — and says nothing about whether the remaining four are
   `\u0001` or `\u0001` in some other case. The two implementations happen to agree (lowercase, as RFC 8785
   has it), which is exactly the kind of agreement that should not be left to luck. The specification now
   states it, and `claim-contains-a-control-character` pins it: before that vector existed, **no fixture
   contained a control character at all**, so the whole escaping rule was unexercised.
3. **The stage order is stated as a principle, not as gates.** Section 7 says a claim is checked before
   anything that depends on a key, a third party or a network. What a second implementer needs to know is
   narrower: an unknown `spec_version` stops *before* the canonical form is compared, and a claim that does
   not parse records `manifest.parseable: fail` with everything after it `not_checked`. The kit records what
   the reference did, so it is discoverable — which is what the vectors are for — but the first version of
   this file got both wrong, and reported two disagreements that were its own.

## What this is not

**It is not a conforming implementation, and it must not be listed as one.** Section 11 of the
specification requires every check in section 7.4: this implements two of the twenty-one, and the other
nineteen — the container's own resource hashes, the signature, the anchors, the text fingerprint, the
document digest — are not written yet, let alone agreeing. It is one layer, finished, and it says so in its
own output.

The next slice is the obvious one: Ed25519 over the claim hash, which turns the derived hash into a checked
signature and covers `signature.*` for every signed fixture. Python's standard library has no Ed25519, so
that slice needs either a dependency (which a second implementation may have — it is not the reference) or
an independent RFC 8032 implementation.
