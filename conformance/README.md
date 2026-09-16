# A second implementation

`docs/CONFORMANCE.md` has said since the first draft that the biggest single gap is a second
implementation: *"the vectors pin one implementation's answers, which is agreement rather than
corroboration."* This directory is the beginning of that, and it is deliberately not a copy of anything in
`reference/`.

## What is here

| File | What it is |
| --- | --- |
| `verify_claims.py` | The container, the claim, the claim hash and the signature family, in Python, written from the specification (`docs/RECEIPT-SPEC.md` sections 3, 5, 6, 7 and 12) rather than from `reference/`. No dependencies beyond the standard library. |
| `container.py` | Reading a receipt's ZIP, the names inside it, and the WACZ capture it names - including the resource hashes the capture advertises for itself. |
| `ed25519.py` | Ed25519 verification, written from RFC 8032. Python's standard library has none, and checking a signature with the same library in two languages would be one check rather than two. |

It covers **17 of the 21 checks**: everything except the four that need an anchor, a WARC reader or a text
extractor (`anchor.present`, `anchor.verified`, `subject.document`, `subject.text`).

```bash
node reference/src/vectors.mjs --emit ./kit        # the fixtures and the answers
python conformance/verify_claims.py ./kit          # exit 0 when nothing disagrees
```

## The result

```
claim hashes: 42 of 45 fixtures agree
3 refused, and the record says the same (a corroborated refusal, not a pass by silence)
0 disagree
```

Every check this implementation models has, for every fixture, the status the reference recorded — including
the Ed25519 signatures, verified with arithmetic written from RFC 8032 over a message built from the claim
hash this implementation derived itself, against a platform library on the other side. The three refusals are
claims the format does not admit (a float, a `-0`, a version this implementation does not read), and the
record agrees that they are refused.

## What writing it found

Six things that only showed up when somebody implemented the format somewhere else. The first four are now
fixed in the specification, and two have vectors of their own.

1. **`-0` cannot be refused after parsing in Python.** Rule 5 forbids `-0`. JavaScript keeps the sign
   through `JSON.parse`, so the reference rejects it there; Python's `json` returns `0`, and the sign is gone
   before any check can see it. An implementation in that position must read the **raw bytes** — which is
   what this one does, with a scan that tracks string state so that the characters `-0` inside a string are
   not mistaken for a number. The specification now says so.
2. **The escaping rule did not state the case of its hex digits** — and, worse, **no fixture contained a
   control character at all**, so a whole rule was unexercised. Both implementations now agree on it byte for
   byte, and `claim-contains-a-control-character` pins it.
3. **`signature.present` means the signature *carries the required fields*, not that it is an object.** The
   first version of this file treated a `signature` object as a pass and got three statuses wrong on
   `signature-shape-broken`. The kit caught it on the first run, which is the whole argument for recording
   statuses rather than prose: an implementer can disagree with every sentence in the specification and still
   be told, precisely, which check they got wrong.
4. **The safe-entry-name rule is only in code.** Section 12 states the principle (*"no absolute paths, no
   `..`, no backslashes, no drive letters"*) and the enumeration — the length cap, the refusal of `//`, of a
   trailing dot-segment, of a colon — is in `reference/src/verify.mjs`. A second implementer cannot infer a
   list from a principle, and this implementation guessed at `MAX_ENTRY_NAME` rather than reading it. **The
   specification should state the list.** It is not yet fixed, and that is stated here rather than left as an
   implication.

And two about *when* checks run, which the specification states as a principle and an implementer needs as a
picture. Both were reported by the kit as disagreements, and both were this implementation's fault:

5. **The stages are not a chain.** A claim that fails the *claim* stage still has its **signature** checked:
   attribution depends on a manifest having parsed, not on the claim being sound. This implementation
   modelled a linear pipeline, so a receipt with an unknown `spec_version` reported three attribution statuses
   as `not_checked` where the record says `pass`. Equally, a claim whose bytes are not canonical is
   `manifest.canonical: fail` **and carries on** — the claim hash comes from the parsed value, not from the
   delivered bytes — while a claim with *no* canonical form at all stops. Two ways to fail, two different
   consequences, and `claim-not-canonical` and `claim-contains-a-float` are the two vectors that tell them
   apart.

## What this is not

**It is not a conforming implementation, and it must not be listed as one.** Section 11 requires every check
in section 7.4: this implements 17 of the 21, and the four it does not — `anchor.present`, `anchor.verified`,
`subject.document` and `subject.text` — are exactly the ones that need an anchor parser, a WARC reader and a
text extractor rather than a claim.

The next slice is **`subject.document`**: reading the response record out of the WACZ's WARC and comparing its
body with the digest the claim states. It needs a WARC reader (the record boundaries, the HTTP block, the
length) and it would take the count to 18 of 21.
