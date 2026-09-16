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
| `warc.py` | The record layer: the magic that separates records, the HTTP block, the WARC-Payload-Digest a record states for itself, and the body cut to the length the response declares. The smallest reader that can answer one question - what was the main document (section 4.2). |
| `anchor.py` | `anchor.present`, and only that: whether the claim carries an anchor and whether its type is one this implementation knows (sections 7.4, 8.1, 8.3). |
| `ed25519.py` | Ed25519 verification, written from RFC 8032. Python's standard library has none, and checking a signature with the same library in two languages would be one check rather than two. |

It covers **19 of the 21 checks**: everything except `anchor.verified` and `subject.text`.

**One of those layers is a weaker check than the others, and it is worth saying which.** The container, the
claim and the signature layers were written from `docs/RECEIPT-SPEC.md` alone, with `reference/` unopened -
that is what makes them corroboration. `warc.py` was not: section 9 delegates WARC semantics to ISO 28500
("the verifier reads the response record for `subject.url` and the body after its HTTP headers, and nothing
else"), which does not say how records are separated, how a stated `Content-Length` is treated, or whether a
record's own `WARC-Payload-Digest` is honoured. So that layer was written with the reference in view, and it
corroborates *understanding of the reference's behaviour* rather than of the specification's text. The
vectors still make it worth having - it is a second implementation of the same rules, in a different
language, over 14 fixtures - but it is not the same class of evidence, and calling it the same would be the
kind of overstatement this project is arranged against.

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

Seven things that only showed up when somebody implemented the format somewhere else. Two are fixed in the
specification; the rest are named as open, because a list that reads as if it were closed is worse than no
list at all.

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
4. **The WARC-reading rules are not in the specification.** Section 9 says a verifier reads *"the response
   record for `subject.url` and the body after its HTTP headers, and nothing else"*. That sentence does not
   say where one record ends and another begins (the reference searches for the seven bytes `WARC/1.0`
   anywhere in the inflated stream, so a payload containing them would split a record in two); whether an
   HTTP `Content-Length` is trusted and what a *longer* one means (a truncated capture, refused); or whether
   the record's own `WARC-Payload-Digest` is checked (it is, and a mismatch stops the read). A second
   implementer has to read another implementation to find any of that out, which is the one thing this
   project is arranged against.

5. **The safe-entry-name rule is only in code.** Section 12 states the principle (*"no absolute paths, no
   `..`, no backslashes, no drive letters"*) and the enumeration — the length cap, the refusal of `//`, of a
   colon, of a trailing dot-segment — is in `reference/src/verify.mjs`. A second implementer cannot infer a
   list from a principle, and this implementation guessed at `MAX_ENTRY_NAME` rather than reading it. **The
   specification should state the list.**

And two about *when* checks run, which the specification states as a principle and an implementer needs as a
picture. Both were reported by the kit as disagreements, and both were this implementation's fault:

6. **The stages are not a chain.** A claim that fails the *claim* stage still has its **signature** checked:
   attribution depends on a manifest having parsed, not on the claim being sound. This implementation
   modelled a linear pipeline, so a receipt with an unknown `spec_version` reported three attribution statuses
   as `not_checked` where the record says `pass`. Equally, a claim whose bytes are not canonical is
   `manifest.canonical: fail` **and carries on** — the claim hash comes from the parsed value, not from the
   delivered bytes — while a claim with *no* canonical form at all stops. Two ways to fail, two different
   consequences, and `claim-not-canonical` and `claim-contains-a-float` are the two vectors that tell them
   apart.

And one thing the specification got *right*, which is worth recording in a document that is otherwise a list
of what it got wrong. Section 8.1 requires an anchorless claim to report `anchor.present: not_applicable` and
`anchor.verified: not_checked` - an asymmetry that looks like a mistake until the reason is read ("there is
nothing here to have a type" against "there was nothing to verify, and this receipt does not have a verified
time"). It is stated, it is complete, and implementing it from the text alone reproduced all four statuses that
check can produce, across 45 fixtures - including the `unsupported` an unknown type gets, which is the rule a
naive implementation would get wrong by calling it a failure. Section 8 is the part of this specification a
second implementer can follow without asking anybody anything.

## What this is not

**It is not a conforming implementation, and it must not be listed as one.** Section 11 requires every check
in section 7.4: this implements 19 of the 21, and the two it does not — `anchor.verified` and `subject.text` —
are the two that need machinery rather than rules.

The next slice is **`anchor.verified`**, which is the largest single piece left: DER parsing, an X.509
certificate and its `timeStamping` extended key usage, RSA signature verification by modular exponentiation,
the CMS signed attributes that bind the signature to the `TSTInfo`, and the token's own `messageImprint`
compared against the claim hash — all four of section 8.3's steps, where getting three of them right and
answering "yes" early is the failure section 8.3 was written to prevent. After that, `subject.text` needs a
`text-v1` extractor (section 4.5), which is a different kind of work again.
