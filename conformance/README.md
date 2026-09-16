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
| `anchor.py` | Both anchor checks: the chain links of section 8.2, and the RFC 3161 tokens of section 8.3. |
| `der.py`, `x509.py`, `rfc3161.py` | A DER reader, the four fields this project needs from a certificate, and the four things section 8.3 requires before a token may be reported as `pass` - including RSA PKCS#1 v1.5 verification by modular exponentiation. |
| `text.py` | `text-v1`: the seven rules of section 4.5.1, as a deterministic walk over a document's bytes. |
| `ed25519.py` | Ed25519 verification, written from RFC 8032. Python's standard library has none, and checking a signature with the same library in two languages would be one check rather than two. |

It covers **all 21 checks** of section 7.4.

**Two of those layers are weaker checks than the others, and it is worth saying which.** The container, the
claim and the signature layers were written from `docs/RECEIPT-SPEC.md` alone, with `reference/` unopened -
that is what makes them corroboration. Two were not:

- `warc.py`, because section 9 delegates WARC semantics to ISO 28500 ("the verifier reads the response record
  for `subject.url` and the body after its HTTP headers, and nothing else"), which does not say how records
  are separated, how a stated `Content-Length` is treated, or whether a record's own `WARC-Payload-Digest` is
  honoured;
- `rfc3161.py`, because section 8.3 states the *rules* completely - trust first, then the extended key usage,
  the validity window, the two CMS bindings, the imprint - and says nothing about the *order* they are applied
  in, nor which of them is a `fail` and which an `unsupported`. The order came from `verify.mjs` and
  `rfc3161.mjs`; the rules came from the specification.

Both still make the vectors worth having - a second implementation, in a different language, over the same
fixtures - but they corroborate *understanding of the reference's behaviour* rather than of the
specification's text, and calling them the same would be the kind of overstatement this project is arranged
against.

What has since happened to them is worth stating precisely, because it is easy to overclaim in either
direction. The rules they needed are now **in the specification** (sections 8.3 and 9, D-035) - so an
implementation started tomorrow would not have to read `reference/` at all. That does not retroactively make
this one specification-derived: it was written with the reference in view, and if the reference is wrong about
record separation or about the re-tagged attributes, this file is wrong in the same way. What the exercise
produced is a specification that no longer needs that shortcut, which is a better outcome than a second
implementation that still does.

`text.py` was in the first group and stays there, but for a reason worth stating: when it was written, section
4.5.1 was silent on three things about a digest, so this implementation had to choose - and those three choices
were then *written into the specification* (D-035). A guess that the format adopts stops being a guess, and the
line between the two groups is exactly where that has and has not happened.

```bash
node reference/src/vectors.mjs --emit ./kit        # the fixtures and the answers
python conformance/verify_claims.py ./kit          # exit 0 when nothing disagrees
```

## The result

```
claim hashes: 42 of 48 fixtures agree
3 refused, and the record says the same (a corroborated refusal, not a pass by silence)
0 disagree
```

Every check this implementation models has, for every fixture, the status the reference recorded — including
the Ed25519 signatures, verified with arithmetic written from RFC 8032 over a message built from the claim
hash this implementation derived itself; including an **RFC 3161 timestamp token**: its CMS structure, its
certificate, the two signed-attribute bindings, the `messageImprint` against the claim hash, and an RSA
PKCS#1 v1.5 signature verified by modular exponentiation; and including the **`text-v1` fingerprint**, the
words extracted from the capture's document by the seven rules of section 4.5.1 and hashed as UTF-8. The three
refusals are claims the format does not admit (a float, a `-0`, a version this implementation does not read),
and the record agrees that they are refused.

Every status each check can produce is exercised across those 48 fixtures: all four of `anchor.verified`
(`pass`, `fail`, `not_checked`, `unsupported`), all four of `anchor.present`, the `pass` and `fail` of the
text fingerprint and its `not_applicable` when a claim carries none, and both the refusals and the stage gaps
of the claim checks. A conformance run that only ever saw the happy path would agree with a reference that did
nothing.

The verdict fields are covered the same way: nine distinct combinations of `attribution`, `time_bound` and
`capture_profile` across the fixtures, including a key the caller vouches for, one it does not, an anchor that
verified and three declared capture profiles - and all three exit codes.

## What writing it found

Nine things that only showed up when somebody implemented the format somewhere else. Six are fixed in the
specification; the rest are named as open, because a list that reads as if it were closed is worse than no
list at all. Each of the fixed ones was fixed *after* a second implementation got it wrong - which is the only
argument for a rule that a reader cannot talk back to.

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
4. **The WARC-reading rules were not in the specification.** Section 9 says a verifier reads *"the response
   record for `subject.url` and the body after its HTTP headers, and nothing else"*. That sentence does not
   say where one record ends and another begins (the reference searches for the seven bytes `WARC/1.0`
   anywhere in the inflated stream, so a payload containing them would split a record in two); whether an
   HTTP `Content-Length` is trusted and what a *longer* one means (a truncated capture, refused); or whether
   the record's own `WARC-Payload-Digest` is checked (it is, and a mismatch stops the read). A second
   implementer has to read another implementation to find any of that out, which is the one thing this
   project is arranged against. **Now stated** in section 9, beside the check that depends on it.

5. **The safe-entry-name rule is only in code.** Section 12 states the principle (*"no absolute paths, no
   `..`, no backslashes, no drive letters"*) and the enumeration — the length cap, the refusal of `//`, of a
   colon, of a trailing dot-segment — is in `reference/src/verify.mjs`. A second implementer cannot infer a
   list from a principle, and this implementation guessed at `MAX_ENTRY_NAME` rather than reading it. **The
   specification now states the list** (section 12), and the guess turned out to match it exactly - which is
   luck, not method: the guessing is the finding, not whether it happened to be right.

8. **What a timestamp token's signature covers is not stated.** Section 8.3 lists the CMS bindings a token
   must carry - the signed attributes must name the `TSTInfo`, and must carry its digest - and says nothing
   about the fact that what is *signed* is those attributes **re-tagged** as a `SET OF`: the same bytes after
   the tag that identifies them, length octets included. My first version reconstructed them from the `[0]`
   element's *value*, which silently drops the length octets and produces a shorter byte string. The result
   was `anchor.verified: fail` on a perfectly good token, with everything else - the certificate, the imprint,
   the key usage, the validity window - checking out. The vectors caught it in one run, and an implementer with
   no vectors would have concluded the TSA was lying. **Now stated** in section 8.3.

Nine findings, six of them closed by changing the specification rather than the code:

| Finding | Now stated in |
| --- | --- |
| 1. `-0` cannot be refused after parsing everywhere | Section 5.1, rule 5 - and pinned by `claim-contains-minus-zero` |
| 2. Escaping did not say the case of its hex digits | Section 5.1, rule 4 - and pinned by `claim-contains-a-control-character` |
| 4. The WARC-reading rules a digest depends on | Section 9: record separation, the `Content-Length` cut, the truncation refusal, the payload digest |
| 5. The safe-entry-name enumeration | Section 12: the length, the leading slash, the backslash, the colon, `//`, and the dot segments |
| 8. What a timestamp token's signature actually covers | Section 8.3: the attributes re-tagged as a `SET OF`, length octets and all |
| 9. Whitespace, named references and decoding in `text-v1` | Section 4.5.1 rules 5 and 6, and section 4.5.2 (D-035) |

The three that remain open are #3 (the shape of the stage structure), #6 (the stage order as a picture) and #7
(the `signature.present` reading) - all three about *when* a check runs rather than what it means, and all
three discoverable from the vectors, which is the mechanism working as intended.

9. **`text-v1` left three things to the reader, and it now does not.** Section 4.5.1 was otherwise a model of
   how to write an extraction down - seven rules, a named element list, a stated degradation for malformed
   markup - and it did not say **which characters count as whitespace** for rule 5, **which named character
   references are known** ("no full HTML5 entity table" ruled some out and named none), or **how a document
   that is not UTF-8 becomes characters** at all. Each is a difference that changes the digest, and a digest
   that differs between two implementations is the failure this section exists to prevent.

   **All three are now stated**, and the way they were found is the argument for writing them down. The
   vector set had two text fixtures and both used the same trivial document - an `h1` and a `p` - so no
   fixture had ever exercised a character reference, a hidden element, or a `<` that was not a tag.
   `text-extraction-rules` does all three at once, and it found **two bugs in this implementation on its first
   run**: `&nbsp;` was not in the named set, so `a&nbsp;b` did not collapse the way `a b` does; and a `<` that
   did not begin a tag made the walk append its text chunk *undecoded*, so `five &gt; three, and 3 < 5`
   fingerprinted differently from the same line without the malformed `<`. Neither bug was visible to any
   existing fixture, and neither would have been visible to a reader of the rules - rule 1 says references are
   decoded and rule 7 says this is text, and the two rules meet in a place the section did not describe.

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
check can produce, across 48 fixtures - including the `unsupported` an unknown type gets, which is the rule a
naive implementation would get wrong by calling it a failure. Section 8 is the part of this specification a
second implementer can follow without asking anybody anything.

## What this is not

## Whether this counts as conforming

Section 11 lists four conditions, and this implementation meets them:

1. **every check in section 7.4, reported in every verdict** - all 21, with the checks a stopped stage never
   reached filled in as `not_checked` rather than omitted;
2. **the status, level-rollup and `verified` rules of sections 7.1-7.5** - derived independently and compared,
   and agreeing;
3. **the canonical form, byte for byte, including the refusals** - 45 of 48 fixtures agree, and the three
   refusals are corroborated as refusals rather than passed over in silence;
4. **the recorded verdicts** - comparing every rule-derived field, and agreeing on all nine distinct
   combinations of `attribution`, `time_bound` and `capture_profile` the fixtures contain.

The one field it does not produce is `caveat_count`, and section 11.1 says a conforming run need not reproduce
it: a caveat is a sentence about something that was not established, and how many a verifier raises is a
question of how much it explains.

**That clarification is convenient for this implementation, which is exactly why it deserves a second
opinion.** Its argument is the one already made for excluding the *wording* of a reason - a conformance suite
that fails when somebody improves a sentence teaches people to re-record vectors without reading them - and a
count of prose is the same kind of thing. But somebody who thinks a count *is* checkable should say so, and
the decision is one line to reverse.
