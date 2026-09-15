# The Receipt specification

**Version 0.1.0** · Licence: CC BY 4.0 for this document, MIT for the code (see `LICENSE`)

Published by the **Vidimus** project, whose reference implementation is `vidimus`. The document is
the format; the project is the tool that writes and checks it, in the same way Webrecorder publishes
WACZ.

A **receipt** is a single file that answers one question:

> What did this page say when I cited it, and can anyone check that answer without trusting me?

It binds three things together so that none of them can be swapped afterwards:

1. a **capture** of the page in the [WACZ](https://specs.webrecorder.net/wacz/1.1.1/) format,
   which is somebody else's standard and already solves packaging;
2. a **claim** about that capture - the URL, when it was taken, what the bytes hash to;
3. optionally a **signature** saying who asserts it, and a **time anchor** saying that
   somebody other than the author saw that assertion at a particular moment.

Everything the format does is in service of one property: **a verifier that has only the file
can tell you which parts held up, which parts did not, and which parts it could not check at
all - and it never lets a green tick stand for work it did not do.**

## Status of this document

A draft, and the version number says so. The reference implementation in `reference/` is
`0.1.0` and isomorphic: the checks it performs are the checks below, the conformance vectors
in `spec/vectors/receipt-vectors.json` are the record of what it answers, and
`npm run verify` re-derives that record on every run.

Two things are deliberately unfinished and named rather than implied: RFC 3161 anchors
(section 8) and the `text-v1` fingerprint (section 9). `docs/CONFORMANCE.md` lists them
alongside what each would take.

## 1. Scope

**In scope.** A container format for a claim plus a capture; a canonical form for the signed
material; a signature scheme; three kinds of time anchor; and a verification procedure whose
output distinguishes "held up", "did not", and "could not be checked here".

**Out of scope, and this list is the honest part.**

- **Crawling.** A receipt is about *the page you are citing*, captured by a person who is
  looking at it. It is not a web archive service and must not grow into one.
- **WACZ validation.** A verifier checks the capture's own advertised resource hashes
  (section 7.4). It does not re-implement the WACZ spec, and says so.
- **Truth.** A receipt records what a server returned, not whether it was accurate, honest,
  or complete. A receipt for a lie is a valid receipt.
- **Identity.** A signature proves a key signed a claim. It does not prove *who* holds the
  key. Key trust is the verifier's caller's decision, always (D-007).
- **Being a timestamping authority.** A receipt with a chain anchor proves ordering inside
  one archive and nothing at all to a stranger. Saying so is part of the format.
- **Altering anything.** Nothing here blocks, rewrites, delays or observes a request. A
  receipt is made from a capture that already happened.

## 2. Terminology

| Term | Meaning |
| --- | --- |
| **Capture** | The WACZ file holding the page as it was served. Byte-for-byte, as stored. |
| **Claim** | `receipt.json`: the signed assertion about the capture and its subject. |
| **Receipt** | The `.receipt` container: the claim, the capture, and any attestations. |
| **Claim hash** | SHA-256 of the canonical form of the signed subtree. Computed, never stored. |
| **Signed subtree** | The claim *minus* `signature` and `anchor` (section 6.1). |
| **Anchor** | Evidence, produced by something other than the author, that the claim hash existed at a time. |
| **Verifier** | A program that reads a receipt and produces a verdict. |
| **Check** | One named question a verdict answers (`capture.digest`, `signature.verify`, …). |
| **Status** | The answer to one check: `pass`, `fail`, `not_checked`, `unsupported`, `not_applicable`. |
| **Level** | A group of checks answering one question about the whole receipt (L0-L3). |

The words `MUST`, `MUST NOT`, `SHOULD` and `MAY` are used in the sense of RFC 2119.

## 3. The container

A receipt **MUST** be a ZIP file with the extension `.receipt`.

- **MUST** contain `receipt.json` at the archive root, holding the claim (section 4).
- **MUST** contain the entry named by `capture.path`, normally `capture.wacz`.
- **MAY** contain entries under `attestations/` - detached signatures, anchor tokens, or
  anything else a tool wants to keep with the claim.
- Any **other** entry is outside this format. A verifier **MUST** report it as a caveat: not
  ignored (it is unsurfaced content the claim does not cover) and not failed (a future minor
  version may define it).

`receipt.json` **MUST** be UTF-8 with no byte order mark, **MUST NOT** be compressed
(method 1, "stored"), and **MUST** be in the canonical form of section 5 with no trailing
newline. Stored rather than deflated because a compressed claim adds a way for two
implementations to disagree about bytes that are supposed to be identical.

Encryption, ZIP64 and multi-disk archives are not supported in 0.1; a verifier that meets one
**MUST** refuse the container rather than guess (D-008).

### 3.1 Why ZIP, and why not a new container

WACZ is already a ZIP, every language can write one, and a `.receipt` is therefore a
`.wacz` with a claim stapled into it - which means the ecosystem can read the capture with
the tools it already has (`py-wacz`, Browsertrix, ReplayWeb.page) and read the claim with
anything that parses JSON. Inventing a container would have bought nothing and cost
interoperability with the only community that has spent twenty years thinking about web
capture. See D-001.

## 4. The claim

`receipt.json` is a JSON object. The fields below are defined; **unknown fields are allowed
and are signed**, which is what makes section 5's "everything except two keys" rule worth
having.

```json
{
  "spec_version": "0.1.0",
  "canonical_form": "canonical-json-v1",
  "capture": {
    "path": "capture.wacz",
    "media_type": "application/wacz",
    "sha256": "9f2c…",
    "bytes": 20481,
    "captured_at": "2026-09-15T11:04:07Z"
  },
  "subject": {
    "url": "https://example.org/article",
    "final_url": "https://example.org/article?utm_source=newsletter",
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "document": { "sha256": "1c07…", "bytes": 18244 },
    "text": { "normalization": "text-v1", "sha256": "ab31…" }
  },
  "tool": { "name": "receipt", "version": "0.1.0" },
  "signature": null,
  "anchor": { "type": "none" }
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `spec_version` | string | yes | Semantic version of this specification the claim is written to. |
| `canonical_form` | string | yes | `"canonical-json-v1"`. A named form, so a future change is visible rather than silent. |
| `capture.path` | string | yes | Entry name of the capture inside the container. |
| `capture.media_type` | string | yes | `"application/wacz"` in 0.1. |
| `capture.profile` | string | no | What *kind* of capture this is. Absent means the producer is not saying. See section 4.4. |
| `capture.sha256` | hex string | yes | SHA-256 of the capture's bytes, exactly as stored. |
| `capture.bytes` | integer | yes | Length of the capture. Redundant with the digest on purpose: a claim that is wrong about its own size should say so precisely, not as "digest mismatch". |
| `capture.captured_at` | UTC timestamp | yes | When the capture was taken, **as claimed**. Whether it is attested is a separate level (section 8). |
| `subject.url` | URL | yes | The address cited. |
| `subject.final_url` | URL | no | Where the capture ended up, when that differs (redirects). |
| `subject.status` | integer | no | HTTP status of the main document. |
| `subject.content_type` | string | no | `Content-Type` of the main document as received. |
| `subject.document` | object | yes | `sha256` and `bytes` of the main document's response body. |
| `subject.text` | object | no | Optional `text-v1` fingerprint (section 9). |
| `tool` | object | yes | `name` and `version` of the program that produced the receipt. |
| `signature` | object or `null` | yes | Section 6. `null` is a value: "nobody signs for this". |
| `anchor` | object | yes | Section 8. `{"type":"none"}` is a value too, and the two are different from a missing field. |

### 4.1 Timestamps

A timestamp **MUST** be UTC to the second, in exactly the form `2026-09-15T11:04:07Z`.

Milliseconds, offsets and local times are refused. This looks pedantic and is not: a claim
that says `+01:00` and a claim that says `Z` for the same instant are different byte strings,
so a signature over one fails over the other, and the failure looks like a signature problem
rather than a formatting one. There is exactly one spelling of a moment, and it is this one.

### 4.2 `subject.document` is a claim about the capture, not a check the verifier performs

The digest of the main document's body is recorded so that two receipts for the same URL can
be compared - "the words changed" versus "the bytes changed" - and so that a tool with a WARC
reader can check it.

**A verifier MUST NOT re-derive it.** Section 7.4 defines no check for it, because a verifier
that mis-parses a WARC reports a change that never happened, and declining costs the reader
nothing.

**A producer MUST derive it**, because the claim requires the field and a producer has no honest
way to decline. `vidimus seal` reads the response record for `subject.url` from the capture's
WARC and digests the body that follows the HTTP headers, cut to the length the response declares.
A producer that cannot read the capture **MUST** refuse to seal rather than write a digest it did
not measure.

That difference is not an inconsistency; it is the difference between the two jobs. A verifier
that declines loses nothing, and a producer that guesses writes a falsehood inside a signature
(D-016).

`subject.text` is the part of this that *is* specified for verification, because "did the page
change" is the question people actually ask. It is defined over a rendered document and is
optional.

### 4.3 Why `anchor` is required even when there is none

`{"type":"none"}` and a missing `anchor` would verify differently in a naive verifier ("no
anchor, so nothing to check"), and the difference between "the author did not anchor this"
and "this receipt does not say" is worth a required field. It is also signed, because an
anchor that could have existed at signing time is inside the signed subtree (section 6.1) -
which matters more than it sounds: see D-011.

## 4.4 `capture.profile`: what kind of capture is it

A capture can hold very different things and still be a valid WACZ. Two of them look identical to a
verifier that only counts bytes:

- **`document-v1`** — the main document as a browser rendered it, with the transport headers that
  describe a wire representation removed (`Content-Length`, `Content-Encoding`,
  `Transfer-Encoding`). This is what a Manifest V3 extension can honestly capture, because it cannot
  read the body of a response the page made.
- **the bytes the server sent** — a WARC response record whose payload is what came over the wire,
  which is what crawling tools produce.

Those are not the same claim. "Here is what the page said to me, as it rendered" and "here is what the
server sent" differ whenever a page is assembled by scripts, and a reader deciding whether a receipt is
good enough for their purpose needs to know which one they are holding.

So `capture.profile` names it. The field is **optional**, and absence is a fact rather than a defect:
it means the producer is not saying, which is the honest position for a tool that captured a WACZ
somebody else wrote.

A verifier **MUST** report the declared profile in its verdict, along with whether it understands it,
and **MUST** raise a caveat when the profile is one it does not interpret. It **MUST NOT** treat an
unrecognised profile as a pass *or* as a failure: the bytes are checkable and the *meaning* of the
capture is not, and those are different statements.

### 4.4.1 Why this is not a check

It was proposed as one, and the proposal does not survive the level rules of section 7.3. A level is
`pass` only when every check in it is `pass`, so a check that *cannot apply* to a receipt - and a
profile check cannot apply to a claim that declares no profile - would make that level unverifiable for
every receipt that omits the optional field. Adding it to L0 in 0.1.0 would have turned every receipt
written without a profile into one whose integrity could not be verified, which is absurd.

Two rules fall out of that, and they are worth stating because they constrain what a check can ever be:

1. **A check must always apply to a receipt that reaches its level.** If a fact is optional, its
   absence is reported as a caveat or a declared field, not as a check.
2. **A field whose meaning a verifier cannot check is reported, and named as uncontrolled.** That is
   what the verdict's `capture` block is for - it is information for a reader, not evidence of anything.

## 5. Canonical form: `canonical-json-v1`

The signed material is a *byte string*, so it needs exactly one spelling. This is that
spelling, and it is deliberately **not** RFC 8785 in full - it is the subset of JCS that a
claim is allowed to contain, enforced rather than assumed.

A canonicaliser **MUST**:

1. Emit UTF-8 with no byte order mark.
2. Sort object keys by UTF-16 code unit - what `Array.prototype.sort` does, and what RFC 8785
   specifies.
3. Emit no whitespace anywhere.
4. Escape only `"`, `\` and C0 controls, using `\b \t \n \f \r` for the five that have short
   forms, and emit every non-ASCII character as itself.
5. Refuse any number that is not an integer, any `-0`, and any integer outside
   `[-(2^53-1), 2^53-1]`.
6. Refuse values with no JSON representation: `undefined`, functions, bigints, symbols, and
   objects that are not plain (`Date`, `Map`, typed arrays, class instances).
7. Refuse a string containing an unpaired surrogate, since it has no UTF-8 encoding two
   implementations will agree on.

A verifier **SHOULD** refuse nesting deeper than 64 levels so a hostile claim cannot exhaust a
stack.

### 5.1 Why integers only, and no floats at all

Nearly every cross-language canonicalisation bug that has ever bitten a signature scheme is a
number. `1e21`, `-0`, `0.1`, `1.0`: JSON allows several spellings of the same value, the
shortest-round-trip rules differ between languages, and the failure mode is a signature that
does not verify for a reason nobody can debug from the error message.

The claim format simply does not need fractions. Sizes, counts and status codes are integers.
Timestamps are strings. So the rule is integers only, and a float anywhere in signed material
is a *named* failure - `non-integer number: canonical-json-v1 admits integers only (at
.subject.document.bytes)` - rather than a rounding difference. The vectors include a receipt
with `1.5` in it so that this refusal is exercised rather than assumed.

### 5.2 The delivered bytes must *be* the canonical bytes

`receipt.json` **MUST** be delivered in canonical form - not merely contain data that could be
canonicalised - and a verifier **MUST** compare the bytes it received against the canonical form
of the value it parsed.

That comparison is not decoration. `JSON.parse` silently keeps the *last* of two identical
keys, so a claim containing `"url":"https://a","url":"https://b"` parses to one value while two
readers of the raw bytes can disagree about which one was signed. Re-canonicalising and
comparing closes that gap, and it also catches a receipt that was pretty-printed or
re-serialised after signing - which is not a formatting problem: it means the bytes that were
signed are not the bytes that were delivered.

The most instructive vector is `claim-not-canonical`: the signature still verifies, because the
*content* is intact, and the receipt is still rejected, because the *document* is not the one
that was signed. Both facts appear in the same verdict (`signature.verify: pass` beside
`manifest.canonical: fail`) so no reader can mistake which check did the work.

### 5.3 The form must be a fixed point

Canonicalising the canonical form **MUST** yield the same bytes. A canonicaliser that is not
idempotent is not deterministic, and a signature over a non-deterministic byte string is a coin
flip. A verifier **SHOULD** check this (`claim.digest`) rather than trust it.

## 6. Signing

### 6.1 The signed subtree

The signature covers the claim **minus** two things, and this is the whole of the rule:

| Key | Signed? | Why |
| --- | --- | --- |
| `signature` | never | A signature cannot cover itself. |
| `anchor` where `type` is `"rfc3161"` | no | An RFC 3161 token is a *response* to a digest, so it cannot exist before the digest it commits to - and it does not need to be inside, because it independently commits to the claim hash. Editing it can only make verification fail or produce a token that must itself be validated. |
| `anchor` of any other type, including `"none"` | yes | `{"type":"none"}` is a statement the author makes at signing time, and a chain link knows its `sequence` and `prev_claim_hash` before the claim hash exists. Leaving these outside the signature would let anyone bolt `{"type":"chain","sequence":1}` onto an unanchored receipt and turn L2 from "not checked" into "verified" (D-011). |
| every other key, **including keys this specification does not define** | yes | A signed document that ignores unknown fields is a document with a signature in one corner. The vectors include a receipt with an undocumented `notes` field, to pin this. |

In one sentence: **an anchor that could have existed when the claim was signed is signed; one
that cannot be is not, and is verifiable on its own instead.**

### 6.2 The claim hash

```
claim_hash = SHA-256( UTF-8( canonicalise( signed_subtree ) ) )
```

Lowercase hex, **computed and never stored** (D-004). A stored claim hash would be a second
source of truth for a value that is already derivable, and the two would eventually disagree -
with the stored one winning, because it is the one that gets copied around.

The claim hash is how a receipt is *referred to*: "receipt `a24994a5…`", "the previous claim
hash", "the token commits to this hash". A verifier **MUST** report it, whether or not the
signature verifies, so that a broken receipt can still be identified.

### 6.3 The signature object

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `alg` | string | yes | `"ed25519"` in 0.1. |
| `key_id` | hex string | yes | SHA-256 of the raw public key. A verifier **MUST** check this before examining the signature: the id is derived, never asserted. |
| `public_key` | base64url | yes | The raw 32-byte Ed25519 public key, carried with the claim. |
| `sig` | base64url | yes | The 64-byte signature. |
| `signer` | string | no | A human-readable name. **Self-asserted and unsigned**, because it lives in the one object that cannot sign itself. A verifier **MUST NOT** present it as verified. |

Ed25519 because it is deterministic (the same key and message always produce the same 64
bytes, so a fixture can record one), because there is no per-signature nonce to get wrong, and
because every runtime now has it: `node:crypto` and WebCrypto both.

Anything that must be trustworthy belongs in the claim, where it is signed - not in this object.
The `notes` field in the vector with `id: valid-signed-with-notes` makes that concrete.

### 6.4 The message that is signed

```
vidimus/claim/<spec_version>:<claim_hash>
```

ASCII, no trailing newline, signed as bytes. The version in the prefix is the one the claim
*declares*, so a receipt written to an older version keeps verifying against an older message
format instead of against whatever the verifier happens to implement (D-013).

The prefix is domain separation: a receipt signature is useless as a signature over anything
else, and a signature over anything else is useless here.

A verifier **MUST** look the prefix up by the major version it is checking rather than building it
from a single constant, and **MUST** report `signature.verify` as `not_checked` - never as a guess -
when it has no prefix for that version. This string is inside every signature ever produced, so the
only safe way to change it is to add an entry for a new major version and leave the old ones alone
(D-015).

### 6.5 The sequence a producer follows

Getting this order wrong is the most likely way to produce receipts that verify nowhere, so it
is stated as a procedure rather than left to the reader:

1. Capture the page. By the time you are here, it is already too late to change it.
2. Hash the capture: `capture.sha256`, `capture.bytes`.
3. Build the claim with `signature: null` and whatever anchor already exists.
4. Canonicalise the signed subtree and hash it: `claim_hash`.
5. Sign `vidimus/claim/<spec_version>:<claim_hash>`; put the result in `signature`.
6. Serialise the **whole** claim, signature included, in canonical form, and write it into the
   container beside the capture.
7. If an RFC 3161 token is obtained afterwards, add it and re-serialise. The claim hash does not
   change, so the signature does not either - which is why that anchor is excluded from the
   signed subtree in the first place.

### 6.6 What a signature proves, and does not

It proves: **the holder of the private key for `public_key` asserted this exact claim hash.**

It does not prove: that the key belongs to the person named in `signer`; that the signer told
the truth; that the capture is complete; that the claim hash was computed correctly; or that
anything happened at the time the claim says. Those are the jobs of key directories (which are
outside this specification), of the anchor (section 8), and of the verifier's judgement.

## 7. Verification

### 7.1 Statuses

Every check reports exactly one of five statuses.

| Status | Means |
| --- | --- |
| `pass` | The check ran and the answer is yes. |
| `fail` | The check ran and the answer is no. |
| `not_checked` | The check could not run *here*, for a reason that is stated. |
| `unsupported` | The receipt asks for something this verifier does not implement. |
| `not_applicable` | The receipt does not contain the thing being checked. |

The distinction between `not_checked` and `not_applicable` is worth the extra state: "there is
no signature to check" and "I could not check the signature" are different sentences, and the
second one is alarming.

### 7.2 Every verdict contains every check

A verdict **MUST** contain a result for every check this specification defines, and a check that
did not run **MUST** appear as `not_checked` or `not_applicable` with a reason.

This is the single most important rule in the document. Omitting a check that never ran makes a
verdict look identical to one where it passed: a reader scanning for problems finds none, and
concludes there were none, when in fact nothing was examined. The reference implementation
asserts the completeness of every verdict before it returns, so a check added to the table and
forgotten in the code fails a test rather than disappearing from every report.

### 7.3 Levels

| Level | Name | The question it answers |
| --- | --- | --- |
| **L0** | integrity | Are these the bytes this receipt names? |
| **L1** | attribution | Did the named key sign this claim? |
| **L2** | time | Did anything other than the author attest that this claim existed? |
| **L3** | currency | Does the page still match, as of now? |

A level is `pass` **only when every check in it is `pass`** - no exceptions and no "pass with
warnings". A level whose checks are a mix of `pass` and `not_checked` is `not_checked`, because
the moment a partially examined level can print as verified, the level stops meaning anything.
`fail` outranks everything; then `unsupported`; then `not_checked`.

### 7.4 The checks

| Check | Level | Holds up when |
| --- | --- | --- |
| `container.readable` | L0 | The file is a ZIP this verifier can read: entries inflate, CRC-32s match, no ZIP64, no encryption. |
| `manifest.present` | L0 | `receipt.json` exists at the archive root. |
| `manifest.parseable` | L0 | It is UTF-8 and parses as a JSON object. |
| `manifest.spec_version` | L0 | The declared version is one this verifier implements. An unknown version is a `fail`, not a soft "unknown": nobody can honestly verify a claim they cannot read. |
| `manifest.canonical` | L0 | The delivered bytes *are* the canonical form of the parsed claim (section 5.2). |
| `manifest.shape` | L0 | Required fields are present and correctly typed, and entry names are confined to the archive (section 12). |
| `claim.digest` | L0 | The signed subtree canonicalises to a fixed point, so the claim hash is well defined. |
| `capture.present` | L0 | The entry named by `capture.path` exists. |
| `capture.bytes` | L0 | Its length equals `capture.bytes`. |
| `capture.digest` | L0 | Its SHA-256 equals `capture.sha256`. |
| `capture.media_type` | L0 | The media type is one this verifier reads (`application/wacz` in 0.1). |
| `capture.wacz.readable` | L0 | The capture is itself a readable container. |
| `capture.wacz.resources` | L0 | Every resource the capture's `datapackage.json` advertises is present and hashes to what it advertises. |
| `signature.present` | L1 | The claim carries a signature with the required fields. |
| `signature.alg` | L1 | The algorithm is implemented here. |
| `signature.key_id` | L1 | `key_id` equals the SHA-256 of `public_key`. |
| `signature.verify` | L1 | The signature verifies over `vidimus/claim/<version>:<claim_hash>`. |
| `anchor.present` | L2 | The claim carries an anchor, and its type is one this verifier knows. |
| `anchor.verified` | L2 | The anchor checks out (section 8). |
| `subject.text` | L3 | The `text-v1` fingerprint matches its definition. |

`capture.wacz.resources` sits in L0 rather than being left to the WACZ ecosystem because it is
the part of the capture that is *self-describing*. Without it, the container digest says only
"you have the same file I have", never "the file contains what it says it does" - a verifier
that skipped it would pass a WACZ whose inner WARC had been swapped for a different one of
exactly the same length.

The check names are the interface: they are the ids in the verdict JSON, the keys in issue
templates, and the headings in `docs/CONFORMANCE.md`. An implementation **MUST NOT** add checks
to a verdict without a specification change, because a consumer that keys off names would
silently ignore them.

### 7.5 `verified`, and the exit codes

`verified` is true when **L0 is `pass`, L1 is `pass`, and no check anywhere is `fail`.** Nothing
else is folded in: an unanchored receipt is verified and its time is not attested, an
unimplemented anchor does not un-verify the bytes, and a signer nobody can trace is still a
signer.

A command-line verifier **SHOULD** exit with three states rather than two:

| Code | Meaning |
| --- | --- |
| `0` | Verified: integrity and attribution both hold. |
| `1` | Nothing failed and nothing was proven: something was `not_checked` or `unsupported`, or the claim was unsigned. |
| `2` | Something failed, or the file could not be read at all. |

Three states, because "this receipt is broken" and "I could not check this receipt" must not
share an exit code in a pipeline. A script that collapses them will eventually assert a fact it
never established - and the vectors include a case for each of the three, so the distinction is
tested rather than described.

### 7.6 The summary

A verifier **SHOULD** produce a plain-language summary, and it **MUST NOT** describe a level as
verified when it is not. The reference implementation on a signed, unanchored receipt:

```
receipt 0.1.0 · claim fbf9d6d7…
subject https://example.org/a-page-worth-citing · captured 2026-01-01T00:00:00Z (self-asserted)
L0 integrity: verified — these are the bytes this receipt names
L1 attribution: verified — the named key signed this claim
L2 time: not checked — a third party attested the claim existed at a time
L3 currency: not applicable — the page still matches, as of now
signed by key 94161df6… (Fixture Signer <fixture@example.org>)
1 caveat
```

No tick, no "success", and the word *self-asserted* wherever a claim about time is the author's
own. The JSON verdict exists for programs; this exists for the person deciding whether to cite
the thing - and it is the summary, not the JSON, that decides whether they trust the wrong part
of it.

## 8. Time anchors

An anchor is evidence, produced by something other than the author, that the claim hash existed
at some time. Three types are defined in 0.1.

### 8.1 `{"type":"none"}`

No anchor. This is not a defect, it is an admission: the capture time is the author's own
statement.

A verifier **MUST** report `anchor.present` as `not_applicable`, `anchor.verified` as
`not_checked` with a reason naming the self-assertion, raise a caveat, and report the receipt's
time as `claimed_only`. It **MUST NOT** describe that time as verified, attested, proven or
confirmed.

### 8.2 `{"type":"chain","sequence":N,"prev_claim_hash":…}`

A link in an archive's own chain: receipt *N* names the claim hash of receipt *N-1*.

| Field | Required | Meaning |
| --- | --- | --- |
| `sequence` | yes | 1-based position. `1` is the head and **MUST NOT** carry `prev_claim_hash`. |
| `prev_claim_hash` | when `sequence > 1` | The claim hash of the preceding receipt. |

A verifier **MUST**:

- report `sequence: 1` with no predecessor as `pass` - "this is the first receipt" is a complete
  and checkable statement, unlike "the link matches", which needs the neighbour in hand;
- report a sequence above 1 whose `prev_claim_hash` does not match the neighbour it was given as
  `fail`;
- report `not_checked` when no neighbour was supplied, with a reason saying the link was not
  followed;
- report `not_checked` - never `pass` - when `signature.verify` is not `pass`, because a chain
  position is a statement the author makes *at signing time* and it commits to nothing if the
  signature does not hold (D-012).

**What a chain anchor proves:** ordering and completeness *within one archive*, to somebody who
holds that archive. **What it does not prove:** anything about time to a stranger, and anything
at all to a reader holding one receipt and taking its word for its own position. The reference
implementation raises a caveat saying exactly that, because the temptation to read "sequence 2"
as "therefore real" is the mistake this format exists to prevent.

### 8.3 `{"type":"rfc3161","token":…}`

A DER-encoded RFC 3161 timestamp token, base64url, whose message imprint is the claim hash.

This is the only anchor that gives a stranger a *time*, and it is the one the reference
implementation does not yet validate: it reports `anchor.present: pass`, `anchor.verified:
unsupported`, and a caveat - and never a level pass (see `docs/CONFORMANCE.md`).

What a conforming implementation **MUST** do before reporting `pass`, written down now so that a
half-implementation cannot answer "yes" too early:

1. Parse the CMS `SignedData` and validate the signature chain to a TSA the verifier is willing
   to trust - that trust being the caller's configuration, not a built-in list.
2. Check that the token's `messageImprint` equals the claim hash, under the same hash algorithm.
3. Check the token's `genTime`, applying the documented rules for a TSA whose certificate was
   valid only for part of that token's life.
4. Report the attested instant as `attested_before`. The honest phrasing is **"this claim
   existed no later than T"**, never "this page was captured at T": a timestamp bounds a claim
   from above, and it does not pin the capture to the instant the author wrote down.

### 8.4 How time is reported

| Field | Meaning |
| --- | --- |
| `time.claimed` | `capture.captured_at`, exactly as claimed. Present whenever the claim parses. |
| `time.bound` | `claimed_only` or `anchored`. |
| `time.anchor_type` | The declared anchor type. |
| `time.attested_before` | The instant an anchor attests the claim existed by, or `null`. |

`attested_before` is `null` in every verdict the reference implementation produces today, and
that is deliberate: no anchor implementation here yields a time, and filling the field from
`captured_at` would be precisely the conflation the field exists to prevent.

## 9. What a verifier in 0.1 does not do

Named here, with the check each one belongs to, because a limitation that is not written down is
a limitation somebody will assume away.

| Not done | Belongs to | Why it is not done yet |
| --- | --- | --- |
| Full WACZ validation | `capture.wacz.*` | The receipt layer depends on the container's own resource hashes, not on re-implementing the WACZ specification. Use `py-wacz` or the Webrecorder tooling for that. |
| WARC parsing, and re-deriving `subject.document` | no check; the **producer** does it | A half-parser that disagrees with a real one reports a *false change*, which is worse than reporting no change. The producer must derive it and refuse when it cannot (section 4.2, D-016). |
| Whether a capture holds the wire bytes or the rendered document | a field that does not exist yet | A Manifest V3 extension cannot read the body of a response the page made, so a browser capture holds the document **as rendered**. Nothing in the claim says which kind of capture it is, and a verifier cannot tell them apart. Section 13 proposes the field that would fix it, and this row exists so that the gap is named rather than assumed away. |
| `text-v1` | `subject.text` | Defined over a rendered document - the same deterministic DOM walk Shelf performs when it indexes a page - and the reference verifier has no HTML engine. It reports `not_checked` and says why (D-009). |
| RFC 3161 token validation | `anchor.verified` | Section 8.3. The check reports `unsupported`, never `pass`. |
| Level 3 (currency) | a comparison that is not yet specified | It needs the network, and this verifier makes no network requests by design. A **caller** that wants L3 performs the fetch itself and reports the result separately; it **MUST NOT** be folded into `verified`. |
| Key directories and trust roots | `signature.*` | Untrusting a key is a policy decision, and a format that hard-codes trust roots is a format that rots. The verdict reports `key_trusted` from a list the caller supplies (D-007). |
| Size limits | `container.readable` | Nothing here caps entry sizes, so a hostile receipt can ask a verifier to inflate a large entry. A caller reading untrusted receipts **SHOULD** cap the file it opens, and a 0.2 verifier **SHOULD** refuse declared sizes above a bound. Named because the current behaviour is "it works until it does not". |
| Provenance of authorship, watermarking | - | Out of scope. A receipt is evidence about a page, not a claim about who wrote it. |

## 10. Versioning and extensibility

**Minor and patch versions** may add optional fields, add anchor types, define checks for new
levels, and clarify language. They **MUST NOT** change the canonical form, the signed-subtree
rule, the message format, or the meaning of an existing check.

**A major version** may change any of those, and requires a new message prefix, so receipts
signed under the old version keep verifying.

| Encounter | A verifier's duty |
| --- | --- |
| Unknown field in the claim | Accept, and include it in the signed subtree. |
| `spec_version` whose major version is not implemented | `manifest.spec_version: fail`, and every other check `not_checked`. A verifier cannot honestly check a claim it cannot read, and must not present a soft "unknown" that reads like a pass. |
| Unknown `capture.media_type` | `capture.media_type: unsupported`; capture checks `not_checked`; the receipt is not verified. |
| Unknown `anchor.type` | `anchor.present` and `anchor.verified`: `unsupported`. The receipt can still be verified on L0 and L1. |
| Unknown `signature.alg` | `signature.alg: unsupported`; the remaining signature checks `not_checked`. |
| Extra check ids in a verdict | Not allowed without a specification change (section 7.4). |

The rule underneath the table: **never let an unrecognised thing become a pass.** Every unknown
lands on `unsupported` or `fail`, and both leave a level short of verified.

## 11. Conformance

An implementation conforms to **Receipt 0.1.0** when:

1. it implements every check in section 7.4 and reports every one of them in every verdict;
2. it applies the status, level-rollup and `verified` rules of sections 7.1-7.5;
3. it round-trips the canonical form of section 5 byte for byte, including the refusals; and
4. it produces the verdicts recorded in `spec/vectors/receipt-vectors.json` for the fixtures
   those vectors name.

The vectors are digests and verdicts, not blobs. Every fixture is generated from a deterministic
recipe in `reference/src/fixtures.mjs`, so a reader can rebuild it and compare, and the record
stays small enough to review in a diff. `node reference/src/vectors.mjs --check` performs
exactly that comparison, and `npm run verify` runs it as part of the repository's own gate.

Listing an implementation here means opening a pull request containing its results against the
vectors. That is a claim about agreement, not about quality: two implementations can conform and
still disagree about everything a user cares about.

## 12. Security considerations

- **A receipt is untrusted input.** Entry names are confined to the archive by `manifest.shape` -
  no absolute paths, no `..`, no backslashes, no drive letters - because that name reaches a
  filesystem call in every consumer. Sizes are not capped (section 9).
- **A receipt proves the existence of bytes, never their meaning.** `capture.digest` says you hold
  the capture the claim names. What the capture says is a question for a human being.
- **The signature covers the claim, not the container.** Bytes outside `receipt.json` and the
  capture - including stray entries - are outside both digests, which is why a verifier reports
  them as a caveat rather than ignoring them.
- **Signing a claim hash rather than a file** keeps the signature stable when an anchor is added
  later, and keeps it verifiable after the container is re-zipped. It also means a receipt
  signature is worthless outside this format, which is the point of the domain prefix.
- **A verifier must not become an oracle for the author's claims.** The caveat list exists so the
  report carries what the claim did *not* establish, not only what it did.

## 13. Open questions for 0.2

Written down now, with the reason each is deferred:

1. **RFC 3161 validation** (section 8.3). The specification is complete; the implementation is the
   work, and it is the first thing to pick up.
2. **`text-v1` in a verifier.** It needs an HTML engine. The natural home is the extension, which
   already has one - Shelf's `extractText` is the normative definition, so a verifier that reuses
   it conforms by construction (D-009).
3. **Level 3 as a procedure**: what to fetch, what to compare, and how to report "the page changed
   but the words did not". It needs a comparison report format, and it needs to be impossible to
   run by accident.
4. **Size limits** for untrusted input (section 9).
5. **Key directories.** A `.well-known` document, or simply a `receipt-keys.json`. Deliberately
   absent until there is a second implementer to disagree with about it.
6. **A claim that spans several URLs** - a bibliography, or a page plus the sources it cites.
7. **Attaching a receipt to the thing it supports**: a PDF (in the shape PAdES uses), a citation
   manager entry, a git commit. This is where the format meets its users, and it is out of scope
   only because 0.1 has to be checkable first.
8. **Filling in the profiles.** `document-v1` is defined and produced (section 4.4); a *wire* profile
   needs a name and something that can write one, which means a crawler rather than a browser extension.
   Naming it before anything can produce it would be a name with no meaning.
