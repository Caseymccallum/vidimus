# Vidimus architecture

This document records how the reference implementation is built and, more importantly, *why
certain obvious-looking designs were rejected*. Decisions are numbered (`D-00x`) so that code
comments, review threads and the specification can cite them, and so that reversing one is a
visible act rather than a quiet edit.

The specification ([`RECEIPT-SPEC.md`](RECEIPT-SPEC.md)) says what conforming implementations must
do. This file says what *this* implementation does and what it refused to do.

## 1. Shape

```
                reference/src/
canonical.mjs   canonical-json-v1: pure, no crypto, no I/O, no clock
encode.mjs      hex, base64 and UTF-8, without Buffer, so a browser can use them too
sha256.mjs      SHA-256 in plain arithmetic: the synchronous digest a browser does not have
digest.mjs      the Node-side hashing and encoding, on node:crypto
zip-common.mjs  the ZIP error type, CRC-32 and signatures, shared by the reader and the writer
zip-write.mjs   the ZIP writer: browser-safe, stored entries only, deterministic
zip.mjs         the ZIP reader: needs node:zlib to inflate, and re-exports the writer
gzip.mjs        a stored-deflate gzip writer, so fixtures are byte-identical everywhere
signature.mjs   Ed25519 over raw keys: sign, verify, key ids, and the one random seed generator
warc.mjs        a strict, narrow WARC reader: pure, with its inflater and digest supplied
wacz.mjs        finding the WARC inside a WACZ, for either runtime
warc-node.mjs   the record layer with Node's inflater and the project's SHA-256 supplied
text.mjs        `text-v1`: the words a reader would see, extracted deterministically from bytes
der.mjs         ASN.1 DER: strict enough to read an untrusted token, and enough to mint a fixture
x509.mjs        the certificate subset an RFC 3161 anchor needs, and no more
rfc3161.mjs     a timestamp token: the four steps of section 8.3, and the CMS bindings they rest on
tst-fixture.mjs a published, worthless TSA and its deterministic tokens, for the vectors
capture.mjs     what a browser knows, turned into a WACZ - browser-safe, and the extension's entry point
verify.mjs      the verifier: the check table, the stages, the verdict, the levels
seal.mjs        the producer: a capture in, a signed receipt out
fixtures.mjs    deterministic fixture construction from two published seeds
cases.mjs       one case per vector: how to build it, and the verdict it must produce
vectors.mjs     assert the expectations, record the vectors, check them
cli.mjs         `keygen`, `seal`, `verify`, `inspect`, and the only place that touches a file
```

`verify.mjs` is pure with respect to the outside world: it is handed bytes and options, reads no
clock, opens no file and makes no network request. `digest.mjs` and `signature.mjs` are the only
modules that touch a Node built-in, and only for cryptography (D-003). `cli.mjs` is the only module
that touches the filesystem, and it is thin on purpose so that there is no second place for a claim
about a verdict to be formed.

`spec/vectors/receipt-vectors.json` is the record: for each case, the fixture's digest and the
verdict it must produce. `spec/fixtures/` is generated on demand and gitignored (D-014).

## 2. Decisions

### D-001 - The container is a ZIP, and the capture inside it is a WACZ

A `.receipt` is a ZIP holding `receipt.json` and a `capture.wacz`. WACZ is the Webrecorder / IIPC
standard for packaged web archives, and it already solves packaging, resource hashing and replay.

**Rejected:** a bespoke container (nothing to gain, interoperability to lose); a single JSON file
with the capture base64ed inside (a third larger, and unreadable by every archive tool); PDF/A
(everyone's instinct, and it would make replay depend on a viewer that cannot be trusted with
untrusted HTML).

The point of adopting WACZ is not tidiness. It means the capture can be opened by `py-wacz`,
Browsertrix and ReplayWeb.page *today*, by people who have never heard of this project.

### D-002 - The reference implementation is plain ESM with JSDoc types, and has no build step

`npm test` runs `node --test` with **zero dependencies**. No `npm install`, no bundler, no
transpiler.

The reason is specific to what this repository is: a conformance suite. A suite that requires an
install step is a suite people skip, and a reference implementation with a dependency tree is one
that may not run in five years - which is exactly the timescale a citation format has to survive.
Sentinel's `scripts/*.mjs` gates (dependency-free Node scripts checking a TypeScript project) are
the precedent already in this codebase family.

**Rejected:** TypeScript with `tsc --noEmit` and vitest - the convention everywhere else in this
workspace, and the right choice for the *extension* later. The cost is real (no type checking) and
`scripts/check-syntax.mjs` exists to pay part of it, catching the mistake a test suite only finds if
it happens to import the file.

### D-003 - Canonicalisation and hashing live in separate modules

`canonical.mjs` has no crypto and no I/O; `digest.mjs` holds the SHA-256 and the encodings. The rule
of what a canonical form *is* can therefore be tested on its own, and a browser verifier can swap
`digest.mjs` for WebCrypto without touching the rules.

**Rejected:** one module that canonicalises and hashes (convenient, and it makes the rules impossible
to test without a crypto provider and impossible to port without re-reading them).

### D-004 - The claim hash is computed, never stored

There is no `claim_hash` field in the claim. The verifier derives it and reports it.

A stored hash would be a second source of truth for a value that is always derivable, and the two
would eventually disagree - with the stored one winning, because it is the one that gets copied into
messages and issue reports. It would also be circular: a hash cannot cover itself.

**Rejected:** storing `claim_hash` at the top level (needs an exclusion rule, creates the
disagreement above, and gains only the ability to name a receipt by a value a reader can compute
anyway).

### D-005 - Five statuses, and every check in every verdict

`pass`, `fail`, `not_checked`, `unsupported`, `not_applicable`; a level is `pass` only when every
check in it is `pass`; a verdict always contains every declared check.

This is the decision the whole project is shaped around. The failure mode of a verification tool is
not being forged - it is being believed when it checked nothing. A verdict that silently omits the
checks it could not run is indistinguishable from one where they passed, and the person reading it
has no way to tell.

**Rejected:** three statuses with `not_checked` collapsed into "unknown" (loses the difference
between "nothing to check" and "could not check"); omitting skipped checks (the failure above);
"pass with warnings" (the moment a partially examined level can print as verified, the level means
nothing).

`verifyReceipt` throws if the result count does not equal the check table's length, and
`verify.test.mjs` asserts completeness for all 34 cases.

### D-006 - `signature` is outside the signed subtree

A signature cannot cover itself. Everything else is inside, including fields this specification does
not define, so a claim cannot be extended after signing.

**Rejected:** signing the whole manifest with a placeholder signature field (a chicken-and-egg rule
every implementation gets subtly wrong the first time).

### D-007 - Key trust is the caller's, and the verdict says which of three states it is in

The verifier reports `key_trusted: trusted | untrusted | not_checked`, and ships no trust root.

A format that hard-codes who is trustworthy has to be reissued when they turn out not to be, and a
verifier that reports a valid signature as "trusted" is making a claim about a person it has never
met. `signature.verify: pass` means the key signed; it never means the key is one you should believe.

### D-008 - Unreadable containers are refused, not guessed at

ZIP64, encrypted entries, multi-disk archives and compression methods other than STORE and DEFLATE
each produce a named refusal.

**Rejected:** best-effort reading. A verifier that mis-reads a container reports a digest mismatch for
content that never changed, and the user learns to distrust the tool instead of the file.

### D-009 - `text-v1` is delegated to a DOM engine, and the CLI says `not_checked`

> **Superseded by D-024.** Everything below was reversed: the fingerprint is defined over the document's
> *bytes* (specification section 4.5) and the CLI checks it. It stays here because the reversal is the
> interesting part.
>
> D-024's answer to the objection in the last paragraph: there is still only *one* extractor, used by both
> runtimes, so the disagreements this decision was protecting against cannot arise - and the premise it
> rested on ("the reference CLI has no HTML engine") was never the obstacle it looked like, because the
> rules are a walk rather than a layout. What was really missing was a written-down definition; the
> hand-written extractor this decision rejected is `text.mjs`, and it is the *only* one.

The `subject.text` fingerprint is defined over a *rendered* document, using the same deterministic
walk Shelf performs when it indexes a page. The reference CLI has no HTML engine, so it validates the
declaration and reports the check as `not_checked` with that reason.

**Rejected:** hashing the raw HTML (useless for detecting a real change, since a nonce or a cookie
banner shifts it), and a hand-written "good enough" HTML-to-text extractor (a second implementation
whose disagreements with the first would look like content changes).

The extension is the natural home for this check: it already has the engine, and reusing
`extractText` means conforming by construction.

### D-010 - Fixture gzip is written here, in stored blocks

`gzip.mjs` wraps the fixture's WARC in a legal gzip stream of *stored* deflate blocks, with the mtime
zeroed and the OS byte pinned to "unknown".

`zlib.gzipSync` is deterministic on one machine and not across them: the header carries an OS byte and
the deflate stream depends on the zlib build. A conformance fixture whose bytes depend on who ran the
generator is not a fixture - it is a coincidence that holds on the author's laptop and fails for the
next person in a way that looks like a specification bug. The same class of trap proof-of-waves
documents under "the failure does not look like its cause".

Nothing here says a real capture tool should store its WARCs uncompressed. The verifier never
decompresses the capture; only the fixture has to be stable.

### D-011 - An anchor that could have existed at signing time is signed

`signedSubtree` drops `signature` always, and `anchor` only when its type is `rfc3161`.

A chain link knows its `sequence` and `prev_claim_hash` before the claim hash exists, and
`{"type":"none"}` is a statement made at signing time, so both are inside the signed subtree. Leaving
every anchor outside - the obvious reading of "the anchor is added after signing" - would have let
anyone add `{"type":"chain","sequence":1}` to an unanchored receipt and turn L2 from "not checked"
into "verified".

This hole was found while writing section 6.1 of the specification, not by a test. It is recorded
here, and the vector `anchor-bolted-on` exists so that it stays closed.

### D-012 - A chain anchor cannot pass without a valid signature

`anchor.verified` is `not_checked` for a chain anchor whenever `signature.verify` is not `pass`.

A chain position is the author's statement about their own archive, and it commits to nothing if the
signature over it does not hold. Without this rule a receipt with a broken signature and a bolted-on
anchor could still show "L2 time: verified - a third party attested the claim existed at a time",
which is the single most misleading sentence this format could produce. (The anchor is therefore
checked *after* the signature, for exactly this reason.)

### D-013 - The signed message is domain-separated and carries the declared version

```
vidimus/claim/<spec_version>:<claim_hash>
```

The version comes from the *claim*, so receipts written to an older version keep verifying against an
older message format rather than against whatever the verifier happens to implement. The prefix means
a receipt signature is worthless as a signature over anything else, and vice versa.

The prefix is held in a table keyed by major version (`SIGNING_PREFIX_BY_MAJOR`) rather than built by
string interpolation, and an unknown major version reports `not_checked` instead of guessing. That
structure exists for D-015's sake: a wire-format string that can be *added to* but never *edited*.

### D-014 - Fixtures are generated from a recipe and recorded as digests

`spec/fixtures/*.receipt` is gitignored; `spec/vectors/receipt-vectors.json` holds each fixture's
digest, length and expected verdict.

**Rejected:** committing the 34 fixture files - roughly 80 KB of binary that no reviewer can read and
no diff can explain. A recorded digest over a fixture rebuilt from a reviewed recipe catches
everything a committed blob would, and the recipe is reviewable. `--check` rebuilds every fixture and
re-hashes it on every run, so staleness is impossible rather than merely unlikely.

### D-015 - The project was renamed to Vidimus, and only the format kept the name

The project is **Vidimus** - repository, CLI, package, extension, and the identity a verifier reports.
The *format* keeps calling the artefact a **receipt**: `.receipt`, `receipt.json`, `verifyReceipt`,
`buildReceipt`, and the noun throughout the specification.

Two consequences, both fixed while the format had no users rather than afterwards:

1. **`verifier.name` is `vidimus`** (and the fixtures' `tool.name` is `vidimus-fixture`), because
   those fields name the *program*. A tool that reports itself as the format is a tool you cannot
   tell apart from the next implementation of it.
2. **The signing prefix changed from `receipt/claim/` to `vidimus/claim/`, and is now looked up per
   major version** (D-013). That string is inside every signature ever produced, so it is frozen from
   here: a future rename adds an entry for a new major version and leaves 0.1.0 alone. Doing it now
   cost one `vectors:generate` and a diff; doing it after the first receipt was published would have
   cost a format version.

**Rejected:** renaming the artefacts too (`.vidimus`, `vidimus.json`). Someone who has never heard of
this project can read `citation.receipt` and know what it is; `citation.vidimus` requires the
project's story first, and the one property a citation format cannot do without is being
self-explanatory to a stranger. The artefact explains itself; the project does not have to.

### D-016 - The producer derives the document digest from the capture, and refuses rather than guesses

`subject.document` is required by the claim, so a sealer has to answer it. It is answered by reading
the capture: `warc.mjs` finds the response record for `subject.url` and digests the body that follows
the HTTP headers, cut to the declared `Content-Length`.

The asymmetry with the verifier is deliberate, and worth stating plainly because it looks like an
inconsistency. The verifier declines to re-derive the same value (section 9 of the specification),
because a verifier that mis-parses reports a change that never happened. A producer cannot decline:
the field is required, and inventing one would put a false statement inside a signed claim, which is
worse than any missed check. So the producer's reader is strict - every shape it does not recognise is
an error, with no fallback and no partial read - and a capture it cannot read stops the seal.

A caller may override the digest with `document`, which exists for captures this reader cannot parse.
When that happens the sealer says so in a warning and the CLI prints it: the receipt is still valid,
but `subject.document` is now the caller's word about the page rather than the capture's.

**Rejected:** guessing the document out of the archive by entry name (`index.html` and its friends),
and treating a missing record as "no document" - the field is required, so absence is not an option.

### D-017 - `seal` verifies what it has just written

The CLI seals, then runs the verifier over the bytes it wrote, and reports success only if the verdict
is `verified`. If it is not, the file is deleted and the failure is reported as a bug in this program.

A producer that hands over an unchecked receipt makes the first person to find the bug somebody who
had already relied on the receipt - and the whole argument of this repository is that a receipt is
checked before it is believed. The habit has a second effect: the sealer's own correctness is
exercised on every invocation, not only by the test suite.

**Rejected:** a `--no-verify` flag for speed. Sealing is not on any hot path, and an escape hatch from
one's own verification is the kind of flag that ends up in a script nobody re-reads.

### D-018 - Making a capture is part of the format, so it lives here

`capture.mjs` turns what a browser knows into a WACZ: one WARC response record, gzipped, inside a
container that advertises it. It lives in the reference implementation rather than in the extension,
which means the extension imports it - and that is the point. There is one definition of what a
capture is, and the code that makes a capture and the code that reads one cannot drift apart.

The alternative - the extension building its own container - is the failure this repository exists to
avoid, and it would be invisible: two containers that both "work" until a reader meets the other one.

**The browser boundary is a tested property, not an aspiration.** A receipt is written in a browser and
read on a command line, so the capture chain (`capture.mjs`, `canonical.mjs`, `encode.mjs`,
`sha256.mjs`, `gzip.mjs`, `zip-common.mjs`, `zip-write.mjs`) must import nothing from Node. That
required splitting the ZIP reader from the ZIP writer, because the reader needs `zlib` and the writer
must not, and it is held in place by `reference/test/browser-safety.test.mjs`, which walks the import
graph from `capture.mjs` and fails on a `node:` import, a `Buffer`, or a reachable module that needs
either. It caught this work's own mistakes twice: a stray `digest.mjs` import, and a rule that broke on
the sentence documenting it.

### D-019 - The capture path carries its own SHA-256, and a test pins it to the runtime's

`sha256.mjs` is SHA-256 in plain arithmetic. A second implementation of a primitive is normally one too
many, and this one is accepted for a specific reason: the capture chain is synchronous (hash the
document, hash the response block, hash the WARC file, hash the canonical claim), and a browser's only
built-in digest is `crypto.subtle.digest`, which is asynchronous. The choice was between a synchronous
implementation here and `await` spread through every producer, fixture and test to satisfy one platform.

What makes it acceptable is that neither implementation is taken on its own word: the test suite checks
the published vectors, the million-character vector, every length around a block boundary (55, 56, 63,
64 - where padding bugs live), and agreement with `node:crypto` on real fixture bytes. If the two ever
disagree, the suite says so rather than a receipt failing to verify for an unexplainable reason.

### D-020 - The extension lives here, imports the format, and asks for the least it can

`extension/` is a WXT and TypeScript Manifest V3 extension that seals the page you are reading. It is in
this repository rather than beside it for one reason: it imports `capture.mjs`, `claim.mjs` and the rest
of the format, so there is exactly one definition of what a capture and a claim are, and the browser
producer cannot drift from the command-line one.

Three decisions inside it are worth recording:

1. **Every permission carries a written reason** (`extension/permissions.mjs`). The manifest is built
   from that file and a test fails if a permission appears without one. The list is `storage`,
   `scripting`, `webRequest` and `<all_urls>`: the host permission is what makes a response status
   observable, and without it the claim would carry no `status` and no `content_type`. That is a real
   trade, written down rather than assumed, and it is the first one to revisit.
2. **The signing key never leaves the browser**, and is never synced. It is generated with WebCrypto the
   first time it is needed and kept in `chrome.storage.local`.
3. **The browser logic is plain ESM in `extension/lib/`**, not TypeScript, so that the project's own test
   suite can run it in Node with Node's WebCrypto and check what it produces with the reference
   verifier. A browser is needed to *use* this extension, not to know that it works.

**What it cannot do yet**, named rather than implied: it cannot verify its own output, because the
verifier needs Node; and its capture is the document as rendered rather than the bytes the server sent,
because Manifest V3 cannot read a response body. Both are in `docs/CONFORMANCE.md` as gaps with what
closing them would take.

### D-021 - The verifier takes a runtime, because a browser cannot check a signature synchronously

The verifier's *rules* are shared; its *primitives* are not. So `verifyReceipt` takes a `runtime`
supplying four things - a digest, a container reader, a key id, and a signature check - and everything on
a command line gets the Node one through `verify-node.mjs`, a one-line wrapper that exists so that no call
site has to care.

The forcing constraint is signature verification. Node's `crypto.verify` is synchronous; a browser's only
option is `crypto.subtle.verify`, which returns a promise. Rather than write a curve implementation in
JavaScript to preserve a synchronous API - and a hand-rolled verifier is precisely what WebCrypto exists
to avoid - the verifier awaits its runtime, and one `await` travels up through the CLI, the vectors
runner and the tests.

Two consequences worth naming:

1. **A runtime may declare a limit instead of a verdict.** An error carrying `code: 'unsupported'` means
   *this* verifier cannot read *that kind* of container, and the check reports `unsupported` rather than
   `fail`. A browser cannot read ZIP64, a multi-disk archive, an encrypted entry or an unknown
   compression method - so those are a gap in the verifier rather than a fault in the receipt, and calling
   them a failure would be a lie in the safer direction, which is still a lie.
2. **The two runtimes are pinned to each other by a test** that does not merely assert that both pass: it
   asserts that the two verdicts are identical, reason for reason. Two runtimes can agree on an outcome
   and still disagree about why.

**Rejected:** a synchronous hand-written Ed25519 verification, and a second verifier written for the
browser. The first is a security decision - verification code that silently accepts a bad signature would
be the worst possible bug in this project - and the second is the duplication this repository exists to
avoid.

### D-022 - A receipt says what kind of capture it holds, and stays silent when it cannot

`capture.profile` is an optional field naming the kind of capture: `document-v1` for a document as a
browser rendered it. The browser shell writes it, because it knows what it made. `vidimus seal` writes it
only when asked (`--profile`), because it seals captures other tools made and has no way to know what is
inside one. The fixtures leave it out, because a synthetic capture has no kind to declare.

**It is not a check, and the reason is a rule the level system imposes on every check.** A level is
`pass` only when every check in it is `pass`, so a check that *cannot apply* to some receipts would make
that level unverifiable for them. A profile check cannot apply to a claim that declares no profile -
which is every receipt written before this field existed, and every receipt from a tool that does not set
it. Adding it to L0 would have turned all of them into receipts whose integrity could not be verified,
which is absurd; and reporting absence as `pass` would be an unearned tick.

So the verdict reports it instead: `capture.profile` and `capture.profile_known`, with a caveat when the
profile is one this verifier does not interpret. The bytes are checked, and the *meaning* of the capture
is declared and named as such. Two rules worth keeping fall out of that, and they are in the
specification (section 4.4.1) where an implementer will meet them:

1. a check must always apply to a receipt that reaches its level;
2. a fact a verifier cannot check is reported, and named as uncontrolled, rather than judged.

**Rejected:** a check (above), and a *required* field - which would invalidate every receipt already
written and would force a sealer of foreign captures to guess at something it cannot see.

### D-023 - A capture can hold the document's files, and the claim says nothing about them

A capture is one archive file holding several WARC records: the document, then a record for each file it
referenced. That is what a WACZ already is - concatenated, individually gzipped records under `archive/` -
so the format needed no change at all, which is the whole return on having adopted it (D-001). A reader
finds a URL by its record, a replay tool intercepts a subresource request by the address it was made to,
and nothing in the document has to be rewritten.

Two decisions inside the implementation:

1. **A record's body may be bytes, not text.** An image is not a string, and a capture that mangles one is
   worse than a capture without it. That change also surfaced a silent wrongness: the HTTP block builder
   used to hand whatever it was given to a text encoder, so a record with no body produced a payload
   containing the word `undefined` - which a reader accepted and a claim would have described. It refuses
   by name now, and a test says so.
2. **Two records for one address are refused.** A capture holding the same URL twice would be ambiguous
   about which of them is the document, and a reader would pick one arbitrarily.

**The claim gains no field for this, deliberately.** How much a capture holds is answerable *from the
capture* - a reader with the file can count the records - so putting it in a signed claim would create a
second source of truth for something already answerable. What the claim says, as ever, is the one digest:
the document, and only the document, whatever travels beside it.

The extension gathers the files by **fetching them again**, and reports how many it kept and left out,
because a browser will not hand over the body of a response the page made. Those fetches are the only
requests the extension makes, and `extension/README.md` says so in the same breath as the permission table.

### D-024 - `text-v1` is defined over bytes, so every verifier can check it

The fingerprint used to be this project's one check that could not run: `subject.text: not_checked`, "this
verifier has no HTML engine". The argument was that the normative definition lived in Shelf's
`extractText`, and that checking it needed a DOM. Both halves of that were wrong, in opposite directions:

- **The definition is now written down** (section 4.5.1 of the specification). A format that defers a
  normative definition to another project's source file is not a format: a second implementer can read a
  rule and disagree with it, but they cannot read a rule that is a TypeScript function. Shelf's
  `extractText` is where the rules came from and the specification says so.
- **A DOM was never needed.** The rules are a walk, not a layout: which elements end a line, which are
  skipped, how whitespace collapses, what a stray `<` means. `innerText` would have needed a browser, and
  that is one of the reasons Shelf refuses it too.

Two consequences worth recording:

1. **One extractor, both runtimes.** `text.mjs` has no DOM and no Node: it walks bytes, which is what a
   verifier holding a capture has. A receipt therefore cannot be a `pass` on a command line and
   `not_checked` in a browser - two answers to one question, which is what the shared rules exist to
   prevent. Reaching that point meant making the WARC record layer pure as well, because a browser has to
   re-read a capture's document before it can check the fingerprint at all: the runtime seam gained
   `mainDocument`, and `warc.mjs` gave up its own `zlib` and digest imports (D-021, extended).
2. **L3 can now pass**, and the level's claim changed to what it actually establishes: *the words in the
   capture are the words the claim fingerprints*. It still does not say the page says them **now** - that
   is a request, and a verifier makes none (D-005). The coverage rule in `docs/CONFORMANCE.md` that said
   "every level reaches a pass except L3" is gone, deliberately, and the level's old wording ("the page
   still matches, as of now") is gone with it.

**This check found a bug in this project's own fixtures.** `valid-with-text` declared a digest over the
heading alone - plausible, and not the words the capture held - and nothing had ever contradicted it,
because nothing checked it. It is now `text-fingerprint-wrong`, kept as a vector *because* it was real: it
is exactly what a producer whose extractor disagreed with the definition would emit.

**What it still does not do** is compare the document it re-read with `subject.document.sha256`. That would
be a new check rather than a new implementation, and the specification's section 9 names it as a candidate
for 0.2 rather than leaving a reader to assume the two are the same thing.

### D-025 - The comparison with the page now is a command of its own, with its own report

`verify` reads no clock and makes no request, so "does the page still say this?" is not a question it can
answer. The tempting shortcut - have `verify` fetch when a flag is given - would make a verdict depend on
whether the machine had a network, which is the same receipt verifying differently in two places for a
reason that has nothing to do with the receipt (D-005).

So the comparison is `vidimus check`, and it is a separate command rather than a flag on `verify`:

- **It says what it is doing.** Its own name, its own output, and a line that names the request it is about
  to make. "Impossible to run by accident" is a property of the interface, not of a warning.
- **It compares two claims, not a claim and a fetch.** The second look is sealed into a real receipt by the
  same producer, so both fingerprints were computed by the same rules over the same kind of input. That is
  what lets `words_unchanged` mean anything at all.
- **The report is a separate object** (`reference/src/currency.mjs`), returned and printed beside the
  verdict and never merged into it.
- **The exit code is the verdict's**, unless `--require-same-words` is passed, in which case the comparison
  decides: `0` the words are unchanged, `1` they are not, `2` they could not be compared. A build that
  fails because a page changed is a decision somebody made; a build that fails because a page changed while
  claiming to check a receipt is not.

The outcome set is five values rather than a boolean, because the useful cases are not "same" and
"different": `words_unchanged` is the one people cannot construct for themselves from two hashes without
getting the framing wrong, and `gone` exists so that a 404 is never reported as a page whose words changed.

**Rejected:** a `--fetch` flag on `verify` (a verdict that depends on the network); an `L3` check that
compares against a fetched page (checks must be answerable by a verifier holding the file, and this one is
not); and adding the comparison to the verdict JSON (the two would be read as one answer).

### D-026 - The verdict reports what the claim asserts

`subject` in the verdict JSON: the URL, the final URL, the status, the capture time, the document digest
and its length, and the text fingerprint - each `null` when the claim does not carry it.

This exists because `check` needs it and the alternative was worse. A command that compares a receipt with
a page has to know which URL to fetch and which words to compare against, and without this field it would
have to open `receipt.json` itself, canonical form and all - a second parser for the format in the one
module that is deliberately thin (`cli.mjs`). A verdict that cannot say *what the claim asserts* is also a
poor thing to hand a program: before this, a script could read a claim hash and nothing about the page.

What it is not: a check. Nothing here is judged, and no level depends on it. It is the same kind of
information as `capture.profile` - reported so a reader knows what they are holding (section 4.4), not
offered as evidence that it is true.

### D-027 - A key directory is trusted because it was chosen, not because it is signed

The gap was named a long time ago and left open on purpose: `signature.signer` lives inside the signature,
which proves the key asserted the name and nothing about whether the name is true. What the format could
always prove is *a* key signed; it could never prove *whose* (D-007).

What was missing was not identity - it was a way for a caller to say "this key is Example Org's", and a
document to say it in. `reference/src/key-directory.mjs` is that document's reader: pure, browser-safe, and
with exactly two self-consistency rules, each refused by name rather than resolved.

1. **`key_id` must be the digest of `public_key`.** The same derived-never-asserted rule as everywhere
   else, applied to the one file that names keys without being signed by them. A directory cannot disagree
   with itself about which key an id names.
2. **No two entries may share a key id.** A directory that says two things about one key is not one.

Three refusals in the design are worth recording, because each is the tempting alternative:

- **No signature on a directory.** It moves the question back one step, and nothing on the receiving end
  can check the answer without another directory. A `.well-known` fetch of one is *also* declined: a
  directory reached over the network is one an attacker can replace, so fetching is the caller's decision
  to make (the open question in section 13), not a side effect of running a verifier.
- **No level depends on a directory.** Key trust is a field in the verdict (`key_trusted`,
  `attribution.trusted_by`), and the levels are exactly as they were. This is what keeps "the same receipt
  verifies the same way on two machines" true when the two machines have different directories.
- **No judging of validity windows.** `valid_from`/`valid_until` are compared with the claim's own
  `captured_at` and the result is reported, because the only timestamp available is the author's statement
  about themselves - the same distinction as `time.bound: claimed_only`. A verifier that failed a receipt
  for being outside a directory's window would be asserting a time nobody established.

**A caller's mistake is a caveat, not damage.** A directory that cannot be read leaves `key_trusted` where
it was and adds a line saying why: mistyping a path must not make somebody's receipt look worse.

### D-028 - A citation is built from what the claim asserts, and adds nothing to it

A receipt is evidence, and evidence travels with a reference to the work it supports. So `vidimus cite`
writes one - in CSL-JSON, which citation managers already read, rather than in a format invented here - plus
a plain sentence and a `Receipt:` line for a commit message.

The decision worth recording is what the citation *does not* contain. A claim asserts a URL, a capture time,
a document digest and the words on the page. It does **not** assert a title, an author or a publication
date: those are facts about a work, and a capture of a page is not a claim about one. So the citation
carries a URL, an access date and the claim hash as its identifier, and a title only when the person citing
supplies one (`--title`). Inventing a title from, say, the first line of the text fingerprint would be the
plausible falsehood this project refuses inside a signed claim, and a bibliography is no place to start
writing them.

Three smaller decisions:

1. **The identifier is the claim hash.** It is what makes a citation checkable: somebody holding the receipt
   recomputes it, and somebody holding the citation can search an index by it.
2. **`--index` appends one JSON line.** A repository that cites pages needs a list of what it cites, and a
   file of receipts nobody can search is not a list. The line records the receipt's path, so the index
   points at the evidence rather than duplicating it.
3. **A receipt that did not verify is still citable, and says so.** The citer may know something this
   machine does not; what must not happen is a citation that looks confirmed when it was not, so the
   command prints the warning beside it and exits non-zero.

**Rejected:** a PDF attachment in the shape PAdES uses, for now. It needs a CMS `SignedData` over the
document's byte range and an incremental update, neither of which exists here - and an "attachment" that no
viewer can verify would look like evidence while being a file next to a document. Named in section 13 of the
specification with what it would take, and the sidecar pattern (a `.receipt` beside the file, an index line
in the repository) covers the need honestly in the meantime.

### D-029 - An RFC 3161 anchor is validated against a certificate the caller pins

Section 8.3 was written before any implementation existed, listing four things a verifier must do before it
may answer `pass`. This is that list, implemented, plus the two decisions the list left open.

**Trust is a pin, not a chain.** RFC 3161 says to validate the signature "to a TSA the verifier is willing
to trust", and the narrowest honest reading of that is a certificate the caller supplied - by DER or by
SHA-256 fingerprint. There is no built-in authority list, and no chain building to a root: a pin *is* an
anchor, so a token signed by anything else is `not_checked` with the signer's fingerprint reported, which is
the same shape as `key_trusted` and for the same reason (D-007). Anything else would mean choosing a
bundle, shipping it, and owning its expiry.

**A pin does not suspend the protocol.** A certificate the caller trusts still has to *be* a timestamping
certificate: RFC 3161 requires the `timeStamping` extended key usage, and its key usage has to permit
signing. A pinned certificate that fails either is a `fail`, not a shrug - the pin says "believe these
bytes", not "believe anything they sign".

Three smaller decisions:

1. **`genTime` must fall inside the signing certificate's validity window**, and nothing consults a
   revocation list. Both halves are stated in the specification, because a verifier that implied "valid
   certificate" while checking no revocation would be answering a question it was not asked.
2. **Four outcomes, not two.** `verified` and `invalid` are the answers; `untrusted_signer` and
   `unreadable` are the *verifier's* position, and they map to `not_checked` and `unsupported` - so a
   token this code cannot read, or an algorithm it does not implement, never becomes a fault in somebody's
   receipt (D-021).
3. **The two CMS bindings are checked**, because a signature over attributes that describe nothing verifies
   perfectly: the signed attributes must name the `TSTInfo` content type and carry the digest of the content
   they sign. The token's signature is checked over the attributes re-tagged as `SET OF`, which is the one
   detail everybody gets wrong once.

**The fixture is a published, worthless key.** The vectors need a token, and a fixture has to be a
deterministic function of committed bytes: RSA PKCS#1 v1.5 signing is deterministic, so a token minted from
fixed values is byte-identical everywhere (D-014). The key lives in `tst-fixture.mjs` with a common name
that says what it is, for the same reason the Ed25519 seeds already did. The certificate it signs is
self-signed with no chain, which is exactly what a fixture should be and exactly what a real TSA should not.

Two things this work found, both worth recording:

- **A DER reader bug**, caught by the fixture before a single vector existed: `tag` held the low five bits
  of the first byte, so `SEQUENCE` (`0x30`) read as `0x10`. Every universal primitive tag happens to have
  the same low five bits as its whole byte, which is why the bug survived the first three tests; the
  constructed tags are where it shows, and the typedef now says so in as many words.
- **`keyUsage` is a `BIT STRING`**, so its first content byte is the count of unused trailing bits rather
  than the bits themselves. Reading it one byte early is how a certificate that permits signing reports
  itself as forbidding it.

### D-030 - A verifier decides what it will inflate, before it inflates anything

A receipt is untrusted input, and both of its layers expand: `.receipt` is a ZIP, the WACZ inside it is
another ZIP, and the WARC inside that is gzipped. The old behaviour was to inflate whatever a file asked
for, which meant a few kilobytes could ask for gigabytes - named as a limitation in the threat model for
long enough that it stopped being a note and started being a hole.

Three decisions:

1. **The ceiling is checked twice.** Before the bytes are touched, against the declared size - which costs
   nothing and refuses the honest bomb - and again *while* inflating, because a declaration is not evidence.
   Node's `inflateRawSync` and `gunzipSync` take `maxOutputLength`, which stops mid-stream; a browser has no
   such option, so `browser-zip.mjs` reads the stream in chunks and cancels the reader the moment the total
   passes the ceiling. That is the difference between refusing a bomb and surviving one.
2. **A limit is the verifier's, so it is reported as the verifier's.** Every limit refusal carries
   `code: 'unsupported'`, which the verifier already maps to `unsupported` with the reason - the distinction
   D-021 draws everywhere else (a gap in the verifier is not a fault in a receipt), and D-008 draws for
   containers (refuse by name rather than guess). This work also closed a *pre-existing* asymmetry: the
   capture's WACZ was the one read that reported `fail` for a container it could not open, while the outer
   container reported `unsupported` for the same thing.
3. **The limits are the caller's to raise, and this format states none.** They are passed *into* the
   runtime rather than baked into the readers, so a caller that needs more says so - and the producer passes
   none at all, because a producer sealing a capture the user chose is not defending against that user.

The numbers - 64 MB an entry, 256 MB a container, 4096 entries - are chosen to be larger than anything this
project's own producer can write, and a test asserts that against the extension's 8 MB capture limit. A cap
that refused every receipt this project makes would be a bug with a number attached.

**Found while writing the tests:** Node rejects `maxOutputLength: Infinity`, so "no ceiling" has to mean
omitting the option rather than passing an infinite one. Two existing tests caught it immediately, because
they read real DEFLATE archives written by other tools - which is the argument for having vectors made of
somebody else's output rather than only your own.

### D-031 - The vectors ship as a kit, so a second implementation need not rebuild ours

The conformance vectors have always recorded each fixture's SHA-256, and the fixtures have never been
committed: they are generated from a recipe in `fixtures.mjs`, and the recipes are the record (D-014). That
is right for *this* repository and useless to a stranger, which is the only audience a conformance suite
has. A digest nobody can produce the file for is not evidence of anything, and the alternative on offer was
"reimplement our fixture builder before writing a line of your own reader" - which is a test suite that
tests nothing about the reader.

So `--emit <dir>` writes a **kit**: the 45 fixtures, the answers, and a README that says what to do with
them. Three decisions inside that:

1. **The kit carries the committed record byte for byte.** A kit that described answers the repository does
   not hold would be a second source of truth, and this project has spent a lot of effort having none.
2. **`--check-kit <dir>` exists to run a stranger's path here.** It reads the fixtures from disk, hashes them
   against the kit's own record, verifies them and compares against the promised verdicts - rebuilding
   nothing. Without it, the emit path would be the one code path in the repository with no test, and it
   would rot in the usual way: quietly, and in the direction of being believed.
3. **The kit is not committed.** Emitting on demand costs one command, and committing 41 binaries so that
   they can drift against the recipes that generate them would trade a real guarantee for a convenience.

What the kit deliberately excludes is as much the point: reasons, prose and the `expect` field stay behind,
because they are documentation of *why*, and a second implementation should be free to disagree with the
wording. What it must not be free to disagree with is which check reported what.

### D-032 - `subject.document` is re-derived, and a record nobody can read no longer passes L0

Section 4.2 used to say **"A verifier MUST NOT re-derive it"**, on the argument that a verifier which
mis-parses a WARC reports a change that never happened. That argument was sound about *change* and wrong about
*verification*: the field is the claim's own account of what its capture holds, and an account nobody checks
is taken on the word of whoever wrote it. A producer that hashed something else - or that pointed the claim at
another document entirely - passed L0 on a signed *assertion*, which is the "lying author" the threat model
has named since its first draft.

The objection is answered rather than dropped. A capture this narrow reader cannot open is reported
`not_checked` **with the reason**, never as a change and never as a pass - the rule the rest of the verifier
already follows for its own limits (D-021). The consequence is deliberate and worth stating plainly: **a
receipt whose record this verifier cannot read no longer passes L0**, because "these are the bytes this
receipt names" now includes "and this claim describes them". That is a tightening, and it moves `verified`
for receipts that were previously green on the strength of a digest nobody had confirmed.

Three details:

1. **One read, two checks.** `subject.text` and `subject.document` share a cached read of the capture, so
   neither pays for the other's inflation.
2. **The length is checked as well as the digest.** Redundant by construction, and kept, because it is the
   one a person checks by eye - and "the claim describes a document of another size" is a different sentence
   from "the bytes hash differently".
3. **The producer now refuses to write a claim that lies.** `seal --document` exists for captures this
   reader cannot open; aimed at a capture it *can* open, the override makes the claim describe bytes the
   capture does not hold, and `seal`'s self-check catches it and removes the file (D-017).

**Found while doing this, and worth recording:** `seal`'s self-check demanded exit code 0, so *any* receipt
that was sound but not fully verified was deleted with "that is a bug in this program". That included
`seal --unsigned` - a documented flag - and a caller-supplied document on a capture this reader cannot open,
which is that flag's entire purpose. A producer should refuse receipts that **fail** (exit 2) and hand over
receipts that say what they are (exit 0 or 1). It now does, and says which.

### D-033 - Timestamping is two steps, because the token cannot exist first

A token is a response to a digest, so it cannot be inside the thing it commits to - which is why an `rfc3161`
anchor is excluded from the signed subtree (section 6.1). What nobody had worked out is how a *user* is meant
to obtain one: the claim hash a token must commit to was not obtainable without sealing first, and sealing with
`{"type":"none"}` gives a **different** hash, because the anchor's **type** is inside the signed subtree while
its **value** is not.

So `seal --digest-only` prints the claim hash under a placeholder `rfc3161` anchor, and `seal --timestamp`
writes the token in. Three notes:

1. **The distinction is the whole trick, and it is easy to get wrong.** The first version of `--digest-only`
   used `{"type":"none"}` and printed a digest nobody would ever sign. The library test passed - it used a
   placeholder on *both* sides - and an end-to-end smoke test caught it. The test now asserts both halves: that
   a real token leaves the hash alone, **and** that a `none` anchor does not.
2. **The verifier needed no change at all.** A receipt sealed this way is an ordinary one carrying an anchor,
   and it passes L2 when the TSA is pinned.
3. **This is the first thing in the project a person performs by hand, in steps, with tools that are not
   ours** - which is why it has its own document (`docs/TIMESTAMPING.md`) rather than a paragraph in the usage
   text, and why that document says plainly that no live authority has ever been tried.

**Rejected:** having `seal` fetch a token itself. That would mean a network request inside the producer, an
endpoint to configure, and a receipt whose content depended on whether an authority was up - all to save one
`openssl ts` invocation. D-005's reasoning, applied to the producer.

### D-034 - A second implementation, written from the specification, in Python

`docs/CONFORMANCE.md` has called the single-implementation problem the biggest gap since the first draft, and
the kits made it reachable: the fixtures now ship, so an implementer does not start by reimplementing
`fixtures.mjs`. `conformance/verify_claims.py` is the first slice - the canonical form and the claim hash,
which is the layer most likely to differ between languages and needs no cryptography at all, because the
signature is outside the signed subtree.

Three decisions about how it was done, which matter more than what it covered:

1. **Written from the specification, not from the reference.** The rules came from sections 5, 5.1, 5.2 and
   6.1. Where the two disagreed, the disagreement was the finding rather than something to silently match -
   and there were three of them, all now fixed in the specification (below).
2. **One layer, complete, and named as partial.** It implements 2 of the 21 checks and says so in its own
   output; `conformance/README.md` states that it must not be listed as a conforming implementation. A
   second implementation that quietly covered half the table would be worse than none, because "agreement"
   would then mean less than it sounds like.
3. **It reports what it did not reach, by name.** Four vectors stop at a gate (a fixture that is not a
   container, a claim that does not parse, an unknown `spec_version`), and two are refused. Those are
   counted and listed separately from the 39 that agree, because a conformance report that says "no
   disagreement" without saying what it never looked at is the exact failure mode this project is arranged
   against.

**What it found**, and what changed because of it:

- **`-0` is only findable on the raw bytes in some languages.** JavaScript keeps the sign through
  `JSON.parse`; Python's `json` does not. The rule cannot be stated as a check on the parsed value, and the
  specification now says an implementation may have to read the bytes.
- **The escaping rule did not state the case of its hex digits** - and, worse, **no fixture contained a
  control character at all**, so a whole rule was unexercised. There is a vector now
  (`claim-contains-a-control-character`), and both implementations agree on it byte for byte.
- **The stage order was a principle rather than gates.** The first version of the second implementation got
  it wrong and reported two disagreements that were its own - which is the cheapest possible place to learn
  that "a claim is checked before anything that depends on a key" does not tell an implementer where the
  gates are.

And two vectors came out of it that would not otherwise exist: the control-character case, and
`claim-contains-minus-zero`. Both pin behaviour that the vector set had been asserting in prose only.

## 3. What this implementation deliberately does not have

- **A JSON Schema for the claim.** `validateManifestShape` is the normative shape check, in code,
  with tests. A schema file beside it would be a second source of truth that nothing forces to agree
  with the first.
- **A conformance table of other implementations.** There is one implementation; a table with one row
  would be decoration.
- **A network layer.** Level 3 is specified as a *report* and not performed: a caller that wants it runs
  the comparison and prints it separately, and D-005 forbids folding it into `verified`.
- **In-browser verification.** Landed in D-021: the verifier takes a runtime, so the extension checks a
  receipt with the same rules the command line uses, including the text fingerprint below.
- **None of it attached to anything yet.** A receipt stands beside the work it supports - a citation, a
  PDF, a commit - and nothing here writes a citation entry or embeds a receipt in a document. Named as
  the remaining distance between the format and its users (section 13 of the specification).
