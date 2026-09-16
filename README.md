<div align="center">

# Vidimus

**Proof of what a page said.**

[![Specification](https://img.shields.io/badge/specification-0.1.0-2F6FEB)](docs/RECEIPT-SPEC.md)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-3DA639)](LICENSE)
[![Spec licence: CC BY 4.0](https://img.shields.io/badge/spec%20licence-CC%20BY%204.0-8A8A8A)](docs/RECEIPT-SPEC.md)
[![Node.js](https://img.shields.io/badge/node-22%2B-5FA04E?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![Dependencies](https://img.shields.io/badge/dependencies-0-3DA639)](#verify-the-claims-yourself)
[![Tests](https://img.shields.io/badge/tests-107-3DA639)](#verify-the-claims-yourself)
[![Vectors](https://img.shields.io/badge/vectors-36-3DA639)](spec/vectors/receipt-vectors.json)
[![verify](https://github.com/Caseymccallum/vidimus/actions/workflows/verify.yml/badge.svg)](https://github.com/Caseymccallum/vidimus/actions/workflows/verify.yml)

</div>

---

MIT for the code · CC BY 4.0 for the specification · © 2026 Casey McCallum

---

**A page you cited has changed, or gone, and you would like to be able to show what it said.**

Vidimus makes one file for that. A **receipt** holds a copy of the page, a signed claim about that
copy, and everything a stranger needs in order to check the claim without trusting you.

*Vidimus* is Latin for "we have seen". In the Middle Ages it was an instrument: an official certified
that they had inspected a document and issued a certified copy, because the original would not
survive being carried around. This is that, for a web page.

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

Every line of that output is a decision. `self-asserted`, because nothing witnessed the capture time.
`not checked` rather than a tick, because the verifier has no clock and no network. And if the page
had been edited after the receipt was signed, L0 would read `FAILED` while L1 still read `verified` -
both facts true, both reported, neither hidden behind the other.

> **A receipt is evidence about bytes, not about truth.** It records what a server returned to the
> person who captured it. A site that serves different content to different people, a dishonest
> capture tool, and an author who simply wrote a false claim are all outside what any of this can
> detect. [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) is the full list, ordered by how easy each
> one is to misread.

> **⚠️ Early, and deliberately so.** 0.1.0 is the specification and a reference verifier: 107 tests,
> 36 conformance vectors, no dependencies. The extension that will make a receipt in one click is the
> next piece of work. The format had to be checkable before anything wrote it at scale.

## Feature Highlights

### Making one

- **`vidimus seal capture.wacz --key key.json`** writes a signed receipt from a capture you already
  have - from `py-wacz`, from Browsertrix, or from Shelf.
- **It reads the page's URL, status and capture time out of the capture itself**, so the claim
  describes what was captured rather than what the caller remembers.
- **It refuses to guess.** A capture it cannot read stops the seal, because a document digest nobody
  measured is a falsehood inside a signature rather than a missed check.
- **It verifies what it has just written**, and deletes the file if its own output does not check out.
- **One button in the browser**, too: [`extension/`](extension/README.md) seals the page you are reading,
  with a key that never leaves the profile and a permission list that carries a reason per entry.

### The receipt

- **One file, and nothing to fetch later.** A `.receipt` holds the claim and the capture together, so
  a citation keeps working when the site it points at does not.
- **Adopts WACZ instead of inventing a container.** The capture inside a receipt opens today in
  `py-wacz`, Browsertrix and ReplayWeb.page.
- **Binds the capture three ways** — entry name, length and SHA-256 — plus the resource hashes inside
  the capture, so swapping the inner record for another one of the same length is caught.
- **Signs the claim, not the file.** An Ed25519 signature over a canonical hash: edit a cited URL, a
  timestamp or an undocumented field and the signature fails.
- **Refuses a re-serialised claim.** Pretty-print `receipt.json` and the receipt is rejected even
  though its content is intact, because the bytes that were signed are not the bytes that were
  delivered.

### Verification

- **Four levels, reported separately** — L0 integrity, L1 attribution, L2 time, L3 currency.
- **Twenty named checks**, every one of which appears in every verdict.
- **A level passes only when every check in it passes.** No "pass with warnings", and an unrecognised
  thing is never a pass.
- **Three exit codes** — `0` verified, `1` nothing proven, `2` broken — because "this receipt is
  broken" and "I could not check this receipt" must not share a code in a pipeline.
- **Caveats that travel with the verdict**, saying what was not checked and why.

### The format

- **A specification with conformance vectors**, not merely an implementation: 34 recorded fixtures and
  verdicts, rebuilt and re-hashed on every run.
- **A canonical form that admits integers only**, because floating-point formatting is where
  cross-language signature schemes break.
- **Time anchors named honestly** — none, a chain, or an RFC 3161 token — each with what it does and
  does not prove, and `unsupported` where an implementation has not got there yet.
- **The artefact is called a receipt; the project is called Vidimus.** A stranger reading
  `citation.receipt` needs no explanation.

### Engineering

- **No dependencies and no build step.** Plain ESM with JSDoc types, run by `node --test`.
- **The verifier is pure** — no clock, no filesystem, no network — and a test scans its source to keep
  that true rather than merely intended.
- **Six gates, each shown to be able to fail**, and two of them are about the documentation itself: the
  prose is checked for British English, and the counts the README quotes are checked against reality.
- **The capture chain is browser-safe by test.** Everything the extension will bundle - the canonical
  form, the SHA-256, the gzip and ZIP writers, the capture itself - imports nothing from Node, and a
  test walks the import graph from `capture.mjs` and fails on the first breach (D-018).

## What it deliberately does not do

- **Crawl the web.** A receipt is about the page *you* are citing. This is not a web archive service
  and will not become one.
- **Decide what is true.** It records what a server returned to the person who captured it and
  reports which parts of the claim held up. What the capture means is a question for a person.
- **Block or alter anything.** Nothing here blocks, rewrites or observes a request. A receipt is made
  from a capture that already happened.
- **Replace the Internet Archive.** It is a receipt for one page, kept by the person who cited it.

## Status

**0.1.0 — specification, verifier and sealer.** The format is settled enough to implement against, the
reference verifier conforms to it, and the conformance vectors are recorded rather than asserted. What
exists today:

- the specification, the threat model, the conformance rules and a numbered decision record;
- a reference verifier and a command-line tool, in plain ESM with no dependencies and no build step;
- a producer that turns a capture into a signed receipt, and verifies its own output before reporting
  success;
- a capture core that turns what a browser knows into a WACZ - browser-safe, and the module the
  extension will import rather than reimplement (`capture.mjs`);
- 36 conformance vectors, rebuilt and re-hashed on every run;
- six gates, run by `npm run verify` and by CI on Linux and Windows.

The browser shell exists now too, in `extension/`: one button that seals the page you are reading,
importing the format rather than reimplementing it, and keeping its signing key in the browser.
[`extension/README.md`](extension/README.md) says exactly what it can and cannot do.

## Quick start

There is nothing to install.

```bash
npm run verify                                            # the whole gate
npm run vectors:generate                                  # rebuild spec/fixtures/ to look at one
node reference/src/cli.mjs verify spec/fixtures/valid-signed.receipt
npm run vidimus -- verify spec/fixtures/claim-not-canonical.receipt --json
```

That last command exits `2` and prints the interesting line: the signature verifies, and the receipt
is still rejected, because the bytes that were signed are not the bytes that were delivered.

Making one, from a capture you already have:

```bash
vidimus keygen --out key.json --signer "Your Name"     # once. This file signs your claims.
vidimus seal capture.wacz --key key.json              # reads the URL and the date from the capture
vidimus verify capture.receipt
```

`seal` writes `capture.receipt` beside the capture, signs the claim, and then **verifies what it has
just written** before it reports success. If that verification fails, the file is deleted and the
failure is reported as a bug in this program.

(`vidimus` is the CLI; before publishing it, `npm run vidimus -- seal …` runs the same thing.)

## Verify the claims yourself

Every claim in this README is a command, and every gate has been shown to be capable of failing.

| Claim | Command |
| --- | --- |
| Nothing American slipped into the prose | `npm run check:language` |
| The counts this README quotes are real | `npm run check:docs` |
| Every check has been seen not passing | `npm test` — the coverage test fails if any of the 20 checks has only ever passed |
| The recorded verdicts are current | `npm run vectors:check` — rebuilds every fixture and re-hashes it |
| The verifier is honest about what it did not check | `node reference/src/cli.mjs verify spec/fixtures/anchor-rfc3161-unimplemented.receipt` |
| A tampered capture is caught | `node reference/src/cli.mjs verify spec/fixtures/capture-digest-mismatch.receipt` |
| A re-serialised claim is refused | `node reference/src/cli.mjs verify spec/fixtures/claim-not-canonical.receipt` |

[`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) has the full table, including how to break each gate in
under a minute and what it should say when you do.

## Where this comes from

Three sibling projects in the same workspace, put together:

- **Shelf** captures a page as it looked - the rendered DOM, the stylesheets, the images - locally
  and searchably. That is the capture engine a receipt needs.
- **Sentinel** scores what a page is doing and shows what changed since your last visit, with no
  network calls and every number inspectable. That is the discipline a verification report needs,
  and its "not measured never costs points" rule became "a check that did not run is never a pass".
- **proof-of-waves** has a server re-execute a client's replay rather than trust its score. That is
  the same move as a verifier that recomputes a digest instead of believing a claim about it.

None of the three is part of this repository; they are where the ideas came from, and they are named
here because a format that cannot say what it grew out of is a format nobody can date.

## What is deliberately not here yet

- **The browser shell.** `capture.mjs` turns a page's facts into a WACZ; what is missing is the
  extension that gathers those facts - the rendered DOM, the observed status and headers - calls the
  capture core, seals the receipt and keeps the key.
- **RFC 3161 anchors** - a real timestamp from a third party. Specified in section 8.3, reported as
  `unsupported`, not faked.
- **`text-v1`**, the fingerprint that answers "did the page's words change". It needs an HTML engine,
  so the CLI says `not_checked` and the extension will do it properly.
- **Level 3**, the live comparison against the page as it is now. It needs the network, and this
  verifier deliberately has none.
- **Key directories** - who a key belongs to. Deliberately absent until there is a second
  implementation to disagree with about it.

## Read next

- [`docs/RECEIPT-SPEC.md`](docs/RECEIPT-SPEC.md) - the format, section by section.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) - what a receipt cannot do, and why.
- [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) - what is unfinished and what it would take.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - the decisions, including the ones that were
  reversed while writing the specification.

## Layout

```
docs/        the specification, the threat model, conformance, and the decision record
reference/   the reference implementation: pure ESM, no dependencies, no build step
  src/       canonical.mjs, digest.mjs, zip.mjs, gzip.mjs, signature.mjs, verify.mjs, …
  test/      the canonical form, the container, the verifier's invariants, the vectors
spec/        receipt-vectors.json (the record) and fixtures/ (generated, gitignored)
scripts/     the gates: check-syntax.mjs, check-language.mjs, check-docs.mjs
.github/     the workflow that runs npm run verify on Linux and Windows
```

## Licence

MIT for the code. **CC BY 4.0** for [`docs/RECEIPT-SPEC.md`](docs/RECEIPT-SPEC.md); the reasoning
behind both is in [`docs/LICENSING.md`](docs/LICENSING.md).

Both are deliberate. The code is permissive so it can be used anywhere; the specification is freely
reimplementable so that it can become a format rather than a product with a file extension.

---

Created by Casey McCallum.
