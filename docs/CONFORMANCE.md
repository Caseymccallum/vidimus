# Conformance

What it means to conform, how the reference implementation proves it does, how to see each gate
fail, and what is honestly not finished.

## 1. The claim of conformance

An implementation conforms to Receipt 0.1.0 when it satisfies section 11 of
[`RECEIPT-SPEC.md`](RECEIPT-SPEC.md):

1. it implements every check in section 7.4 and reports all of them in every verdict;
2. it applies the status, rollup and `verified` rules of sections 7.1-7.5;
3. it reproduces the canonical form of section 5 byte for byte, including the refusals; and
4. it produces the recorded verdicts in [`../spec/vectors/receipt-vectors.json`](../spec/vectors/receipt-vectors.json).

The reference implementation's own conformance is not asserted anywhere. It is re-derived on every
run, by rebuilding every fixture and comparing the answer to the record.

**Before any of that, get the fixtures.** They are not committed to this repository, because they are
regenerable from a recipe - and a recipe is not a kit, so there is a command that writes one:

```bash
node reference/src/vectors.mjs --emit ./kit
```

`./kit` holds the 45 fixtures, `receipt-vectors.json`, and a README with the three steps: check each fixture
against its recorded digest, verify it, compare the statuses. Nothing in it requires this repository's code.
Believing a conformance suite without checking a fixture's digest first is the failure mode the digest is
there to prevent.

## 2. Running the gate

```bash
npm run verify      # syntax, then tests, then the vectors
```

| Command | Proves |
| --- | --- |
| `npm run syntax` | Every `.mjs` module in the repository parses. Stands in for the type check this project deliberately does without (D-002). |
| `npm run check:language` | The prose, comments and identifiers are British English (`scripts/check-language.mjs`). |
| `npm test` | 165 tests: the canonical form's rules, the container reader, the text fingerprint's rules, the verifier's invariants, and the vectors. |
| `npm run check:docs` | Every count the documentation quotes - tests, vectors, fixtures, checks - matches reality. It re-runs the suite to read the count, so `npm run verify` runs the tests twice; that is one second, and it buys numbers that cannot go stale. |
| `npm run vectors:check` | Every fixture rebuilds to its recorded digest, and every verdict equals its recorded answer. |
| `node reference/src/vectors.mjs --emit <dir>` | Writes a conformance kit: the fixtures, the answers and a README saying what to do with them. Nothing in it needs this repository. |
| `node reference/src/vectors.mjs --check-kit <dir>` | Checks a kit the way a stranger would - files from disk, hashed against the kit's own record - so that the emit path cannot rot unchecked. |
| `node reference/src/cli.mjs verify <file>` | The same verifier from the command line, with a readable summary and a three-state exit code. `--trusted-key`, `--key-directory` and `--tsa` are how a caller answers "whose key signed this?" and "whose timestamp is this?" (sections 6.7 and 8.3 of the specification). |
| `node reference/src/cli.mjs keys <directory.json>` | Reads a key directory and says what is in it, refusing the entries it will not use rather than waiting for a receipt to fail against them. |
| `node reference/src/cli.mjs check <file>` | The comparison with the page as it is now: the only command that makes a request, and the only one whose output includes a currency report. `--require-same-words` makes that report, rather than the receipt, decide the exit code. |
| `node reference/src/cli.mjs seal <capture.wacz> --key <key.json>` | The producer: it builds a claim from a capture, signs it, and verifies its own output before reporting success (D-017). `--timestamp` attaches an RFC 3161 token, and `--digest-only` prints the claim hash such a token must commit to - together, the two-step workflow in [`TIMESTAMPING.md`](TIMESTAMPING.md). |
| `node reference/src/cli.mjs keygen --out <key.json>` | A signing key, written with its derived key id, and a warning about what that file is. |

## 3. Proving the gates can fail

A guardrail that cannot fail is worse than no guardrail, because it is believed. Each row is a
change you can make in under a minute that must produce the stated failure. The rows marked
**observed** were performed rather than reasoned about.

| Gate | Break it by | It must say |
| --- | --- | --- |
| `syntax` | Add a stray `{` to any module. | `N of M modules do not parse`, with the file and line. **Observed:** appending one brace to `digest.mjs` printed `1 of 15 modules do not parse` and the line number, and exit code 1. |
| `test` | Make `canonicalise` sort keys case-insensitively. | `keys are sorted, so insertion order cannot change the bytes` fails. |
| `test` | Drop the byte-level BOM check in `assertCanonicalBytes`. | `bytes that are canonical pass, and a BOM does not` fails. **Observed** - that check was silently dead: `TextDecoder` removes a leading BOM, so `charCodeAt(0) === 0xFEFF` never fired on a decoded string. |
| `test` | Delete a check from `CHECKS`. | `every verdict reports every check, exactly once, in the declared order` fails, and `verifyReceipt` throws rather than returning an incomplete verdict. |
| `vectors:check` | Edit any recorded status in `receipt-vectors.json`. | The diff names the vector and the field. **Observed:** changing one recorded `capture.digest` status produced `vectors[7].expect.checks.capture.digest: expected "pass", got "fail"` and the matching `verdict` line, and exit code 1. |
| `vectors:check` | Change a fixture's HTML by one character. | Every vector using that fixture reports a digest mismatch, because the record names the digest. **Observed:** changing one word in `DEFAULT_HTML` made 32 of the 34 answers stop matching. |
| `vectors:check` | Change an expectation in `cases.mjs`. | The run fails *before* recording anything, naming the case and the check that disagreed. **Observed** - eight expectation mismatches during development, three of which were the implementation being imprecise rather than the expectation being wrong, and none of them spurious. |
| `test` | Change the claim hash quoted in `README.md` or the specification. | `the worked examples in the documentation are real ones` fails, naming the file and both values. **Observed:** a mutated README produced `README.md quotes claim 00000000…, which no fixture produces (expected fbf9d6d7…)`. Documentation that quotes a number is documentation that can go stale, so the number is checked. |
| `check:language` | Write an American spelling anywhere in a document. | The gate names the file, the line and the word. **Observed, and the second attempt is the instructive one.** The first mutation - a capitalised American spelling at the start of a sentence - *passed*, because the patterns had been declared without the case-insensitive flag. Fixing that exposed a second bug: with the flag applied, the `-ize` rule swallowed the capital in camelCase identifiers and reported 19 false positives such as `compressedSize`. Both are fixed and the rule table now explains why. Neither bug would have been found by reading the gate. *(This line quotes a spelling deliberately: gate-check: allow)* |
| `check:docs` | Change a number the documentation quotes. | The diff names the document, the line, the quoted number and the real one: `README.md:12 says 99 tests, and there are 47`. **Observed.** *(This line quotes a wrong count deliberately: gate-check: allow)* |
| `seal`'s own verification (D-017) | Make `seal` write the claim pretty-printed instead of in canonical form. | `seal` must report `L0 integrity: FAILED`, remove the file it wrote, and exit `2` rather than reporting success. **Observed:** the mutated sealer printed `manifest.canonical - document bytes are not in canonical form: it was re-serialised before delivery`, then `bad.receipt did not verify, so it has been removed`, then exited `2`, and the file was gone. A producer that cannot fail its own check is a producer whose first bug is found by a stranger holding the receipt. |

## 4. The vectors

`spec/vectors/receipt-vectors.json` holds the check table, then one entry per case: how it was built,
the fixture's SHA-256 and length, the options it was verified with, the expectation written down in
`reference/src/cases.mjs`, and the verdict that was recorded.

Recorded verdicts list only the checks that are **not** `pass`. That is enough to detect any change -
a passing check that starts failing appears, and a failing one that starts passing disappears - while
keeping the file reviewable in a diff. Reasons are deliberately not recorded: a vector that breaks
when somebody improves a sentence teaches people to re-record vectors without reading them, and once
that habit forms the vectors stop being evidence. That every non-passing check carries a specific
reason is asserted by a test instead.

Grouped by what they are for:

| Group | Cases |
| --- | --- |
| **Happy paths** | `valid-signed`, `valid-signed-trusted`, `valid-signed-trusted-wrong`, `valid-unsigned`, `valid-http-page`, `valid-with-text`, `valid-signed-with-notes` |
| **Tampering with the capture** | `capture-digest-mismatch`, `capture-resource-mismatch`, `capture-length-wrong`, `capture-not-a-wacz`, `capture-media-type-unknown`, `capture-missing` |
| **Tampering with the claim** | `claim-edited-after-signing`, `claim-not-canonical`, `claim-contains-a-float`, `spec-version-unknown`, `manifest-missing`, `manifest-not-json`, `capture-path-escapes` |
| **The text fingerprint** | `text-fingerprint-wrong` - a claim whose fingerprint is plausible and not what its capture says. Kept because it was a real bug in this project's own fixture |
| **The document digest** | `document-digest-wrong`, `document-length-wrong` - the claim's own account of its capture, re-derived and contradicted (section 4.2) |
| **The capture profile** | `capture-profile-declared`, `capture-profile-wire`, `capture-profile-unrecognised` - declared, reported, never judged |
| **Signature** | `signature-from-another-claim`, `signature-key-id-mismatch`, `signature-algorithm-unsupported`, `signature-shape-broken` |
| **Anchors** | `anchor-chain-head`, `anchor-chain-linked`, `anchor-chain-unlinked`, `anchor-chain-unfollowed`, `anchor-chain-head-with-predecessor`, `anchor-bolted-on`, `anchor-rfc3161-no-tsa`, `anchor-rfc3161-verified`, `anchor-rfc3161-wrong-imprint`, `anchor-rfc3161-untrusted-tsa`, `anchor-unknown-type` |
| **Container** | `container-not-a-zip`, `container-with-stray-entry` |

## 5. Coverage rules, asserted by tests

- **Every check has been seen not passing at least once.** A check whose failure path has never run
  is not a check. The suite fails if any of the 20 is only ever observed passing.
- **All three exit codes occur.** `0`, `1` and `2` each appear in the record, so the distinction
  between "verified", "nothing proven" and "broken" is tested rather than described.
- **Every level reaches `pass` at least once**, including L3. The text fingerprint is defined over bytes
  (section 4.5 of the specification), so `valid-with-text` is a pass rather than a `not_checked` of this
  implementation's own. The rule that used to exclude L3 is gone, and so is the row in section 6 that
  named it as a gap.
- **Every non-passing check carries a reason.**
- **Verdicts are reproducible.** The same bytes produce byte-identical verdicts, asserted for every
  case.

## 6. What is limited, and what is not conformant yet

Named here, with what each would take, so that none of them is mistaken for a decision. The first row is a
limit inside something that *is* implemented, which is why this section is not titled "gaps" any more:
a limitation written down is part of conformance, and one left implicit is a claim nobody made.

| Gap | Where it shows | What it would take |
| --- | --- | --- |
| **RFC 3161 anchors** | `anchor.verified` | **Implemented** against a TSA the caller pins (`--tsa`): content type and imprint, `genTime` inside the signing certificate's validity, the `timeStamping` extended key usage, and the signature over the `signedAttrs` as a `SET OF`. The limits are named rather than implied: no chain building to a root (a pin *is* an anchor, and a token signed by anything else is `not_checked` with its fingerprint reported), no revocation checking, and only RSA PKCS#1 v1.5 or ECDSA signatures with SHA-256, SHA-384 or SHA-512, SHA-256 imprints, SHA-256 content digests, and signers named by issuer and serial number. Anything outside that is `unsupported`, never `pass` and never `fail`. |
| **`subject.document`** | `subject.document: fail` | **Implemented** (section 4.2, D-032): the capture's document is re-derived and compared with the digest and length the claim states. A receipt whose record this reader cannot open reports `not_checked`, which means L0 does not pass - a tightening that is deliberate and named. |
| **Level 3 (currency)** | L3 verifies the claim's own fingerprint; nothing compares a receipt with the live page | The comparison is specified (section 7.7 of the specification) and implemented as `vidimus check`: it verifies the receipt, fetches the URL, seals a second receipt for what the page says now, and prints a report with five outcomes - including "the bytes changed and the words did not". It never touches `verified`, and `--require-same-words` opts in to letting the comparison decide an exit code. |
| **Size limits** | `container.readable: unsupported` past the ceiling | A verifier caps what it will inflate, before and during (section 7.8 of the specification, D-030). The numbers are the implementation's and a caller may raise them; exceeding one is `unsupported` with the number named, never a `fail` - a limit belongs to the verifier, not to the receipt. |
| **A second implementation** | `conformance/verify_claims.py` | **Started, and 19 of the 21 checks**: the container, the claim, the claim hash, the capture's document, the signature family and `anchor.present`, in Python, written from the specification, with Ed25519 from RFC 8032 in `conformance/ed25519.py`. It agrees with the record on **42 of 45** fixtures, corroborates 3 refusals, and disagrees on none - a snapshot, to be re-run and re-stated after any vector changes. It is explicitly **not** a conforming implementation: `conformance/README.md` says what is missing, which layer is weaker evidence than the others, and the seven things writing it found. |
| **Attaching a receipt to what it supports** | `subject.url` is a claim field; a citation built from a receipt is a *new* file | `vidimus cite` emits CSL-JSON, a plain sentence and a commit trailer built from what the claim asserts - a URL, an access date and the claim hash as the identifier. A title is the citer's to supply (`--title`), because a receipt never asserts one. Embedding a receipt in a PDF in the shape PAdES uses is **not** implemented: it needs a CMS `SignedData` over a PDF byte range and an incremental update, and an attachment that no viewer can verify would be worse than a sidecar. |


## 7. Adding a check

A new check is a specification change, not a code change. In order:

1. Add it to section 7.4 of the specification, with its level and what it proves.
2. Add it to `CHECKS` in `reference/src/verify.mjs`. The completeness assertion now requires it in
   every verdict, so the remaining steps are enforced rather than remembered.
3. Add a case in `reference/src/cases.mjs` that exercises it **not** passing, and one that exercises
   it passing. The coverage test in section 5 fails without both.
4. Record: `node reference/src/vectors.mjs --write`.
5. Update the gap table above if the check closes a gap, and the threat model if it changes what a
   receipt can claim.
