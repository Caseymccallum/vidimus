# Contributing

This repository is a format and a conformance suite, which makes it unusual in one way worth stating
up front: **the most valuable contribution is usually a failing vector, not a passing test.** If you
can describe a receipt that the specification says should be rejected and the verifier accepts - or
one that should pass and it rejects - you have found something the format gets wrong, and that is
worth more than any amount of additional code.

## What is needed most

1. **A second implementation.** Another language reading
   [`spec/vectors/receipt-vectors.json`](spec/vectors/receipt-vectors.json) would turn "the reference
   implementation agrees with itself" into corroboration. It has been started:
   [`conformance/verify_claims.py`](conformance/verify_claims.py) covers the canonical form, the claim hash
   and the signature family - 17 of the 21 checks - and agrees with the record on 39 of 50 fixtures. The
   fixtures ship for extending it, so nobody starts by reimplementing anybody's fixture builder:

   ```bash
   node reference/src/vectors.mjs --emit ./kit   # 50 fixtures, the answers, and what to do with them
   python conformance/verify_claims.py ./kit     # the second implementation, against them
   ```

   The recorded answers are statuses and not prose, so an implementation that disagrees with every word of
   our reasons is still conformant. It now meets section 11: all 21 checks, the rollup rules, the canonical
   form and every rule-derived verdict field. The one thing it does not produce is a caveat count, which
   section 11.1 records for a reader rather than for comparison (`conformance/README.md`).
2. **Token validation against a real authority.** Section 8.3 is implemented (`rfc3161.mjs`) and validated
   against a TSA certificate the caller pins. What nobody has tried yet is a token from a real timestamping
   authority: a certificate whose key is a chain rather than a pin, which is where the refusal to build
   chains will meet reality for the first time - and where a real `<hash>` and signer identifier will test
   the limits `docs/CONFORMANCE.md` lists.
3. **A case that shows the verifier is wrong.** See above.
4. **Users.** People who cite things for a living - librarians, journalists, law review editors,
   Wikipedia editors, researchers - telling us what their actual workflow is, especially where a
   receipt would be more trouble than it is worth.

## Ground rules

- **A specification change comes before a code change.** Adding, removing or changing a check,
  a status, a field or a level means editing `docs/RECEIPT-SPEC.md` first. A new check without a
  specification change is a check no other implementation can be expected to have, which makes
  verdicts incomparable.
- **Vectors are recorded, not asserted.** If behaviour changes, re-record with
  `node reference/src/vectors.mjs --write` and say in the commit message *why* the answer moved. A
  re-record without a reason is how a suite quietly stops meaning anything. The expectations in
  `reference/src/cases.mjs` are checked on every run, so a number that changes without somebody
  writing it down fails the build.
- **A guardrail must be shown to be able to fail.** If you add one, break it once and put the
  recipe in `docs/CONFORMANCE.md` section 3. "A guardrail that cannot fail is worse than no
  guardrail, because it is believed."
- **No new dependencies.** `npm test` runs on plain Node with nothing installed, and that is a
  feature of a conformance suite rather than a preference. If you think a dependency is genuinely
  needed, open an issue with the alternative you rejected first.
- **The verifier stays pure.** `reference/src/verify.mjs` and `canonical.mjs` read no clock, open no
  file and make no request; a test scans their source for it. Cryptography lives in `digest.mjs` and
  `signature.mjs`, and filesystem access lives in `cli.mjs`. That is the whole of the rule.
- **The capture chain stays browser-safe.** Everything reachable from `capture.mjs` must import nothing
  from Node - no `node:` modules, no `Buffer` - because the extension bundles that graph into a browser
  where neither exists. `reference/test/browser-safety.test.mjs` walks the import graph from the entry
  point and fails on the first breach (D-018), so a convenient import that only works here is caught
  here rather than in a build somebody runs at the worst moment.
- **Nothing in a verdict may be more confident than the bytes justify.** If your change makes a
  report say something it did not check, it is the wrong change, however useful the output looks.

## Running things

```bash
npm run verify                              # what CI runs: everything below, in order
npm run syntax                              # every module parses
npm run check:language                      # British English, enforced
npm test                                    # 165 tests, no install
npm run check:docs                          # the counts the documentation quotes are real
npm run vectors:generate                    # rebuild the fixtures to look at one
node reference/src/cli.mjs verify spec/fixtures/capture-digest-mismatch.receipt
node reference/src/vectors.mjs --check      # rebuild every fixture and compare to the record
```

To look at a fixture as a file rather than through the CLI:

```bash
npm run vectors:generate
node --input-type=module -e "const {readZip}=await import('./reference/src/zip.mjs');const {readFileSync}=await import('node:fs');const z=readZip(new Uint8Array(readFileSync('spec/fixtures/valid-signed.receipt')));console.log([...z.entries.keys()]);console.log(new TextDecoder().decode(z.entries.get('receipt.json')))"
```

## Style

- **Comments explain why, and name what was rejected.** The codebase has one house rule: a comment
  that restates the code is noise, and a comment that records a decision is the reason the code can
  be changed safely. Numbered decisions (`D-00x`) live in `docs/ARCHITECTURE.md`; cite them.
- **Tests are named for the rule they check**, not the function they call: `a level passes only when
  every check in it passes` rather than `rollUpLevel works`.
- **Prose argues.** Where a doc makes a choice, it says what the alternative was and why it lost.
  If you cannot write the rejected alternative down, the choice has not been made yet.
- **Limitations are named in the documents, not discovered later.** A gap that is written down with
  what it would take is finished work; a gap that is implied is a bug report waiting for a user to
  file it.

## English

The prose, the comments and the identifiers are **British English**: `canonicalise`, `artefact`,
`licence`, `behaviour`, and `-ise` rather than `-ize`. `npm run check:language` enforces it rather
than trusting anybody to remember, because a convention that lives in a contributor's memory lasts
about three pull requests.

Two deliberate exceptions, both recorded in `scripts/check-language.mjs` where you will find them:

- **Wire-format field names keep the spelling of the standard they come from.** `normalization` is
  spelled the way Unicode spells it, because the `text-v1` fingerprint is defined in terms of
  Normalization Form KC. Changing a field name would also invalidate every receipt already signed,
  which is a far larger change than a spelling one.
- **Things that belong to other people keep their spelling**: npm's `license` field, `LICENSE` as a
  filename, anything named by a dependency, and `align="center"` in a line of HTML, where the
  attribute value is spelled that way by HTML and not by us.
- **A line can opt out for itself** by containing `gate-check: allow`, which is how a document is
  allowed to quote the spelling it is warning about, or a wrong count while explaining a rule. Both
  documentation gates honour it, the marker is defined once in `scripts/gate-exemptions.mjs`, and it
  is verbose on purpose so that it cannot appear by accident.

If the gate flags a word that is correct, add it to `ALLOWED` with the reason rather than rewording
the sentence around it. An exception written down is a decision; an exception not written down is a
hole.

## Pull requests

Before opening one:

- [ ] `npm run verify` passes.
- [ ] If behaviour changed, the vectors were re-recorded **and** the commit message says why.
- [ ] If a check or field was added or changed, `docs/RECEIPT-SPEC.md` was updated first.
- [ ] If the threat model's claims changed, `docs/THREAT-MODEL.md` was updated - it is the promise,
  so it changes first.
- [ ] If a new guardrail was added, `docs/CONFORMANCE.md` section 3 says how to break it.

## Reporting a bug

A receipt that the verifier gets wrong is the ideal bug report, and it usually needs only the receipt
and the verdict. Two cautions:

- **A receipt contains the page you were looking at.** Redact `subject.url` if it is private - but
  note that redacting it changes the claim, so a redacted receipt is a new receipt and its digests
  and signature will not match anything. Say that you have done it.
- **Include the verdict, not a summary of it.** `node reference/src/cli.mjs verify file.receipt
  --json` output is what makes a bug reproducible; a description of the output is what makes it
  arguable.
