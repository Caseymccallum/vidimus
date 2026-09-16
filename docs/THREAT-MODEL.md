# Vidimus threat model

A receipt's promise is narrow and specific: it says what a page said when somebody captured it,
and it lets a stranger check that the record has not been altered. This document says which
attacks that defends against, which it does not, and where it would be wrong to rely on it. It
exists because the failure mode of a provenance tool is not being forged - it is being trusted
for something it never claimed.

Every claim below is either enforced by a check (`docs/RECEIPT-SPEC.md` section 7.4) or named as
a limitation. If this file and the code disagree, the code is the bug.

## 1. What a receipt is for

Answering one question about a citation: **what did this page say when I looked at it, and can you
check that without trusting me?** It records a capture, signs a claim about that capture, and
reports which parts of the claim held up.

## 2. What it protects against

- **Silent edits.** A page that changes after it was cited produces a receipt whose
  `capture.digest` no longer matches anything the site serves, and whose `subject.document` digest
  can be compared. The change is detectable by anyone holding the receipt.
- **Link rot and deletion.** The record survives the page. It is a file, not a URL.
- **Re-serialisation and format drift.** `manifest.canonical` refuses a claim that is not the byte
  string that was signed, so a receipt cannot be quietly reformatted in transit.
- **Claim substitution.** `signature.verify` covers the whole claim except the signature and a
  post-hoc anchor (section 6.1), so editing a cited URL, a timestamp or an undocumented field
  breaks it.
- **Capture substitution.** `capture.digest` binds the exact capture bytes, and
  `capture.wacz.resources` binds what is *inside* them, so swapping the inner record for another
  one of the same length is caught.
- **A fabricated anchor.** An anchor that could have existed at signing time is signed (D-011); a chain
  anchor cannot pass without a valid signature (D-012); and an RFC 3161 token cannot pass unless it
  commits to *this* claim's hash (section 8.3) and is signed by a timestamping authority the caller
  pinned. A token therefore cannot be moved from one receipt to another, and cannot be invented for one.
- **Its own report overstating what it found.** Every check appears in every verdict, a level
  passes only when every check in it passes, and an unknown is never a pass (D-005). This is the
  threat this project takes most seriously, because it is the one the user cannot see.

## 3. What it does not protect against

**A receipt is evidence about bytes, not about truth.** In rough order of how likely a user is to
misread them:

- **The site serving different content to different people.** A receipt records what *this* client
  was sent. A site that cloaks - by geography, by account, by user agent, by time - is invisible to
  the format, and two valid receipts for the same URL can show different pages without either being
  forged. This is the biggest gap between "verified receipt" and "I have proved what the site said",
  and no amount of cryptography closes it.
- **The choice of what got captured.** A receipt proves what somebody decided to record. An archive
  assembled by a partisan is a partisan archive, and every one of its receipts can be perfectly
  valid.
- **A lying author.** Nothing stops someone capturing a page they edited themselves, or writing a
  claim whose `subject.document` digest does not describe the capture. That digest is *serialised*
  by the claim and *not re-derived* by a 0.1 verifier (section 4.2), so a claim that lies about its
  own contents verifies.
- **A dishonest or compromised capture tool.** The tool writes the claim and hashes the capture. A
  tool that hashes a different capture than it writes, or that silently omits half the page,
  produces a receipt that verifies perfectly. Trust in a receipt begins with trust in the program
  that made it, which is why the tool's name and version are in the claim.
- **An unauthenticated signer.** `signature.verify` proves a *key* signed. `signer` is
  self-asserted text. Without a key directory supplied by the verifier, a valid signature means
  "this key signed this", and nothing about whose key it is (D-007).
- **Anything before the anchor.** With no anchor, `captured_at` is a claim, and the receipt says so.
  With an anchor, the honest statement is "this claim existed no later than T": a timestamp bounds a
  claim from above, and does not pin the capture to the instant the author wrote down.
- **A chain anchor, to a stranger.** It proves ordering within one archive. The format raises a
  caveat saying exactly that, because "sequence 2" reads as "therefore real" to almost everyone.
- **The verifier itself.** A verifier modified to print `verified: true` is undetectable from its
  output. The defences are the ones this repository uses: the reference implementation is small,
  pure, dependency-free, and pinned by recorded vectors.
- **Everything downstream of the verifier.** Once a verdict is copied into a footnote, a slide or a
  spreadsheet, the caveats do not travel with it. Section 7.6 of the specification asks a verifier
  to state what it did *not* check, for exactly this reason - and it is a request, not a guarantee.

## 4. Trust boundaries

- **The page cannot affect the receipt.** Nothing in this project reads or touches a live page; a
  receipt is made from a capture that already happened. The verifier performs no network request at
  all, and a test scans its source for `fetch`, file access, `Date.now()` and `Math.random` to keep
  that true rather than merely intended.
- **A receipt cannot affect anything.** It is bytes. Nothing here blocks, redirects, rewrites or
  observes a request.
- **The verifier never trusts the claim for anything it can compute.** Digests, key ids, lengths, hashes
  and the text fingerprint are recomputed from the bytes. The fields a verifier does *not* recompute -
  `subject.document`, and the name a claim gives its signer - are named as unchecked in section 9 of the
  specification, and are reported as unchecked rather than presented as findings. A key directory is how
  a caller answers the second of those; it is the caller's document, never this project's (section 6.7).
- **An anchor is trusted only as far as its own rules.** A chain anchor is checked for internal
  consistency, not confirmation: it orders receipts inside one archive and attests nothing to a stranger.
  An RFC 3161 token is validated against a certificate *the caller pinned*, by DER or fingerprint, and
  a token signed by anything else is `not_checked` - so the verdict never implies a trust decision the
  caller did not make (D-029).
- **The key list and the TSA list belong to the caller.** Trust roots are configuration, never a built-in
  list: this project ships no authority bundle, and a verifier with nothing pinned calls nothing trusted.
- **The comparison with the page now makes a request, and cannot change a verdict.** `vidimus check`
  fetches the URL a receipt cites, seals what it finds into a *second* receipt, and prints a report
  beside the verdict. The bytes it fetches reach that report and nothing else, and no level of the
  verdict depends on them (D-025).
- **The extension makes requests while capturing.** It fetches the stylesheets and images a page
  references, because a browser will not hand over the body of a response the page made. Those responses
  become data inside the capture, they are addressed by URL, and they cannot execute when the capture is
  replayed. How many were kept and how many were left out is reported to the user.

## 5. Where it can be wrong

- **Capture fidelity.** A capture tool that loses a stylesheet, a frame or an image produces a
  receipt that verifies and a record that is incomplete. The 0.1 format has no field for "what this
  capture could not save", so a producer that wants to be honest about that has to put it in the
  claim - an undocumented field is signed, so it travels with the claim rather than being dropped.
- **The text fingerprint is checked, and it is not the whole page.** `text-v1` is defined over the
  document's bytes (section 4.5), so a verifier recomputes it and reports `pass` or `fail` rather than
  `not_checked`. What it cannot see is layout: text hidden by a *stylesheet* is in the fingerprint,
  because only an element's own `hidden`, `aria-hidden` or inline `style` excludes it. A page that hides
  words by class name is a page whose words did not change.
- **A revoked TSA certificate still verifies.** Nothing here consults a revocation list, so a token
  signed by a certificate that was valid at the time and revoked since still passes L2. The
  specification says so next to the rule it belongs to (section 8.3), because a verifier that implied
  "valid certificate" while checking no revocation would be answering a question it was not asked.
- **A chain anchor's claim about its own position.** `sequence: 1` always passes, because "this is
  the first receipt" is unfalsifiable from one receipt. It is a complete statement and a weak one.
- **Timestamps to the second.** Two captures within the same second are indistinguishable by time.
- **Sizes are not capped.** A hostile receipt can declare a large entry and ask a verifier to
  inflate it. Callers reading untrusted receipts should cap what they will open (section 9).
- **The vectors prove agreement, not correctness.** They pin the reference implementation's answers,
  including the answers that rest on a decision somebody had to argue for. The arguments are in
  `docs/ARCHITECTURE.md` and in the specification, and reasonable people can disagree with them.

## 6. Changing this document

A change to what a receipt can claim, or to what a verifier may report as checked, needs a numbered
decision in [`ARCHITECTURE.md`](ARCHITECTURE.md) with the alternatives that were rejected, and a
vector that fails before the change and passes after. This file is what the promise means, so it
changes first.
