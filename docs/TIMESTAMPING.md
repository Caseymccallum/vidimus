# Timestamping a receipt

A receipt's capture time is the author's own statement. `vidimus verify` says so: `time.bound` is
`claimed_only` until an anchor verifies, and a verified anchor gives `attested_before` - an instant a *third
party* attests the claim existed by. This document is the part a user needs and the code cannot supply:
**where a token comes from, and how to pin the authority that made it.**

Nothing here fetches anything. There is no built-in list of timestamping authorities, because a format that
hard-codes trust roots is a format that rots: you bring the certificate, and the verifier believes exactly
what you hand it (section 8.3 of the specification).

## 1. What you need

Two things, both from your timestamping authority:

- **A token** for one specific digest - a small DER file, or the reply it arrives in.
- **The authority's certificate**, in PEM or DER. Public CAs publish theirs in their certificate repository;
  a private TSA has one of its own. Free public services exist as well. This project ships no list and
  endorses none: whichever you choose, *you* are the one pinning it.

## 2. The catch, and why this is two steps

A token is a *response to a digest*, so it cannot exist before the claim it commits to - and a claim cannot
be signed around a token that does not exist yet. That sounds circular, and is not, because of one property
that the format has by design:

> An `rfc3161` anchor is **outside the signed subtree** (section 6.1). The token's *value* does not affect
> the claim hash at all.

So the digest can be computed first, a token obtained over it, and the receipt sealed afterwards - and the
claim hash comes out the same. `--digest-only` prints it, with a placeholder anchor of the right *kind*:
the anchor's `type` **is** inside the signed subtree, so a digest printed under `{"type":"none"}` would
describe a claim nobody is going to sign. (That mistake was made while writing this, and the test that pins
the property now catches it.)

## 3. The workflow

```bash
# 1. Seal once, writing nothing, to learn the digest a token must commit to.
digest=$(vidimus seal page.wacz --url https://example.org/x --captured-at 2026-09-15T12:00:00Z \
           --key key.json --digest-only | head -1)

# 2. Ask your authority for a token over that digest, with openssl's own client.
openssl ts -query -digest "$digest" -sha256 -cert -out request.tsq
curl -s -H 'Content-Type: application/timestamp-query' \
     --data-binary @request.tsq https://<your-tsa>/ > response.tsr
openssl ts -reply -in response.tsr -token_out -out token.der

# 3. Seal again, with the same arguments plus the token.
vidimus seal page.wacz --url https://example.org/x --captured-at 2026-09-15T12:00:00Z \
       --key key.json --timestamp token.der
```

Step 3 prints the same claim hash as step 1, because nothing between them changed the signed subtree. If it
ever does not, the receipt will say so rather than seal a claim the token does not describe.

**These commands are openssl's, not this project's, and the endpoint and certificate are your authority's.**
Nothing in this repository has been run against a live timestamping authority, and `CONTRIBUTING.md` names
that as an open item rather than implying otherwise. What *is* tested exhaustively is the other half: tokens
are minted deterministically by a published fixture authority and validated by the verifier
(`reference/src/tst-fixture.mjs`, `reference/test/rfc3161.test.mjs`).

## 4. Verifying one

```bash
vidimus verify page.receipt --tsa authority.pem     # PEM or DER, and repeatable
```

With the certificate pinned, `L2 time` verifies and the verdict reports the attestation:

```
L2 time: verified — a third party attested the claim existed at a time
notarised: this claim existed no later than 2026-09-15T12:00:04Z, per <the authority's name>
```

### "No later than", never "captured at"

The wording is deliberate and load-bearing. A timestamp bounds a claim *from above*: it says the claim
existed by that instant, not that the page was captured at it. A capture time is what the author wrote down;
the attested instant is what a third party will answer for. Conflating the two would be the most misleading
thing this format could do, so the summary says one and `time.attested_before` says the other.

### Without a pinned certificate

`L2 time` reports `unsupported`, with the reason: the token is not wrong, you have simply not told the
verifier what to trust. The `untrusted_signer` path reports the signing certificate's **SHA-256
fingerprint**, which is the other form `--tsa` accepts:

```bash
vidimus verify page.receipt --tsa <that fingerprint>
```

That is the intended way to discover which authority signed a receipt you were handed.

## 5. What is checked, and what is not

Checked, in this order, before L2 can pass (section 8.3):

1. the token is signed by a certificate you pinned, by DER or by fingerprint;
2. the token's `messageImprint` is the claim hash, under SHA-256;
3. `genTime` falls inside the signing certificate's validity window;
4. the signature verifies over the signed attributes, re-encoded as a `SET OF` - plus the two CMS bindings,
   so that the signature covers the content it claims to cover.

Also checked, because RFC 3161 requires it: the certificate carries the `timeStamping` extended key usage,
and its key usage permits signing. A pinned certificate that fails either is a `fail`, because a pin says
"believe these bytes", not "believe anything they sign".

**Not checked, and named rather than implied:** no chain building to a root (a pin *is* an anchor), no
revocation checking (a certificate valid at the time and revoked since still passes), SHA-256 imprints and
content digests only, and signers identified by issuer and serial number only. Anything outside that is
reported `unsupported` - never `pass`, and never `fail`, because a gap in the verifier is not a fault in the
receipt (D-021). `docs/CONFORMANCE.md` lists the same limits in one place.

## 6. The fixture authority

`reference/src/tst-fixture.mjs` mints tokens with a **published, worthless key**, and says so in the
certificate's own common name. It exists so that the conformance vectors can be a deterministic function of
committed bytes: RSA PKCS#1 v1.5 signing is deterministic, so a token minted from fixed values is
byte-identical everywhere and the recorded verdicts stay meaningful (D-014, D-029).

It proves the *rules*. It proves nothing about any real authority, and it must never be pinned for anything
that matters.
