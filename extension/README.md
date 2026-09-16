# The Vidimus extension

**Seal the page you are reading.** One button: the rendered document, the response facts the browser
observed, a claim signed with a key that never leaves this browser, and a `.receipt` file you own.

This is the capture half of the project. The specification, the verifier and the command-line sealer
live one directory up, and this extension *imports* them rather than reimplementing them - which is why
the two producers cannot drift apart (D-018).

## What it does, in order

1. The service worker observes the status line and the response headers of each tab's main document and
   keeps them in memory. Nothing is written to disk, and nothing is sent anywhere.
2. You click **Seal this page**. The popup reads the rendered DOM and gathers the observation.
3. The claim is built by `reference/src/claim.mjs`, signed with Ed25519 through WebCrypto, using a key
   generated on first use and kept in `chrome.storage.local`.
4. The file is handed to the browser's downloads through a link, so no `downloads` permission is needed.

## What it does and does not do

- **It checks its own receipt before handing it over.** The verifier runs here, on the same rules the
  command line uses (D-021): if what it has just written does not verify, the file is not saved and the
  popup says so. The two runtimes are pinned together by a test that asserts their verdicts are identical,
  reason for reason.
- **It reads containers the way they come**: stored or deflated, so a receipt written by another tool is
  checked here as well as on the command line. What it cannot read it refuses by name - ZIP64, encrypted
  entries, an unknown compression method - and the check reports `unsupported` rather than pretending.
- **It captures the document and the files it references** - the stylesheets and images, addressed by
  their own URLs, which is what a WACZ-aware replayer looks up when it serves them from the archive.
  There are limits (40 files, 2 MB each, 8 MB in total), and the popup tells you how many were kept and
  how many were left out rather than folding the difference into a receipt quietly.
- **It says what kind of capture it holds.** Its claims declare `capture.profile: "document-v1"` - the
  document as the browser rendered it. That is a different claim from one holding the bytes a server
  sent, and a reader deciding whether a receipt is good enough now has a way to tell the two apart.
- **It declares the words it captured, and checks them.** Every claim it writes carries a `text-v1`
  fingerprint of the rendered document, so "did the page's words change?" is answerable years later
  without re-reading the page - and the check runs here, in this browser, from the capture's own bytes
  rather than from anything the page says now.
- **It can check a receipt that carries a timestamp.** An RFC 3161 anchor is validated against a TSA
  certificate the *caller* pins; the extension does not ship one, so an anchored receipt checked here
  reports what it could not validate rather than implying it did.
- **It asks for `<all_urls>`.** That host permission is what makes a response status observable; without
  it the claim would carry no `status` and no `content_type` (both optional in the format). A real trade,
  and the first one to revisit.

## Permissions

Every permission carries a written reason in [`permissions.mjs`](permissions.mjs), the manifest is built
from that file, and a test fails if a permission appears without one. There is no analytics and no remote
code. The only requests the extension makes are the ones that gather the files a capture holds: they go
to the page's own sources, they are made when you press the button and not before, and the popup tells you
how many succeeded.

| Permission | Why |
| --- | --- |
| `storage` | the sealing key and nothing else |
| `scripting` | to read the rendered document of the page you asked to capture |
| `webRequest` | to observe the status line and response headers of that page |
| `<all_urls>` | the pages you capture can be anywhere, and a host permission is per-site |

## Development

```bash
npm install
npm run dev       # Chrome, with live reload
npm run verify    # type check, then build
```

The logic that matters - the capture, the claim, the signature - is plain ESM in `lib/`, and it is
tested from the project's own suite in Node, using Node's WebCrypto
(`reference/test/extension.test.mjs`). A browser is needed to *use* this extension, not to know that
it works.

## Security

What this extension does with the signing key, what a stolen key can and cannot do, and what a compromised
profile means: [`SECURITY.md`](SECURITY.md). It is short, and it answers the question a reviewer asked first.
