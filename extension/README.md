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

## What it cannot do yet

- **Check its own receipt.** The verifier needs Node's `crypto` and a synchronous digest, so it lives on
  the command line: run `vidimus verify <file>` afterwards. The CLI refuses to hand over a receipt it has
  not checked; this shell cannot keep that promise yet, and says so rather than implying otherwise.
- **Capture subresources.** The capture holds the document as it was rendered, not the stylesheets and
  images around it. It does not claim more than that, but nothing in the claim yet *says* which kind of
  capture it is - see section 13 of the specification, where a `capture.profile` field is proposed.
- **Ask for fewer permissions than it does.** `<all_urls>` is what makes the status line observable;
  without it the claim would carry no `status` and no `content_type` (both optional in the format). That
  is the trade to revisit first, and it is written down here so that it is a decision rather than a
  detail.

## Permissions

Every permission carries a written reason in [`permissions.mjs`](permissions.mjs), the manifest is built
from that file, and a test fails if a permission appears without one. There is no analytics, no remote
code, and no network request of this extension's own.

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
