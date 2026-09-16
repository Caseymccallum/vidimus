# The extension's security model

The format has a threat model ([`docs/THREAT-MODEL.md`](../docs/THREAT-MODEL.md)). This is a different one,
about a different thing: **a small program holding a signing key on a machine that somebody else may have
access to.** A review of this project asked how the key is stored and what happens when the profile is
compromised, which was a fair question to ask of code that had not answered it in writing.

## 1. The key, and where it lives

- It is generated on first use, in the browser, with WebCrypto (Ed25519) - `lib/keys.mjs`. There is no
  server in this project to send it to, and no code path that does.
- It is stored as PKCS#8 in `chrome.storage.local`, under the single key `vidimus:key`, together with its
  raw public key and the derived key id.
- **It is not in memory only.** A key that vanished on every restart would give every receipt a different
  signer, and attribution that changes by the day is not attribution. It survives restarts, and it does
  not sync: there is no `storage.sync` call anywhere in this extension, so the key stays on one machine and
  Chrome is never sent it.
- **There is no export.** A user cannot move this key to another browser or another profile. A new profile
  means a new key, and receipts signed by the old one remain attributable to the old key id - which is the
  point of the id being derived from the key rather than asserted beside it.

## 2. What "in storage" means, exactly

`chrome.storage.local` is per-extension and per-profile. That gives three boundaries worth stating plainly,
because "it is in local storage" sounds vaguer than it is:

| Who | Can read the key? |
| --- | --- |
| A web page the extension is running on | **No.** Injected scripts run in an isolated world; a page cannot reach `chrome.storage` at all. |
| Another extension | **No.** Extension storage is namespaced per extension. |
| This extension's own code | **Yes.** The popup and the service worker can both read it, so anything that can run code in this extension's context has the key. |
| Anyone with the browser profile on disk | As far as the profile is protected. Chrome encrypts profile storage with OS-level keys; on a shared account where the other user can read your profile, that is not protection. |

So the trust boundary is **the extension's own bundle, and the operating-system account it runs under**.
Everything below follows from that.

## 3. What an attacker with the key can and cannot do

- **Can: sign anything.** A stolen key produces receipts for pages the thief never captured, and every one
  of them verifies. This is the strongest argument for a time anchor: a receipt anchored by a third party
  cannot be forged *after* the anchor's instant, so a key compromise is detectable for every claim older
  than the last honest anchor (`docs/TIMESTAMPING.md`).
- **Cannot: rewrite what has already been delivered.** A receipt is self-contained and signed, and its
  capture is covered by a digest. Changing a receipt somebody already holds is not a thing a key can do.
- **Cannot: pass as another signer.** The key id is derived from the public key, so a forgery is
  attributable to the *stolen* key and not to the person it was stolen from.
- **Cannot: forge a second extension's receipts**, or be forged by one. A different extension has its own
  key, and its receipts carry its own key id.

## 4. What is not defended, and is not pretended to be

- **A malicious update to this extension.** It can read the key and sign whatever it likes. The defence is
  the ordinary one: the code is small, dependency-free, in this repository, and reviewable.
- **Malware running as the same user**, which can read the profile and take the key.
- **Another extension that can read pages.** It cannot take this key, but it can record a page and sign a
  receipt of its own - which would be attributable to *its* key, not this one. A receipt always says which
  key made it.
- **A hostile page.** It can lie about what it contains, and the receipt will faithfully record the lie:
  a receipt is evidence about bytes, not about truth.
- **Losing the key.** Clearing extension data destroys it, and there is no backup and no recovery. Receipts
  already signed stay verifiable - the public key and the signature travel inside each one.

## 5. What the extension does *not* do with the key

- It does not sign anything except a claim it built from a capture you asked for, when you pressed the
  button.
- It does not sign a claim it has not verified: every receipt is checked in the same browser before it is
  saved (`reference/test/extension.test.mjs` pins the two runtimes to identical verdicts).
- It does not send the key, the receipts, or anything about them anywhere. The only requests it makes are
  the ones that gather the files a capture holds, and [`README.md`](README.md) says so beside the
  permission table.

## 6. Checking is always safe

Verification involves no key at all: it recomputes digests and checks a signature. Any receipt from
anybody can be checked in this browser, and the *sealing* key is only touched when a receipt is made.
