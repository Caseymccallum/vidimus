/**
 * The popup: one button, and an honest account of what it did.
 *
 * What it can and cannot do is worth writing down here, because the button is the whole interface:
 *
 * - It **can** seal. It reads the rendered document, takes the response facts the service worker
 *   observed, signs the claim with a key that has never left this browser, and hands you the file.
 * - It **cannot** check the receipt it just wrote. The verifier needs a synchronous digest and Node's
 *   `crypto`, and it lives on the command line. That is a named limitation of this shell rather than a
 *   claim that it is complete - the CLI's rule ("a producer does not hand over a receipt it has not
 *   checked") is not yet enforceable here, and that is the first thing a v0.2 should close.
 */

import { browser } from 'wxt/browser';

import { fromBase64Url, toBase64Url } from '../../../reference/src/encode.mjs';
import { generateKey } from '../../lib/keys.mjs';
import { checkReceipt } from '../../lib/checking.mjs';
import { sealPage } from '../../lib/sealing.mjs';

/** Where the key lives. Local storage only: there is no sync, and no server to sync it with. */
const KEY_STORAGE = 'vidimus:key';

interface StoredKey {
  pkcs8: string;
  publicRaw: string;
  keyId: string;
  signer: string | null;
}

interface Observation {
  url: string;
  status: number;
  statusText: string;
  contentType: string | null;
  headers: Array<[string, string]>;
}

const where = document.querySelector<HTMLParagraphElement>('#where');
const button = document.querySelector<HTMLButtonElement>('#seal');
const result = document.querySelector<HTMLPreElement>('#result');
const note = document.querySelector<HTMLParagraphElement>('#note');

let tabId: number | null = null;

/** UTC to the second: the only form the claim admits. */
function utcSecond(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** A file name that says what it is and which page it is for. */
function fileNameFor(url: string): string {
  let host = 'page';
  try {
    host = new URL(url).hostname;
  } catch {
    // A URL the browser gave us that cannot be parsed gets the boring name rather than no name.
  }
  return `${host}-${utcSecond().replace(/:/g, '')}.receipt`;
}

/**
 * The signing key, generated the first time it is needed and kept in extension storage.
 *
 * The public half travels inside every receipt; the private half is exported as PKCS#8 for no other
 * reason than to be written down and read back. It is not synced, not shared, and not sent anywhere:
 * there is nothing in this project to send it to.
 */
async function loadKey() {
  const stored = await browser.storage.local.get(KEY_STORAGE);
  const existing = stored?.[KEY_STORAGE] as StoredKey | undefined;
  if (existing !== undefined) {
    return {
      pkcs8: fromBase64Url(existing.pkcs8),
      publicRaw: fromBase64Url(existing.publicRaw),
      keyId: existing.keyId,
      signer: existing.signer,
    };
  }

  const key = await generateKey(null);
  const record: StoredKey = {
    pkcs8: toBase64Url(key.pkcs8),
    publicRaw: toBase64Url(key.publicRaw),
    keyId: key.keyId,
    signer: key.signer,
  };
  await browser.storage.local.set({ [KEY_STORAGE]: record });
  return key;
}

/** Hand the file to the browser, through a link rather than a permission. */
function save(bytes: Uint8Array, name: string): void {
  // Copied into a buffer this function owns, for two reasons: a Blob takes ownership of its parts, and
  // the bytes handed to us may be a view over somebody else's (larger) buffer.
  const bytesForFile = new Uint8Array(bytes.length);
  bytesForFile.set(bytes);

  const url = URL.createObjectURL(new Blob([bytesForFile], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  // The popup stays open, so the browser has time to start the download before the blob is dropped.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function say(text: string): void {
  if (result) {
    result.hidden = false;
    result.textContent = text;
  }
}

function fail(text: string): void {
  if (note) note.textContent = text;
  if (button) button.disabled = false;
}

async function seal(): Promise<void> {
  if (tabId === null) {
    fail('There is no page to seal.');
    return;
  }
  if (button) button.disabled = true;
  if (note) note.textContent = 'Sealing…';

  try {
    const observation = await browser.runtime.sendMessage({
      type: 'vidimus:observed',
      tabId,
    }) as Observation | null;

    if (observation === null || observation === undefined) {
      fail('This page\'s response was not observed. Reload the page, then seal it.');
      return;
    }

    const [injected] = await browser.scripting.executeScript({
      target: { tabId },
      func: () => document.documentElement.outerHTML,
    });
    const html = typeof injected?.result === 'string' ? injected.result : '';
    if (html === '') {
      fail('This page has no document to capture.');
      return;
    }

    const key = await loadKey();
    const sealed = await sealPage({
      facts: {
        url: observation.url,
        finalUrl: observation.url,
        status: observation.status,
        statusText: observation.statusText,
        contentType: observation.contentType,
        headers: observation.headers,
        html,
        capturedAt: utcSecond(),
      },
      key,
    });

    // D-017, in the browser: a receipt this program has not checked is not handed over. The same rule
    // the command line follows, now that the verifier can run here at all.
    const verdict = await checkReceipt(sealed.bytes);
    if (verdict.verified !== true) {
      say(verdict.summary.join('\n'));
      fail(
        `This receipt did not check out (integrity ${verdict.levels.L0.status}, `
        + `attribution ${verdict.levels.L1.status}), so it was not saved. That is a bug in this `
        + 'extension rather than anything you did.',
      );
      return;
    }

    const name = fileNameFor(observation.url);
    save(sealed.bytes, name);
    say([
      ...verdict.summary,
      '',
      `file      ${name}`,
    ].join('\n'));
    if (note) note.textContent = `Signed and checked here. vidimus verify ${name} checks it elsewhere.`;
  } catch (error) {
    fail(`Could not seal this page: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    if (button) button.disabled = false;
  }
}

async function start(): Promise<void> {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  tabId = tab?.id ?? null;

  if (where) where.textContent = tab?.url ?? 'No page is open.';
  if (tabId === null || tab?.url === undefined || !/^https?:/.test(tab.url)) {
    if (button) button.disabled = true;
    fail('Only a page served over http or https can be sealed.');
    return;
  }

  if (button) {
    button.disabled = false;
    button.addEventListener('click', () => {
      void seal();
    });
  }
}

void start();
