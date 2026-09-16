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

/** Limits, so that a capture stays something a person can attach to a citation. */
const MAX_RESOURCES = 40;
const MAX_RESOURCE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;

interface Resource {
  url: string;
  status: number;
  statusText: string;
  contentType: string | null;
  headers: Array<[string, string]>;
  body: Uint8Array;
}

/**
 * The files the document referenced, fetched so the capture can hold them.
 *
 * This is the one place where the extension makes a request of its own, and it is worth being plain about
 * it: the browser will not hand over the body of a response the *page* made, so a capture that wants the
 * stylesheet and the images has to ask for them. They are fetched again, so what is captured is what the
 * server sends now - which is why the count of files kept and left out is reported to the user rather
 * than folded silently into the receipt.
 *
 * Anything that cannot be fetched, is too large, or returns an error is **left out and counted**. A
 * capture that quietly drops half a page is worse than one that says how much it holds.
 *
 * @returns The resources to capture, and how many were left out.
 */
async function collectResources(urls: string[]): Promise<{ resources: Resource[]; skipped: number }> {
  const resources: Resource[] = [];
  let skipped = 0;
  let total = 0;

  for (const url of urls) {
    if (resources.length >= MAX_RESOURCES || total >= MAX_TOTAL_BYTES) {
      skipped += 1;
      continue;
    }
    try {
      const response = await fetch(url, { credentials: 'include' });
      if (!response.ok) {
        skipped += 1;
        continue;
      }
      const body = new Uint8Array(await response.arrayBuffer());
      if (body.length > MAX_RESOURCE_BYTES || total + body.length > MAX_TOTAL_BYTES) {
        skipped += 1;
        continue;
      }
      total += body.length;
      resources.push({
        url,
        status: response.status,
        statusText: response.statusText,
        contentType: response.headers.get('content-type'),
        headers: [...response.headers.entries()],
        body,
      });
    } catch {
      skipped += 1;
    }
  }

  return { resources, skipped };
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
      func: () => ({
        html: document.documentElement.outerHTML,
        // The document, and the files it points at. Anything the page assembles at runtime and does not
        // reference by URL is beyond a capture of this kind, and the profile says which kind it is.
        urls: [...new Set([
          ...[...document.querySelectorAll('link[rel="stylesheet"]')]
            .map((element) => (element as HTMLLinkElement).href),
          ...[...document.querySelectorAll('img[src]')]
            .map((element) => (element as HTMLImageElement).src),
        ])].filter((url) => url !== ''),
      }),
    });
    const page = injected?.result as { html: string; urls: string[] } | undefined;
    const html = typeof page?.html === 'string' ? page.html : '';
    if (html === '') {
      fail('This page has no document to capture.');
      return;
    }

    if (note) note.textContent = 'Fetching the files this page uses…';
    const { resources, skipped } = await collectResources(page?.urls ?? []);

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
      resources,
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
      `files     ${resources.length} kept${skipped > 0 ? `, ${skipped} left out` : ''}`,
      `file      ${name}`,
    ].join('\n'));
    if (note) {
      note.textContent = skipped > 0
        ? `Signed and checked here. ${skipped} file(s) could not be fetched, so this capture does not hold them.`
        : `Signed and checked here. vidimus verify ${name} checks it elsewhere.`;
    }
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
