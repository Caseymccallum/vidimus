/**
 * The service worker: what the browser was told about each page, kept for the seconds until the popup
 * asks.
 *
 * **Observation only**, and that is a design decision rather than a limitation of the moment: the
 * listener is registered without blocking, so nothing here can delay, rewrite or stop a request.
 * Neither does it make a request of its own - no fetch, no beacon, no endpoint - which is what makes
 * the extension's permission list defensible rather than merely declared.
 *
 * The observations live in memory and nowhere else. They are needed between a page loading and the
 * popup sealing it, and a copy on disk would be a record of browsing that nobody asked for.
 */

import { browser } from 'wxt/browser';

/** What a page's response looked like, as far as the browser will say. */
export interface Observation {
  url: string;
  status: number;
  statusText: string;
  contentType: string | null;
  headers: Array<[string, string]>;
}

const observed = new Map<number, Observation>();

export default defineBackground(() => {
  browser.webRequest.onHeadersReceived.addListener(
    // The listener returns `undefined`, which is how a `webRequest` listener says "I am not blocking
    // this". Returning anything else would be asking to modify a response, which this extension never
    // does; the type is what makes that explicit rather than a matter of good intentions.
    (details): undefined => {
      if (details.tabId < 0 || details.type !== 'main_frame') return undefined;
      const headers = details.responseHeaders ?? [];

      observed.set(details.tabId, {
        url: details.url,
        status: details.statusCode,
        // "HTTP/1.1 200 OK" carries the reason phrase after the status code.
        statusText: (details.statusLine ?? '').split(' ').slice(2).join(' '),
        contentType: headers.find((header) => header.name.toLowerCase() === 'content-type')?.value ?? null,
        headers: headers.map((header) => [header.name, header.value ?? '']),
      });
      return undefined;
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['responseHeaders'],
  );

  browser.tabs.onRemoved.addListener((tabId) => {
    observed.delete(tabId);
  });

  browser.runtime.onMessage.addListener((message: unknown) => {
    const request = message as { type?: string; tabId?: number } | null;
    if (request?.type !== 'vidimus:observed' || typeof request.tabId !== 'number') return undefined;
    return Promise.resolve(observed.get(request.tabId) ?? null);
  });
});
