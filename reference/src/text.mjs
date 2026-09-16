/**
 * `text-v1`: the text a reader would see, extracted deterministically from bytes.
 *
 * A receipt that carries a text fingerprint is making a small, sharp claim: *these are the words this
 * page put in front of me*. Checking that claim has two halves, and this module is the first one:
 *
 * 1. **the fingerprint matches its definition** - the words re-extracted from the capture's own document
 *    hash to what the claim says (the `subject.text` check);
 * 2. **the page still says the same words** - that needs a request to the page, which a verifier does not
 *    make, and it is a separate act with a separate report (`reference/src/currency.mjs`).
 *
 * **The definition is written down in the specification** (section 4.5) rather than deferred to a
 * browser. `innerText` is the obvious tool and is deliberately not used: it depends on layout, so it
 * differs between engines, returns nothing at all for a detached document, and would make the
 * fingerprint provable only by running a browser. The rules here are a deterministic walk - which
 * elements are text, which are not, what ends a line, how whitespace collapses - so the same bytes give
 * the same answer in a command line and in an extension, which is what a verifier needs.
 *
 * The rules are derived from Shelf's `extractText` (D-009), which remains the implementation they came
 * from. The difference is the input: this walk runs over the *bytes*, not over a live DOM, because a
 * verifier holding a capture has bytes and no DOM.
 *
 * **What it deliberately does not do.** No layout, no `display:none` from a stylesheet (only the
 * element's own `style` attribute), no error recovery of the kind a browser performs on malformed HTML,
 * and no full HTML5 entity table. A document a browser serialised is well-formed and every rule above is
 * exact for it; a document a crawler fetched may not be, and the specification says so rather than
 * implying otherwise (section 4.5.4). Both sides of a comparison run the same walk over the same bytes,
 * so what the fingerprint is *for* - noticing that the words changed - holds either way.
 *
 * @module text
 */

import { toHex, utf8 } from './encode.mjs';
import { sha256 } from './sha256.mjs';

/** The only normalisation this version of the format defines. */
export const TEXT_NORMALIZATION = 'text-v1';

/** Elements whose text is not prose: code, styles, and machine-readable leftovers. */
const SKIPPED = new Set([
  'script', 'style', 'noscript', 'template', 'head', 'title', 'meta', 'link',
  'svg', 'canvas', 'iframe', 'object', 'embed', 'audio', 'video',
]);

/** Elements that end a line, so paragraphs and list items do not run into each other. */
const BLOCKS = new Set([
  'address', 'article', 'aside', 'blockquote', 'br', 'dd', 'div', 'dl', 'dt', 'fieldset',
  'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr',
  'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'tbody', 'td', 'tfoot', 'th',
  'thead', 'tr', 'ul',
]);

/** Elements that never have children or an end tag, so one must not be expected. */
const VOID = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
  'param', 'source', 'track', 'wbr',
]);

/** Elements whose content is text even when it looks like markup, so it must not be scanned for tags. */
const RAW_TEXT = new Set(['script', 'style', 'title', 'textarea']);

/**
 * The named entities this module decodes.
 *
 * Not the HTML5 table: it is two thousand entries, most of them mathematical, and a receipt does not need
 * them. What is here is what a page in the wild uses for punctuation and spacing - and anything else is
 * left as written rather than guessed at, which is the honest half of a short list.
 */
const NAMED_ENTITIES = new Map(Object.entries({
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0',
  copy: '\u00a9', reg: '\u00ae', trade: '\u2122', deg: '\u00b0',
  hellip: '\u2026', mdash: '\u2014', ndash: '\u2013', minus: '\u2212',
  lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201c', rdquo: '\u201d',
  laquo: '\u00ab', raquo: '\u00bb', bull: '\u2022', middot: '\u00b7',
  sect: '\u00a7', para: '\u00b6', dagger: '\u2020', Dagger: '\u2021',
  times: '\u00d7', plusmn: '\u00b1', frac12: '\u00bd', frac14: '\u00bc',
  euro: '\u20ac', pound: '\u00a3', yen: '\u00a5', cent: '\u00a2',
  eacute: '\u00e9', egrave: '\u00e8', uuml: '\u00fc', ouml: '\u00f6', auml: '\u00e4',
}));

/**
 * @param {string} text
 * @returns {string}
 */
function decodeEntities(text) {
  if (!text.includes('&')) return text;
  return text.replace(/&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, body) => {
    if (body.startsWith('#')) {
      const hex = body[1] === 'x' || body[1] === 'X';
      const code = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
      // A code point that cannot be a character, or that a lone surrogate would corrupt, is left as
      // written. A browser would substitute U+FFFD; a fingerprint that silently substitutes is one
      // nobody can reproduce from the rules.
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
      if (code >= 0xd800 && code <= 0xdfff) return whole;
      return String.fromCodePoint(code);
    }
    return NAMED_ENTITIES.get(body) ?? whole;
  });
}

/**
 * @typedef {object} Tag
 * @property {'start' | 'end'} kind
 * @property {string} name Lowercase.
 * @property {Map<string, string | null>} attrs
 * @property {boolean} selfClosing
 * @property {number} end Index just past the tag.
 */

/**
 * Read one tag, tolerantly.
 *
 * Tolerance is deliberate and bounded: a stray `<` is text (`3 < 4` is a sentence), and an unterminated
 * tag is the end of the document rather than a reason to throw. Nothing here tries to recover the way a
 * browser does, because a fingerprint that depends on which error-recovery path a particular engine
 * takes is a fingerprint a second implementation cannot reproduce.
 *
 * @param {string} html
 * @param {number} start Index of the `<`.
 * @returns {Tag | null} Null when this is not a tag at all.
 */
function readTag(html, start) {
  let i = start + 1;
  let kind = /** @type {'start' | 'end'} */ ('start');
  if (html[i] === '/') {
    kind = 'end';
    i += 1;
  }
  const nameStart = i;
  while (i < html.length && /[a-zA-Z0-9:_-]/.test(html[i])) i += 1;
  const name = html.slice(nameStart, i).toLowerCase();
  if (name === '') return null;

  const attrs = new Map();
  let selfClosing = false;
  while (i < html.length) {
    while (i < html.length && /\s/.test(html[i])) i += 1;
    if (i >= html.length) break;
    if (html[i] === '>') {
      i += 1;
      break;
    }
    if (html[i] === '/' && html[i + 1] === '>') {
      selfClosing = true;
      i += 2;
      break;
    }
    if (html[i] === '/') {
      i += 1;
      continue;
    }

    const attrStart = i;
    while (i < html.length && !/[\s=/>]/.test(html[i])) i += 1;
    const attrName = html.slice(attrStart, i).toLowerCase();
    while (i < html.length && /\s/.test(html[i])) i += 1;

    let value = null;
    if (html[i] === '=') {
      i += 1;
      while (i < html.length && /\s/.test(html[i])) i += 1;
      const quote = html[i];
      if (quote === '"' || quote === "'") {
        const close = html.indexOf(quote, i + 1);
        const stop = close === -1 ? html.length : close;
        value = html.slice(i + 1, stop);
        i = close === -1 ? html.length : close + 1;
      } else {
        const valueStart = i;
        while (i < html.length && !/[\s>]/.test(html[i])) i += 1;
        value = html.slice(valueStart, i);
      }
    }
    if (attrName !== '') attrs.set(attrName, value);
  }

  return { kind, name, attrs, selfClosing, end: i };
}

/**
 * True when an element asks not to be read out: hidden, or explicitly hidden from assistive technology.
 *
 * Only the element's own attributes are consulted. A stylesheet's `display: none` is not visible here,
 * and pretending otherwise would mean implementing a cascade (section 4.5.4 of the specification).
 *
 * @param {Map<string, string | null>} attrs
 * @returns {boolean}
 */
function isHidden(attrs) {
  if (attrs.has('hidden')) return true;
  if (attrs.get('aria-hidden') === 'true') return true;
  const style = attrs.get('style');
  return typeof style === 'string' && /display\s*:\s*none|visibility\s*:\s*hidden/i.test(style);
}

/**
 * @typedef {object} OpenElement
 * @property {string} name
 * @property {boolean} skipped
 * @property {boolean} hidden
 */

/**
 * The visible text of a document, one line per block, with whitespace collapsed inside a line.
 *
 * `current` accumulates the line being built. A block element ends it - before its content and after it -
 * and an element that is skipped, or that is inside one, contributes nothing at all.
 *
 * @param {Uint8Array | string} input The document's bytes, or its text.
 * @returns {string}
 */
export function extractText(input) {
  const html = typeof input === 'string' ? input : new TextDecoder('utf-8').decode(input);
  const lowered = html.toLowerCase();

  /** @type {string[]} */
  const lines = [];
  let current = '';
  /** @type {OpenElement[]} */
  const open = [];

  const readable = () => !open.some((element) => element.skipped || element.hidden);
  const flush = () => {
    const line = current.replace(/\s+/g, ' ').trim();
    if (line !== '') lines.push(line);
    current = '';
  };

  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt === -1) {
      if (readable()) current += decodeEntities(html.slice(i));
      break;
    }
    if (lt > i && readable()) current += decodeEntities(html.slice(i, lt));

    if (html.startsWith('<!--', lt)) {
      const close = html.indexOf('-->', lt + 4);
      i = close === -1 ? html.length : close + 3;
      continue;
    }
    if (html.startsWith('<!', lt) || html.startsWith('<?', lt)) {
      const close = html.indexOf('>', lt);
      i = close === -1 ? html.length : close + 1;
      continue;
    }

    const tag = readTag(html, lt);
    if (tag === null) {
      // A lone `<` in a sentence. It is text, and dropping it would change the words.
      if (readable()) current += '<';
      i = lt + 1;
      continue;
    }
    i = tag.end;

    if (tag.kind === 'end') {
      // Pop to the matching element, if it is open. An end tag with no start is ignored rather than
      // treated as a block boundary: bad markup should not silently reflow a line.
      const at = open.map((element) => element.name).lastIndexOf(tag.name);
      if (at === -1) continue;
      const wasBlock = BLOCKS.has(tag.name);
      const wasReadable = readable();
      open.length = at;
      if (wasBlock && wasReadable) flush();
      continue;
    }

    const isVoid = VOID.has(tag.name) || tag.selfClosing;
    const block = BLOCKS.has(tag.name);
    if (block && !isVoid && readable()) flush();
    if (isVoid) {
      if (block && readable()) flush();
      continue;
    }

    open.push({
      name: tag.name,
      skipped: SKIPPED.has(tag.name),
      hidden: isHidden(tag.attrs),
    });

    if (RAW_TEXT.has(tag.name)) {
      // Scan to the end tag rather than scanning for tags inside: `<style>` full of `a > b` selectors is
      // not markup, and a `<script>` containing `'<div>'` is a string.
      const close = lowered.indexOf(`</${tag.name}`, i);
      if (close === -1) {
        open.pop();
        break;
      }
      i = close;
    }
  }

  flush();
  return lines.join('\n');
}

/**
 * The `text-v1` fingerprint of a document: the SHA-256 of the extracted text, as UTF-8.
 *
 * No trailing newline. Lines are joined by `\n` and nothing is added, so a fingerprint is reproducible
 * from the rules alone.
 *
 * @param {Uint8Array | string} input
 * @returns {string} Lowercase hex.
 */
export function textDigest(input) {
  return toHex(sha256(utf8(extractText(input))));
}
