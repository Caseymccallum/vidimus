/**
 * Level 3: comparing a receipt with the page as it is now.
 *
 * This is the piece the verifier deliberately does not contain. `verifyReceipt` reads no clock and makes
 * no request, so "does the page still match?" is not a question it can answer - and folding an answer
 * into `verified` would let a green tick stand for work no verifier did (D-005). Instead the comparison
 * lives here, pure, and a *caller* performs the fetch and reports the result separately.
 *
 * Pure means: two sets of facts in, one report out. No clock, no network, no receipts opened. What it
 * cannot do is fetch, and what it must never do is decide whether a receipt is valid - that is
 * `verify.mjs`, and nothing here changes its answer.
 *
 * ## The comparison that matters
 *
 * Byte-for-byte equality of two captures is worthless as a currency test, because two captures of one
 * unchanged page differ anyway: the WARC records their own timestamps, and a page's footer usually does
 * too. What is worth comparing is what a reader actually cares about:
 *
 * - **the document**, byte for byte - `document_sha256`;
 * - **the words**, through the `text-v1` fingerprint of section 4.5 - `text_sha256`.
 *
 * Those two together give the report its most useful sentence, and the reason this module exists:
 * *the bytes changed and the words did not.* A nonce, a timestamp or a re-ordered attribute in the markup
 * is a `words_unchanged`; a sentence rewritten is a `changed`.
 *
 * @module currency
 */

/**
 * The outcomes, each with the sentence it means. Named rather than inferred by a caller from a set of
 * booleans, because "the bytes differ but the words are the same" is a distinction people get wrong when
 * they have to assemble it themselves.
 */
export const OUTCOMES = {
  unchanged: 'the page is byte-for-byte what it was',
  words_unchanged: 'the bytes changed and the words did not',
  changed: 'the words changed',
  gone: 'the page did not come back',
  not_compared: 'the two were not compared',
};

/** @typedef {{ sha256: string | null, bytes?: number | null }} DocumentFacts */

/**
 * @typedef {object} PageFactsNow
 * @property {string} url
 * @property {string | null} capturedAt
 * @property {number | null} status
 * @property {string | null} documentSha256
 * @property {number | null} documentBytes
 * @property {string | null} textSha256
 */

/**
 * @typedef {object} CurrencyReport
 * @property {string} url
 * @property {keyof typeof OUTCOMES} outcome
 * @property {string} meaning
 * @property {{ captured_at: string | null, status: number | null, document_sha256: string | null, text_sha256: string | null }} claimed
 * @property {{ captured_at: string | null, status: number | null, document_sha256: string | null, text_sha256: string | null }} now
 * @property {string[]} differences Field names, so a caller can act on them without parsing prose.
 * @property {string[]} caveats
 */

/**
 * Compare a receipt's account of a page with a fresh look at the same page.
 *
 * @param {{
 *   url: string,
 *   capturedAt: string | null,
 *   status: number | null,
 *   document: DocumentFacts, textSha256?: string | null,
 * }} claimed
 * @param {PageFactsNow | null} now Null when the fetch did not happen, which is a report of its own
 * rather than an error: a caller that could not reach the page has learned something too.
 * @param {string} [whyNotCompared] Said plainly when `now` is null.
 * @returns {CurrencyReport}
 */
export function compareCurrency(claimed, now, whyNotCompared) {
  const left = {
    captured_at: claimed.capturedAt ?? null,
    status: claimed.status ?? null,
    document_sha256: claimed.document?.sha256 ?? null,
    text_sha256: claimed.textSha256 ?? null,
  };

  const caveats = [];
  if (left.text_sha256 === null) {
    caveats.push(
      'the receipt declares no text fingerprint, so whether the words changed cannot be answered - '
      + 'only whether the bytes did',
    );
  }

  if (now === null) {
    return {
      url: claimed.url,
      outcome: 'not_compared',
      meaning: OUTCOMES.not_compared,
      claimed: left,
      now: { captured_at: null, status: null, document_sha256: null, text_sha256: null },
      differences: [],
      caveats: [whyNotCompared ?? 'the page was not fetched', ...caveats],
    };
  }

  const right = {
    captured_at: now.capturedAt ?? null,
    status: now.status ?? null,
    document_sha256: now.documentSha256 ?? null,
    text_sha256: now.textSha256 ?? null,
  };

  const differences = [];
  if (claimed.document?.sha256 != null && claimed.document.sha256 !== right.document_sha256) {
    differences.push('document_sha256');
  }
  if (left.text_sha256 !== null && right.text_sha256 !== null && left.text_sha256 !== right.text_sha256) {
    differences.push('text_sha256');
  }
  if (left.status !== null && right.status !== null && left.status !== right.status) {
    differences.push('status');
  }

  // A page that answered with an error is not a page that changed its words, and saying so would be the
  // most misleading answer this module could give.
  const gone = typeof right.status === 'number' && right.status >= 400;
  const wordsDiffer = differences.includes('text_sha256');
  const bytesDiffer = differences.includes('document_sha256');

  let outcome = 'unchanged';
  if (gone) outcome = 'gone';
  else if (wordsDiffer) outcome = 'changed';
  else if (bytesDiffer) outcome = 'words_unchanged';

  if (gone) {
    caveats.push(
      `the page answered ${right.status}, so what it holds now was not compared with what it held then`,
    );
  }
  if (right.text_sha256 === null && left.text_sha256 !== null) {
    caveats.push('the page as it is now produced no text to compare');
  }

  return {
    url: claimed.url,
    outcome,
    meaning: OUTCOMES[outcome],
    claimed: left,
    now: right,
    differences,
    caveats,
  };
}
