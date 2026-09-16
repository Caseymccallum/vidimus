/**
 * Citing a receipt: what to write down, and what a receipt cannot say.
 *
 * A receipt is evidence, and evidence is only useful if it travels with a reference to the work it
 * supports. That reference has a standard shape already - CSL-JSON, which every citation manager reads -
 * and this module emits it rather than inventing one.
 *
 * **What a receipt can support, and what it cannot.** A claim asserts a URL, a time, a document digest and
 * the words on the page. It does **not** assert a title, an author, a publication or a date of publication:
 * those are facts about a work, and a capture of a page is not a claim about a work. So a citation built
 * from a receipt has a URL, an access date, an identifier - and no title unless the person citing
 * supplies one. A guessed title inside a citation is exactly the kind of plausible falsehood this project
 * refuses to write into a signed claim; there is no reason to write it into a bibliography either.
 *
 * The identifier is the claim hash, which is what makes the citation *checkable*: somebody holding the
 * receipt can recompute it, and somebody holding the citation can search an index for it.
 *
 * @module cite
 */

/**
 * CSL's type for a page on the web. Not `article`, not `document`: a capture is a page, and a citation that
 * claimed more would be claiming something the receipt does not support.
 */
export const CITATION_TYPE = 'webpage';

/**
 * A UTC instant to CSL's date format: `{"date-parts": [[2026, 1, 1]]}`, with months numbered from one.
 *
 * @param {string | null} timestamp
 * @returns {{ 'date-parts': number[][] } | null}
 */
function dateParts(timestamp) {
  if (typeof timestamp !== 'string') return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T/.exec(timestamp);
  if (match === null) return null;
  return { 'date-parts': [[Number(match[1]), Number(match[2]), Number(match[3])]] };
}

/**
 * Build the citation for a receipt.
 *
 * @param {{
 *   url: string,
 *   capturedAt?: string | null,
 *   claimHash?: string | null,
 *   title?: string | null,
 *   receiptName?: string | null,
 * }} input
 * @returns {{
 *   csl: Record<string, any>, text: string, trailer: string,
 *   caveats: string[],
 * }}
 */
export function citationFor(input) {
  const claimHash = typeof input.claimHash === 'string' && input.claimHash !== '' ? input.claimHash : null;
  const capturedAt = typeof input.capturedAt === 'string' ? input.capturedAt : null;
  const title = typeof input.title === 'string' && input.title !== '' ? input.title : null;

  const caveats = [];
  if (title === null) {
    caveats.push(
      'no title is given: a receipt asserts a URL, a time and the words on the page, and never a title, '
      + 'so the title of a citation is the citer\'s to supply (--title)',
    );
  }
  if (claimHash === null) {
    caveats.push('the claim hash could not be computed, so the citation has no identifier to be found by');
  }

  /** @type {Record<string, any>} */
  const csl = {
    ...(claimHash === null ? {} : { id: claimHash }),
    type: CITATION_TYPE,
    URL: input.url,
    ...(title === null ? {} : { title }),
    ...(dateParts(capturedAt) === null ? {} : { accessed: dateParts(capturedAt) }),
    ...(claimHash === null ? {} : {
      note: `Verified receipt${input.receiptName ? ` (${input.receiptName})` : ''}: ${claimHash}`,
    }),
  };

  const accessed = capturedAt === null ? 'a time the claim does not state' : `accessed ${capturedAt.slice(0, 10)}`;
  const text = [
    title === null ? '' : `${title}. `,
    input.url,
    ` (${accessed})`,
    claimHash === null ? '' : `. Receipt ${claimHash}.`,
  ].join('');

  // The line a commit message carries. A trailer is read by people and by scripts, and it is the shortest
  // form of "this document cites this capture" that survives being copied out of a message.
  const trailer = claimHash === null ? '' : `Receipt: ${claimHash}`;

  return { csl, text, trailer, caveats };
}

/**
 * One line for a citation index: a file people commit next to the work, so that a repository has a list of
 * what it cites rather than a directory of receipts nobody can search.
 *
 * @param {Record<string, any>} csl
 * @param {string | null} receiptName
 * @returns {string} A JSON object, without a trailing newline.
 */
export function indexEntry(csl, receiptName) {
  return JSON.stringify({
    id: csl.id ?? null,
    url: csl.URL ?? null,
    used: csl.accessed ?? null,
    title: csl.title ?? null,
    receipt: receiptName ?? null,
  });
}
