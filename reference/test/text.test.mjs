/**
 * `text-v1`: the rules, executed.
 *
 * Every test here is a rule from section 4.5 of the specification, and the ones that matter most are the
 * ones that would let a fingerprint disagree with itself: whitespace, entities, hidden elements, and
 * markup inside a `<script>`. A verifier that gets any of those wrong reports that a page changed when it
 * did not - or, worse, that it did not when it did.
 *
 * The last test is the one that closes the loop with the fixtures: the text of the page the conformance
 * vectors capture, extracted exactly as the spec defines it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TEXT_NORMALIZATION, extractText, textDigest } from '../src/text.mjs';
import { DEFAULT_HTML } from '../src/fixtures.mjs';
import { sha256 } from '../src/digest.mjs';
import { utf8 } from '../src/encode.mjs';

test('the normalisation has a name, and it is the one the claim states', () => {
  assert.equal(TEXT_NORMALIZATION, 'text-v1');
});

test('block elements end a line, inline elements do not', () => {
  assert.equal(extractText('<div><p>one</p><p>two</p></div>'), 'one\ntwo');
  assert.equal(extractText('<p>Hello <b>there</b>, friend</p>'), 'Hello there, friend');
  assert.equal(extractText('<ul><li>a</li><li>b</li></ul>'), 'a\nb');
  // A `<br>` is a block, so it ends a line without needing to be closed.
  assert.equal(extractText('<p>one<br>two</p>'), 'one\ntwo');
});

test('whitespace inside a line collapses, and empty blocks leave no line behind', () => {
  assert.equal(extractText('<p>\n  too   many\n  spaces\n</p>'), 'too many spaces');
  assert.equal(extractText('<div></div><p>only this</p><div> </div>'), 'only this');
  assert.equal(extractText('<p>&nbsp;&nbsp;indented</p>'), 'indented');
});

test('elements that are not prose are not read', () => {
  // The title is deliberately excluded: it is metadata, and a page whose title changed its wording
  // without changing its body is not a page whose text changed in the way this fingerprint means.
  assert.equal(
    extractText('<head><title>A title</title><style>p{margin:0}</style></head><body><p>Body</p></body>'),
    'Body',
  );
  assert.equal(extractText('<p>before</p><script>var x = 1;</script><p>after</p>'), 'before\nafter');
  // Markup inside a script is a string, not markup: scanning for tags here would invent content.
  assert.equal(extractText('<script>var html = "<p>not text</p>";</script><p>yes</p>'), 'yes');
  assert.equal(extractText('<svg><text>chart label</text></svg><p>prose</p>'), 'prose');
});

test('hidden elements are skipped, and so is everything inside them', () => {
  assert.equal(extractText('<p>shown</p><p hidden>hidden</p>'), 'shown');
  assert.equal(extractText('<p>shown</p><p aria-hidden="true">hidden</p>'), 'shown');
  assert.equal(extractText('<p>shown</p><p style="display: none">hidden</p>'), 'shown');
  assert.equal(extractText('<p>shown</p><p style="visibility:hidden">hidden</p>'), 'shown');
  assert.equal(
    extractText('<div hidden><p>hidden</p><p>also hidden</p></div><p>shown</p>'),
    'shown',
  );
});

test('entities become their characters, and unknown ones are left as written', () => {
  assert.equal(extractText('<p>fish &amp; chips</p>'), 'fish & chips');
  assert.equal(extractText('<p>&lt;not a tag&gt;</p>'), '<not a tag>');
  assert.equal(extractText('<p>caf&#233; &#x2014; open</p>'), 'caf\u00e9 \u2014 open');
  // A named entity this module does not know is data, not a guess: it stays exactly as the page wrote it.
  assert.equal(extractText('<p>&zigzag; stays</p>'), '&zigzag; stays');
  // An entity that cannot be a character is left alone rather than substituted with a replacement mark,
  // because a substitution a second implementation cannot reproduce is not a fingerprint.
  assert.equal(extractText('<p>&#xD800; stays</p>'), '&#xD800; stays');
});

test('malformed markup degrades in defined ways', () => {
  // A lone `<` is text: "3 < 4" is a sentence, and dropping the character would change the words.
  assert.equal(extractText('<p>3 < 4</p>'), '3 < 4');
  assert.equal(extractText('<p>unterminated'), 'unterminated');
  assert.equal(extractText('<p>one</p></nonsense><p>two</p>'), 'one\ntwo');
  assert.equal(extractText('plain text with no markup at all'), 'plain text with no markup at all');
  assert.equal(extractText(''), '');
});

test('the same bytes give the same answer, and the fingerprint is of the text', () => {
  const html = '<html><body><h1>One</h1><p>Two &amp; three</p></body></html>';
  const once = extractText(utf8(html));
  assert.equal(once, extractText(utf8(html)));
  assert.equal(once, 'One\nTwo & three');
  // Bytes and text are the same input: a producer has bytes, a caller debugging has a string.
  assert.equal(textDigest(utf8(html)), textDigest(html));
  assert.equal(textDigest(html), sha256(utf8(once)));
});

test('the fixture page extracts to what the conformance vectors say it does', () => {
  // The title is skipped and both heading and paragraph are blocks, so this is the whole text of the
  // page every fixture captures. `cases.mjs` fingerprints this same string, which is what makes
  // `subject.text` a pass rather than a fail - and what makes a wrong fingerprint a fail.
  assert.equal(extractText(DEFAULT_HTML), 'A page worth citing\nClaims were made here.');
  assert.equal(textDigest(DEFAULT_HTML), sha256(utf8('A page worth citing\nClaims were made here.')));
});
