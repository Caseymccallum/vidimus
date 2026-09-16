#!/usr/bin/env python3
"""`text-v1`: the words, extracted from a document's bytes.

Section 4.5.1 of `docs/RECEIPT-SPEC.md` is the normative definition, and this file is that section and
nothing else - all seven of its rules, in its order, over bytes. That is the strongest kind of check this
directory has: the container, the claim, the signature and the anchor layers were written from the
specification too, and the record layer and the token verifier were not.

The reason a fingerprint needs its rules written down rather than inherited from a browser: `innerText`
depends on layout, differs between engines, and returns nothing for a detached document - and a receipt
verified in one runtime and reported `not_checked` in another is two answers to one question.

Where the section is silent, this implementation says so rather than guessing quietly, and
`conformance/README.md` lists it:

* **which characters count as whitespace** (rule 5 says "interior runs of whitespace become one space" and
  does not enumerate them, so this collapses Unicode whitespace, which is what the specification's own
  implementation does);
* **which named character references are known** (rule 6 says "named, decimal and hexadecimal", and section
  4.5.4 says "no full HTML5 entity table", so this knows the five that XML and HTML share);
* **how a document that is not UTF-8 is decoded** (section 4.5 says the walk is over bytes and not how bytes
  become characters, so this decodes UTF-8 with replacement, as a platform decoder does by default).
"""

from __future__ import annotations

import hashlib
import re

# Rule 2: these end a line, before and after. Everything else joins its neighbours.
BLOCK_ELEMENTS = frozenset({
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "fieldset", "figcaption",
    "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav",
    "ol", "p", "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
})

# Rule 3: neither these nor anything inside them is read.
UNREAD_ELEMENTS = frozenset({
    "script", "style", "noscript", "template", "head", "title", "meta", "link", "svg", "canvas", "iframe",
    "object", "embed", "audio", "video",
})

# Rule 7: inside these, a tag is content rather than markup, so only the matching end tag ends them.
RAW_TEXT_ELEMENTS = frozenset({"script", "style", "title", "textarea"})

# Rule 3: an element that never has children, so it can never be on the open stack.
VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track",
    "wbr",
})

# Rule 6: the named references this implementation knows, and no more (section 4.5.4: no full HTML5 table).
# `nbsp` is the one that matters beyond the five XML shares: it decodes to U+00A0, which rule 5 then collapses
# to a space - so a page that writes `a&nbsp;b` and a page that writes `a b` fingerprint the same way.
NAMED_REFERENCES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": "\u00a0"}

# Rule 5: the whitespace a line collapses. Spelled out rather than left to Python's `str.split()`, because
# the two sets differ at their edges - Python counts U+0085 and the C0 separators as whitespace and not
# U+FEFF, and the other side counts U+FEFF and not U+0085 - and a fingerprint cannot afford a disagreement at
# an edge. This is the set the specification's own implementation collapses with, written down.
WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
WHITESPACE_RUN = re.compile("[" + re.escape(WHITESPACE) + "]+")

TAG_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9:-]*")
REFERENCE = re.compile(r"&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);")


def extract(document: bytes) -> str:
    """The extracted text: the lines the document says, joined with `\\n` (rule 5)."""
    return "\n".join(_lines(document.decode("utf-8", "replace")))


def fingerprint(document: bytes) -> str:
    """The `text-v1` fingerprint: SHA-256 of the extracted text as UTF-8, with no trailing newline."""
    return hashlib.sha256(extract(document).encode("utf-8")).hexdigest()


def _lines(text: str) -> list[str]:
    """Walk the markup, collect lines, then collapse and trim each one."""
    lines: list[str] = []
    current: list[str] = []
    open_elements: list[str] = []
    position = 0

    def end_line() -> None:
        collapsed = WHITESPACE_RUN.sub(" ", "".join(current)).strip(WHITESPACE)
        if collapsed:
            lines.append(collapsed)
        current.clear()

    while position < len(text):
        marker = text.find("<", position)
        if marker == -1:
            current.append(_decode(text[position:]))
            break

        # Rule 7: a `<` that does not begin a tag is text.
        following = text[marker + 1:marker + 2]
        if following == "" or (not following.isalpha() and following not in ("/", "!", "?")):
            # Decoded like any other text: rule 1 says a text node contributes its characters with
            # references decoded, and rule 7 says this is text. Missing that turns `&gt; three, and 3 < 5`
            # into a line with a literal `&gt;` in it, which is how this was found.
            current.append(_decode(text[position:marker + 1]))
            position = marker + 1
            continue

        current.append(_decode(text[position:marker]))
        position = marker

        if text.startswith("<!--", position):
            end = text.find("-->", position + 4)
            if end == -1:
                break  # An unterminated comment ends the document, as an unterminated tag does.
            position = end + 3
            continue

        if following in ("!", "?"):
            end = text.find(">", position)
            if end == -1:
                break
            position = end + 1
            continue

        if following == "/":
            name, position = _end_tag(text, position)
            if name is None:
                break  # unterminated
            if name in open_elements:
                # Rule 7: an end tag with no matching start is ignored - including its line break, which is
                # why the break belongs on the open branch and not before it.
                open_elements.pop()
                if name in BLOCK_ELEMENTS:
                    end_line()
            continue

        name, attributes, position = _start_tag(text, position)
        if name is None:
            break  # an unterminated tag ends the document

        if name in UNREAD_ELEMENTS or _asks_not_to_be_read(attributes):
            # Skip everything inside it: for a raw-text element by looking for its own end tag, and for the
            # others by walking their nested tags until the matching end tag.
            position = _skip_element(text, position, name)
            continue

        if name not in VOID_ELEMENTS:
            open_elements.append(name)
        if name in BLOCK_ELEMENTS:
            end_line()

    end_line()
    return lines


def _start_tag(text: str, position: int) -> tuple[str | None, dict[str, str], int]:
    """A start tag: its lowercased name, its attributes, and where the walk resumes - or `None` if unterminated."""
    match = TAG_NAME.match(text, position + 1)
    if match is None:
        # Rule 7: `<` followed by something that is not a name is text, and the caller handles that.
        return None, {}, len(text)

    name = match.group(0).lower()
    cursor = match.end()
    attributes: dict[str, str] = {}

    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            return None, {}, len(text)  # an unterminated tag ends the document
        if text.startswith("/>", cursor):
            return name, attributes, cursor + 2
        if text[cursor] == ">":
            return name, attributes, cursor + 1

        attribute = TAG_NAME.match(text, cursor)
        if attribute is None:
            cursor += 1
            continue
        key = attribute.group(0).lower()
        cursor = attribute.end()

        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        value = ""
        if cursor < len(text) and text[cursor] == "=":
            cursor += 1
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
            quote = text[cursor:cursor + 1]
            if quote in ("'", '"'):
                end = text.find(quote, cursor + 1)
                if end == -1:
                    return None, {}, len(text)
                value = text[cursor + 1:end]
                cursor = end + 1
            else:
                end = cursor
                while end < len(text) and not text[end].isspace() and text[end] != ">":
                    end += 1
                value = text[cursor:end]
                cursor = end
        if key not in attributes:
            attributes[key] = value

    return None, {}, len(text)


def _end_tag(text: str, position: int) -> tuple[str | None, int]:
    """An end tag's lowercased name and where the walk resumes, or `None` if it is unterminated."""
    match = TAG_NAME.match(text, position + 2)
    if match is None:
        return None, len(text)
    end = text.find(">", match.end())
    if end == -1:
        return None, len(text)
    return match.group(0).lower(), end + 1


def _asks_not_to_be_read(attributes: dict[str, str]) -> bool:
    """Rule 4: `hidden`, `aria-hidden="true"`, or a `style` that hides the element.

    Only the element's own attributes count, which is what section 4.5.4 means by no cascade: a class that
    hides something in a stylesheet is invisible to this walk.
    """
    if "hidden" in attributes:
        return True
    if attributes.get("aria-hidden", "").strip().lower() == "true":
        return True
    style = attributes.get("style", "").replace(" ", "").replace("\t", "").lower()
    return "display:none" in style or "visibility:hidden" in style


def _skip_element(text: str, position: int, name: str) -> int:
    """Where the walk resumes after an element whose contents are not read.

    A raw-text element (`script`, `style`, `title`, `textarea`) is skipped by looking for its own end tag,
    because rule 7 says a tag inside one is content rather than markup - which is what stops `if (a < b)` in
    a script from being parsed as a start tag. Anything else is skipped by counting nested same-name
    elements, so that a `div` inside a `div` does not end the skip early.
    """
    if name in RAW_TEXT_ELEMENTS:
        search = re.compile(r"</" + re.escape(name) + r"(?=[\s/>])", re.IGNORECASE)
        match = search.search(text, position)
        if match is None:
            return len(text)
        end = text.find(">", match.end())
        return len(text) if end == -1 else end + 1

    depth = 1
    cursor = position
    while cursor < len(text) and depth > 0:
        marker = text.find("<", cursor)
        if marker == -1:
            return len(text)
        if text.startswith("<!--", marker):
            end = text.find("-->", marker + 4)
            if end == -1:
                return len(text)
            cursor = end + 3
            continue
        closing = text[marker + 1:marker + 2] == "/"
        tag, _, after = _start_tag(text, marker + 1) if closing else _start_tag(text, marker)
        if tag is None:
            return len(text)
        if tag == name:
            depth += -1 if closing else 1
        cursor = after

    return cursor


def _decode(text: str) -> str:
    """Rule 6: character references become their characters; one that cannot be a character stays as written.

    Including an out-of-range numeric reference, which section 4.5.4 says is *not* replaced with U+FFFD:
    substituting a character the producer never wrote would make the fingerprint unreproducible, which is
    the one thing it must not be.
    """

    def replace(match: re.Match) -> str:
        body = match.group(1)
        if body.startswith("#"):
            try:
                code = int(body[2:], 16) if body[1:2] in ("x", "X") else int(body[1:])
            except ValueError:
                return match.group(0)
            if code == 0 or code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
                return match.group(0)
            return chr(code)
        return NAMED_REFERENCES.get(body, match.group(0))

    return REFERENCE.sub(replace, text)
