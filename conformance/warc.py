#!/usr/bin/env python3
"""The smallest WARC reader that can answer one question: what was the main document?

Written from `docs/RECEIPT-SPEC.md` section 4.2 and section 9 - *"the verifier reads the response record
for `subject.url` and the body after its HTTP headers, and nothing else: no deduplication, no revisit
records, no site reconstruction"* - and from ISO 28500 for the parts the specification does not restate.

It is deliberately the same shape as `reference/src/warc.mjs` and was written without reading its body:
strict (anything unrecognised is an error, never a guess), narrow (one response record for one URL), and
pure (bytes in, bytes out). Two details are worth stating because a second implementer cannot infer them:

* **Records are split on the magic**, the seven bytes `WARC/1.0` searched for anywhere in the inflated
  stream - not on the record's own `Content-Length`, which is optional in practice and which writers
  disagree about. A payload containing those seven bytes would therefore split a record in two. That is a
  fragility inherited from the reference implementation rather than a rule of the format, and it is named in
  `conformance/README.md` as a specification gap.
* **The document is cut to the HTTP `Content-Length`, when the response states one**, because a record may
  carry padding or a trailing block and digesting that would make the document depend on the crawler's
  filler. A stated length longer than the record is a *truncated capture*, which is an error and never a
  partial document.
"""

from __future__ import annotations

import hashlib
import gzip
import json
import re
from base64 import b64decode

# Every WARC record begins with this.
RECORD_MAGIC = b"WARC/1.0"

# A WACZ advertises its records in `datapackage.json`, and the WARC is the one this project reads.
WARC_RESOURCE = re.compile(r"\.warc(\.gz)?$", re.IGNORECASE)

# The digest form this reader understands in `WARC-Payload-Digest`. Anything else is left alone.
PAYLOAD_DIGEST = re.compile(r"^sha256:([A-Za-z0-9+/=_-]+)$")


class WarcError(Exception):
    """Anything this reader will not guess at."""


def is_gzipped(data: bytes) -> bool:
    """A WACZ holds its records gzipped, each member on its own so an index can seek to it."""
    return len(data) > 2 and data[0] == 0x1F and data[1] == 0x8B


def inflate(data: bytes) -> bytes:
    """A plain WARC is returned unchanged; a gzipped one is inflated, members and all.

    Python's `gzip.decompress` walks concatenated members, which is the same guarantee the reference
    implementation gets from `zlib.gunzipSync`. A stream that will not inflate - including one cut short -
    is an error here rather than a half-read document.
    """
    if not is_gzipped(data):
        return data
    try:
        return gzip.decompress(data)
    except (OSError, EOFError) as error:
        raise WarcError("the capture's WARC file could not be decompressed: %s" % error) from None


def headers_of(block: bytes, position: int) -> dict[str, str]:
    """The header lines of a record or of an HTTP response: lowercase names, first occurrence wins."""
    headers: dict[str, str] = {}
    for line in block.split(b"\r\n"):
        if line.strip() == b"":
            continue
        colon = line.find(b":")
        if colon == -1:
            raise WarcError("block %d has an unparsable header: %s" % (position, line.decode("latin1")))
        name = line[:colon].decode("latin1").strip().lower()
        if name not in headers:
            headers[name] = line[colon + 1:].decode("latin1").strip()
    return headers


def read_records(plain: bytes) -> list[dict]:
    """Split an inflated WARC into records, on the record magic (see the module docstring)."""
    starts = []
    found = plain.find(RECORD_MAGIC)
    while found != -1:
        starts.append(found)
        found = plain.find(RECORD_MAGIC, found + len(RECORD_MAGIC))

    if not starts:
        raise WarcError('the file contains no WARC records: it does not begin with "WARC/1.0"')

    records = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(plain)
        block = plain[start:end]
        header_end = block.find(b"\r\n\r\n")
        if header_end == -1:
            raise WarcError("WARC record %d has no blank line after its headers" % (position + 1))
        headers = headers_of(block[len(RECORD_MAGIC):header_end], position + 1)
        records.append({
            "type": headers.get("warc-type", ""),
            "target_uri": headers.get("warc-target-uri"),
            "date": headers.get("warc-date"),
            "headers": headers,
            "payload": block[header_end + 4:],
        })
    return records


def parse_http_response(payload: bytes, position: int = 1) -> dict:
    """The HTTP response embedded in a `response` record's payload, with the body cut to its length."""
    header_end = payload.find(b"\r\n\r\n")
    if header_end == -1:
        raise WarcError("the response record has no HTTP header block, so it holds no document")

    lines = payload[:header_end].split(b"\r\n")
    status_line = re.match(rb"^HTTP/\d(?:\.\d)? (\d{3})(?: .*)?$", lines[0] or b"")
    if status_line is None:
        raise WarcError(
            "the response record does not begin with an HTTP status line: \"%s\""
            % (lines[0] or b"")[:60].decode("latin1")
        )

    headers = headers_of(b"\r\n".join(lines[1:]), position)
    body = payload[header_end + 4:]

    declared = headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise WarcError(
                'the response states a Content-Length of "%s", which is not a number' % declared
            )
        length = int(declared)
        if length > len(body):
            raise WarcError(
                "the response declares %d bytes of body and the record holds %d: the record appears to be "
                "truncated" % (length, len(body))
            )
        body = body[:length]

    return {"status": int(status_line.group(1)), "headers": headers, "body": body}


def check_payload_digest(record: dict) -> None:
    """Compare a record's own `WARC-Payload-Digest` with the payload it describes.

    A capture that disagrees with itself about its own bytes is not a capture to read a document out of. A
    digest in an algorithm this reader does not implement is left alone, because guessing the conventions of
    an unimplemented algorithm would be worse than silence - and a base64 digest it cannot decode is refused
    by name rather than passed over.
    """
    stated = record["headers"].get("warc-payload-digest")
    if stated is None:
        return
    match = PAYLOAD_DIGEST.match(stated)
    if match is None:
        return

    try:
        stated_bytes = b64decode(match.group(1), validate=True)
    except Exception:
        raise WarcError(
            "the capture states a WARC-Payload-Digest this reader cannot decode: %s" % stated
        ) from None

    actual = hashlib.sha256(record["payload"]).hexdigest()
    if stated_bytes.hex() != actual:
        raise WarcError(
            "the capture states %s for this record's payload, and the payload hashes to sha256:%s"
            % (stated, actual)
        )


def warc_of(inner: dict[str, bytes]) -> bytes:
    """The WARC a WACZ advertises, refusing by name when it advertises none or does not hold it.

    Nothing here interprets WACZ beyond that lookup: not the profile, not the index, not the page list. What
    it does do is refuse by name, because a reader that cannot find the record it is about to read a document
    from must stop rather than guess (section 9, D-016).
    """
    advertised = inner.get("datapackage.json")
    if advertised is None:
        raise WarcError("the capture has no datapackage.json, so it advertises no WARC to read")

    try:
        data_package = json.loads(advertised.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WarcError("the capture's datapackage.json is not valid JSON: %s" % error) from None

    resources = data_package.get("resources") if isinstance(data_package, dict) else None
    resources = resources if isinstance(resources, list) else []
    advertised_paths = [r.get("path") for r in resources if isinstance(r, dict)]
    path = next(
        (p for p in advertised_paths if isinstance(p, str) and WARC_RESOURCE.search(p)),
        None,
    )
    if path is None:
        raise WarcError(
            "the capture advertises no WARC record to read: %s"
            % (", ".join(p for p in advertised_paths if isinstance(p, str)) or "nothing")
        )

    contents = inner.get(path)
    if contents is None:
        raise WarcError('the capture advertises "%s" and does not contain it' % path)
    return contents


def main_document(inner: dict[str, bytes], url: str | None) -> bytes:
    """The main document's response body, from one read of the capture (section 4.2).

    With a URL, the response record whose `WARC-Target-URI` is *exactly* it - because "no record for your
    page" is a fact the caller needs, not a reason to fall back to a different page. With no URL, the first
    response record, which is what a single-page capture holds.
    """
    records = read_records(inflate(warc_of(inner)))
    responses = [record for record in records if record["type"] == "response"]
    if not responses:
        raise WarcError(
            "the capture holds %d WARC record%s and none of them is an HTTP response"
            % (len(records), "" if len(records) == 1 else "s")
        )

    chosen = responses[0]
    if isinstance(url, str) and url != "":
        match = next((record for record in responses if record["target_uri"] == url), None)
        if match is None:
            seen = sorted({record["target_uri"] or "(no WARC-Target-URI)" for record in responses})
            raise WarcError(
                "the capture holds no response for %s. It holds responses for: %s" % (url, ", ".join(seen))
            )
        chosen = match

    check_payload_digest(chosen)
    return parse_http_response(chosen["payload"])["body"]
