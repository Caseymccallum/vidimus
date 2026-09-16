#!/usr/bin/env python3
"""Reading a receipt's container, and the capture inside it.

The second implementation's second layer, written from `docs/RECEIPT-SPEC.md` sections 3, 7.4 and 12 rather
than from `reference/src/zip.mjs`. It answers the container questions a verdict asks:

    container.readable        the file is a ZIP that reads
    manifest.shape            the names inside it are names this format admits
    capture.present           the capture the claim names is there
    capture.bytes             it is the length the claim states
    capture.digest            it hashes to the digest the claim states
    capture.media_type        it is a container this implementation reads
    capture.wacz.readable     that container reads
    capture.wacz.resources    every resource it advertises matches the hash it advertises

Three things are worth naming about how it is written:

* **The names are checked before anything is read.** `capture.path` reaches a filesystem call in every
  consumer, so a receipt is untrusted input to `open()`. Section 12 states the principle; the enumeration is
  in `is_safe_entry_name`, and one of this file's findings is that the specification lists the principle and
  leaves an implementer to guess the list (`conformance/README.md`).
* **A container this implementation cannot read is `unsupported`, never a failure.** Section 7.1's statuses
  exist so that a gap in a verifier is not reported as a fault in a receipt.
* **The advertised resource hashes are checked**, because they are the part of a capture that is
  self-describing: without them, a digest over the container says only "you have the same file I have".
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

# Section 7.4's container checks, in the order a verdict lists them.
CONTAINER_CHECKS = (
    "container.readable",
    "manifest.shape",
    "capture.present",
    "capture.bytes",
    "capture.digest",
    "capture.media_type",
    "capture.wacz.readable",
    "capture.wacz.resources",
)

# Every entry of a WACZ is a name this format admits, or it is not looked up at all.
MAX_ENTRY_NAME = 255


def is_safe_entry_name(name) -> bool:
    """Whether a name inside a receipt is one this format admits.

    Section 12's rule, enumerated: a relative, forward-slashed entry name, confined to the archive. No
    absolute path, no backslash, no drive letter or colon, no empty segment, and no `..` - because every
    consumer of a receipt resolves that name against a directory of its own.
    """
    if not isinstance(name, str) or name == "" or len(name) > MAX_ENTRY_NAME:
        return False
    if name.startswith("/") or "\\" in name or ":" in name or "//" in name:
        return False
    return not any(segment in ("", ".", "..") for segment in name.split("/"))


def entries_of(source) -> dict[str, bytes]:
    """Every entry of a ZIP, by name, reading through the archive's own index.

    Raises `zipfile.BadZipFile` when the bytes are not a ZIP. A `Path` or a `bytes`-like object both work.
    """
    opener = source if isinstance(source, Path) else io.BytesIO(source)
    with zipfile.ZipFile(opener) as archive:
        return {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if not info.is_dir()
        }


def container_statuses(entries: dict[str, bytes] | None, manifest: dict) -> dict:
    """The container checks, as this implementation sees them.

    `entries` is None when the container itself could not be read, in which case everything that depends on it
    is `not_checked` - section 7.2: a verdict contains every check, and one that never ran is not a pass.
    """
    if entries is None:
        return dict.fromkeys(CONTAINER_CHECKS, "not_checked")

    def stopped(statuses: dict) -> dict:
        return {**dict.fromkeys(CONTAINER_CHECKS, "not_checked"), **statuses}

    capture = manifest.get("capture")
    if not isinstance(capture, dict) or not is_safe_entry_name(capture.get("path")):
        # The name is not one this format admits, so nothing is looked up with it.
        return stopped({"manifest.shape": "fail"})

    statuses = {"manifest.shape": "pass"}
    contents = entries.get(capture["path"])
    if contents is None:
        return stopped({**statuses, "capture.present": "fail"})
    statuses["capture.present"] = "pass"

    statuses["capture.bytes"] = "pass" if len(contents) == capture.get("bytes") else "fail"
    digest = hashlib.sha256(contents).hexdigest()
    statuses["capture.digest"] = "pass" if digest == capture.get("sha256") else "fail"

    if capture.get("media_type") != "application/wacz":
        # A container this implementation does not read is a gap in it, not a fault in the receipt.
        return stopped({**statuses, "capture.media_type": "unsupported"})
    statuses["capture.media_type"] = "pass"

    try:
        inner = entries_of(contents)
    except zipfile.BadZipFile:
        return stopped({**statuses, "capture.wacz.readable": "fail"})
    statuses["capture.wacz.readable"] = "pass"

    return {**statuses, "capture.wacz.resources": wacz_resources(inner)}


def wacz_resources(inner: dict[str, bytes]) -> str:
    """Whether every resource the capture's `datapackage.json` advertises matches what it advertises."""
    advertised = inner.get("datapackage.json")
    if advertised is None:
        return "fail"
    try:
        data_package = json.loads(advertised.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "fail"

    resources = data_package.get("resources") if isinstance(data_package, dict) else None
    if not isinstance(resources, list) or not resources:
        # A capture that advertises no resources binds nothing at all.
        return "fail"

    for resource in resources:
        if not isinstance(resource, dict) or not is_safe_entry_name(resource.get("path")):
            return "fail"
        contents = inner.get(resource["path"])
        if contents is None:
            return "fail"
        if "sha256:" + hashlib.sha256(contents).hexdigest() != resource.get("hash"):
            return "fail"
        if isinstance(resource.get("bytes"), int) and resource["bytes"] != len(contents):
            return "fail"

    return "pass"
