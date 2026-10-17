"""Canonical path validation for project-pack archive members."""

from __future__ import annotations

import re
import unicodedata
from pathlib import PurePosixPath

from project_pack.errors import fail


MAX_MEMBER_PATH_BYTES = 240
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def validate_member_path(raw: str) -> PurePosixPath:
    """Return a canonical relative POSIX path or raise ``PATH_INVALID``."""

    if not isinstance(raw, str) or not raw:
        raise fail("PATH_INVALID", "member path must be a non-empty string")
    if unicodedata.normalize("NFC", raw) != raw:
        raise fail("PATH_INVALID", "member path must use NFC normalization")
    if raw.startswith("/") or _WINDOWS_DRIVE.match(raw):
        raise fail("PATH_INVALID", "member path must be relative")
    if "\\" in raw:
        raise fail("PATH_INVALID", "member path must use POSIX separators")
    if any(unicodedata.category(character).startswith("C") for character in raw):
        raise fail("PATH_INVALID", "member path contains a control character")

    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise fail("PATH_INVALID", "member path is not valid UTF-8") from exc
    if len(encoded) > MAX_MEMBER_PATH_BYTES:
        raise fail("PATH_INVALID", "member path exceeds the schema-v1 byte limit")

    segments = raw.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise fail("PATH_INVALID", "member path contains an invalid segment")

    return PurePosixPath(*segments)


def canonical_path_key(path: str | PurePosixPath) -> bytes:
    """Return the deterministic UTF-8 byte-order key for a canonical path."""

    raw = path.as_posix() if isinstance(path, PurePosixPath) else path
    return raw.encode("utf-8")
