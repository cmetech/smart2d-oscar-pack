"""Template reference grammar shared by pack validation and delivery."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Literal

from project_pack.errors import fail
from project_pack.model import PACK_ID_PATTERN


STEM_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
MAX_REFERENCE_CHARS = 100
MAX_MANIFEST_MEMBERS = 10_000
TemplateCapability = Literal["single_body", "paired_email"]


def parse_reference(value: str) -> tuple[str | None, str]:
    """Split a template reference into its optional pack id and logical stem."""

    if not isinstance(value, str) or value != value.strip() or "\x00" in value:
        raise fail("TEMPLATE_REFERENCE", "template reference is malformed")
    if value.count(":") > 1:
        raise fail(
            "TEMPLATE_REFERENCE",
            "template reference has more than one namespace separator",
        )

    pack_id: str | None = None
    stem = value
    if ":" in value:
        pack_id, stem = value.split(":", 1)
        if not PACK_ID_PATTERN.fullmatch(pack_id):
            raise fail("TEMPLATE_REFERENCE", "template reference has an invalid pack id")
    if not STEM_PATTERN.fullmatch(stem) or ".." in stem:
        raise fail("TEMPLATE_REFERENCE", "template reference has an invalid name")
    return pack_id, stem


def validate_reference_budget(pack_id: str, stem: str) -> None:
    """Refuse a namespaced reference that cannot fit persisted storage."""

    if len(f"{pack_id}:{stem}") > MAX_REFERENCE_CHARS:
        raise fail(
            "TEMPLATE_REFERENCE",
            f"template reference exceeds {MAX_REFERENCE_CHARS} characters",
        )


def template_capabilities(
    pack_id: str,
    manifest_files: Mapping[str, object] | Iterable[str],
) -> frozenset[tuple[str, TemplateCapability]]:
    """Derive canonical reference/capability bindings from manifest file keys."""

    if not PACK_ID_PATTERN.fullmatch(pack_id):
        raise fail("TEMPLATE_REFERENCE", "template capability pack id is invalid")
    source_keys = (
        manifest_files.keys() if isinstance(manifest_files, Mapping) else manifest_files
    )
    keys: list[str] = []
    seen_keys: set[str] = set()
    for relative in source_keys:
        if not isinstance(relative, str):
            raise fail("MANIFEST_SCHEMA", "manifest file keys must be strings")
        if relative in seen_keys:
            raise fail("MANIFEST_SCHEMA", "manifest contains duplicate file keys")
        seen_keys.add(relative)
        keys.append(relative)
        if len(keys) > MAX_MANIFEST_MEMBERS:
            raise fail("ARCHIVE_LIMIT", "manifest exceeds the archive member limit")

    direct: set[str] = set()
    email_html: set[str] = set()
    email_text: set[str] = set()

    for relative in keys:
        if not relative.startswith("templates/"):
            continue

        parts = relative.split("/")
        stem: str | None = None
        destination: set[str] | None = None
        if len(parts) == 2 and parts[-1].endswith(".j2"):
            stem = parts[-1][:-3]
            destination = direct
        elif (
            len(parts) == 4
            and parts[1:3] == ["email", "html"]
            and parts[-1].endswith(".j2")
        ):
            stem = parts[-1][:-3]
            destination = email_html
        elif (
            len(parts) == 4
            and parts[1:3] == ["email", "text"]
            and parts[-1].endswith(".j2")
        ):
            stem = parts[-1][:-3]
            destination = email_text
        elif (
            (len(parts) == 2 or (len(parts) == 4 and parts[1:3] == ["email", "html"]))
            and (parts[-1].endswith(".yml") or parts[-1].endswith(".yaml"))
        ):
            continue
        else:
            raise fail("TEMPLATE_PATH", "manifest contains an invalid template key")

        reference = f"{pack_id}:{stem}"
        parse_reference(reference)
        validate_reference_budget(pack_id, stem)
        destination.add(stem)

    if email_html != email_text:
        raise fail("TEMPLATE_PAIR", "manifest contains an incomplete email template pair")

    bindings: set[tuple[str, TemplateCapability]] = {
        (f"{pack_id}:{stem}", "single_body") for stem in direct
    }
    bindings.update(
        (f"{pack_id}:{stem}", "paired_email") for stem in email_html
    )
    return frozenset(bindings)
