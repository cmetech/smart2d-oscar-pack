"""Strict versioned models and parsers for OSCAR project packs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Literal, Mapping

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from project_pack.errors import PackError, fail
from project_pack.paths import canonical_path_key, validate_member_path
from project_pack.tables import TABLE_NAME


MANIFEST_MAX_BYTES = 1024 * 1024
PACK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
TASK_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4, 5, 6, 7})
TRIGGER_SCHEMA_VERSION = 5
WORKFLOW_SCHEMA_VERSION = 6
TABLE_SCHEMA_VERSION = 7
_WORKFLOW_ROOTS = frozenset({"dags", "lib"})
_BYTECODE_SUFFIXES = frozenset({".pyc", ".pyo"})
RESERVED_LOCAL_PACK_ID = "local"
_SUPPORTED_ROOTS = frozenset(
    {"jobs", "tasks", "fabfile", "scripts", "rules", "templates", "conf"}
)
_SCHEMA_1_CONFIGURATION_ROOTS = frozenset(
    {"rules", "mappings", "roles", "dashboards"}
)
_SUPPORTED_ANSIBLE_ROOTS = frozenset(
    {"playbooks", "roles", "collections", "library"}
)


@dataclass(frozen=True)
class PackContents:
    jobs: int
    tasks: tuple[str, ...]
    fabfile: tuple[str, ...]
    scripts: tuple[str, ...]
    playbooks: tuple[str, ...]
    rules: int
    templates: int
    tables: tuple[str, ...] = ()


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    size: int


@dataclass(frozen=True)
class PackManifest:
    schema_version: Literal[1, 2, 3, 4, 5, 6, 7]
    id: str
    version: str
    requires_oscar: str
    requires_tasks_common: tuple[str, ...]
    requires_tasks_local: tuple[str, ...]
    contents: PackContents
    archive_file_count: int
    archive_expanded_bytes: int
    files: Mapping[str, FileRecord]


@dataclass(frozen=True)
class PackSource:
    """Author input from pack.source.yml; never included in an artifact."""

    schema_version: Literal[1, 2, 3, 4, 5, 6, 7]
    id: str
    version: str
    requires_oscar: str
    requires_tasks_common: tuple[str, ...]
    requires_tasks_local: tuple[str, ...]


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects aliases and ambiguous mappings."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            raise yaml.YAMLError("aliases are not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, Any]:
        if not isinstance(node, MappingNode):
            raise yaml.YAMLError("expected a mapping")

        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.YAMLError("mapping keys must be strings")
            if key in mapping:
                raise yaml.YAMLError("duplicate mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _load_strict_yaml(document: bytes | str) -> Any:
    if isinstance(document, bytes):
        if len(document) > MANIFEST_MAX_BYTES:
            raise fail("MANIFEST_LIMIT", "manifest exceeds the schema-v1 byte limit")
        try:
            text = document.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise fail("MANIFEST_SCHEMA", "manifest is not valid UTF-8") from exc
    elif isinstance(document, str):
        try:
            encoded = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise fail("MANIFEST_SCHEMA", "manifest is not valid UTF-8") from exc
        if len(encoded) > MANIFEST_MAX_BYTES:
            raise fail("MANIFEST_LIMIT", "manifest exceeds the schema-v1 byte limit")
        text = document
    else:
        raise fail("MANIFEST_SCHEMA", "manifest must be bytes or text")

    loader = _StrictSafeLoader(text)
    try:
        return loader.get_single_data()
    except PackError:
        raise
    except yaml.YAMLError as exc:
        raise fail("MANIFEST_SCHEMA", "manifest YAML is invalid or ambiguous") from exc
    finally:
        loader.dispose()


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise fail("MANIFEST_SCHEMA", f"{label} must be a mapping")
    return value


def _require_exact_keys(
    value: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    if frozenset(value) != expected:
        raise fail("MANIFEST_SCHEMA", f"{label} keys do not match schema v1")


def _require_nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise fail("MANIFEST_SCHEMA", f"{label} must be a nonnegative integer")
    return value


def _parse_identity(data: dict[str, Any], schema_version: int) -> tuple[str, str, str]:
    pack_id = data["id"]
    if not isinstance(pack_id, str) or not PACK_ID_PATTERN.fullmatch(pack_id):
        raise fail("MANIFEST_SCHEMA", "pack id does not match schema v1")
    if schema_version >= TRIGGER_SCHEMA_VERSION and pack_id == RESERVED_LOCAL_PACK_ID:
        # ``local`` names UI-created triggers (``local.<name>``); schemas 1–4 keep accepting it.
        raise fail("MANIFEST_SCHEMA", "pack id 'local' is reserved from schema_version 5")

    version = data["version"]
    if not isinstance(version, str):
        raise fail("MANIFEST_SCHEMA", "pack version must be a string")
    try:
        Version(version)
    except InvalidVersion as exc:
        raise fail("MANIFEST_SCHEMA", "pack version is not valid PEP 440") from exc

    requires_oscar = data["requires_oscar"]
    if not isinstance(requires_oscar, str) or not requires_oscar.strip():
        raise fail("MANIFEST_SCHEMA", "requires_oscar must be a specifier string")
    try:
        specifiers = SpecifierSet(requires_oscar)
    except InvalidSpecifier as exc:
        raise fail("MANIFEST_SCHEMA", "requires_oscar is not valid PEP 440") from exc
    if not str(specifiers):
        raise fail("MANIFEST_SCHEMA", "requires_oscar must not be empty")

    return pack_id, version, requires_oscar


def _parse_task_list(value: Any, label: str, *, canonical: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise fail("MANIFEST_SCHEMA", f"{label} must be a string list")
    if any(not TASK_REFERENCE_PATTERN.fullmatch(item) for item in value):
        raise fail("MANIFEST_SCHEMA", f"{label} contains an invalid task reference")
    if len(set(value)) != len(value):
        raise fail("MANIFEST_SCHEMA", f"{label} contains duplicate task references")
    if canonical and value != sorted(value, key=str.encode):
        raise fail("MANIFEST_SCHEMA", f"{label} must use canonical ordering")
    return tuple(value)


def _parse_requires_tasks(
    value: Any, *, canonical: bool
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    requires = _require_mapping(value, "requires_tasks")
    _require_exact_keys(requires, frozenset({"common", "local"}), "requires_tasks")
    return (
        _parse_task_list(requires["common"], "requires_tasks.common", canonical=canonical),
        _parse_task_list(requires["local"], "requires_tasks.local", canonical=canonical),
    )


def _parse_logical_names(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise fail("MANIFEST_SCHEMA", f"contents.{label} must be a string list")
    if len(set(value)) != len(value) or value != sorted(value, key=str.encode):
        raise fail("MANIFEST_SCHEMA", f"contents.{label} must be sorted and unique")
    return tuple(value)


def _parse_contents(value: Any, schema_version: int) -> PackContents:
    contents = _require_mapping(value, "contents")
    _require_exact_keys(
        contents,
        frozenset({"jobs", "tasks", "fabfile", "scripts", "playbooks", "rules", "templates"}
                  | ({"tables"} if schema_version >= TABLE_SCHEMA_VERSION else set())),
        "contents",
    )
    return PackContents(
        jobs=_require_nonnegative_int(contents["jobs"], "contents.jobs"),
        tasks=_parse_logical_names(contents["tasks"], "tasks"),
        fabfile=_parse_logical_names(contents["fabfile"], "fabfile"),
        scripts=_parse_logical_names(contents["scripts"], "scripts"),
        playbooks=_parse_logical_names(contents["playbooks"], "playbooks"),
        rules=_require_nonnegative_int(contents["rules"], "contents.rules"),
        templates=_require_nonnegative_int(
            contents["templates"], "contents.templates"
        ),
        tables=_parse_logical_names(contents["tables"], "tables") if schema_version >= TABLE_SCHEMA_VERSION else (),
    )


def _validate_payload_path(raw: str, schema_version: int = 1) -> None:
    path = validate_member_path(raw)
    parts = path.parts
    if schema_version >= WORKFLOW_SCHEMA_VERSION and (
        "__pycache__" in parts or path.suffix in _BYTECODE_SUFFIXES
    ):
        raise fail(
            "MANIFEST_SCHEMA",
            "schema 6 packs must not contain __pycache__ or compiled bytecode; delete it before building",
        )
    if parts[0] == "workflow":
        if schema_version >= WORKFLOW_SCHEMA_VERSION and len(parts) >= 3 and parts[1] in _WORKFLOW_ROOTS:
            return
        raise fail("MANIFEST_SCHEMA", "workflow content requires schema 6 under workflow/dags/ or workflow/lib/")
    if parts[0] == "tables":
        if schema_version >= TABLE_SCHEMA_VERSION and len(parts) == 2 and parts[1].endswith(".sql") \
                and TABLE_NAME.fullmatch(parts[1][:-4]):
            return
        raise fail("MANIFEST_SCHEMA", "table SQL requires schema 7 under tables/<lowercase_name>.sql")
    if parts[0] == "catalog":
        if schema_version >= 3 and raw == "catalog/functions.yml":
            return
        raise fail("MANIFEST_SCHEMA", "catalog requires schema 3 or later and catalog/functions.yml")
    if parts[0] == "templates":
        if len(parts) == 2:
            return
        if (
            len(parts) == 4
            and parts[1] == "email"
            and parts[2] in {"html", "text"}
        ):
            return
        raise fail(
            "MANIFEST_SCHEMA", "template path is outside the templates layout"
        )
    if parts[0] == "conf" and len(parts) >= 2 and parts[1] == "triggers":
        if schema_version >= TRIGGER_SCHEMA_VERSION and len(parts) == 3 and len(parts[2]) > 4 \
                and parts[2].endswith(".yml"):
            return
        raise fail("MANIFEST_SCHEMA", "trigger definitions require schema 5 and conf/triggers/<name>.yml")
    if parts[0] == "triggers":
        if schema_version >= TRIGGER_SCHEMA_VERSION and len(parts) >= 2 and parts[-1].endswith(".py"):
            return
        raise fail("MANIFEST_SCHEMA", "trigger source requires schema 5 and triggers/**/*.py")
    if parts[0] == "conf":
        roots = _SCHEMA_1_CONFIGURATION_ROOTS | ({"hooks"} if schema_version >= 2 else set()) | ({"suppressions", "probes"} if schema_version >= 4 else set())
        if len(parts) >= 3 and parts[1] in roots:
            return
        raise fail(
            "MANIFEST_SCHEMA", "configuration path is outside the fixed conf layout"
        )
    if parts[0] in _SUPPORTED_ROOTS and len(parts) >= 2:
        return
    if (
        parts[0] == "ansible"
        and len(parts) >= 3
        and parts[1] in _SUPPORTED_ANSIBLE_ROOTS
    ):
        return
    raise fail("MANIFEST_SCHEMA", "payload path is outside schema-v1 content roots")


def workflow_module_name(pack_id: str) -> str:
    """Return the importable top-level package for a pack's workflow tree (spec §4.2)."""

    return "pack_" + pack_id.replace("-", "_")


def has_workflow(files: Iterable[str]) -> bool:
    """Return whether a manifest file inventory carries workflow content."""

    return any(path.startswith("workflow/") for path in files)


def _parse_files(value: Any, schema_version: int) -> Mapping[str, FileRecord]:
    files_data = _require_mapping(value, "files")
    if list(files_data) != sorted(files_data, key=canonical_path_key):
        raise fail("MANIFEST_SCHEMA", "files must use canonical path ordering")

    files: dict[str, FileRecord] = {}
    for raw_path, raw_record in files_data.items():
        _validate_payload_path(raw_path, schema_version)
        record = _require_mapping(raw_record, "file record")
        _require_exact_keys(record, frozenset({"sha256", "size"}), "file record")
        sha256 = record["sha256"]
        if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
            raise fail("MANIFEST_SCHEMA", "file hash must be lowercase SHA-256")
        size = _require_nonnegative_int(record["size"], "file size")
        files[raw_path] = FileRecord(sha256=sha256, size=size)
    return MappingProxyType(files)


def parse_pack_manifest(document: bytes | str) -> PackManifest:
    """Parse and fully validate one strict schema-v1 ``pack.yml`` document."""

    data = _require_mapping(_load_strict_yaml(document), "manifest")
    _require_exact_keys(
        data,
        frozenset(
            {
                "schema_version",
                "id",
                "version",
                "requires_oscar",
                "requires_tasks",
                "contents",
                "archive",
                "files",
            }
        ),
        "manifest",
    )
    schema_version = data["schema_version"]
    if type(schema_version) is not int or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise fail("MANIFEST_SCHEMA", "schema_version must equal 1, 2, 3, 4, 5, 6 or 7")

    pack_id, version, requires_oscar = _parse_identity(data, schema_version)
    common_tasks, local_tasks = _parse_requires_tasks(
        data["requires_tasks"], canonical=True
    )
    contents = _parse_contents(data["contents"], schema_version)
    archive = _require_mapping(data["archive"], "archive")
    _require_exact_keys(
        archive, frozenset({"file_count", "expanded_bytes"}), "archive"
    )
    file_count = _require_nonnegative_int(archive["file_count"], "archive.file_count")
    expanded_bytes = _require_nonnegative_int(
        archive["expanded_bytes"], "archive.expanded_bytes"
    )
    files = _parse_files(data["files"], schema_version)

    if file_count != len(files):
        raise fail("MANIFEST_SCHEMA", "archive file count does not match files")
    if expanded_bytes != sum(record.size for record in files.values()):
        raise fail("MANIFEST_SCHEMA", "archive byte total does not match files")
    if contents != compute_contents(files):
        raise fail("MANIFEST_SCHEMA", "contents summary does not match files")

    return PackManifest(
        schema_version=schema_version,
        id=pack_id,
        version=version,
        requires_oscar=requires_oscar,
        requires_tasks_common=common_tasks,
        requires_tasks_local=local_tasks,
        contents=contents,
        archive_file_count=file_count,
        archive_expanded_bytes=expanded_bytes,
        files=files,
    )


def parse_pack_source(document: bytes | str) -> PackSource:
    """Parse the strict author-only ``pack.source.yml`` schema."""

    data = _require_mapping(_load_strict_yaml(document), "pack source")
    _require_exact_keys(
        data,
        frozenset(
            {"schema_version", "id", "version", "requires_oscar", "requires_tasks"}
        ),
        "pack source",
    )
    schema_version = data["schema_version"]
    if type(schema_version) is not int or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise fail("MANIFEST_SCHEMA", "schema_version must equal 1, 2, 3, 4, 5, 6 or 7")
    pack_id, version, requires_oscar = _parse_identity(data, schema_version)
    common_tasks, local_tasks = _parse_requires_tasks(
        data["requires_tasks"], canonical=False
    )
    return PackSource(
        schema_version=schema_version,
        id=pack_id,
        version=version,
        requires_oscar=requires_oscar,
        requires_tasks_common=common_tasks,
        requires_tasks_local=local_tasks,
    )


def compute_contents(paths: Any) -> PackContents:
    """Compute the non-security manifest summary from canonical payload paths."""

    jobs = 0
    rules = 0
    templates: set[str] = set()
    tables: set[str] = set()
    logical: dict[str, set[str]] = {
        "tasks": set(),
        "fabfile": set(),
        "scripts": set(),
        "playbooks": set(),
    }
    for raw_path in paths:
        path = validate_member_path(raw_path)
        parts = path.parts
        if parts[0] == "jobs" and len(parts) == 2:
            jobs += 1
        elif parts[0] == "rules" and len(parts) == 2:
            rules += 1
        elif parts[0] in {"tasks", "fabfile", "scripts"} and len(parts) == 2:
            logical[parts[0]].add(Path(parts[-1]).stem)
        elif parts[:2] == ("ansible", "playbooks") and len(parts) == 3:
            logical["playbooks"].add(Path(parts[-1]).stem)
        elif parts[0] == "templates" and Path(parts[-1]).suffix == ".j2":
            if len(parts) == 2:
                templates.add(Path(parts[-1]).stem)
            elif (
                len(parts) == 4
                and parts[1] == "email"
                and parts[2] in {"html", "text"}
            ):
                templates.add(Path(parts[-1]).stem)
        elif parts[0] == "tables" and len(parts) == 2 and Path(parts[-1]).suffix == ".sql":
            tables.add(Path(parts[-1]).stem)

    return PackContents(
        jobs=jobs,
        tasks=tuple(sorted(logical["tasks"], key=str.encode)),
        fabfile=tuple(sorted(logical["fabfile"], key=str.encode)),
        scripts=tuple(sorted(logical["scripts"], key=str.encode)),
        playbooks=tuple(sorted(logical["playbooks"], key=str.encode)),
        rules=rules,
        templates=len(templates),
        tables=tuple(sorted(tables, key=str.encode)),
    )
