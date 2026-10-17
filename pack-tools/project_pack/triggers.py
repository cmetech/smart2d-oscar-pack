"""Portable validation for scheduled-trigger definitions (``kind: Trigger``).

One strict contract shared by pack parsing, UI authoring, YAML import/export
and Scheduler runtime validation. Nothing here imports or executes author
code: Python is parsed and compiled only, SQL is scanned only, and callable
bundles are parsed without being imported.
"""

from __future__ import annotations

import ast
import copy
import functools
import hashlib
import json
import math
import re
import sys
import zoneinfo
from dataclasses import dataclass
from datetime import datetime, timezone
from types import CodeType
from typing import Any, Mapping, Optional

import yaml
from apscheduler.triggers.cron import CronTrigger
from jinja2 import StrictUndefined, TemplateSyntaxError, nodes as jinja_nodes
from jinja2.filters import FILTERS as JINJA_FILTERS
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2.tests import TESTS as JINJA_TESTS

from project_pack.errors import PackError
from project_pack.model import PACK_ID_PATTERN, _StrictSafeLoader
from project_pack.paths import canonical_path_key, validate_member_path


API_VERSION = "oscar/v1"
KIND = "Trigger"
LOCAL_OWNER = "local"
TRIGGER_DEFINITION_ROOT = "conf/triggers/"
TRIGGER_SOURCE_ROOT = "triggers/"
RESERVED_PARAMETER = "trigger_now"

NAME_MAX_CHARS = 100
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,99}$")
PARAMETER_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TIMEZONE_PATTERN = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$")

DEFINITION_MAX_BYTES = 256 * 1024
INLINE_CODE_MAX_BYTES = 64 * 1024
PARAMETERS_MAX_BYTES = 32 * 1024
PARAMETERS_MAX_DEPTH = 16
DESCRIPTION_MAX_BYTES = 4096
BUNDLE_MAX_BYTES = 1024 * 1024
BUNDLE_MAX_FILES = 100
RESULT_MAX_BYTES = 16 * 1024
LOG_MAX_BYTES = 32 * 1024
SELECT_MAX_ROWS = 100
INTERVAL_MIN_SECONDS = 1
INTERVAL_MAX_SECONDS = 86400
CRON_FIELDS = (
    "year",
    "month",
    "day",
    "week",
    "day_of_week",
    "hour",
    "minute",
    "second",
)
CRON_FIELD_MAX_CHARS = 128
SQL_KINDS = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})
# Cron possibility is judged from a fixed instant, never the wall clock: an expired
# schedule stays valid, an impossible one never is. The origin precedes the first
# instant of 1970 (APScheduler's minimum year) in every timezone, UTC+14 included.
CRON_POSSIBILITY_ORIGIN = datetime(1969, 12, 30, tzinfo=timezone.utc)
# Deeply nested author code exhausts the parser/compiler stack; treat as invalid.
_COMPILE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)
# YAML composition/construction failures: parser errors, stack exhaustion from deep
# flow nesting, and constructor errors for scalars the resolvers hand over.
_YAML_ERRORS = (yaml.YAMLError, RecursionError, MemoryError, ValueError, TypeError, OverflowError)

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_TOP_LEVEL_KEYS = frozenset(
    {"api_version", "kind", "name", "description", "enabled", "schedule", "parameters", "run", "outputs"}
)
_RESERVED_TOP_LEVEL = {"metrics": "is reserved for phase 2 trigger metrics"}
_REQUIRED_KEYS = ("api_version", "kind", "name", "schedule", "run")
_RUN_MODES = ("sql", "python", "function")
_ENTRY_FUNCTION = "__oscar_trigger__"
# Mirrors sqlalchemy.sql.elements.TextClause._bind_params_regex so validation
# sees exactly the bind names text() will require at execution time.
_SQL_BIND_PATTERN = re.compile(r"(?<![:\w\x5c]):(\w+)(?!:)", re.UNICODE)
_FUNCTION_REFERENCE = re.compile(
    r"^pack:(?P<pack>[^:]+):(?P<module>[^:]+):(?P<function>[^:]+)$"
)


class TriggerValidationError(PackError):
    """A safe trigger validation failure; ``path`` locates the rejected field."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        super().__init__("TRIGGER_INVALID", f"{path}: {message}")


def _invalid(path: str, message: str) -> TriggerValidationError:
    return TriggerValidationError(path, message)


# --- strict YAML ---------------------------------------------------------------


class _TriggerYamlLoader(_StrictSafeLoader):
    """Alias/duplicate-rejecting loader with YAML-1.2-style scalar resolution.

    PyYAML's YAML 1.1 resolvers silently turn ``yes``/``no``/``on`` into
    booleans, ``1:30`` into 90, ``0755`` into 493 and dates into ``date``
    objects. Trigger documents only resolve ``true``/``false``, ``null``,
    decimal integers and decimal floats; everything else stays a string.
    Explicit tags (``!!bool yes``, ``!!int 0755``, ``!custom``) are rejected,
    since they would bypass those rules and reach arbitrary constructors.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if getattr(event, "tag", None) is not None:
            raise yaml.YAMLError("explicit tags are not allowed")
        return super().compose_node(parent, index)


_TriggerYamlLoader.yaml_implicit_resolvers = {}
_TriggerYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)
_TriggerYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"),
    list("-+0123456789"),
)
_TriggerYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(
        r"^(?:[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?"
        r"|[-+]?[0-9]+[eE][-+]?[0-9]+"
        r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
    ),
    list("-+0123456789."),
)
_TriggerYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:null",
    re.compile(r"^(?:~|null|Null|NULL|)$"),
    ["~", "n", "N", ""],
)


def parse_trigger_yaml(
    document: bytes | str, *, pack_id: str | None = None
) -> dict[str, Any]:
    """Parse one strict trigger YAML document and return its canonical form."""

    if isinstance(document, bytes):
        raw = document
        try:
            text = document.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _invalid("document", "YAML must be UTF-8") from exc
    elif isinstance(document, str):
        text = document
        try:
            raw = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise _invalid("document", "YAML must be UTF-8") from exc
    else:
        raise _invalid("document", "YAML must be bytes or text")
    if len(raw) > DEFINITION_MAX_BYTES:
        raise _invalid("document", "definition exceeds 256 KiB")

    loader: _TriggerYamlLoader | None = None
    try:
        # The reader rejects NUL/control characters while constructing.
        loader = _TriggerYamlLoader(text)
        data = loader.get_single_data()
    except _YAML_ERRORS as exc:
        raise _invalid("document", "YAML is invalid or ambiguous") from exc
    finally:
        if loader is not None:
            loader.dispose()
    return validate_trigger_document(data, pack_id=pack_id)


class _LiteralDumper(yaml.SafeDumper):
    """Quotes exactly the strings the trigger loader would otherwise resolve."""


_LiteralDumper.yaml_implicit_resolvers = {
    key: list(value) for key, value in _TriggerYamlLoader.yaml_implicit_resolvers.items()
}


def _represent_str(dumper: yaml.SafeDumper, value: str) -> yaml.Node:
    if "\n" in value:
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", value)


_LiteralDumper.add_representer(str, _represent_str)


def dump_trigger_yaml(canonical: Mapping[str, Any]) -> str:
    """Emit portable YAML for a canonical definition (code as literal blocks)."""

    ordered = {key: canonical[key] for key in (
        "api_version", "kind", "name", "description", "enabled", "schedule", "parameters", "run", "outputs"
    ) if key in canonical}
    text = yaml.dump(
        ordered,
        Dumper=_LiteralDumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=4096,
    )
    loader = _TriggerYamlLoader(text)
    try:
        lossless = loader.get_single_data() == dict(ordered)
    finally:
        loader.dispose()
    if not lossless:
        raise _invalid("document", "definition cannot be exported losslessly")
    return text


# --- canonical JSON --------------------------------------------------------------


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def definition_hash(canonical: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON form; equal for semantically equal documents."""

    return hashlib.sha256(canonical_json(dict(canonical)).encode("utf-8")).hexdigest()


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


def _check_json(value: Any, path: str, depth: int, max_depth: int) -> Any:
    """Return a detached copy of a JSON value or raise at the offending path."""

    if type(value) in (list, dict) and depth > max_depth:
        raise _invalid(path, f"nesting exceeds depth {max_depth}")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not _INT64_MIN <= value <= _INT64_MAX:
            raise _invalid(path, "integer is outside the signed 64-bit range")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise _invalid(path, "numbers must be finite")
        return value
    if type(value) is str:
        _require_encodable(value, path)
        return value
    if type(value) is list:
        return [_check_json(item, path, depth + 1, max_depth) for item in value]
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise _invalid(path, "object keys must be strings")
            _require_encodable(key, path)
            result[key] = _check_json(item, path, depth + 1, max_depth)
        return result
    raise _invalid(path, "value is not JSON")


def _require_encodable(value: str, path: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _invalid(path, "text is not valid UTF-8") from exc


# --- document validation -------------------------------------------------------------


def ensure_trigger_pack_id(pack_id: Any) -> str:
    """Validate a pack ID that owns or supplies trigger artifacts (schema 5).

    ``local`` is reserved for UI-created triggers and their metric label.
    Schemas 1–4 do not call this and keep their prior behavior.
    """

    if not isinstance(pack_id, str) or not PACK_ID_PATTERN.fullmatch(pack_id):
        raise _invalid("pack_id", "pack id does not match the pack schema")
    if pack_id == LOCAL_OWNER:
        raise _invalid("pack_id", "pack id 'local' is reserved for UI triggers")
    return pack_id


def validate_trigger_document(
    document: Any, *, pack_id: str | None = None
) -> dict[str, Any]:
    """Validate a trigger definition and return its canonical portable form.

    ``pack_id`` names the owning pack; ``None`` means a UI/local trigger whose
    name must start with ``local.``. The input is never mutated.
    """

    owner = LOCAL_OWNER if pack_id is None else ensure_trigger_pack_id(pack_id)
    if type(document) is not dict:
        raise _invalid("document", "definition must be a mapping")
    for key in document:
        if type(key) is not str:
            raise _invalid("document", "keys must be strings")
        if key in _RESERVED_TOP_LEVEL:
            raise _invalid(key, _RESERVED_TOP_LEVEL[key])
        if key not in _TOP_LEVEL_KEYS:
            safe = key if IDENTIFIER_PATTERN.fullmatch(key) else "document"
            raise _invalid(safe, "unknown key")
    for key in _REQUIRED_KEYS:
        if key not in document:
            raise _invalid(key, "is required")

    if document["api_version"] != API_VERSION:
        raise _invalid("api_version", f"must be {API_VERSION}")
    if document["kind"] != KIND:
        raise _invalid("kind", f"must be {KIND}")

    name = _validate_name(document["name"], owner)
    description = document.get("description")
    if description is not None:
        if type(description) is not str:
            raise _invalid("description", "must be a string")
        _require_encodable(description, "description")
        if _utf8_len(description) > DESCRIPTION_MAX_BYTES:
            raise _invalid("description", "exceeds 4096 bytes")
    enabled = document.get("enabled", False)
    if type(enabled) is not bool:
        raise _invalid("enabled", "must be a boolean")

    schedule = validate_schedule(document["schedule"])
    run = validate_run(document["run"], owner=owner)
    parameters = validate_parameters(
        document.get("parameters", {}), sql_mode="sql" in run
    )
    if "sql" in run:
        _require_declared_binds(run["sql"], parameters)
    outputs = validate_outputs(document["outputs"], run_mode=next(iter(run))) if "outputs" in document else []

    canonical = {
        "api_version": API_VERSION,
        "kind": KIND,
        "name": name,
        "description": description,
        "enabled": enabled,
        "schedule": schedule,
        "parameters": parameters,
        "run": run,
    }
    if outputs:
        # Present only when declared, so definitions without outputs keep their hashes.
        canonical["outputs"] = outputs
    if _utf8_len(canonical_json(canonical)) > DEFINITION_MAX_BYTES:
        raise _invalid("document", "definition exceeds 256 KiB")
    return canonical


def _validate_name(name: Any, owner: str) -> str:
    if type(name) is not str or not NAME_PATTERN.fullmatch(name):
        raise _invalid("name", "must match [a-z0-9][a-z0-9_.-]{0,99}")
    prefix, separator, rest = name.partition(".")
    if not separator or not rest or prefix != owner:
        raise _invalid("name", f"must start with '{owner}.'")
    return name


def validate_schedule(schedule: Any) -> dict[str, Any]:
    if type(schedule) is not dict:
        raise _invalid("schedule", "must be a mapping")
    kind = schedule.get("type")
    if kind == "interval":
        if set(schedule) != {"type", "seconds"}:
            raise _invalid("schedule", "interval takes exactly type and seconds")
        seconds = schedule["seconds"]
        if (
            type(seconds) is not int
            or not INTERVAL_MIN_SECONDS <= seconds <= INTERVAL_MAX_SECONDS
        ):
            raise _invalid("schedule.seconds", "must be an integer from 1 to 86400")
        return {"type": "interval", "seconds": seconds}
    if kind == "cron":
        return _validate_cron(schedule)
    raise _invalid("schedule.type", "must be interval or cron")


def _validate_cron(schedule: dict[str, Any]) -> dict[str, Any]:
    allowed = {"type", "timezone", *CRON_FIELDS}
    if any(key not in allowed for key in schedule):
        raise _invalid("schedule", "unknown cron field")
    fields: dict[str, str] = {}
    for field in CRON_FIELDS:
        if field not in schedule:
            continue
        value = schedule[field]
        if type(value) is int:
            value = str(value)
        if type(value) is not str or not value.strip() or len(value) > CRON_FIELD_MAX_CHARS:
            raise _invalid(f"schedule.{field}", "must be an integer or expression string")
        fields[field] = value
    if not fields:
        raise _invalid("schedule", "cron needs at least one field")

    tz_name = schedule.get("timezone", "UTC")
    zone = _resolve_timezone(tz_name)
    try:
        trigger = CronTrigger(timezone=zone, **fields)
    except (ValueError, TypeError) as exc:
        raise _invalid("schedule", "cron expression is invalid") from exc
    if trigger.get_next_fire_time(None, CRON_POSSIBILITY_ORIGIN) is None:
        raise _invalid("schedule", "cron schedule can never fire")
    return {"type": "cron", **fields, "timezone": tz_name}


@functools.lru_cache(maxsize=1)
def _available_timezones() -> frozenset[str]:
    return frozenset(zoneinfo.available_timezones())


def _resolve_timezone(name: Any) -> zoneinfo.ZoneInfo:
    if (
        type(name) is not str
        or not TIMEZONE_PATTERN.fullmatch(name)
        or name not in _available_timezones()
    ):
        raise _invalid("schedule.timezone", "must be an IANA timezone name")
    try:
        return zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError) as exc:
        raise _invalid("schedule.timezone", "must be an IANA timezone name") from exc


def validate_parameters(parameters: Any, *, sql_mode: bool) -> dict[str, Any]:
    """Validate top-level parameter names and bounded JSON values."""

    if type(parameters) is not dict:
        raise _invalid("parameters", "must be a mapping")
    result: dict[str, Any] = {}
    for key, value in parameters.items():
        if type(key) is not str or not PARAMETER_KEY_PATTERN.fullmatch(key):
            raise _invalid("parameters", "names must match [A-Za-z_][A-Za-z0-9_]{0,63}")
        path = f"parameters.{key}"
        if key == RESERVED_PARAMETER:
            raise _invalid(path, "is reserved for the runtime")
        checked = _check_json(value, path, 2, PARAMETERS_MAX_DEPTH)
        if sql_mode and type(checked) in (list, dict):
            raise _invalid(path, "SQL parameters must be JSON scalars")
        result[key] = checked
    if _utf8_len(canonical_json(result)) > PARAMETERS_MAX_BYTES:
        raise _invalid("parameters", "exceed 32 KiB")
    return result


def validate_run(run: Any, *, owner: str = LOCAL_OWNER) -> dict[str, str]:
    """Validate a ``run`` block: exactly one of sql, python or function."""

    if type(run) is not dict or len(run) != 1 or next(iter(run)) not in _RUN_MODES:
        raise _invalid("run", "must contain exactly one of sql, python or function")
    mode, value = next(iter(run.items()))
    path = f"run.{mode}"
    if type(value) is not str:
        raise _invalid(path, "must be a string")
    _require_encodable(value, path)
    if mode == "function":
        parse_function_reference(value, owner=owner)
        return {"function": value}
    if _utf8_len(value) > INLINE_CODE_MAX_BYTES:
        raise _invalid(path, "exceeds 64 KiB")
    if mode == "sql":
        scan_sql(value)
    else:
        compile_trigger_body(value)
    return {mode: value}


def sql_bind_names(statement: str) -> list[str]:
    """Bind names SQLAlchemy ``text()`` will require for ``statement``, in order."""

    return list(dict.fromkeys(_SQL_BIND_PATTERN.findall(statement)))


def _require_declared_binds(sql: str, parameters: Mapping[str, Any]) -> None:
    statement = scan_sql(sql).statement
    for name in sql_bind_names(statement):
        if name != RESERVED_PARAMETER and name not in parameters:
            raise _invalid("run.sql", "references an undeclared parameter")


# --- SQL scanning ----------------------------------------------------------------------


@dataclass(frozen=True)
class SqlScan:
    """One validated statement: its keyword and executable text (no terminator)."""

    kind: str
    statement: str


def scan_sql(sql: Any) -> SqlScan:
    """Quote/comment-aware single-statement scanner for SQL mode.

    Accepts one SELECT/INSERT/UPDATE/DELETE with an optional trailing ``;``.
    Rejects multi-statements, other statement kinds, CTEs, INTO/OUTFILE/
    DUMPFILE, locking reads and MySQL executable comments. String literals may
    not contain backslashes, so the scan cannot disagree with a server running
    NO_BACKSLASH_ESCAPES; pass such values as bind parameters instead.
    """

    path = "run.sql"
    if type(sql) is not str:
        raise _invalid(path, "must be a string")
    if "\x00" in sql:
        raise _invalid(path, "contains a NUL character")

    words: list[str] = []
    first_token: str | None = None
    end: int | None = None
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if end is not None:
            # Only whitespace and comments may follow the terminator.
            if char.isspace():
                index += 1
                continue
            skipped = _skip_comment(sql, index)
            if skipped is None:
                raise _invalid(path, "must contain exactly one statement")
            index = skipped
            continue
        if char.isspace():
            index += 1
            continue
        skipped = _skip_comment(sql, index)
        if skipped is not None:
            index = skipped
            continue
        if char in "'\"`":
            index = _skip_quoted(sql, index, char)
            first_token = first_token or char
            continue
        if char == ";":
            end = index
            index += 1
            continue
        if char.isalpha() or char == "_":
            stop = index
            while stop < length and (sql[stop].isalnum() or sql[stop] in "_$"):
                stop += 1
            word = sql[index:stop].upper()
            words.append(word)
            first_token = first_token or word
            index = stop
            continue
        first_token = first_token or char
        index += 1

    if first_token is None:
        raise _invalid(path, "is empty")
    if first_token not in SQL_KINDS:
        raise _invalid(path, "must be one SELECT, INSERT, UPDATE or DELETE statement")
    kind = first_token
    for position, word in enumerate(words):
        following = words[position + 1] if position + 1 < len(words) else ""
        if word in {"OUTFILE", "DUMPFILE"}:
            raise _invalid(path, "file output is not allowed")
        if word == "WITH" and following != "ROLLUP":
            raise _invalid(path, "common table expressions are not supported")
        if word == "FOR" and following in {"UPDATE", "SHARE"}:
            raise _invalid(path, "locking reads are not allowed")
        if word == "LOCK" and following == "IN":
            raise _invalid(path, "locking reads are not allowed")
        if word == "INTO" and kind == "SELECT":
            raise _invalid(path, "SELECT ... INTO is not allowed")
    statement = sql if end is None else sql[:end]
    if kind == "SELECT":
        names = [name.casefold() for name in select_output_names(statement)]
        if len(set(names)) != len(names):
            raise _invalid(path, "output column names must be unique")
    return SqlScan(kind=kind, statement=statement)


def _skip_comment(sql: str, index: int) -> int | None:
    """Return the index after a comment starting at ``index``, else ``None``."""

    char = sql[index]
    if char == "#" or (
        sql.startswith("--", index)
        and (index + 2 >= len(sql) or sql[index + 2].isspace() or ord(sql[index + 2]) < 32)
    ):
        newline = sql.find("\n", index)
        return len(sql) if newline < 0 else newline + 1
    if sql.startswith("/*", index):
        if sql.startswith("/*!", index) or sql.startswith("/*M!", index):
            raise _invalid("run.sql", "executable comments are not allowed")
        close = sql.find("*/", index + 2)
        if close < 0:
            raise _invalid("run.sql", "has an unterminated comment")
        return close + 2
    return None


def _skip_quoted(sql: str, index: int, quote: str) -> int:
    position = index + 1
    while position < len(sql):
        char = sql[position]
        if char == "\\" and quote != "`":
            raise _invalid("run.sql", "string literals may not contain backslashes")
        if char == quote:
            if position + 1 < len(sql) and sql[position + 1] == quote:
                position += 2
                continue
            return position + 1
        position += 1
    raise _invalid("run.sql", "has an unterminated quoted value")


_SELECT_MODIFIERS = frozenset(
    {
        "ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY", "STRAIGHT_JOIN", "SQL_SMALL_RESULT",
        "SQL_BIG_RESULT", "SQL_BUFFER_RESULT", "SQL_NO_CACHE", "SQL_CALC_FOUND_ROWS",
    }
)
_OPERATOR_WORDS = frozenset(
    {
        "AND", "OR", "XOR", "NOT", "IS", "IN", "LIKE", "BETWEEN", "DIV", "MOD", "REGEXP", "RLIKE",
        "CASE", "WHEN", "THEN", "ELSE", "END", "NULL", "ASC", "DESC", "DISTINCT", "OVER", "SEPARATOR",
        "COLLATE", "INTERVAL", "BINARY",
    }
)
# Top-level keywords that end the SELECT list.
_SELECT_LIST_END = frozenset(
    {
        "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "UNION", "EXCEPT", "INTERSECT",
        "INTO", "WINDOW", "FOR", "LOCK", "PROCEDURE",
    }
)
_BARE_NAME = r"[A-Za-z_][A-Za-z0-9_$]*"
_COLUMN_REFERENCE = re.compile(rf"^(?:(?:`(?:[^`]|``)+`|{_BARE_NAME})\.)*(?P<name>`(?:[^`]|``)+`|{_BARE_NAME})$")


def _strip_comments(sql: str) -> str:
    """Replace comments with a space, keeping quoted spans verbatim."""

    out: list[str] = []
    index = 0
    while index < len(sql):
        char = sql[index]
        skipped = _skip_comment(sql, index)
        if skipped is not None:
            out.append(" ")
            index = skipped
            continue
        if char in "'\"`":
            stop = _skip_quoted(sql, index, char)
            out.append(sql[index:stop])
            index = stop
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _unquote(name: str) -> str:
    if name[:1] in "`\"'" and name[-1:] == name[:1]:
        quote = name[0]
        return name[1:-1].replace(quote * 2, quote)
    return name


def _select_items(clean: str) -> list[str]:
    """Top-level items of the first SELECT list (up to its first top-level clause)."""

    depth = 0
    index = 0
    start: Optional[int] = None
    items: list[str] = []
    item_start = 0
    while index < len(clean):
        char = clean[index]
        if char in "'\"`":
            index = _skip_quoted(clean, index, char)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and (char.isalpha() or char == "_"):
            stop = index
            while stop < len(clean) and (clean[stop].isalnum() or clean[stop] in "_$"):
                stop += 1
            word = clean[index:stop].upper()
            if start is None and word == "SELECT":
                start = item_start = stop
            elif start is not None and word in _SELECT_LIST_END:
                items.append(clean[item_start:index])
                return items
            index = stop
            continue
        elif depth == 0 and char == "," and start is not None:
            items.append(clean[item_start:index])
            item_start = index + 1
        index += 1
    if start is not None:
        items.append(clean[item_start:])
    return items


def _is_name_start(char: str) -> bool:
    return char == "_" or ("A" <= char <= "Z") or ("a" <= char <= "z")


def _is_name_char(char: str) -> bool:
    return _is_name_start(char) or ("0" <= char <= "9") or char == "$"


def _trailing_alias(item: str) -> Optional[tuple[str, str]]:
    """Split ``<expr> [AS] <alias>`` in one linear pass (``item`` is stripped).

    The alias is the final token when it is a bare or non-empty quoted name
    preceded by whitespace; a preceding ``AS`` is dropped unless it is the whole
    expression.
    """

    index, last = 0, None
    while index < len(item):
        char = item[index]
        if char in "'\"`":
            stop = _skip_quoted(item, index, char)
            last = (index, stop) if stop - index > 2 else None
        elif _is_name_start(char):
            stop = index + 1
            while stop < len(item) and _is_name_char(item[stop]):
                stop += 1
            last = (index, stop)
        elif char.isdigit():
            stop = index + 1
            while stop < len(item) and _is_name_char(item[stop]):
                stop += 1
            last = None
        else:
            stop = index + 1
            if not char.isspace():
                last = None
        index = stop
    if last is None or last[1] != len(item) or not item[: last[0]][-1:].isspace():
        return None
    expression = item[: last[0]].rstrip()
    if expression[-2:].upper() == "AS" and (len(expression) == 2 or expression[-3].isspace()):
        without = expression[:-2].rstrip()
        if without:
            expression = without
    return (expression, item[last[0]:]) if expression else None


def _output_name(item: str) -> Optional[str]:
    item = item.strip()
    split = _trailing_alias(item)
    if split:
        expression, alias = split
        last_word = re.split(r"\s+", expression)[-1].upper()
        bare = alias[0] not in "`\"'"
        if not (bare and (alias.upper() in _OPERATOR_WORDS or expression[-1] in "+-*/%=<>|&^~!(,." or last_word in _OPERATOR_WORDS)):
            return _unquote(alias)
    reference = _COLUMN_REFERENCE.match(item)
    if reference:
        return _unquote(reference["name"])
    # Unaliased literals and expressions: the label is engine-specific; skip.
    return None


def select_output_names(statement: str) -> list[str]:
    """Explicit output column names of a validated SELECT, in order.

    Names are derived only where unambiguous (aliases and column references);
    unaliased expressions and literals, ``*`` and ``t.*`` are skipped. MySQL still rejects ambiguous duplicates at execution (error 1060).
    """

    items = _select_items(_strip_comments(statement))
    if items:
        first = items[0].strip()
        while True:
            head, _, rest = first.partition(" ")
            if head.upper() in _SELECT_MODIFIERS and rest:
                first = rest.strip()
                continue
            break
        items[0] = first
    names = [_output_name(item) for item in items]
    return [name for name in names if name is not None]

# --- Python compilation ----------------------------------------------------------------


def compile_trigger_body(
    source: Any, *, trigger_id: str = "validation", revision_id: str = "validation"
) -> CodeType:
    """Compile an inline function body without running it.

    The body is parsed as-is and wrapped in an AST ``def __oscar_trigger__(ctx)``
    (no textual re-indentation), so string contents and line numbers are
    preserved. Executing the returned code only defines that function.
    """

    path = "run.python"
    if type(source) is not str:
        raise _invalid(path, "must be a string")
    filename = f"<oscar-trigger {trigger_id} revision {revision_id}>"
    try:
        module = ast.parse(source, filename=filename, mode="exec")
    except _COMPILE_ERRORS as exc:
        raise _invalid(path, "has a syntax error or is nested too deeply") from exc
    if not module.body:
        raise _invalid(path, "is empty")
    if _contains_generator_or_await(module.body):
        raise _invalid(path, "generators and async code are not supported")

    extra: dict[str, Any] = {"type_params": []} if sys.version_info >= (3, 12) else {}
    function = ast.FunctionDef(
        name=_ENTRY_FUNCTION,
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="ctx")],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        ),
        body=module.body,
        decorator_list=[],
        returns=None,
        lineno=1,
        **extra,
        col_offset=0,
    )
    wrapper = ast.Module(body=[function], type_ignores=[])
    try:
        ast.fix_missing_locations(wrapper)
        return compile(wrapper, filename, "exec", dont_inherit=True)
    except _COMPILE_ERRORS as exc:
        raise _invalid(path, "does not compile as a function body") from exc


def _contains_generator_or_await(body: list[ast.stmt]) -> bool:
    """Whether yield/await occur in this scope (nested defs are their own scope)."""

    pending: list[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await)):
            return True
        if isinstance(node, (ast.AsyncFor, ast.AsyncWith)):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(_header_expressions(node))
            continue
        pending.extend(ast.iter_child_nodes(node))
    return False


def _header_expressions(node: ast.AST) -> list[ast.AST]:
    """Expressions a def/lambda/class evaluates in its *enclosing* scope.

    Decorators, argument defaults, annotations, return annotations, class bases
    and class keywords run where the definition appears, so a ``yield`` or a
    walrus there affects the enclosing function or module; bodies do not.
    """

    expressions: list[ast.AST] = list(getattr(node, "decorator_list", []))
    if isinstance(node, ast.ClassDef):
        return expressions + list(node.bases) + list(node.keywords)
    arguments = node.args
    expressions += arguments.defaults
    expressions += [default for default in arguments.kw_defaults if default is not None]
    for argument in (
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
        arguments.vararg,
        arguments.kwarg,
    ):
        if argument is not None and argument.annotation is not None:
            expressions.append(argument.annotation)
    returns = getattr(node, "returns", None)
    if returns is not None:
        expressions.append(returns)
    return expressions


# --- callable references and bundles -----------------------------------------------------


@dataclass(frozen=True)
class FunctionReference:
    pack_id: str
    module: str
    function: str

    @property
    def entry_path(self) -> str:
        return "triggers/" + "/".join(self.module.split(".")) + ".py"


def parse_function_reference(reference: Any, *, owner: str | None = None) -> FunctionReference:
    """Parse ``pack:<pack-id>:<dotted.module>:<function>``.

    ``owner`` is the owning pack of a pack trigger (which may only reference
    its own verified bundle) or ``local``/``None`` for UI triggers.
    """

    path = "run.function"
    if type(reference) is not str:
        raise _invalid(path, "must be a string")
    match = _FUNCTION_REFERENCE.fullmatch(reference)
    if match is None:
        raise _invalid(path, "must be pack:<pack-id>:<module>:<function>")
    pack_id = match["pack"]
    if not PACK_ID_PATTERN.fullmatch(pack_id) or pack_id == LOCAL_OWNER:
        raise _invalid(path, "names an invalid or reserved pack")
    module = match["module"]
    if any(
        not IDENTIFIER_PATTERN.fullmatch(segment) or _is_dunder(segment)
        for segment in module.split(".")
    ):
        raise _invalid(path, "module must be dotted Python identifiers")
    function = match["function"]
    if not IDENTIFIER_PATTERN.fullmatch(function) or _is_dunder(function):
        raise _invalid(path, "function must be a Python identifier")
    if owner not in (None, LOCAL_OWNER) and pack_id != owner:
        raise _invalid(path, "a pack trigger may only reference its own pack")
    return FunctionReference(pack_id=pack_id, module=module, function=function)


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def validate_trigger_bundle(files: Any, reference: Any) -> dict[str, Any]:
    """Validate a verified-pack Python bundle for one callable reference.

    ``files`` maps pack-relative ``triggers/**.py`` paths to source text. The
    sources are parsed, never imported. Returns per-file SHA-256 digests, the
    order-independent bundle digest and the resolved entry point.
    """

    parsed_reference = parse_function_reference(reference)
    trees, digests = _bundle_trees(files)
    entry_path = parsed_reference.entry_path
    if entry_path not in trees:
        raise _invalid("run.function", "module is not in the bundle")
    _require_entry_function(trees[entry_path], parsed_reference.function)

    ordered = {path: digests[path] for path in sorted(digests, key=canonical_path_key)}
    digest = hashlib.sha256(canonical_json(ordered).encode("utf-8")).hexdigest()
    return {
        "reference": reference,
        "pack_id": parsed_reference.pack_id,
        "module": parsed_reference.module,
        "function": parsed_reference.function,
        "entry_path": entry_path,
        "files": ordered,
        "digest": digest,
    }


def validate_trigger_sources(files: Any) -> dict[str, str]:
    """Validate a pack's complete ``triggers/`` tree (bounds, paths, compilation).

    Used by static pack validation so source that no definition references still
    has to be a valid bounded bundle. Returns per-file SHA-256 digests.
    """

    return _bundle_trees(files)[1]


def trigger_inventory(files: Mapping[str, Any]) -> dict[str, list[str]]:
    """Schema-5 trigger artifacts of a manifest file listing, in canonical order."""

    definitions = [path for path in files if path.startswith(TRIGGER_DEFINITION_ROOT)]
    modules = [path for path in files if path.startswith(TRIGGER_SOURCE_ROOT)]
    return {
        "definitions": sorted(definitions, key=canonical_path_key),
        "modules": sorted(modules, key=canonical_path_key),
    }


def _bundle_trees(files: Any) -> tuple[dict[str, ast.Module], dict[str, str]]:
    if type(files) is not dict or not files:
        raise _invalid("bundle", "must be a non-empty mapping of paths to source")
    if len(files) > BUNDLE_MAX_FILES:
        raise _invalid("bundle", "exceeds 100 files")

    digests: dict[str, str] = {}
    trees: dict[str, ast.Module] = {}
    spellings: dict[str, str] = {}
    total = 0
    for raw_path, source in files.items():
        try:
            member = validate_member_path(raw_path)
        except PackError as exc:
            raise _invalid("bundle", "contains an invalid path") from exc
        # Every directory and file must keep one spelling on case-insensitive
        # filesystems, or materialization could silently merge entries.
        for depth in range(1, len(member.parts) + 1):
            prefix = "/".join(member.parts[:depth])
            if depth == len(member.parts) and prefix.casefold() in spellings:
                raise _invalid("bundle", "contains paths that collide case-insensitively")
            if spellings.setdefault(prefix.casefold(), prefix) != prefix:
                raise _invalid("bundle", "contains paths that collide case-insensitively")
        parts = member.parts
        if len(parts) < 2 or parts[0] != "triggers" or not parts[-1].endswith(".py"):
            raise _invalid("bundle", "paths must be .py files under triggers/")
        if any(not IDENTIFIER_PATTERN.fullmatch(part) for part in parts[1:-1]) or not (
            IDENTIFIER_PATTERN.fullmatch(parts[-1][:-3])
        ):
            raise _invalid("bundle", "paths must be importable module names")
        if type(source) is not str:
            raise _invalid("bundle", "sources must be text")
        try:
            encoded = source.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise _invalid("bundle", "sources must be UTF-8") from exc
        total += len(encoded)
        if total > BUNDLE_MAX_BYTES:
            raise _invalid("bundle", "exceeds 1 MiB")
        try:
            tree = ast.parse(source, filename=raw_path, mode="exec")
            # Compile (never execute) so scope errors such as a module-level
            # ``return`` fail here rather than at import time.
            compile(tree, raw_path, "exec", dont_inherit=True)
        except _COMPILE_ERRORS as exc:
            raise _invalid("bundle", "contains a module that does not compile") from exc
        trees[raw_path] = tree
        digests[raw_path] = hashlib.sha256(encoded).hexdigest()

    # A module file and a package directory of the same (case-folded) name make
    # imports ambiguous: Python prefers the package, hiding the validated module.
    directories = {
        "/".join(path.split("/")[:depth]).casefold()
        for path in trees
        for depth in range(2, path.count("/") + 1)
    }
    if any(path[:-3].casefold() in directories for path in trees):
        raise _invalid("bundle", "a module file and a package directory share a name")
    return trees, digests


def _require_entry_function(module: ast.Module, name: str) -> None:
    path = "run.function"
    definition: ast.stmt | None = None
    for statement in module.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == name:
            definition = statement
    if definition is None:
        raise _invalid(path, "is not a top-level function in its module")
    if isinstance(definition, ast.AsyncFunctionDef):
        raise _invalid(path, "must be a synchronous function")
    if definition.decorator_list:
        raise _invalid(path, "must not be decorated")
    if _contains_generator_or_await(definition.body):
        raise _invalid(path, "must not be a generator")
    if _rebinds_after(module, name, definition.lineno):
        raise _invalid(path, "is rebound after its definition")

    arguments = definition.args
    positional = [*arguments.posonlyargs, *arguments.args]
    required_positional = len(positional) - len(arguments.defaults)
    required_keyword = sum(1 for default in arguments.kw_defaults if default is None)
    if len(positional) < 1 or required_positional != 1 or required_keyword:
        raise _invalid(path, "must accept exactly one required argument (ctx)")


def _rebinds_after(module: ast.Module, name: str, lineno: int) -> bool:
    """Whether module scope binds ``name`` again after its ``def``."""

    pending: list[ast.AST] = [s for s in module.body if s.lineno > lineno]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
            pending.extend(_header_expressions(node))
            continue
        if isinstance(node, ast.Lambda):
            pending.extend(_header_expressions(node))
            continue
        if isinstance(node, ast.Name) and node.id == name and not isinstance(node.ctx, ast.Load):
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if bound == name or alias.name == "*":
                    return True
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return True
        # Bindings stored as plain strings rather than Name nodes.
        if isinstance(node, (ast.MatchAs, ast.MatchStar, ast.ExceptHandler)) and node.name == name:
            return True
        if isinstance(node, ast.MatchMapping) and node.rest == name:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


# --- results -----------------------------------------------------------------------------


def validate_trigger_result(result: Any) -> dict[str, Any] | None:
    """Validate an author return value: ``None`` or a bounded JSON object."""

    path = "result"
    if result is None:
        return None
    if type(result) is not dict:
        raise _invalid(path, "must be None or a JSON object")
    checked = _check_json(result, path, 1, 64)
    for key in ("matched", "rows_affected"):
        if key in checked and (type(checked[key]) is not int or checked[key] < 0):
            raise _invalid(f"{path}.{key}", "must be a nonnegative integer")
    if "summary" in checked and type(checked["summary"]) is not str:
        raise _invalid(f"{path}.summary", "must be a string")
    if _utf8_len(canonical_json(checked)) > RESULT_MAX_BYTES:
        raise _invalid(path, "exceeds 16 KiB")
    return copy.deepcopy(checked)


# --- outputs: alerts and notifications (Amendment A1, spec §14) ---------------------------

OUTPUTS_MAX = 10
OUTPUT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
ALERT_INSTANCES_MAX = 100
NOTIFICATIONS_MAX = 10
LABELS_MAX = 32
LABEL_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
ALERTNAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_:.-]{0,127}$")
SEVERITY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
NOTIFIER_NAME_MAX_CHARS = 255
LABEL_VALUE_MAX_BYTES = 1024
ANNOTATION_VALUE_MAX_BYTES = 1024
SUBJECT_MAX_BYTES = 1024
MESSAGE_MAX_BYTES = 16 * 1024
TEMPLATE_SOURCE_MAX_BYTES = 16 * 1024
CONDITION_MAX_CHARS = 1024
CONDITION_MAX_NODES = 64
CONDITION_MAX_ATTRIBUTE_DEPTH = 8
TEMPLATE_MAX_LOOP_NESTING = 2
REPEAT_SECONDS_MIN = 60
REPEAT_SECONDS_MAX = 7 * 86400
DEFAULT_SEVERITY = "major"
ALERT_CATEGORY = "oscar_triggers"
# category stays overridable through labels (spec §14.2); these never are.
RESERVED_LABELS = frozenset({"alertname", "severity", "oscar_trigger", "oscar_trigger_output"})
CONTEXT_ROOTS = ("trigger", "run", "result", "item", "error")
OUTPUT_ON = ("success", "failure", "always")
NOTIFY_MODES = ("on_change", "every_run")
_FOR_EACH_PATTERN = re.compile(r"^result(?:\.[A-Za-z][A-Za-z0-9_]{0,63}){1,8}$")
_OUTPUT_KEYS = frozenset({"id", "alert", "notification", "when", "on"})
_ALERT_KEYS = frozenset({"alertname", "severity", "labels", "annotations", "summary", "description", "for_each"})
_NOTIFICATION_KEYS = frozenset({"notifier", "subject", "message", "notify", "repeat_seconds"})
_INSTANCE_KEYS = frozenset({"labels", "annotations", "vars"})


def validate_outputs(outputs: Any, *, run_mode: Optional[str] = None) -> list[dict[str, Any]]:
    """Validate a trigger's ``outputs`` list and return its canonical form.

    ``run_mode`` (sql/python/function) restricts SQL triggers to declarations
    only (``for_each: result.rows``). Conditions and templates are compiled here,
    so a stored definition never carries an unparseable one.
    """

    if type(outputs) is not list:
        raise _invalid("outputs", "must be a list")
    if len(outputs) > OUTPUTS_MAX:
        raise _invalid("outputs", f"at most {OUTPUTS_MAX} outputs")
    canonical: list[dict[str, Any]] = []
    seen: set[str] = set()
    for output in outputs:
        if type(output) is not dict:
            raise _invalid("outputs", "each output must be a mapping")
        output_id = output.get("id")
        if type(output_id) is not str or not OUTPUT_ID_PATTERN.fullmatch(output_id):
            raise _invalid("outputs", "output ids must match [a-z][a-z0-9_]{0,31}")
        if output_id in seen:
            raise _invalid("outputs", "output ids must be unique")
        seen.add(output_id)
        path = f"outputs.{output_id}"
        if any(type(key) is not str or key not in _OUTPUT_KEYS for key in output):
            raise _invalid(path, "unknown key")
        kinds = [key for key in ("alert", "notification") if key in output]
        if len(kinds) != 1:
            raise _invalid(path, "needs exactly one of alert or notification")
        on = output.get("on", "success")
        if on not in OUTPUT_ON:
            raise _invalid(f"{path}.on", "must be success, failure or always")
        when = output.get("when")
        if when is not None:
            compile_condition(when, f"{path}.when")
        entry: dict[str, Any] = {"id": output_id, "on": on, "when": when}
        if kinds[0] == "alert":
            entry["alert"] = _validate_alert(output["alert"], f"{path}.alert", run_mode)
        else:
            entry["notification"] = _validate_notification(output["notification"], f"{path}.notification")
        canonical.append(entry)
    return canonical


def _static_text(value: Any, path: str, pattern: Optional[re.Pattern[str]] = None, max_chars: int = 255) -> str:
    if type(value) is not str or not value or len(value) > max_chars:
        raise _invalid(path, "must be a non-empty string")
    _require_encodable(value, path)
    if "{{" in value or "{%" in value or "{#" in value or any(ord(char) < 32 for char in value):
        raise _invalid(path, "must be static text")
    if pattern is not None and not pattern.fullmatch(value):
        raise _invalid(path, "has an invalid format")
    return value


def _template_field(value: Any, path: str) -> Optional[str]:
    if value is None:
        return None
    compile_template(value, path)
    return value


def _template_map(value: Any, path: str, *, labels: bool) -> dict[str, str]:
    if value is None:
        return {}
    if type(value) is not dict or len(value) > LABELS_MAX:
        raise _invalid(path, f"must be a mapping of at most {LABELS_MAX} entries")
    result: dict[str, str] = {}
    for name, template in value.items():
        if type(name) is not str or not LABEL_NAME_PATTERN.fullmatch(name) or name.startswith("__"):
            raise _invalid(path, "names must match [A-Za-z_][A-Za-z0-9_]{0,63} and not start with __")
        if labels and name in RESERVED_LABELS:
            raise _invalid(path, f"{name} is set by the trigger runtime")
        if type(template) is not str:
            raise _invalid(path, "values must be template strings")
        result[name] = _template_field(template, path)
    return result


def _validate_alert(alert: Any, path: str, run_mode: Optional[str]) -> dict[str, Any]:
    if type(alert) is not dict:
        raise _invalid(path, "must be a mapping")
    if any(type(key) is not str or key not in _ALERT_KEYS for key in alert):
        raise _invalid(path, "unknown key")
    if "alertname" not in alert:
        raise _invalid(f"{path}.alertname", "is required")
    alertname = _static_text(alert["alertname"], f"{path}.alertname", ALERTNAME_PATTERN, 128)
    severity = _static_text(alert.get("severity", DEFAULT_SEVERITY), f"{path}.severity", SEVERITY_PATTERN, 32)
    for_each = alert.get("for_each")
    if for_each is not None:
        if type(for_each) is not str or not _FOR_EACH_PATTERN.fullmatch(for_each):
            raise _invalid(f"{path}.for_each", "must be a result field path such as result.rows")
        if run_mode == "sql" and for_each != "result.rows":
            raise _invalid(f"{path}.for_each", "SQL triggers can only iterate result.rows")
    return {
        "alertname": alertname,
        "severity": severity,
        "labels": _template_map(alert.get("labels"), f"{path}.labels", labels=True),
        "annotations": _template_map(alert.get("annotations"), f"{path}.annotations", labels=False),
        "summary": _template_field(alert.get("summary"), f"{path}.summary"),
        "description": _template_field(alert.get("description"), f"{path}.description"),
        "for_each": for_each,
    }


def _validate_notification(notification: Any, path: str) -> dict[str, Any]:
    if type(notification) is not dict:
        raise _invalid(path, "must be a mapping")
    if any(type(key) is not str or key not in _NOTIFICATION_KEYS for key in notification):
        raise _invalid(path, "unknown key")
    if "notifier" not in notification:
        raise _invalid(f"{path}.notifier", "is required")
    notifier = _static_text(notification["notifier"], f"{path}.notifier", None, NOTIFIER_NAME_MAX_CHARS)
    notify = notification.get("notify", "on_change")
    if notify not in NOTIFY_MODES:
        raise _invalid(f"{path}.notify", "must be on_change or every_run")
    repeat = notification.get("repeat_seconds")
    if repeat is not None:
        if notify != "on_change":
            raise _invalid(f"{path}.repeat_seconds", "only applies to notify: on_change")
        if type(repeat) is not int or not REPEAT_SECONDS_MIN <= repeat <= REPEAT_SECONDS_MAX:
            raise _invalid(f"{path}.repeat_seconds", f"must be an integer from {REPEAT_SECONDS_MIN} to {REPEAT_SECONDS_MAX}")
    return {
        "notifier": notifier,
        "subject": _template_field(notification.get("subject"), f"{path}.subject"),
        "message": _template_field(notification.get("message"), f"{path}.message"),
        "notify": notify,
        "repeat_seconds": repeat,
    }


# --- output conditions (`when`): parsed once, walked, never eval'd ------------------------


class ConditionError(Exception):
    """A condition could not be evaluated against this run; it counts as false."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Condition:
    source: str
    tree: tuple


# YAML-style literals authors write in conditions (Python's True/False/None also work).
_CONDITION_LITERALS = {"true": True, "false": False, "null": None}
_COMPARE_OPS = {
    ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
    ast.In: "in", ast.NotIn: "not in",
}


def compile_condition(source: Any, path: str = "when") -> Condition:
    if type(source) is not str or not source.strip() or len(source) > CONDITION_MAX_CHARS:
        raise _invalid(path, f"must be a non-empty expression of at most {CONDITION_MAX_CHARS} characters")
    _require_encodable(source, path)
    try:
        return _compile_condition_cached(source)
    except ValueError as exc:
        raise _invalid(path, str(exc)) from None


@functools.lru_cache(maxsize=1024)
def _compile_condition_cached(source: str) -> Condition:
    try:
        parsed = ast.parse(source, mode="eval")
    except _COMPILE_ERRORS:
        raise ValueError("is not a valid expression") from None
    if sum(1 for _ in ast.walk(parsed)) > CONDITION_MAX_NODES:
        raise ValueError(f"exceeds {CONDITION_MAX_NODES} syntax nodes")
    return Condition(source, _condition_node(parsed.body))


def _condition_node(node: ast.AST) -> tuple:
    if isinstance(node, ast.Constant):
        if node.value is None or type(node.value) in (bool, int, float, str):
            return ("const", node.value)
        raise ValueError("unsupported literal")
    if isinstance(node, ast.Name) and node.id in _CONDITION_LITERALS:
        return ("const", _CONDITION_LITERALS[node.id])
    if isinstance(node, (ast.Name, ast.Attribute)):
        chain: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            if current.attr.startswith("_"):
                raise ValueError("attribute names may not start with _")
            chain.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name) or current.id not in CONTEXT_ROOTS:
            raise ValueError(f"names must start with one of {', '.join(CONTEXT_ROOTS)}")
        if len(chain) > CONDITION_MAX_ATTRIBUTE_DEPTH:
            raise ValueError("attribute chain is too deep")
        return ("path", (current.id, *reversed(chain)))
    if isinstance(node, ast.Compare):
        ops = []
        for op, right in zip(node.ops, node.comparators):
            if type(op) not in _COMPARE_OPS:
                raise ValueError("unsupported comparison")
            ops.append((_COMPARE_OPS[type(op)], _condition_node(right)))
        return ("cmp", _condition_node(node.left), tuple(ops))
    if isinstance(node, ast.BoolOp) and type(node.op) in (ast.And, ast.Or):
        return ("and" if isinstance(node.op, ast.And) else "or", tuple(_condition_node(v) for v in node.values))
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return ("not", _condition_node(node.operand))
        if isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and type(node.operand.value) in (int, float):
            return ("const", -node.operand.value)
        raise ValueError("unsupported operator")
    if isinstance(node, (ast.List, ast.Tuple)):
        return ("list", tuple(_condition_node(item) for item in node.elts))
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
        and len(node.args) == 1
        and not node.keywords
        and not isinstance(node.args[0], ast.Starred)
    ):
        return ("len", _condition_node(node.args[0]))
    raise ValueError("uses syntax outside the condition grammar")


def evaluate_condition(compiled: Condition, context: Mapping[str, Any]) -> bool:
    """Evaluate a compiled condition; missing fields/type mismatches raise ``ConditionError``."""

    return bool(_evaluate(compiled.tree, context))


def _evaluate(node: tuple, context: Mapping[str, Any]) -> Any:
    kind = node[0]
    if kind == "const":
        return node[1]
    if kind == "path":
        root, *chain = node[1]
        if root not in context or context[root] is None and chain:
            raise ConditionError("missing_field")
        value = context[root]
        for name in chain:
            if type(value) is not dict or name not in value:
                raise ConditionError("missing_field")
            value = value[name]
        return value
    if kind == "list":
        return [_evaluate(item, context) for item in node[1]]
    if kind == "len":
        value = _evaluate(node[1], context)
        if type(value) not in (str, list, dict):
            raise ConditionError("type_mismatch")
        return len(value)
    if kind == "not":
        return not _evaluate(node[1], context)
    if kind == "and":
        return all(_evaluate(value, context) for value in node[1])
    if kind == "or":
        return any(_evaluate(value, context) for value in node[1])
    left = _evaluate(node[1], context)
    for op, right_node in node[2]:
        right = _evaluate(right_node, context)
        try:
            if op in ("in", "not in"):
                if type(right) not in (list, str, dict) or (type(right) is str and type(left) is not str):
                    raise ConditionError("type_mismatch")
                outcome = (left in right) == (op == "in")
            elif op == "==":
                outcome = left == right
            elif op == "!=":
                outcome = left != right
            elif op == "<":
                outcome = left < right
            elif op == "<=":
                outcome = left <= right
            elif op == ">":
                outcome = left > right
            else:
                outcome = left >= right
        except TypeError:
            raise ConditionError("type_mismatch") from None
        if not outcome:
            return False
        left = right
    return True


# --- output templates: immutable sandbox, no globals, static allowlist ------------------------

_TEMPLATE_FILTERS = frozenset(
    {
        "default", "d", "lower", "upper", "title", "capitalize", "trim", "string", "int", "float", "round",
        "abs", "length", "count", "first", "last", "join", "tojson", "truncate", "sort", "unique", "list",
        "min", "max",
    }
)
# Filters whose arguments can amplify output before the streaming cap applies.
_ARGUMENT_FREE_FILTERS = frozenset({"tojson"})
# Filter arguments are constants with small bounds (join separators, round
# precision, truncate lengths) so no argument can amplify work before the cap.
_FILTER_STRING_MAX = 16
_FILTER_DEFAULT_STRING_MAX = 1024
_FILTER_INT_MAX = 16 * 1024
_ROUND_PRECISION_MAX = 15
_TEMPLATE_TESTS = frozenset(
    {
        "defined", "undefined", "none", "number", "string", "mapping", "sequence", "boolean", "true", "false",
        "integer", "float", "eq", "ne", "lt", "le", "gt", "ge", "in", "lower", "upper",
    }
)
_TEMPLATE_NODES = (
    jinja_nodes.Template, jinja_nodes.Output, jinja_nodes.TemplateData, jinja_nodes.Name, jinja_nodes.Getattr,
    jinja_nodes.Getitem, jinja_nodes.Const, jinja_nodes.Filter, jinja_nodes.Test, jinja_nodes.CondExpr,
    jinja_nodes.Compare, jinja_nodes.Operand, jinja_nodes.And, jinja_nodes.Or, jinja_nodes.Not,
    jinja_nodes.Concat, jinja_nodes.If, jinja_nodes.For, jinja_nodes.List, jinja_nodes.Tuple, jinja_nodes.Add,
    jinja_nodes.Sub, jinja_nodes.Div, jinja_nodes.FloorDiv, jinja_nodes.Neg, jinja_nodes.Pos,
    jinja_nodes.Keyword, jinja_nodes.Dict, jinja_nodes.Pair,
)


def _template_environment() -> ImmutableSandboxedEnvironment:
    env = ImmutableSandboxedEnvironment(undefined=StrictUndefined, autoescape=False, cache_size=0)
    env.globals.clear()
    env.filters = {name: JINJA_FILTERS[name] for name in _TEMPLATE_FILTERS if name in JINJA_FILTERS}
    env.tests = {name: JINJA_TESTS[name] for name in _TEMPLATE_TESTS if name in JINJA_TESTS}
    return env


_TEMPLATE_ENV = _template_environment()


def compile_template(source: Any, path: str = "template") -> Any:
    """Parse, statically check and compile an output template (never rendered here)."""

    if type(source) is not str:
        raise _invalid(path, "must be a template string")
    _require_encodable(source, path)
    if _utf8_len(source) > TEMPLATE_SOURCE_MAX_BYTES:
        raise _invalid(path, f"exceeds {TEMPLATE_SOURCE_MAX_BYTES // 1024} KiB")
    try:
        return _compile_template_cached(source)
    except ValueError as exc:
        raise _invalid(path, str(exc)) from None


@functools.lru_cache(maxsize=1024)
def _compile_template_cached(source: str) -> Any:
    try:
        parsed = _TEMPLATE_ENV.parse(source)
    except (TemplateSyntaxError, RecursionError, MemoryError):
        raise ValueError("is not a valid template") from None
    loop_names = {
        target.name
        for loop in parsed.find_all(jinja_nodes.For)
        for target in ([loop.target] if isinstance(loop.target, jinja_nodes.Name) else loop.target.find_all(jinja_nodes.Name))
    }
    _check_template_node(parsed, {*CONTEXT_ROOTS, "loop", *loop_names}, 0)
    try:
        return _TEMPLATE_ENV.from_string(source)
    except (TemplateSyntaxError, RecursionError, MemoryError):
        raise ValueError("is not a valid template") from None


def _check_template_node(node: Any, names: set[str], loops: int) -> None:
    if not isinstance(node, _TEMPLATE_NODES):
        raise ValueError(f"uses unsupported template syntax ({type(node).__name__})")
    if isinstance(node, jinja_nodes.Name) and node.ctx == "load" and node.name not in names:
        raise ValueError(f"names must be one of {', '.join(CONTEXT_ROOTS)} or a loop variable")
    if isinstance(node, jinja_nodes.Getattr) and node.attr.startswith("_"):
        raise ValueError("attribute names may not start with _")
    if isinstance(node, jinja_nodes.Getitem):
        key = node.arg
        if not isinstance(key, jinja_nodes.Const) or type(key.value) not in (str, int) or str(key.value).startswith("_"):
            raise ValueError("subscripts must be constant names or indexes")
    if isinstance(node, (jinja_nodes.Filter, jinja_nodes.Test)):
        allowed = _TEMPLATE_FILTERS if isinstance(node, jinja_nodes.Filter) else _TEMPLATE_TESTS
        if node.name not in allowed or node.dyn_args is not None or node.dyn_kwargs is not None:
            raise ValueError(f"filter or test '{node.name}' is not allowed")
        if node.name in _ARGUMENT_FREE_FILTERS and isinstance(node, jinja_nodes.Filter) and (node.args or node.kwargs):
            raise ValueError(f"filter '{node.name}' takes no arguments")
        _check_filter_arguments(node)
    if isinstance(node, jinja_nodes.For):
        if node.recursive or loops + 1 > TEMPLATE_MAX_LOOP_NESTING:
            raise ValueError(f"loops may nest at most {TEMPLATE_MAX_LOOP_NESTING} deep")
        loops += 1
    for child in node.iter_child_nodes():
        _check_template_node(child, names, loops)


class TemplateValueTooLarge(ValueError):
    """A strictly bounded field (e.g. an identity label) rendered past its cap."""


def _check_filter_arguments(node: Any) -> None:
    values = [*node.args, *(keyword.value for keyword in node.kwargs)]
    string_max = _FILTER_DEFAULT_STRING_MAX if node.name in ("default", "d") else _FILTER_STRING_MAX
    for value in values:
        if not isinstance(value, jinja_nodes.Const):
            raise ValueError(f"filter '{node.name}' arguments must be constants")
        constant = value.value
        if type(constant) is str and len(constant) > string_max:
            raise ValueError(f"filter '{node.name}' string arguments are limited to {string_max} characters")
        if type(constant) in (int, float) and abs(constant) > _FILTER_INT_MAX:
            raise ValueError(f"filter '{node.name}' numeric arguments are limited to {_FILTER_INT_MAX}")
        if type(constant) not in (str, int, float, bool) and constant is not None:
            raise ValueError(f"filter '{node.name}' arguments must be scalar constants")
    if node.name == "round":
        precision = node.args[0].value if node.args else next(
            (keyword.value.value for keyword in node.kwargs if keyword.key == "precision"), 0
        )
        if type(precision) is not int or not 0 <= precision <= _ROUND_PRECISION_MAX:
            raise ValueError(f"round precision must be an integer from 0 to {_ROUND_PRECISION_MAX}")


def render_template(template: Any, context: Mapping[str, Any], limit_bytes: int, *, strict: bool = False) -> str:
    """Render with every context root present, streaming and stopping at ``limit_bytes``.

    Over the cap the value is truncated, or with ``strict`` refused
    (``TemplateValueTooLarge``) so identity-bearing values never collapse.
    Errors (StrictUndefined, sandbox refusals, type errors) propagate; the caller
    records them as that output's failure.
    """

    values = {root: context.get(root) for root in CONTEXT_ROOTS}
    chunks: list[str] = []
    used = 0
    for chunk in template.generate(**values):
        size = _utf8_len(chunk)
        if used + size > limit_bytes:
            if strict:
                raise TemplateValueTooLarge(f"rendered value exceeds {limit_bytes} bytes")
            remaining = chunk.encode("utf-8", "surrogatepass")[: max(0, limit_bytes - used)]
            chunks.append(remaining.decode("utf-8", "ignore"))
            break
        chunks.append(chunk)
        used += size
    return "".join(chunks)


# --- code-filled outputs ----------------------------------------------------------------------


def validate_code_outputs(payload: Any, outputs: list[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Split ``result["outputs"]`` into accepted per-output payloads and per-output errors.

    Alert outputs take a list of ``{labels, annotations, vars}`` instances (≤ 100);
    notification outputs take a ``vars`` object. Code can never add an output,
    destination or notifier: unknown ids are one ``code_outputs`` error.
    """

    if type(payload) is not dict:
        return {}, {"code_outputs": "invalid_payload"}
    declared = {output["id"]: output for output in outputs}
    accepted: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for output_id, value in payload.items():
        output = declared.get(output_id) if type(output_id) is str else None
        if output is None:
            errors["code_outputs"] = "unknown_output"
            continue
        reason = _code_output_error(value, "alert" in output)
        if reason:
            errors[output_id] = reason
        else:
            accepted[output_id] = copy.deepcopy(value)
    return accepted, errors


def _code_output_error(value: Any, alert: bool) -> Optional[str]:
    if not alert:
        return None if type(value) is dict else "invalid_vars"
    if type(value) is not list:
        return "invalid_instances"
    if len(value) > ALERT_INSTANCES_MAX:
        return "too_many_instances"
    for instance in value:
        if type(instance) is not dict or any(key not in _INSTANCE_KEYS for key in instance):
            return "invalid_instance"
        if "vars" in instance and type(instance["vars"]) is not dict:
            return "invalid_instance"
        for field, labels in (("labels", True), ("annotations", False)):
            mapping = instance.get(field, {})
            if type(mapping) is not dict or len(mapping) > LABELS_MAX:
                return "invalid_instance"
            for name, text in mapping.items():
                if type(name) is not str or not LABEL_NAME_PATTERN.fullmatch(name) or name.startswith("__"):
                    return "invalid_instance"
                if labels and name in RESERVED_LABELS:
                    return "reserved_label"
                if type(text) is not str:
                    return "invalid_instance"
                if _utf8_len(text) > LABEL_VALUE_MAX_BYTES:
                    return "value_too_large"
    return None
