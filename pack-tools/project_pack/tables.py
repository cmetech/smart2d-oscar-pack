"""Narrow SQL contract shared by the external-table editor and project packs."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from project_pack.errors import fail


SQL_MAX_BYTES = 64 * 1024
TABLE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


@dataclass(frozen=True)
class TableDeclaration:
    name: str
    source_sha256: str
    sql: str


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


def _tokens(sql: str) -> list[_Token]:
    if not isinstance(sql, str):
        raise fail("TABLE_SQL_INVALID", "SQL must be text")
    try:
        encoded = sql.encode("utf-8")
    except UnicodeError as exc:
        raise fail("TABLE_SQL_INVALID", "SQL must be valid UTF-8") from exc
    if not encoded or len(encoded) > SQL_MAX_BYTES:
        raise fail("TABLE_SQL_INVALID", "SQL exceeds the 64 KiB limit or is empty")

    result: list[_Token] = []
    index = 0
    while index < len(sql):
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if sql.startswith(("--", "/*"), index) or char == "#":
            raise fail("TABLE_SQL_INVALID", "SQL comments are not supported")
        if char in {"'", "`"}:
            quote = char
            start = index + 1
            index = start
            while index < len(sql):
                if sql[index] == "\\":
                    # Backslash parsing changes with SQL_MODE; reject that ambiguity.
                    raise fail("TABLE_SQL_INVALID", "backslash escapes are not supported")
                if sql[index] == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    break
                index += 1
            if index >= len(sql):
                raise fail("TABLE_SQL_INVALID", "unterminated SQL quote")
            result.append(_Token("identifier" if quote == "`" else "string", sql[start:index]))
            index += 1
            continue
        if char == '"' or char == "@" or char == "\\":
            raise fail("TABLE_SQL_INVALID", "unsupported SQL syntax")
        if char.isascii() and (char.isalpha() or char == "_"):
            start = index
            index += 1
            while index < len(sql) and sql[index].isascii() and (sql[index].isalnum() or sql[index] == "_"):
                index += 1
            result.append(_Token("word", sql[start:index]))
            continue
        if char.isascii() and char.isdigit():
            start = index
            index += 1
            while index < len(sql) and sql[index].isascii() and sql[index].isdigit():
                index += 1
            result.append(_Token("number", sql[start:index]))
            continue
        if char in "(),;.=*+-<>/%":
            result.append(_Token("symbol", char))
            index += 1
            continue
        raise fail("TABLE_SQL_INVALID", "unsupported SQL syntax")
    if result and result[-1].value == ";":
        result.pop()
    if not result or any(token.value == ";" for token in result):
        raise fail("TABLE_SQL_INVALID", "exactly one SQL statement is required")
    return result


def _word(token: _Token, value: str) -> bool:
    return token.kind == "word" and token.value.upper() == value


def parse_create_table(sql: str, *, expected_name: str | None = None) -> TableDeclaration:
    tokens = _tokens(sql)
    if len(tokens) < 6 or not _word(tokens[0], "CREATE") or not _word(tokens[1], "TABLE"):
        raise fail("TABLE_SQL_INVALID", "only CREATE TABLE with an explicit definition is supported")
    name_token = tokens[2]
    name = name_token.value
    if name_token.kind not in {"word", "identifier"} or not TABLE_NAME.fullmatch(name):
        raise fail("TABLE_NAME_INVALID", "table name must be lowercase ASCII")
    if expected_name is not None and name != expected_name:
        raise fail("TABLE_NAME_MISMATCH", "SQL table name differs from pack filename")
    if tokens[3].value != "(":
        raise fail("TABLE_SQL_INVALID", "CREATE TABLE requires an explicit column definition")

    depth = 0
    closing = -1
    for position in range(3, len(tokens)):
        token = tokens[position]
        if token.value == "(":
            depth += 1
        elif token.value == ")":
            depth -= 1
            if depth < 0:
                break
            if depth == 0:
                closing = position
                break
    if closing < 5 or depth != 0:
        raise fail("TABLE_SQL_INVALID", "CREATE TABLE has no valid column definition")
    body = tokens[4:closing]
    if body[0].kind not in {"word", "identifier"} or any(token.value == "." for token in body):
        raise fail("TABLE_SQL_INVALID", "CREATE TABLE has an unsupported definition")
    forbidden = {"SELECT", "AS", "LIKE", "FOREIGN", "REFERENCES", "GENERATED", "CHECK", "CONSTRAINT", "TABLESPACE", "DATA", "DIRECTORY", "PARTITION", "TRIGGER", "PROCEDURE", "FUNCTION"}
    if any(token.kind == "word" and token.value.upper() in forbidden for token in body):
        raise fail("TABLE_SQL_INVALID", "CREATE TABLE contains an unsupported clause")

    tail = tokens[closing + 1 :]
    if tail and not (
        len(tail) == 3
        and _word(tail[0], "ENGINE")
        and tail[1].value == "="
        and _word(tail[2], "INNODB")
    ):
        raise fail("TABLE_SQL_INVALID", "only the InnoDB engine option is supported")
    return TableDeclaration(name, hashlib.sha256(sql.encode("utf-8")).hexdigest(), sql)


_SELECT_FORBIDDEN = {
    "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE",
    "INTO", "OUTFILE", "DUMPFILE", "FOR", "LOCK", "CALL", "EXECUTE", "PREPARE",
    "SET", "LOAD", "GRANT", "REVOKE", "HANDLER", "DO", "PROCEDURE",
}
_SELECT_CALLS = {"COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "IN", "EXISTS"}


def validate_select(sql: str) -> str:
    tokens = _tokens(sql)
    if not _word(tokens[0], "SELECT"):
        raise fail("TABLE_SQL_INVALID", "only SELECT preview is supported")
    for index, token in enumerate(tokens):
        if token.value == ".":
            raise fail("TABLE_SQL_INVALID", "schema-qualified or dotted SQL is not supported")
        if token.kind == "word" and token.value.upper() in _SELECT_FORBIDDEN:
            raise fail("TABLE_SQL_INVALID", "SELECT contains an unsupported clause")
        if token.kind in {"word", "identifier"} and index + 1 < len(tokens) and tokens[index + 1].value == "(":
            if token.kind != "word" or token.value.upper() not in _SELECT_CALLS:
                raise fail("TABLE_SQL_INVALID", "SELECT function calls are not supported")
    return sql


def table_files(manifest, root: Path) -> tuple[TableDeclaration, ...]:
    declarations: list[TableDeclaration] = []
    for relative, record in manifest.files.items():
        if not relative.startswith("tables/"):
            continue
        path = root / relative
        try:
            data = path.read_bytes()
            sql = data.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise fail("TABLE_SQL_INVALID", "pack table SQL is unavailable or not UTF-8") from exc
        if hashlib.sha256(data).hexdigest() != record.sha256 or len(data) != record.size:
            raise fail("HASH_MISMATCH", "pack table SQL changed after validation")
        declarations.append(parse_create_table(sql, expected_name=path.stem))
    return tuple(declarations)
