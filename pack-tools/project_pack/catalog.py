"""Bounded, non-executable documentation shared by pack authors and readers."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from project_pack.errors import PackError, fail
from project_pack.model import TASK_REFERENCE_PATTERN, _load_strict_yaml

CORE_OWNER_TOKEN = '@core'
ENTRY_MAX_BYTES = 65_536
FUNCTIONS_MAX_BYTES = 1_048_576
PACK_MAX_ENTRIES = 1_000
PACK_MAX_BYTES = 4_194_304
FUNCTION_TYPES = frozenset({'invoke', 'fabric', 'script', 'ansible'})
_FIELDS = frozenset({'summary', 'category', 'tags', 'prerequisites', 'inputs', 'output', 'metrics', 'example'})


def _invalid(field: str) -> None:
    # Field paths are fixed by this parser; rejected values never enter errors.
    raise fail('CATALOG_SCHEMA', f'Invalid catalog field: {field}')


def _text(value: object, field: str, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        _invalid(field)
    try:
        value.encode('utf-8')
    except UnicodeError:
        _invalid(field)
    return value


def _mapping(value: object, field: str, allowed: frozenset[str]) -> dict:
    if not isinstance(value, dict) or any(key not in allowed for key in value):
        _invalid(field)
    return value


def _list(value: object, field: str, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        _invalid(field)
    return value


def normalized_size(value: object) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8'))
    except (TypeError, ValueError, UnicodeError):
        _invalid('document')


def _strings(value: object, field: str, count: int, length: int) -> list[str]:
    result = [_text(item, field, length, required=True) for item in _list(value, field, count)]
    if len(set(result)) != len(result):
        _invalid(field)
    return result


def parse_catalog_document(value: object, *, description: object) -> dict[str, Any]:
    source = _mapping(value, 'catalog', _FIELDS)
    result = {
        'summary': _text(source.get('summary'), 'summary', 200, required=True),
        'description': _text(description, 'description', 4_000, required=True),
        'category': _text(source.get('category', ''), 'category', 100),
        'tags': _strings(source.get('tags', []), 'tags', 20, 50),
        'prerequisites': _strings(source.get('prerequisites', []), 'prerequisites', 20, 500),
        'inputs': [], 'metrics': [],
        'output': _text(source.get('output', ''), 'output', 4_000),
        'example': _text(source.get('example', ''), 'example', 8_000),
    }
    for field in ('inputs', 'metrics'):
        allowed = frozenset({'name', 'description', 'type', 'required', 'default'} if field == 'inputs'
                            else {'name', 'description'})
        names = set()
        for item in _list(source.get(field, []), field, 100):
            row = _mapping(item, field, allowed)
            name = _text(row.get('name'), f'{field}.name', 100 if field == 'inputs' else 200, required=True)
            if name in names:
                _invalid(f'{field}.name')
            names.add(name)
            parsed = {'name': name, 'description': _text(row.get('description', ''), f'{field}.description', 1_000)}
            if field == 'inputs':
                parsed['type'] = _text(row.get('type'), 'inputs.type', 50, required=True)
                if type(row.get('required', False)) is not bool:
                    _invalid('inputs.required')
                parsed['required'] = row.get('required', False)
                if 'default' in row:
                    if parsed['type'].casefold() in {'password', 'secret'}:
                        _invalid('inputs.default')
                    parsed['default'] = _text(row['default'], 'inputs.default', 500)
            result[field].append(parsed)
    if normalized_size(result) > ENTRY_MAX_BYTES:
        raise fail('CATALOG_LIMIT', 'Normalized catalog document exceeds 65536 UTF-8 bytes')
    return result


def catalog_entry_id(source_pack: str, kind: str, task_type: str, reference: str) -> str:
    return sha256(json.dumps([source_pack, kind, task_type, reference],
        ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()


def parse_function_catalog(document: bytes) -> list[dict[str, Any]]:
    if not isinstance(document, bytes) or len(document) > FUNCTIONS_MAX_BYTES:
        raise fail('CATALOG_LIMIT', 'Function catalog exceeds 1048576 UTF-8 bytes')
    try:
        source = _mapping(_load_strict_yaml(document), 'document', frozenset({'version', 'functions'}))
    except (PackError, RecursionError) as exc:
        raise fail('CATALOG_SCHEMA', 'Function catalog YAML must be safe and unambiguous') from exc
    if type(source.get('version')) is not int or source['version'] != 1:
        _invalid('version')
    entries = []
    identities = set()
    for item in _list(source.get('functions'), 'functions', PACK_MAX_ENTRIES):
        row = _mapping(item, 'functions', frozenset({'name', 'type', 'description', 'catalog'}))
        name = _text(row.get('name'), 'functions.name', 255, required=True)
        if not TASK_REFERENCE_PATTERN.fullmatch(name):
            _invalid('functions.name')
        runner = row.get('type')
        if not isinstance(runner, str) or runner not in FUNCTION_TYPES:
            _invalid('functions.type')
        identity = (runner, name)
        if identity in identities:
            _invalid('functions.name')
        identities.add(identity)
        parsed = parse_catalog_document(row.get('catalog'), description=row.get('description'))
        description = parsed.pop('description')
        entries.append({'name': name, 'type': runner, 'description': description, 'catalog': parsed})
    if sum(normalized_size(entry) for entry in entries) > PACK_MAX_BYTES:
        raise fail('CATALOG_LIMIT', 'Pack catalog exceeds 4194304 normalized UTF-8 bytes')
    return entries
