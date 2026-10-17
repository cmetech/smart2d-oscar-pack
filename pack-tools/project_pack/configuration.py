"""Strict parsing for loadable pack configuration artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Literal, Mapping, NoReturn
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.triggers.cron import CronTrigger

from project_pack.errors import PackError, fail
from project_pack.paths import canonical_path_key, validate_member_path


MAX_ARTIFACTS = 25_000
MAX_JSON_DEPTH = 32
MAX_JSON_STRING_BYTES = 1024 * 1024
_CONFIGURATION_ROOTS = frozenset({"rules", "mappings", "roles", "dashboards", "hooks", "suppressions", "probes"})
_PORTABLE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,99}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)$")
_CREDENTIAL_KEY = re.compile(r"password|secret|token|credential|privatekey", re.IGNORECASE)
_CREDENTIAL_HEADERS = frozenset({"authorization", "proxyauthorization", "cookie", "setcookie", "xapikey", "apikey"})
_SCHEDULE_FIELDS = frozenset({"year", "month", "day", "week", "day_of_week", "hour", "minute", "second", "start_date", "end_date", "timezone", "jitter"})
_HOOK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
_HOOK_METRIC_SLUG = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_HOOK_TARGET_NAME = re.compile(r"^[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*$")
_HOOK_NOTIFIER_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_HOOK_SECRET_KEY = re.compile(r"password|secret|token|credential|private[_-]?key", re.IGNORECASE)
_HOOK_DESTINATION = re.compile(
    r"^(alert\.labels|alert\.annotations|ticket\.fields)\.([A-Za-z_][A-Za-z0-9_.-]*)$"
)
_HOOK_TICKET_FIELDS = frozenset({"summary", "description", "severity", "assignment_group"})
_HOOK_PROTECTED_DESTINATIONS = frozenset({
    "fingerprint", "suppression", "suppress", "route", "notifier", "notifier_id",
    "hook_plan", "hookplan", "flow_state", "create_ticket", "no_auto_ticket",
    "execute_task", "workflow_id", "oscar_fingerprint", "nats_subject",
    "rabbitmq_routing_key", "oscar_synthetic_source", "oscar_correlation_pattern",
    "oscar_correlation_parent_fingerprint", "cc_notifier_id", "bcc_notifier_id",
    "notifier_type", "autocallout", "autocaller", "autocall", "archive_to_database",
    "archive_to_elastic",
})
_ROLE_NAME = re.compile(r"^[a-z]+(?:[._][a-z]+)*$")
_RESERVED_ROLES = frozenset({"admin", "super", "editor", "viewer"})
_CONDITION_OPERATOR = re.compile(r"!contains|contains|!regex|regex|>=|<=|!=|==|>|<")


def _has_unbounded_regex_quantifier(pattern: str) -> bool:
    escaped = False
    character_class = False
    groups: list[bool] = []
    unbounded = 0
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            character_class = True
        elif character == "]":
            character_class = False
        elif not character_class and character == "(":
            groups.append(False)
        elif not character_class and character == ")":
            contains_unbounded = groups.pop() if groups else False
            if groups:
                groups[-1] = groups[-1] or contains_unbounded
            if contains_unbounded and index + 1 < len(pattern) and pattern[index + 1] in "*+?{":
                return True
        elif not character_class and character in "*+":
            unbounded += 1
            if groups:
                groups[-1] = True
            if index == 0 or pattern[index - 1] == ")":
                return True
        elif not character_class and character == "{":
            closing = pattern.find("}", index + 1)
            if closing != -1:
                quantifier = pattern[index + 1:closing]
                if re.fullmatch(r"\d+,", quantifier):
                    unbounded += 1
                    if groups:
                        groups[-1] = True
                    if index == 0 or pattern[index - 1] == ")":
                        return True
                index = closing
        index += 1
    return unbounded > 1


@dataclass(frozen=True)
class ConfigurationArtifact:
    artifact_type: Literal["rule", "mapping", "role", "dashboard", "hook", "suppression", "probe"]
    identity: Mapping[str, str]
    source_path: str
    source_ordinal: int
    payload: Mapping[str, Any]


def canonical_identity_hash(identity: Mapping[str, str]) -> str:
    document = json.dumps(
        dict(identity), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(document).hexdigest()


def _invalid(message: str) -> NoReturn:
    raise fail("CONFIGURATION_INVALID", message)


def _limit(message: str) -> NoReturn:
    raise fail("CONFIGURATION_LIMIT", message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid("configuration JSON contains a duplicate object key")
        result[key] = value
    return result


def _load_json(data: bytes) -> Any:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: _invalid(
                "configuration JSON contains a non-finite number"
            ),
        )
    except PackError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise fail("CONFIGURATION_INVALID", "configuration file is not strict JSON") from exc
    _validate_json_value(value, 1)
    return value


def _validate_json_value(value: Any, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        _limit("configuration JSON exceeds the nesting-depth limit")
    if isinstance(value, str):
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise fail("CONFIGURATION_INVALID", "configuration string is not valid UTF-8") from exc
        if size > MAX_JSON_STRING_BYTES:
            _limit("configuration JSON string exceeds the byte limit")
    elif isinstance(value, dict):
        for key, child in value.items():
            _validate_json_value(key, depth + 1)
            _validate_json_value(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_value(child, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        _invalid("configuration JSON contains a non-finite number")
    elif value is not None and type(value) not in {bool, int, float}:
        _invalid("configuration JSON contains an unsupported value")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _invalid(f"{label} must be an object")
    return value


def _exact_keys(
    value: dict[str, Any], allowed: frozenset[str], required: frozenset[str], label: str
) -> None:
    if not required.issubset(value) or not set(value).issubset(allowed):
        _invalid(f"{label} keys do not match the accepted API request")


def _string(value: Any, label: str, *, maximum: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        _invalid(f"{label} must be a nonempty string")
    if maximum is not None and len(value.strip()) > maximum:
        _invalid(f"{label} exceeds its owning API limit")
    return value


def _optional_string(value: Any, label: str) -> None:
    if value is not None and not isinstance(value, str):
        _invalid(f"{label} must be a string or null")


def _validate_rule(payload: dict[str, Any], *, schema_version: int) -> dict[str, str]:
    optional = {"name", "description", "condition", "actions", "namespace", "suppression_window_ids"}
    if schema_version >= 2:
        optional.add("hook_action_names")
    if schema_version >= 4:
        optional.discard("suppression_window_ids")
        optional.add("suppression_window_names")
    _exact_keys(
        payload,
        frozenset(optional),
        frozenset({"name", "condition", "actions"}),
        "Rule",
    )
    name = _string(payload["name"], "Rule name", maximum=255)
    namespace = _string(payload.get("namespace", "default"), "Rule namespace", maximum=255)
    _string(payload["condition"], "Rule condition")
    _optional_string(payload.get("description"), "Rule description")
    actions = _object(payload["actions"], "Rule actions")
    _exact_keys(actions, frozenset({"suppress", "add_labels"}), frozenset(), "Rule actions")
    if "suppress" in actions and type(actions["suppress"]) is not bool:
        _invalid("Rule actions.suppress must be boolean")
    labels = actions.get("add_labels")
    if labels is not None and (
        not isinstance(labels, dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items())
    ):
        _invalid("Rule actions.add_labels must map strings to strings")
    suppression_ids = payload.get("suppression_window_ids", [])
    if not isinstance(suppression_ids, list) or any(not isinstance(item, str) for item in suppression_ids):
        _invalid("Rule suppression_window_ids must be a string list")
    if "suppression_window_names" in payload:
        names = payload["suppression_window_names"]
        if not isinstance(names, list) or any(not isinstance(item, str) or not _PORTABLE_NAME.fullmatch(item) for item in names):
            _invalid("Rule suppression_window_names must be a portable-name list")
        if len(names) != len(set(names)):
            _invalid("Rule suppression_window_names contains a duplicate reference")
    hook_names = payload.get("hook_action_names")
    if "hook_action_names" in payload:
        if not isinstance(hook_names, list) or any(
            not isinstance(item, str) or not item.strip() or len(item.strip()) > 255
            for item in hook_names
        ):
            _invalid("Rule hook_action_names must be a nonempty string list")
        if any(not _HOOK_NAME.fullmatch(item) for item in hook_names):
            _invalid("Rule hook_action_names contains an invalid Hook name")
        if len(hook_names) != len(set(hook_names)):
            _invalid("Rule hook_action_names contains a duplicate reference")
    return {"namespace": namespace.strip().lower(), "name": name.strip().casefold()}


def _portable_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _PORTABLE_NAME.fullmatch(value):
        _invalid(f"{label} must be a lowercase portable name")
    return value


def _parse_datetime(value: Any, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _invalid(f"{label} must be an ISO datetime string or null")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _invalid(f"{label} must be an ISO datetime string or null")


def _validate_suppression(payload: dict[str, Any]) -> dict[str, str]:
    allowed = frozenset({"name", "description", "suppression_type", "duration_seconds", "start_hour", "start_minute", "end_hour", "end_minute", "timezone", "is_recurring", "days_of_week", "valid_from", "valid_until", "datacenters", "environments", "servers", "components", "subcomponents"})
    _exact_keys(payload, allowed, frozenset({"name"}), "Suppression")
    name = _portable_name(payload["name"], "Suppression name")
    _optional_string(payload.get("description"), "Suppression description")
    suppression_type = payload.setdefault("suppression_type", "calendar")
    if suppression_type not in {"calendar", "timer"}:
        _invalid("Suppression type must be calendar or timer")
    for field, maximum in (("start_hour", 23), ("end_hour", 23), ("start_minute", 59), ("end_minute", 59)):
        if field in payload and payload[field] is not None:
            _bounded_integer(payload[field], f"Suppression {field}", 0, maximum)
    if suppression_type == "calendar":
        if any(payload.get(field) is None for field in ("start_hour", "start_minute", "end_hour", "end_minute")):
            _invalid("Calendar suppression requires start and end hour/minute")
        if "duration_seconds" in payload:
            _invalid("Calendar suppression does not accept duration_seconds")
    else:
        if type(payload.get("duration_seconds")) is not int or payload["duration_seconds"] <= 0:
            _invalid("Timer suppression requires positive duration_seconds")
        if any(field in payload for field in ("start_hour", "start_minute", "end_hour", "end_minute")):
            _invalid("Timer suppression does not accept calendar clock fields")
    timezone = payload.setdefault("timezone", "UTC")
    if not isinstance(timezone, str):
        _invalid("Suppression timezone must be a string")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        _invalid("Suppression timezone is unknown")
    recurring = payload.setdefault("is_recurring", True)
    if type(recurring) is not bool:
        _invalid("Suppression is_recurring must be boolean")
    days = payload.setdefault("days_of_week", "0,1,2,3,4,5,6")
    if not isinstance(days, str) or any(not day.isascii() or not day.isdecimal() or int(day) not in range(7) for day in days.split(",")):
        _invalid("Suppression days_of_week must be comma-separated numbers 0-6")
    start = _parse_datetime(payload.get("valid_from"), "Suppression valid_from")
    end = _parse_datetime(payload.get("valid_until"), "Suppression valid_until")
    if start is not None and end is not None:
        try:
            invalid_order = start >= end
        except TypeError:
            _invalid("Suppression validity datetimes must use compatible timezone forms")
        if invalid_order:
            _invalid("Suppression valid_from must precede valid_until")
    for field in ("datacenters", "environments", "servers", "components", "subcomponents"):
        value = payload.get(field)
        if value is not None and (not isinstance(value, list) or any(not isinstance(item, str) for item in value)):
            _invalid(f"Suppression {field} must be a string list or null")
    return {"name": name}


def _normalized_credential_key(key: str) -> str:
    return key.casefold().replace("-", "").replace("_", "")


def _inspect_credentials(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = _normalized_credential_key(key)
            if _CREDENTIAL_KEY.search(normalized):
                _invalid(f"Probe credential key is forbidden: {key}")
            _inspect_credentials(child)
    elif isinstance(value, list):
        for child in value:
            _inspect_credentials(child)


def normalize_probe_schedule(schedule):
    values = {key: child for key, child in schedule.items() if child is not None and child != ''}
    for key in ('year', 'month', 'day', 'week', 'day_of_week', 'hour', 'minute', 'second'):
        if key in values:
            values[key] = str(values[key])
            if len(values[key]) > 255:
                raise ValueError('Probe cron expression exceeds 255 characters')
    for key in ('start_date', 'end_date'):
        if values.get(key) and datetime.fromisoformat(str(values[key])).tzinfo is not None and not values.get('timezone'):
            raise ValueError('Timezone-aware probe bounds require schedule.timezone')
    if values.get('start_date') and values.get('end_date'):
        bounds = [datetime.fromisoformat(str(values[key])) for key in ('start_date', 'end_date')]
        if (bounds[0].tzinfo is None) != (bounds[1].tzinfo is None):
            raise ValueError('Probe date bounds must use compatible timezone forms')
    trigger = CronTrigger(timezone=values.get('timezone') or 'UTC', **{key: child for key, child in values.items() if key != 'timezone'})
    for key in ('start_date', 'end_date'):
        if key not in values:
            continue
        bound = getattr(trigger, key)
        if bound.microsecond:
            raise ValueError('Probe date bounds require whole-second precision')
        original = datetime.fromisoformat(str(values[key]))
        if original.tzinfo is None:
            # Preserve legacy wall values, including DST gaps interpreted by APScheduler.
            values[key] = original.isoformat()
            continue
        wall = bound.astimezone(trigger.timezone).replace(tzinfo=None, fold=0)
        if wall.replace(tzinfo=trigger.timezone).timestamp() != bound.timestamp():
            raise ValueError('Probe date bound cannot preserve this ambiguous timezone offset')
        values[key] = wall.isoformat()
    return values


def _validate_schedule(value: Any) -> None:
    schedule = _object(value, "Probe schedule")
    _exact_keys(schedule, _SCHEDULE_FIELDS, frozenset(), "Probe schedule")
    if schedule.get('jitter') is not None:
        _bounded_integer(schedule['jitter'], 'Probe schedule jitter', 0, 2_147_483_647)
    for key, child in schedule.items():
        if child is not None and (type(child) not in (str, int) or key in ('timezone', 'start_date', 'end_date') and not isinstance(child, str)):
            _invalid('Probe schedule field has invalid type')
    try:
        trigger = CronTrigger(**normalize_probe_schedule(schedule))
        if trigger.start_date and trigger.end_date and trigger.start_date >= trigger.end_date:
            _invalid('Probe schedule start_date must precede end_date')
    except (TypeError, ValueError, KeyError) as exc:
        _invalid(f'Probe schedule is invalid: {exc}')


def _validate_probe(payload: dict[str, Any]) -> dict[str, str]:
    allowed = frozenset({"name", "description", "type", "target", "port", "status", "task_type", "owner", "organization", "schedule", "kwargs", "metadata"})
    _exact_keys(payload, allowed, frozenset({"name", "type", "target"}), "Probe")
    for field in ('target', 'description'):
        if isinstance(payload.get(field), str) and len(payload[field]) > 255:
            _invalid('Probe field exceeds 255 characters')
    name = _portable_name(payload["name"], "Probe name")
    probe_type = _string(payload["type"], "Probe type")
    if probe_type not in {"httpurl", "tcpport", "tlsport", "api", "icmpping", "sslport", "sshport"}:
        _invalid("Probe type is unsupported")
    _optional_string(payload.get("description"), "Probe description")
    status = payload.setdefault("status", "disabled")
    if status != "disabled":
        _invalid("Portable probes must be disabled")
    target = _string(payload["target"], "Probe target")
    if any(char.isspace() for char in target):
        _invalid("Probe target must not contain whitespace")
    if probe_type in {"httpurl", "api"}:
        try:
            parsed = urlsplit(target)
            _ = parsed.port
        except ValueError:
            _invalid("HTTP/API probe target must be a valid absolute URL")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            _invalid("HTTP/API probe target must be an absolute HTTP(S) URL without userinfo")
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if _CREDENTIAL_KEY.search(_normalized_credential_key(key)):
                _invalid("Probe target contains a credential query parameter")
        if "port" in payload:
            _invalid("HTTP/API probes do not accept a separate port")
    else:
        if not _HOST.fullmatch(target) or "://" in target:
            _invalid("Probe target must be a hostname or IPv4 address")
        required_port = probe_type in {"tcpport", "tlsport"}
        if required_port and "port" not in payload:
            _invalid(f"{probe_type} probe requires a port")
        if probe_type == "sshport":
            payload.setdefault("port", 22)
        elif probe_type == "sslport":
            payload.setdefault("port", 443)
        if probe_type == "icmpping" and payload.get("port") is not None:
            _invalid("ICMP probes do not accept a separate port")
        if "port" in payload:
            _bounded_integer(payload["port"], "Probe port", 1, 65535)
    task_only = ("task_type", "owner", "organization", "schedule", "kwargs", "metadata")
    if probe_type not in {"api", "sslport"} and any(field in payload and payload[field] not in (None, {}, "") for field in task_only):
        _invalid("Exporter probes do not accept task fields")
    if probe_type in {"api", "sslport"}:
        for field, expected in (("task_type", "celery"), ("owner", "internal"), ("organization", "internal")):
            if field in payload and payload[field] != expected:
                _invalid(f"Probe {field} must use the fixed owner value")
        if payload.get("schedule") is not None:
            _validate_schedule(payload["schedule"])
        for field in ("kwargs", "metadata"):
            value = payload.setdefault(field, {})
            if not isinstance(value, dict) or any(not isinstance(key, str) or type(child) not in {str, bool, int, float} for key, child in value.items()):
                _invalid(f"Probe {field} must map strings to scalar values")
            if any(len(key) > 255 or field == 'kwargs' and len(str(child)) > 255 or field == 'metadata' and len(str(child).encode()) > 65535 for key, child in value.items()):
                _invalid('Probe task value exceeds database storage limit')
            _inspect_credentials(value)
        if {"template_name", "__webhook_endpoint__"}.intersection(payload["kwargs"]):
            _invalid("template_name and __webhook_endpoint__ are reserved for notification delivery")
        if "__endpoint__" in payload["kwargs"]:
            _invalid("Probe __endpoint__ is generated by the owner")
        headers = payload["kwargs"].get("__http_headers__")
        if headers is not None:
            if not isinstance(headers, str):
                _invalid("Probe __http_headers__ must be a JSON-object string")
            try:
                parsed_headers = _load_json(headers.encode())
            except (UnicodeEncodeError, PackError):
                _invalid("Probe __http_headers__ must be strict JSON")
            if not isinstance(parsed_headers, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in parsed_headers.items()):
                _invalid("Probe __http_headers__ must map strings to strings")
            for key in parsed_headers:
                if _normalized_credential_key(key) in _CREDENTIAL_HEADERS or _CREDENTIAL_KEY.search(_normalized_credential_key(key)):
                    _invalid(f"Probe credential header is forbidden: {key}")
        if "payload" in payload["kwargs"]:
            _invalid("Portable probes require metadata.payload instead of kwargs.payload")
        if "payload_type" in payload["metadata"]:
            _invalid("Probe payload_type belongs in kwargs")
        payload_type = payload["kwargs"].get("payload_type")
        if probe_type == "api" and payload_type is None:
            _invalid("API probe kwargs requires payload_type")
        body = payload["metadata"].get("payload")
        if "payload" in payload["metadata"] and not isinstance(body, str):
            _invalid("Probe payload must be a string")
        if payload_type == "json" and body:
            try:
                parsed_body = _load_json(body.encode())
            except (UnicodeEncodeError, PackError):
                _invalid("Probe JSON payload must be strict JSON before rendering")
            _inspect_credentials(parsed_body)
    return {"type": probe_type, "name": name}


def _bounded_integer(value: Any, label: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        _invalid(f"{label} is outside its owning API limit")


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _validate_hook_json(value: Any, *, reject_secret_keys: bool = False) -> None:
    _validate_json_value(value, 1)
    if isinstance(value, dict):
        for key, child in value.items():
            if reject_secret_keys and _HOOK_SECRET_KEY.search(key):
                _invalid(f"Hook static input key is forbidden: {key}")
            _validate_hook_json(child, reject_secret_keys=reject_secret_keys)
    elif isinstance(value, list):
        for child in value:
            _validate_hook_json(child, reject_secret_keys=reject_secret_keys)


def _validate_result_mapping(value: Any, *, ticket_lifecycle: bool) -> None:
    mapping = _object(value, "Hook result mapping")
    _exact_keys(
        mapping,
        frozenset({"source_pointer", "destination", "value_type", "required", "default"}),
        frozenset({"source_pointer", "destination", "value_type"}),
        "Hook result mapping",
    )
    pointer = mapping["source_pointer"]
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")) or re.search(r"~(?:[^01]|$)", pointer):
        _invalid("Hook source_pointer must be an RFC 6901 JSON Pointer")
    destination = mapping["destination"]
    match = _HOOK_DESTINATION.fullmatch(destination) if isinstance(destination, str) else None
    if match is None:
        _invalid("Hook destination must be an allowed structured path")
    key = match.group(2)
    if match.group(1) == "ticket.fields" and (not ticket_lifecycle or key not in _HOOK_TICKET_FIELDS):
        _invalid("Hook ticket destination is not allowed for this lifecycle")
    lowered = key.lower()
    if any(lowered == item or lowered.startswith(item + ".") for item in _HOOK_PROTECTED_DESTINATIONS):
        _invalid("Hook destination is protected")
    if not isinstance(mapping["value_type"], str) or mapping["value_type"] not in {"string", "integer", "number", "boolean", "json"}:
        _invalid("Hook result mapping value_type is invalid")
    if "required" in mapping and type(mapping["required"]) is not bool:
        _invalid("Hook result mapping required must be boolean")
    if "default" in mapping:
        _validate_hook_json(mapping["default"])


def _validate_hook(payload: dict[str, Any]) -> dict[str, str]:
    fields = frozenset({
        "name", "metric_slug", "description", "enabled", "lifecycle_point", "target_type",
        "target_name", "execution_mode", "timeout_seconds", "max_attempts",
        "retry_backoff_seconds", "on_failure", "run_when", "priority", "notifier_scope",
        "static_inputs", "result_mappings", "workflow_result", "rate_limit_per_minute",
    })
    required = frozenset({
        "name", "metric_slug", "lifecycle_point", "target_type", "target_name",
        "execution_mode", "timeout_seconds", "max_attempts", "retry_backoff_seconds",
    })
    _exact_keys(payload, fields, required, "Hook")
    name = _string(payload["name"], "Hook name")
    if len(name) > 255 or name != name.strip() or not _HOOK_NAME.fullmatch(name):
        _invalid("Hook name does not match the portable format")
    metric_slug = _string(payload["metric_slug"], "Hook metric_slug", maximum=64)
    if not _HOOK_METRIC_SLUG.fullmatch(metric_slug):
        _invalid("Hook metric_slug does not match the owning API format")
    _optional_string(payload.get("description"), "Hook description")
    if payload.get("enabled", False) is not False:
        _invalid("Pack Hooks must be disabled")
    lifecycle = payload["lifecycle_point"]
    if not isinstance(lifecycle, str) or lifecycle not in {"ticket.before", "ticket.after", "notifier.before", "notifier.after"}:
        _invalid("Hook lifecycle_point is invalid")
    target_type = payload["target_type"]
    if not isinstance(target_type, str) or target_type not in {"task", "workflow"}:
        _invalid("Hook target_type is invalid")
    target_name = _string(payload["target_name"], "Hook target_name", maximum=255)
    if not _HOOK_TARGET_NAME.fullmatch(target_name):
        _invalid("Hook target_name does not match the current target naming format")
    mode = payload["execution_mode"]
    if not isinstance(mode, str) or mode not in {"fire_and_forget", "result_required"}:
        _invalid("Hook execution_mode is invalid")
    _bounded_integer(payload["timeout_seconds"], "Hook timeout_seconds", 1, 900)
    _bounded_integer(payload["max_attempts"], "Hook max_attempts", 1, 5)
    _bounded_integer(payload["retry_backoff_seconds"], "Hook retry_backoff_seconds", 1, 300)
    on_failure = payload.get("on_failure", "continue")
    run_when = payload.get("run_when", "always")
    if not isinstance(on_failure, str) or not isinstance(run_when, str) or on_failure not in {"continue", "block_primary"} or run_when not in {"success", "failure", "always"}:
        _invalid("Hook failure or run policy is invalid")
    before = lifecycle.endswith(".before")
    if before and run_when != "always":
        _invalid("Hook before lifecycle requires run_when=always")
    if on_failure == "block_primary" and (not before or mode != "result_required"):
        _invalid("Hook block_primary requires a result-required before hook")
    _bounded_integer(payload.get("priority", 0), "Hook priority", 0, 10_000)
    scope = payload.get("notifier_scope", [])
    if not isinstance(scope, list) or any(
        not isinstance(item, str)
        or not _HOOK_NOTIFIER_TYPE.fullmatch(item)
        or _is_uuid(item)
        for item in scope
    ) or len(scope) != len(set(scope)):
        _invalid("Hook notifier_scope must contain unique stable notifier type selectors")
    static_inputs = payload.get("static_inputs", {})
    if not isinstance(static_inputs, dict):
        _invalid("Hook static_inputs must be an object")
    _validate_hook_json(static_inputs, reject_secret_keys=True)
    mappings = payload.get("result_mappings", [])
    if not isinstance(mappings, list) or len(mappings) > 50:
        _invalid("Hook result_mappings exceeds its owning API limit")
    for mapping in mappings:
        _validate_result_mapping(mapping, ticket_lifecycle=lifecycle.startswith("ticket."))
    if mode == "fire_and_forget" and mappings:
        _invalid("Hook fire-and-forget mode cannot define result mappings")
    workflow_result = payload.get("workflow_result")
    needs_workflow_result = target_type == "workflow" and mode == "result_required"
    if needs_workflow_result != (workflow_result is not None):
        _invalid("Hook workflow_result is required only for result-required workflows")
    if workflow_result is not None:
        row = _object(workflow_result, "Hook workflow_result")
        _exact_keys(row, frozenset({"output_task_id", "xcom_key"}), frozenset({"output_task_id", "xcom_key"}), "Hook workflow_result")
        for key in ("output_task_id", "xcom_key"):
            value = _string(row[key], f"Hook workflow_result {key}")
            if len(value) > 255:
                _invalid(f"Hook workflow_result {key} exceeds its owning API limit")
    rate = payload.get("rate_limit_per_minute")
    if rate is not None:
        _bounded_integer(rate, "Hook rate_limit_per_minute", 1, 2**31 - 1)
    expanded = {
        "description": None, "enabled": False, "on_failure": "continue",
        "run_when": "always", "priority": 0, "notifier_scope": [],
        "static_inputs": {}, "result_mappings": [], "workflow_result": None,
        "rate_limit_per_minute": None, **payload,
    }
    expanded["result_mappings"] = [
        {"required": True, **mapping}
        for mapping in expanded["result_mappings"]
    ]
    encoded = json.dumps(expanded, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    static_encoded = json.dumps(static_inputs, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 262_144 or len(static_encoded) > 262_144:
        _limit("Hook configuration exceeds runtime byte limit")
    return {"name": name}


def _validate_key_values(value: Any, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        _invalid(f"{label} must be an array or null")
    seen: set[str] = set()
    for item in value:
        row = _object(item, label)
        _exact_keys(row, frozenset({"key", "value"}), frozenset({"key", "value"}), label)
        key = _string(row["key"], f"{label} key")
        if label == "Mapping element" and isinstance(row["value"], str) and row["value"]:
            pass
        else:
            _string(row["value"], f"{label} value")
        if key in seen:
            _invalid(f"{label} contains a duplicate key")
        seen.add(key)


def _validate_mapping(payload: dict[str, Any]) -> dict[str, str]:
    _exact_keys(
        payload,
        frozenset({"name", "description", "mapping_namespace_name", "comment", "additional_ref", "element", "metadata"}),
        frozenset({"name", "mapping_namespace_name"}),
        "Mapping",
    )
    name = _string(payload["name"], "Mapping name", maximum=255)
    namespace = _string(payload["mapping_namespace_name"], "Mapping namespace", maximum=255)
    for key in ("description", "comment", "additional_ref"):
        _optional_string(payload.get(key), f"Mapping {key}")
    _validate_key_values(payload.get("element"), "Mapping element")
    _validate_key_values(payload.get("metadata"), "Mapping metadata")
    if namespace.strip().lower() == "webhook_profiles":
        _validate_webhook_profile(payload)
    return {"namespace": namespace.strip().lower(), "name": name.strip().lower()}


def _validate_webhook_profile(payload: dict[str, Any]) -> None:
    """Offline schema-v1 checks; shipped profiles also pass the real compiler in CI."""
    name_pattern = r"[a-z0-9][a-z0-9_-]{0,63}"
    semantic = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}"
    namespace_pattern = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"

    def check(valid: bool, message: str) -> None:
        if not valid:
            _invalid(f"Webhook profile: {message}")

    def target(value: str, *, output: bool = False, container: bool = False) -> None:
        roots = {"labels", "annotations"} if output else {"work", "labels", "annotations"}
        check(isinstance(value, str), "invalid target")
        root, _, suffix = value.partition(".")
        check(value in {"event_timestamp", "ends_at"} or container and value in roots
              or root in roots and bool(re.fullmatch(semantic, suffix)), "invalid target")

    def pointer(value: str) -> None:
        check(not value or value.startswith("/"), "invalid JSON Pointer")
        check(re.search(r"~(?![01])", value) is None, "invalid JSON Pointer escape")

    def source(value: str) -> str | None:
        root, colon, path = value.partition(":")
        check(bool(colon) and root in {"body", "header", "context", "field", "field_array", "literal"}, "invalid source root")
        if root == "body":
            pointer(path)
        elif root == "header":
            check(bool(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", path)), "invalid header")
        elif root == "context":
            check(bool(re.fullmatch(semantic, path)), "invalid context")
        elif root in {"field", "field_array"}:
            path, separator, nested = path.partition(":")
            target(path, container=True)
            if separator:
                pointer(nested)
            # Projections must distinguish a nested object from a root-container copy.
            return path + separator + nested
        return None

    def sources(value: str) -> list[str | None]:
        while value.startswith(("policy=", "root_case=")) and ";" in value:
            option, value = value.split(";", 1)
            key, setting = option.split("=", 1)
            check(setting in ({"present", "nonempty", "truthy"} if key == "policy" else {"sensitive", "insensitive"}), "invalid select option")
        result = [source(item) for item in value.split("||")]
        check(len(result) <= 8, "too many select sources")
        return result

    def options(value: str, required: set[str], optional: set[str]) -> dict[str, str]:
        # Source selector options contain one embedded semicolon in schema v1.
        parts = iter(value.split(";"))
        data: dict[str, str] = {}
        for part in parts:
            key, separator, item = part.partition("=")
            check(bool(separator) and key not in data, "invalid or duplicate operation option")
            if key == "source" and item.startswith(("policy=", "root_case=")):
                expression = next(parts, None)
                check(expression is not None, "incomplete source option")
                item += ";" + expression
            data[key] = item
        check(required <= data.keys() <= required | optional, "invalid operation options")
        return data

    def namespace(value: str) -> None:
        check(bool(re.fullmatch(namespace_pattern, value)) and value != "webhook_profiles" and value in declared,
              "undeclared or recursive Mapping namespace")

    def mapping_source(value: str) -> str | None:
        dependency = source(value)
        check(value.startswith(("literal:", "field:")), "invalid Mapping name source")
        if value.startswith("literal:"):
            check(bool(re.fullmatch(namespace_pattern, value[8:])), "invalid Mapping name")
        return dependency

    def document(value: str, required: set[str], optional: set[str]) -> dict[str, Any]:
        data = _object(_load_json(value.encode()), "Profile operation")
        check(required <= data.keys() <= required | optional, "invalid operation fields")
        return data

    def condition(value: str) -> None:
        check(isinstance(value, str) and 0 < len(value) <= 1024, "invalid condition")
        if value == "always":
            return
        for clause in re.split(r"&&|,", value):
            match = _CONDITION_OPERATOR.search(clause.strip())
            if match is None:
                target(clause.strip())
            else:
                target(clause[:match.start()].strip())
                operator, right = match.group(), clause[match.end():].strip()
                check(bool(right), "empty condition operand")
                if right.startswith("field:"):
                    check(operator in {"==", "!="}, "invalid field comparison")
                    target(right[6:])
                if operator in {"regex", "!regex"}:
                    re.compile(right)
                    check(not _has_unbounded_regex_quantifier(right), "unbounded condition regex")

    check(bool(re.fullmatch(name_pattern, payload["name"])), "invalid profile name")
    check(payload["name"] not in {"splunk", "middleware_custom_alert"}, "core identity is reserved")
    check(isinstance(payload.get("description", ""), str) and len(payload.get("description", "")) <= 16384, "invalid description")
    rows = payload.get("element")
    check(isinstance(rows, list) and len(rows) <= 128, "invalid element count")
    elements = {row["key"]: row["value"] for row in rows}
    check(all(len(key) <= 16384 and len(value) <= 16384 for key, value in elements.items()), "element exceeds string limit")
    check({"profile~schema_version", "profile~enabled", "profile~required"} <= elements.keys(), "missing required profile elements")
    check(elements["profile~schema_version"] == "1", "unsupported schema version")
    check(elements["profile~enabled"] in {"true", "false"}, "invalid enabled value")
    if "profile~items_pointer" in elements:
        pointer(elements["profile~items_pointer"])
        check(bool(re.fullmatch(r"/[A-Za-z_][A-Za-z0-9_]*", elements["profile~items_pointer"])), "items pointer must select a top-level array")
    required = [item.strip() for item in elements["profile~required"].split(",") if item.strip()]
    check(len(required) == len(set(required)), "duplicate required output")
    for item in required:
        target(item, output=True)
    declared = [item.strip() for item in elements.get("profile~mapping_namespaces", "").split(",") if item.strip()]
    check(len(declared) == len(set(declared)) and all(re.fullmatch(namespace_pattern, item) for item in declared), "invalid namespace declaration")
    ranks = {"select": 0, "normalize": 1, "parse_time": 2, "jsonselect": 3, "project_object": 4,
             "value_map": 5, "template": 6, "hash": 7, "lookup": 8, "apply_mapping": 9, "if": 10, "when": 10, "remove": 11, "keep": 12}
    operations = []
    filters = {"remove": [], "keep": []}
    apply_count = 0

    def operation(command: str, dest: str, value: str, key: str, order: int = 0, conditional: bool = False) -> None:
        nonlocal apply_count
        check(command in ranks and (not conditional or command not in {"if", "when", "lookup"}), "unknown command or conditional action")
        dependencies: list[str | None] = [None]
        exclusions = None
        if command in {"if", "when"}:
            check(bool(re.fullmatch(semantic, dest)), "invalid conditional stable key")
            data = document(value, {"order", "condition", "action"}, set())
            check(type(data["order"]) is int and 0 <= data["order"] <= 999999, "invalid conditional order")
            condition(data["condition"])
            action = _object(data["action"], "Conditional action")
            check(set(action) == {"command", "target", "value"} and all(isinstance(v, str) for v in action.values()), "invalid conditional action")
            operation(action["command"], action["target"], action["value"], key, data["order"], True)
            return
        if command in filters:
            check(not _has_unbounded_regex_quantifier(dest), f"unbounded {command} pattern")
            pattern = re.compile(dest, re.IGNORECASE)
            if not conditional:
                filters[command].append(pattern)
            return
        target(dest, container=command == "project_object")
        if command == "select":
            dependencies = sources(value)
        elif command == "normalize":
            normalizers = {"lowercase", "alphanumeric", "label_key", "is_object", "is_string", "present", "python_string", "json_object", "seconds", "capitalize"}
            if value.startswith("sha256_json;"):
                length = options(value[12:], {"length"}, set())["length"]
                check(length.isdigit() and 1 <= int(length) <= 64, "invalid digest length")
            else:
                check(value in normalizers, "unsupported normalizer")
            dependencies = [dest]
        elif command == "parse_time":
            expression, separator, fmt = value.rpartition("|")
            check(dest in {"event_timestamp", "ends_at"} and bool(separator) and fmt in {"epoch", "epoch_ms", "rfc3339", "iso8601_wall_clock"}, "invalid timestamp operation")
            check(expression.startswith(("body:", "field:", "context:")), "invalid timestamp source")
            dependencies = [source(expression)]
        elif command == "jsonselect":
            expression, separator, path = value.partition(":")
            check(bool(separator), "jsonselect requires a pointer")
            target(expression)
            pointer(path)
            dependencies = [expression]
        elif command == "project_object":
            data = options(value, {"source"}, {"exclude", "sanitize", "mode", "values", "key_order"})
            dependencies = sources(data["source"])
            check(len(dependencies) == 1 and bool(re.search(r"(?:^|;)(body|field):", data["source"])) and not data["source"].startswith(("policy=present;", "policy=truthy;")), "invalid projection source")
            raw_exclusions = [item.strip() for item in data.get("exclude", "").split(",") if item.strip()]
            check(len(raw_exclusions) <= 64 and all(len(item) <= 253 for item in raw_exclusions), "invalid projection exclusions")
            exclusions = set(raw_exclusions)
            sanitizer = data.get("sanitize", "none")
            check(sanitizer in {"none", "label_key", "lowercase", "alphanumeric"} and (sanitizer != "label_key" or dest == "labels"), "invalid projection sanitizer")
            check(data.get("mode", "merge") in {"merge", "replace"} and data.get("values", "native") in {"native", "python_string"} and data.get("key_order", "sorted") in {"sorted", "input"}, "invalid projection option")
        elif command == "value_map":
            data = document(value, {"source", "values"}, {"default", "match"})
            target(data["source"])
            values = data["values"]
            check(isinstance(values, dict) and 0 < len(values) <= 64 and all(not isinstance(v, (dict, list)) for v in values.values()), "invalid value map")
            check(not isinstance(data.get("default"), (dict, list)) and data.get("match", "exact") in {"exact", "token"}, "invalid value map option")
            dependencies = [data["source"]]
        elif command == "template":
            check(len(value) <= 4096 and "{%" not in value and "%}" not in value, "invalid template")
            tokens = re.findall(r"{{([^{}]+)}}", value)
            for token in tokens:
                target(token)
            remainder = re.sub(r"{{[^{}]+}}", "", value)
            check("{{" not in remainder and "}}" not in remainder and len(tokens) <= 32, "invalid template tokens")
            segments = re.findall(r"\[\[(.*?)]]", value, re.DOTALL)
            remainder = re.sub(r"\[\[.*?]]", "", value, flags=re.DOTALL)
            check(len(segments) <= 16 and all("[[" not in part for part in segments) and "[[" not in remainder and "]]" not in remainder, "invalid optional template segment")
        elif command == "hash":
            check(dest.startswith("labels."), "hash target must be a label")
            fields = [item.strip() for item in value.split(",")]
            check(1 <= len(fields) <= 32 and len(set(fields)) == len(fields), "invalid hash fields")
            for field in fields:
                check(field.startswith("labels.") and field != dest, "invalid hash source")
                target(field, output=True)
        elif command == "lookup":
            identity, separator, expression = value.partition(":")
            mapping, at, ns = identity.partition("@")
            check(bool(separator and at) and bool(re.fullmatch(namespace_pattern, mapping)), "invalid lookup")
            namespace(ns)
            expression, separator, extra = expression.partition(";")
            if separator:
                check(options(extra, {"key_normalizer"}, set())["key_normalizer"] == "alphanumeric", "invalid lookup normalizer")
            dependencies = [mapping_source(expression)]
        elif command == "apply_mapping":
            apply_count += 1
            data = options(value, {"namespace", "name"}, {"input", "depth", "metadata", "add_mode", "replace_mode", "merge_template", "cut_capture", "lookup_namespace"})
            namespace(data["namespace"])
            if "lookup_namespace" in data:
                namespace(data["lookup_namespace"])
            mapping_source(data["name"])
            for option, allowed in {"depth": {"1"}, "metadata": {"omit", "include"}, "add_mode": {"template_insensitive", "literal_exact"}, "replace_mode": {"source_suffix", "rename"}, "merge_template": {"source_keys", "rendered"}, "cut_capture": {"triple_colon", "colon"}}.items():
                check(option not in data or data[option] in allowed, "invalid apply_mapping option")
            dependency = data.get("input", dest)
            target(dependency)
            dependencies = [dependency]
        operations.append((10 if conditional else ranks[command], order, key, dest, dependencies, exclusions))

    try:
        for key, value in elements.items():
            command, separator, dest = key.partition("~")
            if command == "profile":
                check(dest in {"schema_version", "enabled", "required", "mapping_namespaces", "items_pointer"}, "unknown profile element")
                continue
            check(bool(separator), "missing command delimiter")
            operation(command, dest, value, key)
        check(apply_count <= 1, "apply_mapping limit")
        possible: set[str] = set()
        projections: list[tuple[str, set[str]]] = []

        def exists(path: str | None) -> bool:
            if path is not None:
                path = path.partition(":")[0]
            return path is None or path in possible or any(
                path.startswith(root + ".") and path[len(root) + 1:].split(".", 1)[0] not in excluded
                for root, excluded in projections
            ) or path in {"work", "labels", "annotations"} and (
                any(item.startswith(path + ".") for item in possible) or any(root == path for root, _ in projections)
            )

        for _, _, _, dest, dependencies, exclusions in sorted(operations):
            if not any(exists(dependency) for dependency in dependencies):
                continue
            if exclusions is not None and dest in {"work", "labels", "annotations"}:
                dependency = dependencies[0]
                if dependency in {"work", "labels", "annotations"}:
                    for item in tuple(possible):
                        if item.startswith(dependency + ".") and item[len(dependency) + 1:] not in exclusions:
                            possible.add(dest + item[len(dependency):])
                    projections.extend((dest, excluded | exclusions) for root, excluded in tuple(projections) if root == dependency)
                else:
                    projections.append((dest, exclusions))
            else:
                possible.add(dest)
        for item in required:
            check(exists(item) and not any(pattern.search(item) for pattern in filters["remove"])
                  and (not filters["keep"] or any(pattern.search(item) for pattern in filters["keep"])), "required output cannot be produced")
    except (ValueError, TypeError, re.error) as exc:
        _invalid(f"Webhook profile: invalid operation grammar ({type(exc).__name__})")


def _contains_dangerous_condition(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            key in {"$where", "$function", "$accumulator"}
            or _contains_dangerous_condition(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_dangerous_condition(child) for child in value)
    return False


def _validate_permission(value: Any) -> None:
    permission = _object(value, "Role permission")
    _exact_keys(
        permission,
        frozenset({"action", "subject", "conditions", "fields", "inverted", "reason"}),
        frozenset({"action", "subject"}),
        "Role permission",
    )
    _string(permission["action"], "Role permission action")
    _string(permission["subject"], "Role permission subject")
    conditions = permission.get("conditions")
    if conditions is not None and not isinstance(conditions, dict):
        _invalid("Role permission conditions must be an object or null")
    if _contains_dangerous_condition(conditions):
        _invalid("Role permission conditions contain a forbidden operator")
    fields = permission.get("fields")
    if fields is not None and (
        not isinstance(fields, list) or any(not isinstance(field, str) for field in fields)
    ):
        _invalid("Role permission fields must be a string list or null")
    if "inverted" in permission and type(permission["inverted"]) is not bool:
        _invalid("Role permission inverted must be boolean")
    _optional_string(permission.get("reason"), "Role permission reason")


def _validate_role(payload: dict[str, Any]) -> dict[str, str]:
    _exact_keys(
        payload,
        frozenset({"name", "description", "permissions", "is_system", "is_active"}),
        frozenset({"name", "permissions"}),
        "Role",
    )
    name = _string(payload["name"], "Role name", maximum=64)
    canonical_name = name.strip().casefold()
    if len(canonical_name) < 3 or not _ROLE_NAME.fullmatch(canonical_name):
        _invalid("Role name does not match the owning API format")
    if canonical_name in _RESERVED_ROLES:
        _invalid("Role name is reserved")
    _optional_string(payload.get("description"), "Role description")
    if payload.get("is_system", False) is not False:
        _invalid("Pack roles cannot be system roles")
    if "is_active" in payload and type(payload["is_active"]) is not bool:
        _invalid("Role is_active must be boolean")
    permissions = payload["permissions"]
    if not isinstance(permissions, list):
        _invalid("Role permissions must be an array")
    if payload.get("is_active", True) and not permissions:
        _invalid("Active roles require at least one permission")
    for permission in permissions:
        _validate_permission(permission)
    return {"name": canonical_name}


def _validate_dashboard(payload: dict[str, Any]) -> dict[str, str]:
    _exact_keys(
        payload,
        frozenset({"dashboard", "folderUid", "message", "overwrite"}),
        frozenset({"dashboard"}),
        "Dashboard request",
    )
    if payload.get("overwrite", False) is not False:
        _invalid("Dashboard source overwrite must be absent or false")
    _optional_string(payload.get("folderUid"), "Dashboard folderUid")
    _optional_string(payload.get("message"), "Dashboard message")
    dashboard = _object(payload["dashboard"], "Dashboard")
    uid = _string(dashboard.get("uid"), "Dashboard uid", maximum=40)
    typed_fields = {
        "title": str,
        "panels": list,
        "tags": list,
        "templating": dict,
        "schemaVersion": int,
        "version": int,
        "editable": bool,
    }
    for key, expected_type in typed_fields.items():
        if key in dashboard and type(dashboard[key]) is not expected_type:
            _invalid(f"Dashboard {key} has the wrong type")
    if "tags" in dashboard and any(not isinstance(tag, str) for tag in dashboard["tags"]):
        _invalid("Dashboard tags must be strings")
    return {"uid": uid}


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def parse_configuration_files(
    files: Mapping[str, bytes],
    schema_version: int = 1,
) -> tuple[ConfigurationArtifact, ...]:
    if type(schema_version) is not int or schema_version not in {1, 2, 3, 4, 5, 6, 7}:
        _invalid("configuration schema_version must equal 1, 2, 3, 4, 5, 6 or 7")
    artifacts: list[ConfigurationArtifact] = []
    identities: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    validators = {
        "rules": ("rule", lambda payload: _validate_rule(payload, schema_version=schema_version)),
        "mappings": ("mapping", _validate_mapping),
        "roles": ("role", _validate_role),
        "dashboards": ("dashboard", _validate_dashboard),
    }
    if schema_version >= 2:
        validators["hooks"] = ("hook", _validate_hook)
    if schema_version >= 4:
        validators["suppressions"] = ("suppression", _validate_suppression)
        validators["probes"] = ("probe", _validate_probe)

    for raw_path in sorted(files, key=canonical_path_key):
        path = validate_member_path(raw_path)
        parts = path.parts
        if parts[0] != "conf":
            continue
        if len(parts) >= 2 and parts[1] == "triggers":
            # Trigger definitions are YAML validated by project_pack.triggers (schema 5).
            if schema_version < 5:
                _invalid("Trigger definitions require schema_version 5")
            continue
        if len(parts) < 3 or parts[1] not in _CONFIGURATION_ROOTS:
            _invalid("configuration path is outside the fixed conf layout")
        if parts[1] == "hooks" and schema_version < 2:
            _invalid("Hook configuration requires schema_version 2 or later")
        if parts[1] in {"suppressions", "probes"} and schema_version < 4:
            _invalid("Suppression and probe configuration requires schema_version 4")
        if path.suffix != ".json":
            _invalid("configuration files must use the .json extension")
        data = files[raw_path]
        if not isinstance(data, bytes):
            _invalid("configuration file content must be bytes")
        document = _load_json(data)
        artifact_type, validator = validators[parts[1]]
        payloads = [document] if artifact_type == "dashboard" else document
        if not isinstance(payloads, list):
            _invalid(f"{parts[1]} configuration must be a JSON array")
        for ordinal, value in enumerate(payloads):
            payload = _object(value, artifact_type)
            identity = validator(payload)
            identity_key = (artifact_type, tuple(sorted(identity.items())))
            if identity_key in identities:
                raise fail(
                    "CONFIGURATION_DUPLICATE",
                    "configuration contains duplicate canonical artifact identities",
                )
            identities.add(identity_key)
            artifacts.append(
                ConfigurationArtifact(
                    artifact_type=artifact_type,
                    identity=_freeze(identity),
                    source_path=raw_path,
                    source_ordinal=ordinal,
                    payload=_freeze(payload),
                )
            )
            if len(artifacts) > MAX_ARTIFACTS:
                _limit("configuration exceeds the artifact-count limit")
    hook_names = {artifact.identity["name"] for artifact in artifacts if artifact.artifact_type == "hook"}
    suppression_names = {artifact.identity["name"] for artifact in artifacts if artifact.artifact_type == "suppression"}
    metric_slugs: set[str] = set()
    for artifact in artifacts:
        if artifact.artifact_type == "hook":
            slug = str(artifact.payload["metric_slug"])
            if slug in metric_slugs:
                raise fail("CONFIGURATION_DUPLICATE", "configuration contains duplicate Hook metric_slug values")
            metric_slugs.add(slug)
        elif artifact.artifact_type == "rule" and "hook_action_names" in artifact.payload:
            missing = set(artifact.payload["hook_action_names"]) - hook_names
            if missing:
                _invalid("Rule hook_action_names references a Hook not defined in this pack")
        if artifact.artifact_type == "rule" and "suppression_window_names" in artifact.payload:
            missing = set(artifact.payload["suppression_window_names"]) - suppression_names
            if missing:
                _invalid("Rule suppression_window_names references a window not defined in this pack")
    return tuple(artifacts)
