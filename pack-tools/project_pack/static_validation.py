"""Side-effect-free static validation for materialized project-pack content."""

from __future__ import annotations

import ast
import hashlib
import io
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from jinja2 import nodes
from jinja2.exceptions import TemplateSyntaxError
from jinja2.sandbox import SandboxedEnvironment
import yaml

from project_pack.catalog import (
    ENTRY_MAX_BYTES, PACK_MAX_BYTES, PACK_MAX_ENTRIES, normalized_size,
    parse_catalog_document, parse_function_catalog,
)
from project_pack.configuration import parse_configuration_files
from project_pack.errors import PackError, fail
from project_pack.model import (
    PACK_ID_PATTERN,
    TASK_REFERENCE_PATTERN,
    WORKFLOW_SCHEMA_VERSION,
    PackManifest,
    _load_strict_yaml,
    workflow_module_name,
)
from project_pack.paths import MAX_MEMBER_PATH_BYTES
from project_pack.triggers import (
    TriggerValidationError,
    parse_trigger_yaml,
    trigger_inventory,
    validate_trigger_bundle,
    validate_trigger_sources,
)
from project_pack.template_rules import (
    STEM_PATTERN,
    parse_reference,
    validate_reference_budget,
)
from project_pack.tables import parse_create_table


_JOB_TYPES = frozenset({"fabric", "invoke", "script", "ansible", "celery"})
_JOB_STATUSES = frozenset({"enabled", "disabled", "0", "1"})
_SCRIPT_EXTENSIONS = frozenset({".py", ".sh", ".groovy"})
_AMBIGUOUS_PACK_IMPORTS = frozenset({"helper", "utils", "logging_setup"})
_AMBIGUOUS_SCRIPT_IMPORTS = frozenset({"helper", "logging_setup"})
_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_LOCAL_ANSIBLE_KEYS = frozenset(
    {"include_tasks", "import_tasks", "vars_files", "template", "copy"}
)
_FORBIDDEN_TEMPLATE_NODES = (
    nodes.Extends,
    nodes.Include,
    nodes.Import,
    nodes.FromImport,
)
_TEMPLATE_CHANNELS = frozenset(
    {"email", "slack", "discord", "forwarder", "logger", "admin"}
)
_SINGLE_BODY_TEMPLATE_CHANNELS = frozenset(
    {"slack", "discord", "forwarder", "logger"}
)
_DUAL_BODY_TEMPLATE_CHANNELS = frozenset({"email", "admin"})
_TEMPLATE_STRING_FIELD_LIMITS: dict[str, int | None] = {
    "name": None,
    "display_name": 200,
    "description": 500,
    "format": 20,
    "target": 50,
    "notes": None,
    "sample": None,
}


@dataclass(frozen=True, order=True)
class Issue:
    path: str
    code: str
    message: str


@dataclass(frozen=True)
class ValidationReport:
    pack_id: str
    pack_version: str
    transport_verified: bool
    files_checked: int
    expanded_bytes: int
    warnings: tuple[Issue, ...]


class StaticValidationError(PackError):
    """A deterministic collection of static content validation failures."""

    def __init__(self, issues: Iterable[Issue]) -> None:
        self.issues = tuple(sorted(issues))
        super().__init__(
            "CONTENT_INVALID",
            f"static validation found {len(self.issues)} issue(s)",
        )


def _issue(issues: list[Issue], path: str, code: str, message: str) -> None:
    issues.append(Issue(path=path, code=code, message=message))


def _safe_file(root: Path, relative: str, issues: list[Issue]) -> Path | None:
    candidate = root / relative
    try:
        mode = candidate.lstat().st_mode
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _issue(issues, relative, "CONTENT_PATH", "file is missing or escaped the pack root")
        return None
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        _issue(issues, relative, "CONTENT_PATH", "content must be a regular non-link file")
        return None
    return resolved


def _read_and_verify(
    root: Path, manifest: PackManifest, issues: list[Issue]
) -> dict[str, bytes]:
    content: dict[str, bytes] = {}
    for relative, record in manifest.files.items():
        candidate = _safe_file(root, relative, issues)
        if candidate is None:
            continue
        try:
            data = candidate.read_bytes()
        except OSError:
            _issue(issues, relative, "CONTENT_PATH", "content file could not be read")
            continue
        if len(data) != record.size:
            _issue(issues, relative, "SIZE_MISMATCH", "staged file size changed")
            continue
        if hashlib.sha256(data).hexdigest() != record.sha256:
            _issue(issues, relative, "HASH_MISMATCH", "staged file hash changed")
            continue
        content[relative] = data
    return content


def _strict_yaml(data: bytes, path: str, issues: list[Issue]) -> Any | None:
    try:
        return _load_strict_yaml(data)
    except (PackError, yaml.YAMLError, UnicodeError, RecursionError):
        _issue(issues, path, "YAML_INVALID", "YAML must be safe and unambiguous")
        return None


def _contains_key(value: Any, forbidden: str) -> bool:
    if isinstance(value, dict):
        return forbidden in value or any(
            _contains_key(child, forbidden) for child in value.values()
        )
    if isinstance(value, list):
        return any(_contains_key(child, forbidden) for child in value)
    return False


def _python_tree(
    data: bytes,
    path: str,
    ambiguous_imports: frozenset[str],
    issues: list[Issue],
) -> ast.Module | None:
    try:
        tree = ast.parse(data.decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeDecodeError):
        _issue(issues, path, "PYTHON_SYNTAX", "Python source is not valid syntax")
        return None

    importlib_aliases: set[str] = set()
    import_module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            importlib_aliases.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "importlib"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            import_module_aliases.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "import_module"
            )

    relative_reported = False
    ambiguous_reported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level and not relative_reported:
            _issue(
                issues,
                path,
                "PYTHON_RELATIVE_IMPORT",
                "pack Python must not use relative imports",
            )
            relative_reported = True
        imported_modules = (
            (alias.name for alias in node.names)
            if isinstance(node, ast.Import)
            else (node.module,)
            if isinstance(node, ast.ImportFrom) and node.module
            else ()
        )
        dynamic_module = None
        if (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "__import__",
                *import_module_aliases,
            }:
                dynamic_module = node.args[0].value
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in importlib_aliases
            ):
                dynamic_module = node.args[0].value
        if dynamic_module and dynamic_module.startswith(".") and not relative_reported:
            _issue(
                issues,
                path,
                "PYTHON_RELATIVE_IMPORT",
                "pack Python must not use relative imports",
            )
            relative_reported = True
        if not ambiguous_reported and any(
            module.split(".", 1)[0] in ambiguous_imports
            for module in (*imported_modules, *((dynamic_module,) if dynamic_module else ()))
        ):
            _issue(
                issues,
                path,
                "PYTHON_AMBIGUOUS_IMPORT",
                "pack Python must qualify ambiguous helper imports",
            )
            ambiguous_reported = True
    return tree


def _python_inventory(
    content: dict[str, bytes], issues: list[Issue]
) -> tuple[set[str], set[str]]:
    task_functions: set[str] = set()
    fabric_functions: set[str] = set()
    for relative, data in content.items():
        parts = relative.split("/")
        if len(parts) != 2 or parts[0] not in {"tasks", "fabfile"}:
            continue
        if not relative.endswith(".py"):
            _issue(issues, relative, "PYTHON_EXTENSION", "task modules must end in .py")
            continue
        if parts[1] == "__init__.py":
            _issue(
                issues,
                relative,
                "PYTHON_INIT_FORBIDDEN",
                "pack task roots must not contain __init__.py",
            )
            continue
        tree = _python_tree(data, relative, _AMBIGUOUS_PACK_IMPORTS, issues)
        if tree is None:
            continue
        module = Path(parts[1]).stem
        inventory = fabric_functions if parts[0] == "fabfile" else task_functions
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inventory.add(f"{module}:{node.name}")
    return task_functions, fabric_functions


def _script_packages(content: dict[str, bytes]) -> set[str]:
    """Directories under ``scripts/`` that are real Python packages.

    A package is recognised ONLY by its ``__init__.py``. That keeps the rule
    mechanical: a stray subdirectory is still rejected, while a script that has
    grown past one file can ship its modules alongside it.
    """
    packages: set[str] = set()
    for relative in content:
        parts = relative.split("/")
        if (
            len(parts) == 3
            and parts[0] == "scripts"
            and parts[2] == "__init__.py"
            and _SEGMENT.fullmatch(parts[1])
        ):
            packages.add(parts[1])
    return packages


def _script_inventory(content: dict[str, bytes], issues: list[Issue]) -> set[str]:
    by_name: dict[str, list[str]] = {}
    packages = _script_packages(content)
    for relative, data in content.items():
        parts = relative.split("/")
        if parts[0] != "scripts":
            continue
        # A SUPPORTING PACKAGE beside the entry scripts. Permitted for scripts
        # and NOT for tasks/fabfile (see PYTHON_INIT_FORBIDDEN above): a task
        # module is imported into a shared interpreter, where a package can
        # shadow a platform module, while a script is executed as its own
        # subprocess with sys.path[0] set to its own directory. The import
        # guard below still applies, so a package still cannot be named after
        # an ambiguous platform module.
        if len(parts) == 3 and parts[1] in packages:
            if not parts[2].endswith(".py"):
                _issue(
                    issues,
                    relative,
                    "SCRIPT_PACKAGE_CONTENT",
                    "script packages may contain only .py modules",
                )
                continue
            if parts[1] in _AMBIGUOUS_SCRIPT_IMPORTS:
                _issue(
                    issues,
                    relative,
                    "SCRIPT_PACKAGE_AMBIGUOUS",
                    f"script package {parts[1]} shadows a platform module",
                )
                continue
            _python_tree(data, relative, _AMBIGUOUS_SCRIPT_IMPORTS, issues)
            # Deliberately NOT added to by_name: a package module is support
            # code, never a job's script reference.
            continue
        if len(parts) != 2 or Path(parts[1]).suffix not in _SCRIPT_EXTENSIONS:
            _issue(
                issues,
                relative,
                "SCRIPT_EXTENSION",
                "scripts must be direct .py, .sh, or .groovy files, "
                "or .py modules inside a package directory with an __init__.py",
            )
            continue
        if Path(parts[1]).suffix == ".py":
            _python_tree(data, relative, _AMBIGUOUS_SCRIPT_IMPORTS, issues)
        logical_name = Path(parts[1]).stem
        by_name.setdefault(logical_name, []).append(relative)
    for logical_name, paths in by_name.items():
        if len(paths) > 1:
            for path in paths:
                _issue(
                    issues,
                    path,
                    "SCRIPT_AMBIGUOUS",
                    f"script logical name {logical_name} has multiple extensions",
                )
    return set(by_name)


def _task_base(reference: str) -> str:
    return ":".join(reference.split(":")[:2])


def _validate_script_job(
    reference: str,
    path: str,
    pack_id: str,
    local_scripts: set[str],
    issues: list[Issue],
) -> None:
    parts = reference.split(":")
    if len(parts) < 2 or any(not _SEGMENT.fullmatch(part) for part in parts):
        _issue(
            issues,
            path,
            "SCRIPT_NAMESPACE",
            "script names require namespace, script, and optional discriminator segments",
        )
        return
    namespace, script = parts[:2]
    if namespace == pack_id:
        if script not in local_scripts:
            _issue(issues, path, "SCRIPT_MISSING", "pack-local script does not exist")
    elif namespace == "common":
        return
    else:
        _issue(
            issues,
            path,
            "SCRIPT_NAMESPACE",
            "script namespace must select common or the candidate pack",
        )


def _validate_ansible_job(
    row: dict[str, Any],
    path: str,
    pack_id: str,
    playbooks: set[str],
    issues: list[Issue],
) -> None:
    kwargs = row.get("kwargs")
    reference = kwargs.get("playbook_name") if isinstance(kwargs, dict) else None
    if not isinstance(reference, str):
        _issue(issues, path, "PLAYBOOK_MISSING", "ansible job requires playbook_name")
        return
    parts = reference.split(":")
    if len(parts) == 1 and _SEGMENT.fullmatch(parts[0]):
        return
    if len(parts) != 2 or any(not _SEGMENT.fullmatch(part) for part in parts):
        _issue(issues, path, "PLAYBOOK_NAMESPACE", "playbook reference is invalid")
        return
    namespace, playbook = parts
    if namespace != pack_id:
        _issue(
            issues,
            path,
            "ANSIBLE_CROSS_PACK",
            "playbook reference selects a different pack",
        )
    elif playbook not in playbooks:
        _issue(issues, path, "PLAYBOOK_MISSING", "pack-local playbook does not exist")


def _validate_jobs(
    content: dict[str, bytes],
    task_functions: set[str],
    fabric_functions: set[str],
    local_scripts: set[str],
    playbooks: set[str],
    manifest: PackManifest,
    issues: list[Issue],
) -> None:
    required = {"name", "status", "owner", "organization"}
    for relative, data in content.items():
        if not relative.startswith("jobs/"):
            continue
        if len(relative.split("/")) != 2 or Path(relative).suffix not in {".yml", ".yaml"}:
            _issue(issues, relative, "JOB_SCHEMA", "jobs must be direct YAML files")
            continue
        document = _strict_yaml(data, relative, issues)
        if document is None:
            continue
        if not isinstance(document, list):
            _issue(issues, relative, "JOB_SCHEMA", "job file must contain a list")
            continue
        for index, row in enumerate(document):
            row_path = f"{relative}#{index}"
            if not isinstance(row, dict):
                _issue(issues, row_path, "JOB_SCHEMA", "job row must be a mapping")
                continue
            if _contains_key(row, "source_pack"):
                _issue(
                    issues,
                    row_path,
                    "SOURCE_PACK_FORBIDDEN",
                    "pack-owned YAML must not define source_pack",
                )
            if not required.issubset(row) or any(
                not isinstance(row.get(key), str) for key in required
            ):
                _issue(issues, row_path, "JOB_SCHEMA", "job row is missing required strings")
            status = row.get("status")
            task_type = row.get("type", "celery")
            if status not in _JOB_STATUSES or task_type not in _JOB_TYPES:
                _issue(issues, row_path, "JOB_SCHEMA", "job status or type is invalid")
            name = row.get("name")
            if not isinstance(name, str) or not TASK_REFERENCE_PATTERN.fullmatch(name):
                _issue(issues, row_path, "TASK_REFERENCE", "job name is not canonical")
                continue
            base = _task_base(name)
            if task_type == "invoke" and base not in task_functions:
                if base not in manifest.requires_tasks_common:
                    _issue(issues, row_path, "TASK_MISSING", "invoke task does not exist")
            elif task_type == "fabric" and base not in fabric_functions:
                if base not in manifest.requires_tasks_common:
                    _issue(issues, row_path, "TASK_MISSING", "fabric task does not exist")
            elif task_type == "script":
                _validate_script_job(
                    name,
                    row_path,
                    manifest.id,
                    local_scripts,
                    issues,
                )
            elif task_type == "ansible":
                _validate_ansible_job(
                    row,
                    row_path,
                    manifest.id,
                    playbooks,
                    issues,
                )


def _iter_key_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _iter_key_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_key_values(child)


def _reference_strings(key: str, value: Any) -> Iterable[str]:
    if key == "vars_files" and isinstance(value, list):
        yield from (item for item in value if isinstance(item, str))
    elif key in {"include_tasks", "import_tasks"} and isinstance(value, str):
        yield value
    elif key in {"template", "copy"} and isinstance(value, dict):
        source = value.get("src")
        if isinstance(source, str):
            yield source


def _validate_playbooks(
    root: Path, content: dict[str, bytes], issues: list[Issue]
) -> set[str]:
    playbooks: set[str] = set()
    ansible_root = (root / "ansible").resolve(strict=False)
    listed = set(content)
    for relative, data in content.items():
        parts = relative.split("/")
        if parts[:2] != ["ansible", "playbooks"] or len(parts) != 3:
            continue
        if Path(parts[-1]).suffix not in {".yml", ".yaml"}:
            _issue(issues, relative, "PLAYBOOK_SCHEMA", "playbook must be YAML")
            continue
        playbooks.add(Path(parts[-1]).stem)
        document = _strict_yaml(data, relative, issues)
        if document is None:
            continue
        for key, value in _iter_key_values(document):
            if key not in _LOCAL_ANSIBLE_KEYS:
                continue
            for reference in _reference_strings(key, value):
                if "{{" in reference or "://" in reference:
                    continue
                candidate = (root / relative).parent / reference
                try:
                    resolved = candidate.resolve(strict=False)
                    resolved.relative_to(ansible_root)
                    listed_path = resolved.relative_to(root).as_posix()
                except (OSError, ValueError):
                    _issue(
                        issues,
                        relative,
                        "ANSIBLE_CROSS_PACK",
                        "Ansible reference escapes the candidate pack",
                    )
                    continue
                if listed_path not in listed:
                    _issue(
                        issues,
                        relative,
                        "ANSIBLE_REFERENCE_MISSING",
                        "referenced local Ansible file is not listed in the pack",
                    )
    return playbooks


def _validate_rules(content: dict[str, bytes], issues: list[Issue]) -> None:
    group_owners: dict[str, str] = {}
    for relative, data in content.items():
        if not relative.startswith("rules/"):
            continue
        document = _strict_yaml(data, relative, issues)
        if document is None:
            continue
        groups = document.get("groups") if isinstance(document, dict) else None
        if not isinstance(groups, list):
            _issue(issues, relative, "RULE_SCHEMA", "rule file requires a groups list")
            continue
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("name"), str):
                _issue(issues, relative, "RULE_SCHEMA", "rule group requires a name")
                continue
            if not isinstance(group.get("rules"), list):
                _issue(issues, relative, "RULE_SCHEMA", "rule group requires a rules list")
            name = group["name"]
            if name in group_owners:
                _issue(
                    issues,
                    relative,
                    "RULE_GROUP_DUPLICATE",
                    f"rule group {name} is also declared by {group_owners[name]}",
                )
            else:
                group_owners[name] = relative


def _template_location(relative: str) -> tuple[str, str] | None:
    """Return the catalog location and stem for one permitted template path."""

    parts = relative.split("/")
    suffix = Path(relative).suffix
    if len(parts) == 2 and suffix in {".j2", ".yml", ".yaml"}:
        return "single", Path(parts[-1]).stem
    if (
        len(parts) == 4
        and parts[1:3] == ["email", "html"]
        and suffix in {".j2", ".yml", ".yaml"}
    ):
        return "email_html", Path(parts[-1]).stem
    if (
        len(parts) == 4
        and parts[1:3] == ["email", "text"]
        and suffix == ".j2"
    ):
        return "email_text", Path(parts[-1]).stem
    return None


def _validate_templates(
    pack_id: str, content: dict[str, bytes], issues: list[Issue]
) -> None:
    """Validate pack template layout, identity, syntax, and capabilities."""

    environment = SandboxedEnvironment()
    environment.globals.clear()
    bodies: set[tuple[str, str]] = set()
    sidecars: list[tuple[str, str, str]] = []

    for relative, data in sorted(content.items()):
        if not relative.startswith("templates/"):
            continue

        location = _template_location(relative)
        if location is None:
            _issue(
                issues,
                relative,
                "TEMPLATE_PATH",
                "template path is not a permitted layout",
            )
            continue
        kind, stem = location
        if len(relative.encode("utf-8")) > MAX_MEMBER_PATH_BYTES:
            _issue(
                issues,
                relative,
                "TEMPLATE_BUDGET",
                f"template archive path exceeds {MAX_MEMBER_PATH_BYTES} UTF-8 bytes",
            )
        if not STEM_PATTERN.fullmatch(stem) or ".." in stem:
            _issue(
                issues,
                relative,
                "TEMPLATE_PATH",
                "template name is not a valid stem",
            )
            continue

        try:
            parse_reference(f"{pack_id}:{stem}")
        except PackError as error:
            _issue(issues, relative, "TEMPLATE_PATH", error.message)
            continue

        try:
            validate_reference_budget(pack_id, stem)
        except PackError as error:
            _issue(issues, relative, "TEMPLATE_BUDGET", error.message)

        if Path(relative).suffix in {".yml", ".yaml"}:
            sidecars.append((kind, stem, relative))
            continue

        identity = (kind, stem)
        if identity in bodies:
            _issue(
                issues,
                relative,
                "TEMPLATE_PATH",
                "template logical identity is duplicated",
            )
        bodies.add(identity)

        try:
            parsed = environment.parse(data.decode("utf-8"))
        except (UnicodeDecodeError, TemplateSyntaxError):
            _issue(
                issues,
                relative,
                "TEMPLATE_SYNTAX",
                "template does not parse",
            )
            continue
        if any(parsed.find_all(_FORBIDDEN_TEMPLATE_NODES)):
            _issue(
                issues,
                relative,
                "TEMPLATE_CAPABILITY",
                "pack templates may not extend, include, or import",
            )

    html = {stem for kind, stem in bodies if kind == "email_html"}
    text = {stem for kind, stem in bodies if kind == "email_text"}
    single = {stem for kind, stem in bodies if kind == "single"}
    for stem in sorted(html ^ text):
        side = "text" if stem in html else "html"
        _issue(
            issues,
            f"templates/email/{side}/{stem}.j2",
            "TEMPLATE_PAIR",
            "an email template requires both html and text bodies",
        )
    for stem in sorted(single & (html | text)):
        _issue(
            issues,
            f"templates/{stem}.j2",
            "TEMPLATE_PATH",
            "single-body and email templates may not share a logical identity",
        )

    seen_sidecars: set[tuple[str, str]] = set()
    for kind, stem, relative in sidecars:
        issue_count = len(issues)
        metadata = _strict_yaml(content[relative], relative, issues)
        yaml_invalid = len(issues) > issue_count
        if not yaml_invalid and not isinstance(metadata, dict):
            _issue(
                issues,
                relative,
                "TEMPLATE_METADATA",
                "template metadata must be a mapping",
            )
        elif isinstance(metadata, dict):
            for field, limit in _TEMPLATE_STRING_FIELD_LIMITS.items():
                if field not in metadata:
                    continue
                value = metadata[field]
                if not isinstance(value, str):
                    _issue(
                        issues,
                        relative,
                        "TEMPLATE_METADATA",
                        f"template metadata {field} must be a string",
                    )
                else:
                    try:
                        value.encode("utf-8")
                    except UnicodeEncodeError:
                        _issue(
                            issues,
                            relative,
                            "TEMPLATE_METADATA",
                            f"template metadata {field} is not valid UTF-8",
                        )
                        continue
                if isinstance(value, str) and limit is not None and len(value) > limit:
                    _issue(
                        issues,
                        relative,
                        "TEMPLATE_METADATA",
                        f"template metadata {field} exceeds {limit} characters",
                    )
            channels = metadata.get("channels", [])
            if not isinstance(channels, list) or any(
                not isinstance(channel, str) or channel not in _TEMPLATE_CHANNELS
                for channel in channels
            ):
                _issue(
                    issues,
                    relative,
                    "TEMPLATE_METADATA",
                    "template metadata channels must be a list of supported channels",
                )
            elif kind == "single" and not set(channels).issubset(
                _SINGLE_BODY_TEMPLATE_CHANNELS
            ):
                _issue(
                    issues,
                    relative,
                    "TEMPLATE_METADATA",
                    "direct templates support only single-body channels",
                )
            elif kind == "email_html" and not set(channels).issubset(
                _DUAL_BODY_TEMPLATE_CHANNELS
            ):
                _issue(
                    issues,
                    relative,
                    "TEMPLATE_METADATA",
                    "paired email templates support only email and admin channels",
                )
        sidecar_identity = (kind, stem)
        if sidecar_identity in seen_sidecars:
            _issue(
                issues,
                relative,
                "TEMPLATE_PATH",
                "template metadata is duplicated",
            )
        seen_sidecars.add(sidecar_identity)
        if sidecar_identity not in bodies:
            _issue(
                issues,
                relative,
                "TEMPLATE_PATH",
                "template metadata has no matching body",
            )


def _catalog_declarations(content: dict[str, bytes], runner: str) -> set[str]:
    """Qualify declarations syntactically; never execute decorators or imports."""
    prefix = 'fabfile/' if runner == 'fabric' else 'tasks/'
    declared = set()
    for path, data in content.items():
        if not path.startswith(prefix) or len(path.split('/')) != 2 or not path.endswith('.py'):
            continue
        try:
            tree = ast.parse(data)
        except (SyntaxError, UnicodeError, ValueError):
            continue  # The ordinary Python validator reports syntax errors.
        task_names = {'task'}
        module_names = {runner}
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.module in {runner, f'{runner}.tasks'}:
                task_names.update(alias.asname or alias.name for alias in statement.names if alias.name == 'task')
            elif isinstance(statement, ast.Import):
                module_names.update(alias.asname or alias.name for alias in statement.names if alias.name == runner)
        for index, node in enumerate(tree.body):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith('_'):
                continue
            decorators = [item.func if isinstance(item, ast.Call) else item for item in node.decorator_list]
            if decorators and not any(
                (isinstance(item, ast.Name) and item.id in task_names) or
                (isinstance(item, ast.Attribute) and item.attr == 'task' and
                 isinstance(item.value, ast.Name) and item.value.id in module_names)
                for item in decorators
            ):
                continue
            if any(node.name in _module_bound_names(later) for later in tree.body[index + 1:]):
                continue
            declared.add(f'{Path(path).stem}:{node.name}')
    return declared


def _module_bound_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Lambda):
        return set()
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {item.asname or item.name.split('.')[0] for item in node.names}
    names = {node.id} if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) else set()
    for child in ast.iter_child_nodes(node):
        names.update(_module_bound_names(child))
    return names


def _validate_catalog(content: dict[str, bytes], manifest: PackManifest, issues: list[Issue]) -> None:
    entries = []
    configured_names = set()
    formatted_names = set()
    for path, data in content.items():
        if not path.startswith('jobs/'):
            continue
        rows = _strict_yaml(data, path, issues)
        if not isinstance(rows, list):
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            row_path = f'{path}#{index}'
            name = row.get('name')
            if manifest.schema_version >= 3 and isinstance(name, str):
                formatted = 'tm.' + name.replace(':', '.')
                if (':' not in name or len(formatted) > 255 or formatted == 'tm.tasks.common' or
                        name.casefold() in configured_names or formatted.casefold() in formatted_names):
                    _issue(issues, row_path, 'TASK_REFERENCE', 'configured/formatted job identity is invalid or duplicated')
                configured_names.add(name.casefold())
                formatted_names.add(formatted.casefold())
            if manifest.schema_version < 3 and 'catalog' not in row:
                continue
            try:
                document = parse_catalog_document(row.get('catalog'), description=row.get('description'))
                entries.append({'name': name, 'type': row.get('type', 'celery'), 'kind': 'job', **document})
            except PackError as exc:
                _issue(issues, row_path, exc.code, exc.message)
    functions = []
    if 'catalog/functions.yml' in content:
        try:
            functions = parse_function_catalog(content['catalog/functions.yml'])
        except PackError as exc:
            _issue(issues, 'catalog/functions.yml', exc.code, exc.message)
    if manifest.schema_version < 3:
        return
    inventories = {
        'invoke': _catalog_declarations(content, 'invoke'),
        'fabric': _catalog_declarations(content, 'fabric'),
        'script': {f'{manifest.id}:{Path(path).stem}' for path in content if path.startswith('scripts/')},
        'ansible': {f'{manifest.id}:{Path(path).stem}' for path in content if path.startswith('ansible/playbooks/')},
    }
    documented = set()
    for row in functions:
        identity = (row['type'], row['name'])
        documented.add(identity)
        if row['name'] not in inventories[row['type']]:
            _issue(issues, 'catalog/functions.yml', 'CATALOG_REFERENCE', 'documented capability is not a supported local declaration')
        entries.append({'name': row['name'], 'type': row['type'], 'kind': 'function',
                        'description': row['description'], **row['catalog']})
    for reference in manifest.requires_tasks_local:
        matched = [runner for runner in ('invoke', 'fabric') if reference in inventories[runner]]
        if not matched or any((runner, reference) not in documented for runner in matched):
            _issue(issues, 'catalog/functions.yml', 'CATALOG_REFERENCE', 'required local capability lacks supported documentation')
    if len(entries) > PACK_MAX_ENTRIES or sum(normalized_size(row) for row in entries) > PACK_MAX_BYTES:
        _issue(issues, 'catalog', 'CATALOG_LIMIT', 'pack catalog exceeds entry count or normalized byte limit')
    if any(normalized_size(row) > ENTRY_MAX_BYTES for row in entries):
        _issue(issues, 'catalog', 'CATALOG_LIMIT', 'normalized catalog entry exceeds byte limit')


def _validate_triggers(content: dict[str, bytes], manifest: PackManifest, issues: list[Issue]) -> None:
    """Schema 5: parse every definition and verify each callable's complete bounded bundle.

    Nothing is imported or executed. The whole ``triggers/`` tree is one bundle (spec §7),
    so source no definition references must still compile within the bundle limits.
    """

    if manifest.schema_version < 5:
        return
    inventory = trigger_inventory(manifest.files)
    sources: dict[str, str] = {}
    for path in inventory["modules"]:
        if path not in content:
            continue  # already reported by verification
        try:
            sources[path] = content[path].decode("utf-8")
        except UnicodeDecodeError:
            _issue(issues, path, "TRIGGER_INVALID", "trigger source must be UTF-8")
    bundle_valid = True
    if sources:
        try:
            validate_trigger_sources(sources)
        except TriggerValidationError as error:
            bundle_valid = False
            _issue(issues, "triggers", error.code, error.message)
    names: dict[str, str] = {}
    for path in inventory["definitions"]:
        if path not in content:
            continue
        try:
            definition = parse_trigger_yaml(content[path], pack_id=manifest.id)
        except TriggerValidationError as error:
            _issue(issues, path, error.code, error.message)
            continue
        if definition["name"] in names:
            _issue(issues, path, "TRIGGER_DUPLICATE", f"trigger name is also defined in {names[definition['name']]}")
            continue
        names[definition["name"]] = path
        reference = definition["run"].get("function")
        if reference is None or not bundle_valid:
            continue
        try:
            validate_trigger_bundle(sources, reference)
        except TriggerValidationError as error:
            _issue(issues, path, error.code, error.message)


_DAG_DECLARERS = frozenset({"DAG", "dag"})


def _is_airflow_or_importlib(module: str) -> bool:
    return module in {"airflow", "importlib"} or module.startswith(("airflow.", "importlib."))


def _rebound_names(tree: ast.Module) -> frozenset[str]:
    """Names also bound by a def, class, argument or a non-Airflow/importlib import.

    Plain assignments are deliberately not counted: ``dag = my_dag()`` is a common TaskFlow
    idiom and must not switch the DAG-id check off (review r3 FABLE-PW-202).
    """

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".")[0]
                         for alias in node.names if not _is_airflow_or_importlib(alias.name))
        elif isinstance(node, ast.ImportFrom) and not (
            node.level == 0 and node.module and _is_airflow_or_importlib(node.module)
        ):
            names.update(alias.asname or alias.name for alias in node.names)
    return frozenset(names)


def _workflow_bindings(tree: ast.Module) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    """Return (DAG declarers, airflow module names, import_module names, importlib module names)."""

    declarers: set[str] = set()
    modules: set[str] = set()
    import_module_names: set[str] = {"__import__"}
    importlib_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "airflow" or alias.name.startswith("airflow."):
                    modules.add(alias.asname or alias.name.split(".")[0])
                elif alias.name == "importlib":
                    importlib_modules.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module == "airflow" or node.module.startswith("airflow."):
                for alias in node.names:
                    (declarers if alias.name in _DAG_DECLARERS else modules).add(alias.asname or alias.name)
            elif node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_module_names.add(alias.asname or alias.name)
    rebound = _rebound_names(tree)
    return (
        frozenset(declarers - rebound),
        frozenset(modules - rebound),
        frozenset(import_module_names - rebound),
        frozenset(importlib_modules - rebound),
    )


def _rooted_at(node: ast.Attribute, names: frozenset[str]) -> bool:
    root = node.value
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id in names


def _is_declarer(node: ast.AST, declarers: frozenset[str], modules: frozenset[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in declarers
    if isinstance(node, ast.Attribute) and node.attr in _DAG_DECLARERS:
        return _rooted_at(node, modules)
    return False


def _literal_dag_id(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "dag_id":
            value = keyword.value
            return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


def _imported_modules(
    node: ast.AST, import_module_names: frozenset[str], importlib_modules: frozenset[str]
) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        return [node.module]
    if not isinstance(node, ast.Call) or not node.args:
        return []
    function = node.func
    dynamic = (isinstance(function, ast.Name) and function.id in import_module_names) or (
        isinstance(function, ast.Attribute)
        and function.attr == "import_module"
        and _rooted_at(function, importlib_modules)
    )
    first = node.args[0]
    if dynamic and isinstance(first, ast.Constant) and isinstance(first.value, str):
        return [first.value]
    return []


def _references_airflow_plugin(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "AirflowPlugin"
    if isinstance(node, ast.Attribute):
        return node.attr == "AirflowPlugin"
    if isinstance(node, ast.ImportFrom):
        return any(alias.name == "AirflowPlugin" for alias in node.names)
    return False


def _validate_workflow(content: dict[str, bytes], manifest: PackManifest, issues: list[Issue]) -> None:
    """Schema 6: statically check workflow sources (spec §4.3). Nothing is imported."""

    if manifest.schema_version < WORKFLOW_SCHEMA_VERSION:
        return
    own_module = workflow_module_name(manifest.id)
    dag_prefix = f"{manifest.id}."
    for relative in sorted(content, key=str.encode):
        if not relative.startswith("workflow/"):
            continue
        dag_file = relative.startswith("workflow/dags/")
        if dag_file and zipfile.is_zipfile(io.BytesIO(content[relative])):
            _issue(issues, relative, "WORKFLOW_ZIP_UNSUPPORTED",
                   "Airflow loads every archive under workflow/dags as a zipped DAG; put data archives under workflow/lib")
            continue
        if not relative.endswith(".py"):
            continue
        try:
            tree = ast.parse(content[relative].decode("utf-8"), filename=relative)
        except (SyntaxError, UnicodeDecodeError, ValueError, RecursionError, MemoryError):
            _issue(issues, relative, "WORKFLOW_PYTHON", "workflow Python must be UTF-8 and valid syntax")
            continue
        declarers, modules, import_module_names, importlib_modules = _workflow_bindings(tree)
        plugin_reported = False
        for node in ast.walk(tree):
            if not plugin_reported and _references_airflow_plugin(node):
                _issue(issues, relative, "WORKFLOW_PLUGIN_UNSUPPORTED",
                       "AirflowPlugin is not supported in project packs")
                plugin_reported = True
            for module in _imported_modules(node, import_module_names, importlib_modules):
                top = module.split(".")[0]
                if top.startswith("pack_") and top != own_module:
                    _issue(issues, relative, "WORKFLOW_FOREIGN_PACK_IMPORT",
                           f"workflow code may import only its own pack module {own_module}")
            if not dag_file:
                continue
            if isinstance(node, ast.ImportFrom) and node.level > 0:
                _issue(issues, relative, "WORKFLOW_DAG_RELATIVE_IMPORT",
                       f"DAG files load as top-level modules; import pack code as {own_module}.lib...")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for decorator in node.decorator_list:
                    if not isinstance(decorator, ast.Call) and _is_declarer(decorator, declarers, modules):
                        _issue(issues, relative, "WORKFLOW_DAG_ID",
                               f"@dag needs a literal dag_id starting with {dag_prefix!r}")
            if isinstance(node, ast.Call) and _is_declarer(node.func, declarers, modules):
                dag_id = _literal_dag_id(node)
                if dag_id is None or not dag_id.startswith(dag_prefix) or dag_id == dag_prefix:
                    _issue(issues, relative, "WORKFLOW_DAG_ID",
                           f"DAG declarations need a literal dag_id starting with {dag_prefix!r}")


def validate_pack_content(
    pack_root: Path,
    manifest: PackManifest,
    *,
    transport_verified: bool,
) -> ValidationReport:
    """Validate one staged candidate using only its bytes and manifest declarations."""

    try:
        root = pack_root.resolve(strict=True)
    except OSError as exc:
        raise fail("CONTENT_PATH", "candidate pack root is unavailable") from exc
    if root.name != manifest.id or not PACK_ID_PATTERN.fullmatch(root.name):
        raise fail("CONTENT_PATH", "candidate directory does not match the manifest id")
    issues: list[Issue] = []
    content = _read_and_verify(root, manifest, issues)
    task_functions, fabric_functions = _python_inventory(content, issues)
    local_scripts = _script_inventory(content, issues)
    playbooks = _validate_playbooks(root, content, issues)
    _validate_jobs(
        content,
        task_functions,
        fabric_functions,
        local_scripts,
        playbooks,
        manifest,
        issues,
    )
    _validate_catalog(content, manifest, issues)
    _validate_rules(content, issues)
    _validate_templates(manifest.id, content, issues)
    _validate_triggers(content, manifest, issues)
    _validate_workflow(content, manifest, issues)
    for relative, data in content.items():
        if relative.startswith("tables/"):
            try:
                parse_create_table(data.decode("utf-8"), expected_name=Path(relative).stem)
            except (PackError, UnicodeError) as error:
                _issue(issues, relative, "TABLE_SQL_INVALID", "table SQL must be one supported CREATE TABLE statement")
    try:
        parse_configuration_files(content, schema_version=manifest.schema_version)
    except PackError as error:
        _issue(issues, "conf", error.code, error.message)

    local_tasks = task_functions | fabric_functions
    for reference in manifest.requires_tasks_local:
        if reference not in local_tasks:
            _issue(
                issues,
                "pack.yml",
                "LOCAL_TASK_MISSING",
                f"required local task {reference} is unavailable",
            )

    if issues:
        raise StaticValidationError(issues)
    return ValidationReport(
        pack_id=manifest.id,
        pack_version=manifest.version,
        transport_verified=transport_verified,
        files_checked=manifest.archive_file_count,
        expanded_bytes=manifest.archive_expanded_bytes,
        warnings=(),
    )
