"""Bounded project-pack archive inspection and safe staging materialization."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from project_pack.errors import PackError, fail
from project_pack.model import (
    MANIFEST_MAX_BYTES,
    PackManifest,
    compute_contents,
    parse_pack_manifest,
    parse_pack_source,
)
from project_pack.paths import (
    MAX_MEMBER_PATH_BYTES,
    canonical_path_key,
    validate_member_path,
)
from project_pack.static_validation import (
    ValidationReport,
    validate_pack_content,
)


MAX_MEMBERS = 10_000
MAX_MANIFEST_BYTES = MANIFEST_MAX_BYTES
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = MAX_MEMBER_PATH_BYTES
_CHUNK_SIZE = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIDECAR = re.compile(r"^([0-9a-f]{64})(?:  ([^\r\n]+))?\r?\n?$")
_ACCEPTED_TYPES = frozenset({tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE})


@dataclass(frozen=True)
class InspectedFile:
    archive_name: str
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ArchiveInspection:
    archive: Path
    archive_sha256: str
    manifest: PackManifest
    manifest_file: InspectedFile
    payloads: tuple[InspectedFile, ...]


@dataclass(frozen=True)
class TransportVerification:
    archive_sha256: str
    transport_verified: bool
    verification_source: str | None


@dataclass(frozen=True)
class PackResult:
    archive: Path
    sidecar: Path
    sha256: str
    inspection: ArchiveInspection
    validation_report: ValidationReport


@dataclass(frozen=True)
class _ObservedFile:
    archive_name: str
    parts: tuple[str, ...]
    size: int
    sha256: str
    data: bytes | None = None


@dataclass(frozen=True)
class _SourceFile:
    path: Path
    relative_path: str
    size: int
    sha256: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(_CHUNK_SIZE):
                digest.update(chunk)
    except OSError as exc:
        raise fail("ARCHIVE_FORMAT", "archive cannot be read") from exc
    return digest.hexdigest()


def _resolve_archive(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise OSError("archive is not a regular file")
        return resolved
    except OSError as exc:
        raise fail("ARCHIVE_FORMAT", "archive is unavailable") from exc


def _validate_gzip_profile(path: Path) -> None:
    try:
        with path.open("rb") as source:
            header = source.read(10)
    except OSError as exc:
        raise fail("ARCHIVE_FORMAT", "archive cannot be read") from exc
    if (
        len(header) != 10
        or header[:3] != b"\x1f\x8b\x08"
        or header[3] != 0
        or header[4:8] != b"\x00\x00\x00\x00"
        or header[8] != 2
        or header[9] != 255
    ):
        raise fail("ARCHIVE_PROFILE", "gzip metadata is not canonical schema v1")


def _validate_tar_profile(member: tarfile.TarInfo) -> None:
    expected_mode = 0o755 if member.isdir() else 0o644
    if (
        member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mtime != 0
        or member.mode & 0o7777 != expected_mode
        or set(member.pax_headers) - {"path"}
    ):
        raise fail("ARCHIVE_PROFILE", "tar member metadata is not canonical schema v1")


def _read_member(
    tar: tarfile.TarFile, member: tarfile.TarInfo, *, retain: bool
) -> tuple[int, str, bytes | None]:
    if member.size < 0 or member.size > MAX_FILE_BYTES:
        raise fail("ARCHIVE_LIMIT", "regular member exceeds the schema-v1 size limit")
    extracted = tar.extractfile(member)
    if extracted is None:
        raise fail("ARCHIVE_FORMAT", "regular member has no readable content")

    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if retain else None
    actual_size = 0
    while chunk := extracted.read(min(_CHUNK_SIZE, MAX_FILE_BYTES + 1 - actual_size)):
        actual_size += len(chunk)
        if actual_size > MAX_FILE_BYTES:
            raise fail("ARCHIVE_LIMIT", "regular member exceeds the schema-v1 size limit")
        digest.update(chunk)
        if chunks is not None:
            chunks.append(chunk)
    if actual_size != member.size:
        raise fail("ARCHIVE_FORMAT", "regular member is truncated")
    return actual_size, digest.hexdigest(), b"".join(chunks) if chunks is not None else None


def _has_prefix_collision(
    name: str, is_directory: bool, known: dict[str, bool]
) -> bool:
    segments = name.split("/")
    for index in range(1, len(segments)):
        parent = "/".join(segments[:index])
        if parent in known and not known[parent]:
            return True
    if not is_directory:
        prefix = f"{name}/"
        return any(existing.startswith(prefix) for existing in known)
    return False


def _validate_archive_name(raw_name: str) -> tuple[str, ...]:
    path = validate_member_path(raw_name.rstrip("/"))
    if any(part.startswith(".") for part in path.parts):
        raise fail("PATH_INVALID", "archive member uses an unexpected dot path")
    return path.parts


def inspect_archive(archive: Path) -> ArchiveInspection:
    """Inspect one gzip-compressed tar sequentially without creating filesystem paths."""

    archive = _resolve_archive(archive)
    _validate_gzip_profile(archive)
    archive_digest = _sha256_file(archive)
    known: dict[str, bool] = {}
    roots: set[str] = set()
    observed: list[_ObservedFile] = []
    manifest_candidates: list[_ObservedFile] = []
    expanded_bytes = 0
    member_count = 0
    previous_name: bytes | None = None

    try:
        with tarfile.open(archive, mode="r|gz") as tar:
            for member in tar:
                member_count += 1
                if member_count > MAX_MEMBERS:
                    raise fail("ARCHIVE_LIMIT", "archive exceeds the member limit")

                parts = _validate_archive_name(member.name)
                name = "/".join(parts)
                if name in known:
                    raise fail("ARCHIVE_DUPLICATE", "archive contains a duplicate member")
                if member.type not in _ACCEPTED_TYPES or getattr(member, "sparse", None):
                    raise fail("ARCHIVE_TYPE", "archive contains an unsupported member type")
                is_directory = member.isdir()
                if _has_prefix_collision(name, is_directory, known):
                    raise fail("ARCHIVE_PREFIX", "archive contains a file/path prefix collision")
                encoded_name = name.encode("utf-8")
                if previous_name is not None and encoded_name < previous_name:
                    raise fail("ARCHIVE_PROFILE", "tar members are not canonically ordered")
                previous_name = encoded_name
                _validate_tar_profile(member)
                known[name] = is_directory
                roots.add(parts[0])
                if len(roots) > 1:
                    raise fail("ARCHIVE_ROOT", "archive contains more than one top-level root")

                if is_directory:
                    continue
                if member.size > MAX_FILE_BYTES:
                    raise fail(
                        "ARCHIVE_LIMIT", "regular member exceeds the schema-v1 size limit"
                    )
                is_manifest = len(parts) == 2 and parts[1] == "pack.yml"
                if is_manifest and member.size > MAX_MANIFEST_BYTES:
                    raise fail("MANIFEST_LIMIT", "pack.yml exceeds the schema-v1 limit")

                actual_size, sha256, data = _read_member(
                    tar, member, retain=is_manifest
                )
                expanded_bytes += actual_size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise fail("ARCHIVE_LIMIT", "archive exceeds the expanded-byte limit")
                item = _ObservedFile(
                    archive_name=name,
                    parts=parts,
                    size=actual_size,
                    sha256=sha256,
                    data=data,
                )
                observed.append(item)
                if is_manifest:
                    manifest_candidates.append(item)
    except PackError:
        raise
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise fail("ARCHIVE_FORMAT", "archive stream is invalid or truncated") from exc

    if not manifest_candidates:
        raise fail("MANIFEST_MISSING", "archive does not contain a root pack.yml")
    if len(manifest_candidates) != 1:
        raise fail("MANIFEST_DUPLICATE", "archive contains more than one pack.yml")
    manifest_item = manifest_candidates[0]
    if manifest_item.data is None:
        raise fail("ARCHIVE_FORMAT", "pack.yml content was not retained")
    manifest = parse_pack_manifest(manifest_item.data)
    if roots != {manifest.id} or manifest_item.parts[0] != manifest.id:
        raise fail("ARCHIVE_ROOT", "archive root does not equal the manifest pack id")

    payload_by_path: dict[str, _ObservedFile] = {}
    for item in observed:
        if item is manifest_item:
            continue
        if item.parts[0] != manifest.id or len(item.parts) < 2:
            raise fail("ARCHIVE_ROOT", "archive payload is outside the pack root")
        relative = "/".join(item.parts[1:])
        validate_member_path(relative)
        if relative in payload_by_path:
            raise fail("ARCHIVE_DUPLICATE", "archive contains a duplicate payload")
        payload_by_path[relative] = item

    expected_paths = set(manifest.files)
    observed_paths = set(payload_by_path)
    if observed_paths - expected_paths:
        raise fail("UNLISTED_FILE", "archive contains an unlisted payload file")
    if expected_paths - observed_paths:
        raise fail("MISSING_FILE", "archive is missing a listed payload file")

    payloads: list[InspectedFile] = []
    for relative in manifest.files:
        item = payload_by_path[relative]
        record = manifest.files[relative]
        if item.size != record.size:
            raise fail("SIZE_MISMATCH", "payload size does not match pack.yml")
        if item.sha256 != record.sha256:
            raise fail("HASH_MISMATCH", "payload hash does not match pack.yml")
        payloads.append(
            InspectedFile(
                archive_name=item.archive_name,
                relative_path=relative,
                size=item.size,
                sha256=item.sha256,
            )
        )

    if sum(item.size for item in payloads) != manifest.archive_expanded_bytes:
        raise fail("SIZE_MISMATCH", "observed expanded bytes do not match pack.yml")

    return ArchiveInspection(
        archive=archive,
        archive_sha256=archive_digest,
        manifest=manifest,
        manifest_file=InspectedFile(
            archive_name=manifest_item.archive_name,
            relative_path="pack.yml",
            size=manifest_item.size,
            sha256=manifest_item.sha256,
        ),
        payloads=tuple(payloads),
    )


def _read_sidecar(sidecar: Path, archive: Path) -> str:
    try:
        raw = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise fail("TRANSPORT_DIGEST", "digest sidecar cannot be read") from exc
    if len(raw) > 4096:
        raise fail("TRANSPORT_DIGEST", "digest sidecar is invalid")
    match = _SIDECAR.fullmatch(raw)
    if not match:
        raise fail("TRANSPORT_DIGEST", "digest sidecar is invalid")
    digest, filename = match.groups()
    if filename is not None and filename != archive.name:
        raise fail("TRANSPORT_DIGEST", "digest sidecar names a different archive")
    return digest


def verify_transport_digest(
    archive: Path,
    sidecar: Path | None,
    expected_sha256: str | None,
    content_only: bool,
) -> TransportVerification:
    """Verify transport integrity, or explicitly label a content-only inspection."""

    archive = _resolve_archive(archive)
    actual = _sha256_file(archive)
    if content_only:
        if sidecar is not None or expected_sha256 is not None:
            raise fail(
                "TRANSPORT_MODE", "content-only cannot be combined with digest inputs"
            )
        return TransportVerification(
            archive_sha256=actual,
            transport_verified=False,
            verification_source=None,
        )

    if sidecar is None and expected_sha256 is None:
        raise fail("TRANSPORT_REQUIRED", "transport digest verification is required")
    if expected_sha256 is not None and not _SHA256.fullmatch(expected_sha256):
        raise fail("TRANSPORT_DIGEST", "expected digest must be lowercase SHA-256")
    sidecar_digest = _read_sidecar(sidecar, archive) if sidecar is not None else None
    if (
        sidecar_digest is not None
        and expected_sha256 is not None
        and sidecar_digest != expected_sha256
    ):
        raise fail("TRANSPORT_DIGEST", "digest inputs disagree")
    trusted = expected_sha256 or sidecar_digest
    if trusted != actual:
        raise fail("TRANSPORT_DIGEST", "archive transport digest does not match")
    source = "sidecar+expected" if sidecar_digest and expected_sha256 else (
        "sidecar" if sidecar_digest else "expected"
    )
    return TransportVerification(
        archive_sha256=actual,
        transport_verified=True,
        verification_source=source,
    )


def _before_file_open(destination: Path) -> None:
    """Test seam immediately before the containment recheck and exclusive open."""


def _write_all(file_descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(file_descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _assert_contained(path: Path, operation_root: Path) -> None:
    try:
        path.resolve(strict=False).relative_to(operation_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise fail("STAGING_RACE", "staging destination escaped its operation root") from exc


def _ensure_private_parents(destination: Path, operation_root: Path) -> None:
    relative_parent = destination.parent.relative_to(operation_root)
    current = operation_root
    for segment in relative_parent.parts:
        current = current / segment
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            pass
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise fail("STAGING_RACE", "staging parent changed during creation") from exc
        if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            raise fail("STAGING_RACE", "staging parent is not a real directory")
        _assert_contained(current, operation_root)


def _open_exclusive(destination: Path, operation_root: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_fd = os.open(operation_root, parent_flags)
    try:
        for segment in destination.parent.relative_to(operation_root).parts:
            next_fd = os.open(segment, parent_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        return os.open(destination.name, flags, 0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_cleanup(operation_root: Path) -> None:
    try:
        if operation_root.is_symlink():
            operation_root.unlink()
        elif operation_root.exists():
            shutil.rmtree(operation_root)
    except OSError:
        pass


def materialize_validated_archive(
    inspection: ArchiveInspection, staging_root: Path
) -> Path:
    """Re-read a validated archive into one private, operation-specific directory."""

    if not isinstance(inspection, ArchiveInspection):
        raise fail("STAGING_INVALID", "materialization requires a validated inspection")
    staging_root = staging_root.absolute()
    if (
        staging_root.name == inspection.manifest.id
        and staging_root.parent.name == "projects"
    ):
        raise fail("STAGING_INVALID", "live project directories are not staging roots")
    try:
        root_mode = staging_root.lstat().st_mode
    except OSError as exc:
        raise fail("STAGING_INVALID", "staging root must already exist") from exc
    if not stat.S_ISDIR(root_mode) or stat.S_ISLNK(root_mode):
        raise fail("STAGING_INVALID", "staging root must be a real directory")
    if _sha256_file(inspection.archive) != inspection.archive_sha256:
        raise fail("ARCHIVE_CHANGED", "archive changed after bounded inspection")

    operation_root = Path(
        tempfile.mkdtemp(prefix=f".project-pack-{inspection.manifest.id}-", dir=staging_root)
    )
    os.chmod(operation_root, 0o700)
    expected = {
        inspection.manifest_file.archive_name: inspection.manifest_file,
        **{item.archive_name: item for item in inspection.payloads},
    }
    written: set[str] = set()

    try:
        try:
            with tarfile.open(inspection.archive, mode="r|gz") as tar:
                for member in tar:
                    if not member.isreg():
                        continue
                    record = expected.get(member.name.rstrip("/"))
                    if record is None:
                        continue
                    relative = Path(record.relative_path)
                    destination = operation_root / inspection.manifest.id / relative
                    _ensure_private_parents(destination, operation_root)
                    _before_file_open(destination)
                    _assert_contained(destination, operation_root)
                    try:
                        descriptor = _open_exclusive(destination, operation_root)
                    except OSError as exc:
                        raise fail(
                            "STAGING_RACE", "staging file could not be created exclusively"
                        ) from exc
                    digest = hashlib.sha256()
                    actual_size = 0
                    try:
                        source = tar.extractfile(member)
                        if source is None:
                            raise fail("ARCHIVE_FORMAT", "archive member became unreadable")
                        while chunk := source.read(_CHUNK_SIZE):
                            actual_size += len(chunk)
                            if actual_size > record.size:
                                raise fail(
                                    "SIZE_MISMATCH", "archive member changed after inspection"
                                )
                            digest.update(chunk)
                            _write_all(descriptor, chunk)
                        if actual_size != record.size:
                            raise fail(
                                "SIZE_MISMATCH", "archive member changed after inspection"
                            )
                        if digest.hexdigest() != record.sha256:
                            raise fail(
                                "HASH_MISMATCH", "archive member changed after inspection"
                            )
                        os.fchmod(descriptor, 0o644)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    written.add(record.archive_name)
        except PackError:
            raise
        except (OSError, EOFError, tarfile.TarError) as exc:
            raise fail("STAGING_IO", "archive could not be materialized safely") from exc

        if written != set(expected):
            raise fail("ARCHIVE_CHANGED", "archive members changed after inspection")
        if _sha256_file(inspection.archive) != inspection.archive_sha256:
            raise fail("ARCHIVE_CHANGED", "archive changed during materialization")

        pack_dir = operation_root / inspection.manifest.id
        os.chmod(pack_dir, 0o755)
        for directory in sorted(
            (path for path in pack_dir.rglob("*") if path.is_dir()), reverse=True
        ):
            os.chmod(directory, 0o755)
            _fsync_directory(directory)
        _fsync_directory(pack_dir)
        _fsync_directory(operation_root)
        _fsync_directory(staging_root)
        return pack_dir
    except PackError:
        _safe_cleanup(operation_root)
        raise
    except OSError as exc:
        _safe_cleanup(operation_root)
        raise fail("STAGING_IO", "staging write failed") from exc


def _source_file(path: Path, source_root: Path, relative: str) -> _SourceFile:
    try:
        mode = path.lstat().st_mode
        resolved = path.resolve(strict=True)
        resolved.relative_to(source_root)
    except (OSError, ValueError) as exc:
        raise fail("SOURCE_PATH", "source file escaped the source root") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise fail("SOURCE_PATH", "source content must be a regular non-link file")

    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as source:
            while chunk := source.read(_CHUNK_SIZE):
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise fail("ARCHIVE_LIMIT", "source file exceeds the schema-v1 limit")
                digest.update(chunk)
    except PackError:
        raise
    except OSError as exc:
        raise fail("SOURCE_PATH", "source file could not be read safely") from exc
    return _SourceFile(
        path=resolved,
        relative_path=relative,
        size=size,
        sha256=digest.hexdigest(),
    )


def _scan_source(source_root: Path) -> tuple[bytes, tuple[_SourceFile, ...]]:
    try:
        root_mode = source_root.lstat().st_mode
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise fail("SOURCE_PATH", "source root is unavailable") from exc
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise fail("SOURCE_PATH", "source root must be a real directory")

    source_manifest = root / "pack.source.yml"
    manifest_record = _source_file(
        source_manifest, root, "pack.source.yml"
    )
    if manifest_record.size > MAX_MANIFEST_BYTES:
        raise fail("MANIFEST_LIMIT", "pack.source.yml exceeds the schema-v1 limit")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(manifest_record.path, flags)
        with os.fdopen(descriptor, "rb") as source_file:
            source_bytes = source_file.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise fail("SOURCE_PATH", "pack.source.yml could not be read safely") from exc
    if (
        len(source_bytes) != manifest_record.size
        or hashlib.sha256(source_bytes).hexdigest() != manifest_record.sha256
    ):
        raise fail("SOURCE_CHANGED", "pack.source.yml changed during source scanning")

    files: list[_SourceFile] = []
    expanded_bytes = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        relative_path = Path(relative)
        if (
            relative_path.parts[0] in {".git", ".github", ".pytest_cache", "pack-tools", "dist", "tests"}
            or relative
            in {".gitignore", ".gitlab-ci.yml", "README.md", "pack.source.yml"}
        ):
            continue
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise fail("SOURCE_PATH", "source path changed during scanning") from exc
        if stat.S_ISLNK(mode):
            raise fail("SOURCE_PATH", "source trees must not contain symlinks")
        if relative_path.name == ".gitkeep":
            if not stat.S_ISREG(mode):
                raise fail("SOURCE_PATH", ".gitkeep placeholders must be regular files")
            continue
        if any(part.startswith(".") for part in relative_path.parts):
            raise fail("SOURCE_PATH", "source trees must not contain dot paths")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise fail("SOURCE_PATH", "source trees must contain only files and directories")
        if relative == "pack.source.yml":
            continue
        if relative_path.name == "pack.source.yml":
            raise fail("SOURCE_PATH", "pack.source.yml cannot be artifact payload")
        if relative_path.name == "pack.yml":
            raise fail("SOURCE_PATH", "source trees must not contain pack.yml")
        validate_member_path(relative)
        record = _source_file(path, root, relative)
        files.append(record)
        expanded_bytes += record.size
        if expanded_bytes > MAX_EXPANDED_BYTES:
            raise fail("ARCHIVE_LIMIT", "source tree exceeds the expanded-byte limit")
        if len(files) + 2 > MAX_MEMBERS:
            raise fail("ARCHIVE_LIMIT", "source tree exceeds the archive member limit")
    files.sort(key=lambda item: canonical_path_key(item.relative_path))
    return source_bytes, tuple(files)


def _manifest_bytes(source_bytes: bytes, files: tuple[_SourceFile, ...]) -> bytes:
    source = parse_pack_source(source_bytes)
    contents = compute_contents(item.relative_path for item in files)
    file_records = {
        item.relative_path: {"sha256": item.sha256, "size": item.size}
        for item in files
    }
    data = {
        "schema_version": source.schema_version,
        "id": source.id,
        "version": source.version,
        "requires_oscar": source.requires_oscar,
        "requires_tasks": {
            "common": sorted(source.requires_tasks_common, key=str.encode),
            "local": sorted(source.requires_tasks_local, key=str.encode),
        },
        "contents": {
            "jobs": contents.jobs,
            "tasks": list(contents.tasks),
            "fabfile": list(contents.fabfile),
            "scripts": list(contents.scripts),
            "playbooks": list(contents.playbooks),
            "rules": contents.rules,
            "templates": contents.templates,
            **({"tables": list(contents.tables)} if source.schema_version >= 7 else {}),
        },
        "archive": {
            "file_count": len(files),
            "expanded_bytes": sum(item.size for item in files),
        },
        "files": file_records,
    }
    document = yaml.safe_dump(
        data,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=4096,
    ).encode("utf-8")
    if len(document) > MAX_MANIFEST_BYTES:
        raise fail("MANIFEST_LIMIT", "generated pack.yml exceeds the schema-v1 limit")
    parse_pack_manifest(document)
    return document


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = 0 if directory else size
    return info


def _archive_entries(
    pack_id: str, manifest: bytes, files: tuple[_SourceFile, ...]
) -> list[tuple[str, bool, bytes | Path | None, int]]:
    file_entries: list[tuple[str, bool, bytes | Path | None, int]] = [
        (f"{pack_id}/pack.yml", False, manifest, len(manifest))
    ]
    for item in files:
        file_entries.append(
            (f"{pack_id}/{item.relative_path}", False, item.path, item.size)
        )

    directories = {pack_id}
    for name, _, _, _ in file_entries:
        parts = name.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    entries = [(name, True, None, 0) for name in directories] + file_entries
    return sorted(entries, key=lambda entry: canonical_path_key(entry[0]))


def _write_archive_file(
    destination: Path,
    pack_id: str,
    manifest: bytes,
    files: tuple[_SourceFile, ...],
) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_TRUNC)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as raw:
            with gzip.GzipFile(
                fileobj=raw,
                mode="wb",
                filename="",
                compresslevel=9,
                mtime=0,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT
                ) as tar:
                    for name, directory, content, size in _archive_entries(
                        pack_id, manifest, files
                    ):
                        info = _tar_info(name, directory=directory, size=size)
                        if directory:
                            tar.addfile(info)
                        elif isinstance(content, bytes):
                            tar.addfile(info, io.BytesIO(content))
                        else:
                            if not isinstance(content, Path):
                                raise fail("SOURCE_PATH", "archive source is unavailable")
                            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                            source_descriptor = os.open(content, flags)
                            with os.fdopen(source_descriptor, "rb") as source:
                                tar.addfile(info, source)
            raw.flush()
            os.fsync(raw.fileno())
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o644)


def _temporary_file(parent: Path, prefix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=parent)
    os.close(descriptor)
    return Path(name)


def _preflight_destination(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise fail("OUTPUT_PATH", "output destination is unavailable") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise fail("OUTPUT_PATH", "output destination must be a regular file")
    return True


def _write_sidecar(path: Path, digest: str, archive_name: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        data = f"{digest}  {archive_name}\n".encode("ascii")
        _write_all(descriptor, data)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_pack(source_root: Path, output_directory: Path) -> PackResult:
    """Build, self-validate, and atomically publish one deterministic pack."""

    try:
        output_mode = output_directory.lstat().st_mode
        output_root = output_directory.resolve(strict=True)
    except OSError as exc:
        raise fail("OUTPUT_PATH", "output directory is unavailable") from exc
    if stat.S_ISLNK(output_mode) or not stat.S_ISDIR(output_mode):
        raise fail("OUTPUT_PATH", "output directory must be a real directory")

    source_bytes, files = _scan_source(source_root)
    source = parse_pack_source(source_bytes)
    manifest = _manifest_bytes(source_bytes, files)
    archive_name = f"{source.id}-{source.version}.tar.gz"
    archive_path = output_root / archive_name
    sidecar_path = output_root / f"{archive_name}.sha256"
    archive_existed = _preflight_destination(archive_path)
    _preflight_destination(sidecar_path)
    archive_temp = _temporary_file(output_root, f".{archive_name}.")
    sidecar_temp = _temporary_file(output_root, f".{archive_name}.sha256.")
    archive_backup: Path | None = None
    validation_root: Path | None = None

    try:
        _write_archive_file(archive_temp, source.id, manifest, files)
        digest = _sha256_file(archive_temp)
        _write_sidecar(sidecar_temp, digest, archive_name)

        inspection = inspect_archive(archive_temp)
        validation_root = Path(
            tempfile.mkdtemp(prefix=f".{source.id}-self-validate-", dir=output_root)
        )
        staged_pack = materialize_validated_archive(inspection, validation_root)
        validation_report = validate_pack_content(
            staged_pack,
            inspection.manifest,
            transport_verified=True,
        )

        if archive_existed:
            archive_backup = _temporary_file(output_root, f".{archive_name}.rollback.")
            archive_backup.unlink()
            os.link(archive_path, archive_backup, follow_symlinks=False)
        os.replace(archive_temp, archive_path)
        try:
            os.replace(sidecar_temp, sidecar_path)
        except OSError as publication_error:
            try:
                if archive_backup is None:
                    archive_path.unlink(missing_ok=True)
                else:
                    os.replace(archive_backup, archive_path)
                _fsync_directory(output_root)
            except OSError as rollback_error:
                raise fail(
                    "OUTPUT_ROLLBACK",
                    "archive publication failed and rollback was unsuccessful",
                ) from rollback_error
            raise publication_error
        _fsync_directory(output_root)
        published_inspection = replace(inspection, archive=archive_path)
        return PackResult(
            archive=archive_path,
            sidecar=sidecar_path,
            sha256=digest,
            inspection=published_inspection,
            validation_report=validation_report,
        )
    finally:
        for temporary in (archive_temp, sidecar_temp, archive_backup):
            if temporary is None:
                continue
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if validation_root is not None:
            _safe_cleanup(validation_root)
