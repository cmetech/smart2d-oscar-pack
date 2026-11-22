"""The pack builder skips CI-provider metadata (.depot) but still rejects other dot paths."""
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pack-tools"))
sys.dont_write_bytecode = True

from project_pack.archive import write_pack  # noqa: E402
from project_pack.errors import PackError  # noqa: E402


def _copy_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", ".depot", ".pytest_cache", "__pycache__", "dist"))
    return source


def test_pack_build_ignores_depot_ci_directory(tmp_path: Path) -> None:
    """AC-1: a .depot/ directory does not block the build and is not packaged."""
    source = _copy_source(tmp_path)
    (source / ".depot/workflows").mkdir(parents=True)
    (source / ".depot/workflows/ci.yml").write_text("name: ci\n")
    output = tmp_path / "output"
    output.mkdir()

    result = write_pack(source, output)

    assert not [p.relative_path for p in result.inspection.payloads if p.relative_path.startswith(".depot")]


def test_pack_build_still_rejects_other_dot_paths(tmp_path: Path) -> None:
    """AC-2: any other hidden directory is still refused with SOURCE_PATH."""
    source = _copy_source(tmp_path)
    (source / ".hidden").mkdir()
    (source / ".hidden/file.txt").write_text("hidden\n")
    output = tmp_path / "output"
    output.mkdir()

    with pytest.raises(PackError) as exc_info:
        write_pack(source, output)
    assert exc_info.value.code == "SOURCE_PATH"
