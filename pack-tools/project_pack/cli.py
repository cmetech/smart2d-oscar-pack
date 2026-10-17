"""Command-line entry point for the portable project-pack builder."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from packaging.version import InvalidVersion, Version

from project_pack.archive import write_pack
from project_pack.errors import PackError, fail
from project_pack.model import parse_pack_source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic OSCAR project pack.")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-version")
    arguments = parser.parse_args(argv)

    try:
        if arguments.expected_version is not None:
            try:
                Version(arguments.expected_version)
            except InvalidVersion as exc:
                raise fail("VERSION_INVALID", "expected version is invalid") from exc
            try:
                source = parse_pack_source((Path.cwd() / "pack.source.yml").read_bytes())
            except OSError as exc:
                raise fail("SOURCE_MANIFEST", "pack.source.yml is unavailable") from exc
            if source.version != arguments.expected_version:
                raise fail("VERSION_MISMATCH", "source version does not equal expected version")
        arguments.output.mkdir(parents=True, exist_ok=True)
        write_pack(Path.cwd(), arguments.output)
    except PackError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
