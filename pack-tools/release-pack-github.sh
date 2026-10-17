#!/usr/bin/env bash

set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
TAG="${1:?tag is required}"
[[ "$TAG" == v?* ]] || { printf 'tag must start with v\n' >&2; exit 1; }
VERSION="${TAG#v}"
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"
GH_BIN="${GH_BIN:-gh}"

cd "$PACK_ROOT"
"$TOOLS_DIR/build-pack.sh" --output dist --expected-version "$VERSION"
"$TOOLS_DIR/.venv/bin/python" -m pip install -r "$TOOLS_DIR/requirements-pack.txt"
"$TOOLS_DIR/.venv/bin/python" -m pytest -q "$PACK_ROOT/tests"

archive="$(PYTHONPATH="$TOOLS_DIR" "$TOOLS_DIR/.venv/bin/python" - <<'PY'
from pathlib import Path

from project_pack.model import parse_pack_source

source = parse_pack_source(Path("pack.source.yml").read_bytes())
print(f"dist/{source.id}-{source.version}.tar.gz")
PY
)"
[[ -f "$archive" ]] || { printf 'build produced no archive\n' >&2; exit 1; }
sidecar="$archive.sha256"
[[ -f "$sidecar" ]] || { printf 'build produced no checksum sidecar\n' >&2; exit 1; }
(cd dist && sha256sum --check "$(basename "$sidecar")")
printf 'verified %s\n' "$(cat "$sidecar")"

validate_assets() {
    python3 - "$1" "$(basename "$archive")" "$(basename "$sidecar")" <<'PY'
import json
import sys

assets_json, archive, sidecar = sys.argv[1:]
try:
    assets = json.loads(assets_json)["assets"]
    found = {asset["name"] for asset in assets}
    if len(assets) != 2 or found != {archive, sidecar}:
        raise ValueError
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit("release assets do not match the built files")
PY
}

lookup_error="$(mktemp)"
download_dir=""
cleanup() {
    rm -f "$lookup_error"
    [[ -z "$download_dir" ]] || rm -rf "$download_dir"
}
trap cleanup EXIT

if assets="$($GH_BIN release view "$TAG" --repo "$GITHUB_REPOSITORY" --json assets 2>"$lookup_error")"; then
    validate_assets "$assets"
    download_dir="$(mktemp -d)"
    chmod 700 "$download_dir"
    "$GH_BIN" release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$download_dir"
    cmp "$archive" "$download_dir/$(basename "$archive")"
    cmp "$sidecar" "$download_dir/$(basename "$sidecar")"
elif grep -qxF 'HTTP 404: Not Found' "$lookup_error" || grep -qxF 'release not found' "$lookup_error"; then
    "$GH_BIN" release create "$TAG" "$archive" "$sidecar" \
        --repo "$GITHUB_REPOSITORY" --verify-tag --target "$GITHUB_SHA" \
        --title "$TAG" --notes "Release $TAG"
else
    cat "$lookup_error" >&2
    exit 1
fi
