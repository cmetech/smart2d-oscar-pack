#!/usr/bin/env bash

set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"
VENV="$TOOLS_DIR/.venv"

if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install -r "$TOOLS_DIR/requirements-pack.txt"
fi

cd "$PACK_ROOT"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$TOOLS_DIR" "$VENV/bin/python" -m project_pack.cli "$@"
