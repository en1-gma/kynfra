#!/usr/bin/env bash
# Verifica del kit: test degli hook e dell'installer; con --patterns anche i pattern Terraform (il completamento è nel Task 14).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -B -m unittest discover -s "$ROOT/tests/hooks" -v
[ "${1:-}" = "--patterns" ] || exit 0
if [ -d "$ROOT/tests/patterns" ]; then
  python3 -B -m unittest discover -s "$ROOT/tests/patterns" -v
fi
