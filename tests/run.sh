#!/usr/bin/env bash
# Verifica del kit: test degli hook e dell'installer; con --patterns [p…] anche i pattern Terraform (tutti o solo
# quelli indicati), generati in una cartella vuota e controllati in modalità strict.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -B -m unittest discover -s "$ROOT/tests/hooks" -v
[ "${1:-}" = "--patterns" ] || exit 0
shift
KYNFRA_PATTERNS="$*" python3 -B -m unittest discover -s "$ROOT/tests/patterns" -v
