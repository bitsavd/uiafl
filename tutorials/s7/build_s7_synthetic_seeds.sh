#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TARGET="${S7_TARGET:-192.168.0.13}"
PORT="${S7_PORT:-102}"
OUT_DIR="${1:-tutorials/s7/in}"
PYTHON="${PYTHON:-python3}"
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON="$ROOT_DIR/.venv/bin/python"
fi

EXTRA_ARGS=()
if [ "${S7_INCLUDE_WRITES:-1}" != "0" ]; then
  EXTRA_ARGS+=(--include-writes)
fi
if [ "${S7_INCLUDE_AGGRESSIVE:-1}" != "0" ]; then
  EXTRA_ARGS+=(--include-aggressive)
fi

"$PYTHON" tools/s7_synthetic_seeds.py \
  --target "$TARGET" \
  --port "$PORT" \
  --out "$OUT_DIR" \
  --slots "${S7_SLOTS:-0,1,2,3}" \
  --timeout "${S7_PROBE_TIMEOUT:-1.0}" \
  --max-valid "${S7_MAX_VALID_SEEDS:-24}" \
  "${EXTRA_ARGS[@]}" \
  --replace

rm -rf tutorials/s7/in_split
"$PYTHON" tools/s7_seed_prep.py \
  --input-dir "$OUT_DIR" \
  --output-dir tutorials/s7/in_split \
  --keep-original

echo "[*] Synthetic S7COMM seed corpus ready: $OUT_DIR"
