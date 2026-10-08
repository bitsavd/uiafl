#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PCAP_DIR="${1:-pcap_S7comm}"
OUT_DIR="${2:-tutorials/s7/in}"
TOP_N="${TOP_N:-8}"
AUTO_N="${AUTO_N:-12}"
PYTHON="${PYTHON:-python3}"
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON="$ROOT_DIR/.venv/bin/python"
fi

TMP_DIR="$(mktemp -d /tmp/s7-seeds.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

rm -rf "$OUT_DIR" tutorials/s7/in_split
mkdir -p "$OUT_DIR" tutorials/s7/in_split

if "$PYTHON" - <<'PY' >/dev/null 2>&1
from scapy.utils import RawPcapReader, RawPcapNgReader
PY
then
  SOURCE_DIR="$PCAP_DIR"
else
  SOURCE_DIR="$PCAP_DIR/seeds"
  echo "[!] scapy is not installed for $PYTHON; falling back to existing raw seeds: $SOURCE_DIR" >&2
fi

"$PYTHON" tools/extract_s7_seeds.py "$SOURCE_DIR" \
  -o "$TMP_DIR" \
  --split-requests \
  --auto-gen "$AUTO_N" \
  --dedup \
  --keep-threshold 70

"$PYTHON" tools/s7_seed_quality.py "$TMP_DIR" \
  --top "$TOP_N" \
  --output-dir "$OUT_DIR" >/tmp/s7_seed_quality.json

"$PYTHON" tools/s7_seed_prep.py \
  --input-dir "$OUT_DIR" \
  --output-dir tutorials/s7/in_split \
  --keep-original

echo "[*] Rebuilt S7COMM seeds"
echo "    full-session corpus: $OUT_DIR"
echo "    split/debug corpus : tutorials/s7/in_split"
echo "    quality report     : /tmp/s7_seed_quality.json"
