#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TARGET="${S7_TARGET:-192.168.0.13}"
PORT="${S7_PORT:-102}"
PCAP_DIR="${1:-pcap_S7comm}"

python3 tutorials/s7plus/tools/s7plus_seed_builder.py \
  --target "$TARGET" \
  --port "$PORT" \
  --probe

if [ -e "$PCAP_DIR" ]; then
  python3 tutorials/s7plus/tools/s7_tia_pcap_seeds.py \
    "$PCAP_DIR" \
    --top-n 32
fi

python3 tutorials/s7plus/tools/s7plus_merge_corpus.py \
  tutorials/s7plus/in_s7plus \
  tutorials/s7plus/in_s7plus_candidates \
  tutorials/s7plus/in_tia_selected \
  --target "$TARGET" \
  --port "$PORT" \
  --top-n 10
