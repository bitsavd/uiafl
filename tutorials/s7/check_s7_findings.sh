#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TARGET="${S7_TARGET:-192.168.0.13}"
PORT="${S7_PORT:-102}"
OUT_DIR="${1:-tutorials/s7/out}"
REPORT_DIR="${OUT_DIR}/s7_oracle"
REPEATS="${S7_REPLAY_REPEATS:-3}"
LIMIT="${S7_REPLAY_LIMIT:-20}"

mkdir -p "$REPORT_DIR"

echo "[*] PLC health check"
python3 tools/s7_oracle.py --target "$TARGET" --port "$PORT" health | tee "$REPORT_DIR/health.json"

echo "[*] Replaying candidate abnormal cases"
mapfile -t CANDIDATES < <(
  find "$OUT_DIR/s7_events/cases" "$OUT_DIR/replayable-new-ipsm-paths" \
    -maxdepth 1 -type f 2>/dev/null | sort | head -n "$LIMIT"
)

for case_path in "${CANDIDATES[@]}"; do
  base="$(basename "$case_path" | tr '/:,' '___')"
  echo "    - $case_path"
  python3 tools/s7_oracle.py \
    --target "$TARGET" \
    --port "$PORT" \
    replay "$case_path" \
    --repeats "$REPEATS" \
    > "$REPORT_DIR/${base}.json" || true
done

echo "[*] Summary"
python3 - "$REPORT_DIR" <<'PY'
import json
import sys
from pathlib import Path

report_dir = Path(sys.argv[1])
for path in sorted(report_dir.glob("*.json")):
    if path.name == "health.json":
        continue
    data = json.loads(path.read_text())
    print(
        f"{path.name}: severity={data.get('severity')} "
        f"reproducible={data.get('reproducible')} "
        f"bad={data.get('bad_replays')}/{data.get('repeats')} "
        f"post_health={data.get('post_health', {}).get('kind')}"
    )
PY

echo "[*] Wrote oracle reports to $REPORT_DIR"
