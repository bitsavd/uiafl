#!/usr/bin/env bash
set -euo pipefail

AFLNET="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(cd "$AFLNET/.." && pwd)"
LIVE555_DIR="${LIVE555_DIR:-$WORKDIR/live555}"
PORT="${RTSP_PORT:-8554}"
RUN_TIME="${1:-24h}"
OUT_DIR="${RTSP_OUT_DIR:-$LIVE555_DIR/testProgs/out-live555}"
IN_DIR="${RTSP_IN_DIR:-$AFLNET/tutorials/live555/in-rtsp}"
DICT="${RTSP_DICT:-$AFLNET/tutorials/live555/rtsp.dict}"

if [ ! -x "$LIVE555_DIR/testProgs/testOnDemandRTSPServer" ]; then
  echo "[!] Missing Live555 server: $LIVE555_DIR/testProgs/testOnDemandRTSPServer" >&2
  echo "    Build Live555 first." >&2
  exit 1
fi

mkdir -p "$LIVE555_DIR/testProgs"
cp "$AFLNET"/tutorials/live555/sample_media_sources/*.* "$LIVE555_DIR/testProgs"/

if [ -d "$OUT_DIR" ]; then
  echo "[*] Resetting output directory: $OUT_DIR"
  rm -rf "$OUT_DIR"
fi

export AFL_PATH="$AFLNET"
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

cd "$LIVE555_DIR/testProgs"

CMD=(
  "$AFLNET/afl-fuzz"
  -d
  -i "$IN_DIR"
  -o "$OUT_DIR"
  -N "tcp://127.0.0.1/$PORT"
  -x "$DICT"
  -P RTSP
  -D 10000
  -q 3
  -s 3
  -E
  -K
  -R
  ./testOnDemandRTSPServer "$PORT"
)

echo "[*] Live555 dir: $LIVE555_DIR"
echo "[*] Input seeds: $IN_DIR"
echo "[*] Output dir: $OUT_DIR"
echo "[*] Port: $PORT"
echo "[*] Runtime: $RUN_TIME"

if [ "$RUN_TIME" = "none" ]; then
  "${CMD[@]}"
else
  timeout --preserve-status "$RUN_TIME" "${CMD[@]}"
fi
