#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUN_TIME="${1:-24h}"
MODE="${2:-fast}"
TARGET="${MQTT_TARGET:-127.0.0.1}"
PORT="${MQTT_PORT:-1883}"
IN_DIR="${MQTT_IN_DIR:-tutorials/mosquitto/in-mqtt}"
OUT_DIR="${MQTT_OUT_DIR:-mosquitto/out-mqtt}"
BIN="${MQTT_BIN:-mosquitto/src/mosquitto}"
LOGFILE="${MQTT_LOGFILE:-tutorials/mosquitto/run_mqtt_fuzz.log}"

if [ ! -x "$BIN" ]; then
  echo "[!] Missing MQTT target binary: $BIN" >&2
  echo "    Build Mosquitto first, or set MQTT_BIN=/path/to/mosquitto." >&2
  exit 1
fi

if [ ! -d "$IN_DIR" ]; then
  echo "[!] Missing MQTT seed directory: $IN_DIR" >&2
  exit 1
fi

EXISTING_AFL=$(pgrep -af "afl-fuzz -d -i $IN_DIR -o $OUT_DIR" | awk '{print $1}' || true)
if [ -n "$EXISTING_AFL" ]; then
  echo "[!] Found existing AFLNet process using $OUT_DIR: $EXISTING_AFL" >&2
  echo "    Stop it before starting a new run, or use MQTT_OUT_DIR to choose another output directory." >&2
  exit 1
fi

if [ -d "$OUT_DIR" ]; then
  echo "[*] Resetting output directory: $OUT_DIR"
  rm -rf "$OUT_DIR"
fi
mkdir -p "$OUT_DIR" "$(dirname "$LOGFILE")"
rm -f "$LOGFILE" 2>/dev/null || true

case "$MODE" in
  fast)
    AFL_FUZZ_MODE="-d"
    AFL_NET_WAIT_US="${AFL_NET_WAIT_US:-10000}"
    AFL_QUEUE_CYCLES="${AFL_QUEUE_CYCLES:-3}"
    AFL_STATE_CYCLES="${AFL_STATE_CYCLES:-3}"
    AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-1000+}"
    ;;
  stable)
    AFL_FUZZ_MODE="-d"
    AFL_NET_WAIT_US="${AFL_NET_WAIT_US:-20000}"
    # q/s=5/5 can make the MQTT target spin after the dry run on this setup.
    # Keep the longer socket wait and exec timeout, but use the known-good cycle depth.
    AFL_QUEUE_CYCLES="${AFL_QUEUE_CYCLES:-3}"
    AFL_STATE_CYCLES="${AFL_STATE_CYCLES:-3}"
    AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-2000+}"
    ;;
  *)
    AFL_FUZZ_MODE=""
    AFL_NET_WAIT_US="${AFL_NET_WAIT_US:-10000}"
    AFL_QUEUE_CYCLES="${AFL_QUEUE_CYCLES:-3}"
    AFL_STATE_CYCLES="${AFL_STATE_CYCLES:-3}"
    AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-1000+}"
    ;;
esac

cat <<EOF
[*] Starting AFLNet MQTT fuzzing
    - input seeds: $IN_DIR
    - output dir: $OUT_DIR
    - target: $BIN
    - listen/connect: $TARGET:$PORT
    - runtime: $RUN_TIME
    - mode: $MODE
    - net wait: ${AFL_NET_WAIT_US}us
    - queue/state cycles: ${AFL_QUEUE_CYCLES}/${AFL_STATE_CYCLES}
    - log file: $LOGFILE when MQTT_TEE_LOG=1 or non-interactive
EOF

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
if ldd "$BIN" 2>/dev/null | grep -q 'libasan'; then
  export AFL_USE_ASAN=1
  export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:symbolize=0:detect_leaks=0}"
fi
export LD_LIBRARY_PATH="$ROOT_DIR/mosquitto/lib:${LD_LIBRARY_PATH:-}"

AFL_CMD=(stdbuf -oL -eL ./afl-fuzz \
  $AFL_FUZZ_MODE \
  -i "$IN_DIR" \
  -o "$OUT_DIR" \
  -m none \
  -t "$AFL_EXEC_TIMEOUT" \
  -N "tcp://$TARGET/$PORT" \
  -P MQTT \
  -D "$AFL_NET_WAIT_US" \
  -q "$AFL_QUEUE_CYCLES" \
  -s "$AFL_STATE_CYCLES" \
  -E \
  -K \
  -R \
  -- "$BIN" -p "$PORT")

if [ "$RUN_TIME" != "none" ]; then
  CMD=(timeout --preserve-status -k 30s "$RUN_TIME" "${AFL_CMD[@]}")
else
  CMD=("${AFL_CMD[@]}")
fi

if [ "${MQTT_TEE_LOG:-0}" = "1" ] || [ ! -t 1 ]; then
  "${CMD[@]}" 2>&1 | tee -a "$LOGFILE"
else
  "${CMD[@]}"
fi
