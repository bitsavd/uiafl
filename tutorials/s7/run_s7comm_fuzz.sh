#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUN_TIME="${1:-24h}"
MODE="${2:-fast}"
TARGET="${S7_TARGET:-192.168.0.13}"
PORT="${S7_PORT:-102}"
LOGFILE="${S7_LOGFILE:-tutorials/s7/run_s7comm_fuzz.log}"
IN_DIR="${S7_IN_DIR:-tutorials/s7/in}"
OUT_DIR="${S7_OUT_DIR:-tutorials/s7/out}"
DICT_FILE="${S7_DICT:-tutorials/s7/s7.dict}"

mkdir -p "$(dirname "$LOGFILE")"
rm -f "$LOGFILE" 2>/dev/null || true

EXISTING_AFL=$(pgrep -af "afl-fuzz -i $IN_DIR -o $OUT_DIR" | awk '{print $1}' || true)
if [ -n "$EXISTING_AFL" ]; then
  echo "[!] Found existing AFLNet process using $OUT_DIR: $EXISTING_AFL" >&2
  echo "    Stop it before starting a new run, or use a different output directory." >&2
  exit 1
fi

if [ -d "$OUT_DIR" ]; then
  echo "[*] Resetting output directory: $OUT_DIR"
  rm -rf "$OUT_DIR"
fi

mkdir -p "$OUT_DIR"

if [ ! -f "tools/s7_harness.c" ]; then
  echo "[!] Missing harness source: tools/s7_harness.c" >&2
  exit 1
fi

# Fast default mode: reduce response waits and use higher optimization.
if [ "$MODE" = "fast" ]; then
  GCC_OPTS="-O3 -Wall"
  AFL_NET_WAIT_MS="${AFL_NET_WAIT_MS:-100}"
  AFL_NET_FOLLOW_US="${AFL_NET_FOLLOW_US:-100}"
  AFL_FUZZ_MODE="-d"
  AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-3000+}"
  export S7_AFLNET_RESET="${S7_AFLNET_RESET:-0}"
  export S7_RESET_POLICY="${S7_RESET_POLICY:-mutating}"
  export S7_RESET_EVERY="${S7_RESET_EVERY:-1}"
  export S7_RESET_M0="${S7_RESET_M0:-1}"
  export S7_RESET_Q0="${S7_RESET_Q0:-0}"
  export S7_RESET_BEFORE="${S7_RESET_BEFORE:-0}"
  export S7_RESET_AFTER="${S7_RESET_AFTER:-1}"
  export S7_RESET_SETTLE_US="${S7_RESET_SETTLE_US:-0}"
  export S7_RESET_TIMEOUT_US="${S7_RESET_TIMEOUT_US:-10000}"
elif [ "$MODE" = "balanced" ]; then
  GCC_OPTS="-O3 -Wall"
  AFL_NET_WAIT_MS="${AFL_NET_WAIT_MS:-100}"
  AFL_NET_FOLLOW_US="${AFL_NET_FOLLOW_US:-100}"
  AFL_FUZZ_MODE="-d"
  AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-4000+}"
  export S7_AFLNET_RESET="${S7_AFLNET_RESET:-1}"
  export S7_RESET_POLICY="${S7_RESET_POLICY:-mutating}"
  export S7_RESET_EVERY="${S7_RESET_EVERY:-4}"
  export S7_RESET_M0="${S7_RESET_M0:-1}"
  export S7_RESET_Q0="${S7_RESET_Q0:-0}"
  export S7_RESET_BEFORE="${S7_RESET_BEFORE:-0}"
  export S7_RESET_AFTER="${S7_RESET_AFTER:-1}"
  export S7_RESET_SETTLE_US="${S7_RESET_SETTLE_US:-5000}"
  export S7_RESET_TIMEOUT_US="${S7_RESET_TIMEOUT_US:-20000}"
elif [ "$MODE" = "stable" ]; then
  GCC_OPTS="-O3 -Wall"
  AFL_NET_WAIT_MS="${AFL_NET_WAIT_MS:-100}"
  AFL_NET_FOLLOW_US="${AFL_NET_FOLLOW_US:-100}"
  AFL_FUZZ_MODE="-d"
  AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-5000+}"
  export S7_AFLNET_RESET="${S7_AFLNET_RESET:-1}"
  export S7_RESET_POLICY="${S7_RESET_POLICY:-always}"
  export S7_RESET_EVERY="${S7_RESET_EVERY:-1}"
  export S7_RESET_M0="${S7_RESET_M0:-1}"
  export S7_RESET_Q0="${S7_RESET_Q0:-1}"
  export S7_RESET_BEFORE="${S7_RESET_BEFORE:-1}"
  export S7_RESET_AFTER="${S7_RESET_AFTER:-1}"
  export S7_RESET_SETTLE_US="${S7_RESET_SETTLE_US:-10000}"
  export S7_RESET_TIMEOUT_US="${S7_RESET_TIMEOUT_US:-20000}"
else
  GCC_OPTS="-O2 -Wall"
  AFL_NET_WAIT_MS="${AFL_NET_WAIT_MS:-500}"
  AFL_NET_FOLLOW_US="${AFL_NET_FOLLOW_US:-500}"
  AFL_FUZZ_MODE=""
  AFL_EXEC_TIMEOUT="${AFL_EXEC_TIMEOUT:-10000+}"
fi

echo "[*] Building AFL-instrumented harness..."
./afl-gcc $GCC_OPTS -o tools/s7_harness tools/s7_harness.c

cat <<EOF
[*] Starting AFLNet S7COMM fuzzing against remote PLC
    - input seeds: $IN_DIR
    - output dir: $OUT_DIR
    - target PLC: $TARGET:$PORT
    - state-aware mode: yes
    - response wait: ${AFL_NET_WAIT_MS}ms first poll, ${AFL_NET_FOLLOW_US}us socket timeout
    - per-testcase S7 reset: ${S7_AFLNET_RESET:-0}
    - S7 reset policy: ${S7_RESET_POLICY:-always}
    - S7 reset before/after: ${S7_RESET_BEFORE:-0}/${S7_RESET_AFTER:-0}
    - reset every: ${S7_RESET_EVERY:-0}
    - S7 event log: ${S7_EVENT_LOG:-1} (${OUT_DIR}/s7_events/events.log)
    - S7 transport event sample: ${S7_EVENT_TRANSPORT_SAMPLE:-32}
    - S7 event case snapshots: ${S7_EVENT_SAVE_CASES:-1}
    - S7 compact states: ${S7_STATE_COMPACT:-1}
    - S7 strict semantic states: ${S7_STATE_STRICT:-1}
    - S7 binary state bitmap: ${S7_STATE_BINARY_BITMAP:-1}
    - S7 state bitmap feedback: ${S7_STATE_BITMAP_FEEDBACK:-0}
    - S7 require nonzero state feedback: ${S7_STATE_MIN_NONZERO:-1}
    - S7 skip network during calibration: ${S7_SKIP_NET_CALIBRATION:-1}
    - S7 trust local calibration baseline: ${S7_TRUST_LOCAL_CALIBRATION:-1}
    - S7 max testcase length: ${S7_MAX_TESTCASE:-512}
    - S7 max network message: ${S7_NET_MAX_MESSAGE:-4096}
    - S7 harness max input: ${S7_HARNESS_MAX_INPUT:-4096}
    - S7 harness S7-only coverage: ${S7_HARNESS_S7_ONLY_COVERAGE:-1}
    - S7 dictionary: ${DICT_FILE}
    - automatic runtime: $RUN_TIME
    - log file: $LOGFILE when AFL_TEE_LOG=1 or non-interactive
EOF

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_HANG_TMOUT="${AFL_HANG_TMOUT:-1000}"
export S7_EVENT_LOG="${S7_EVENT_LOG:-1}"
export S7_EVENT_MAX="${S7_EVENT_MAX:-20000}"
export S7_EVENT_TRANSPORT_SAMPLE="${S7_EVENT_TRANSPORT_SAMPLE:-32}"
export S7_EVENT_SAVE_CASES="${S7_EVENT_SAVE_CASES:-1}"
export S7_STATE_COMPACT="${S7_STATE_COMPACT:-1}"
export S7_STATE_STRICT="${S7_STATE_STRICT:-1}"
export S7_STATE_BINARY_BITMAP="${S7_STATE_BINARY_BITMAP:-1}"
export S7_STATE_BITMAP_FEEDBACK="${S7_STATE_BITMAP_FEEDBACK:-0}"
export S7_STATE_MIN_NONZERO="${S7_STATE_MIN_NONZERO:-1}"
export S7_SKIP_NET_CALIBRATION="${S7_SKIP_NET_CALIBRATION:-1}"
export S7_TRUST_LOCAL_CALIBRATION="${S7_TRUST_LOCAL_CALIBRATION:-1}"
export S7_MAX_TESTCASE="${S7_MAX_TESTCASE:-512}"
export S7_NET_MAX_MESSAGE="${S7_NET_MAX_MESSAGE:-4096}"
export S7_HARNESS_MAX_INPUT="${S7_HARNESS_MAX_INPUT:-4096}"
export S7_HARNESS_S7_ONLY_COVERAGE="${S7_HARNESS_S7_ONLY_COVERAGE:-1}"
unset S7_HARNESS_CONNECT

DICT_ARGS=()
if [ -f "$DICT_FILE" ]; then
  DICT_ARGS=(-x "$DICT_FILE")
fi

AFL_CMD=(stdbuf -oL -eL ./afl-fuzz \
  -i "$IN_DIR" \
  -o "$OUT_DIR" \
  "${DICT_ARGS[@]}" \
  -t "$AFL_EXEC_TIMEOUT" \
  -N "tcp://$TARGET/$PORT" \
  -P S7COMM \
  -D "${AFL_SERVER_WAIT_US:-0}" \
  -W "$AFL_NET_WAIT_MS" \
  -w "$AFL_NET_FOLLOW_US" \
  -E \
  -R \
  -h 0 \
  $AFL_FUZZ_MODE \
  -- ./tools/s7_harness @@)

if [ "$RUN_TIME" != "none" ]; then
  echo "[*] Running for up to $RUN_TIME"
  CMD=(timeout --preserve-status "$RUN_TIME" "${AFL_CMD[@]}")
else
  echo "[*] Running until manually stopped"
  CMD=("${AFL_CMD[@]}")
fi

echo "[*] Launching AFLNet..."
if [ "${AFL_TEE_LOG:-0}" = "1" ] || [ ! -t 1 ]; then
  "${CMD[@]}" 2>&1 | tee -a "$LOGFILE"
else
  "${CMD[@]}"
fi
