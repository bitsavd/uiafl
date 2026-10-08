#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUN_TIME="${1:-24h}"
PORT="${MODBUS_PORT:-1502}"
IN_DIR="${MODBUS_IN_DIR:-tutorials/modbus/in-modbus}"
OUT_DIR="${MODBUS_OUT_DIR:-tutorials/modbus/out-modbus}"
DICT="${MODBUS_DICT:-tutorials/modbus/modbus.dict}"
BIN="${MODBUS_BIN:-tutorials/modbus/modbus_tcp_server}"

if [ ! -x "$BIN" ]; then
  tutorials/modbus/build_modbus_target.sh
fi

if [ -d "$OUT_DIR" ]; then
  rm -rf "$OUT_DIR"
fi

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

CMD=(
  ./afl-fuzz
  -d
  -i "$IN_DIR"
  -o "$OUT_DIR"
  -m none
  -t "${AFL_EXEC_TIMEOUT:-2000+}"
  -N "tcp://127.0.0.1/$PORT"
  -P MODBUS
  -D "${AFL_NET_WAIT_US:-10000}"
  -q "${AFL_QUEUE_CYCLES:-3}"
  -s "${AFL_STATE_CYCLES:-3}"
  -E
  -K
  -R
  -x "$DICT"
  -- "$BIN" "$PORT"
)

if [ "$RUN_TIME" = "none" ]; then
  "${CMD[@]}"
else
  timeout --preserve-status -k 30s "$RUN_TIME" "${CMD[@]}"
fi
