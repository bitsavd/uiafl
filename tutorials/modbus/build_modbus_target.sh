#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

CC_BIN="${CC:-$ROOT_DIR/afl-gcc}"
if [ ! -x "$CC_BIN" ]; then
  CC_BIN="${CC:-cc}"
fi

"$CC_BIN" -g -O0 -Wall -Wextra tutorials/modbus/modbus_tcp_server.c -o tutorials/modbus/modbus_tcp_server
