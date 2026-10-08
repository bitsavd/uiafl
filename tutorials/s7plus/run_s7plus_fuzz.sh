#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export S7_IN_DIR="${S7_IN_DIR:-tutorials/s7plus/in_s7plus_final}"
export S7_OUT_DIR="${S7_OUT_DIR:-tutorials/s7plus/out}"
export S7_DICT="${S7_DICT:-tutorials/s7plus/s7plus_final.dict}"
export S7_LOGFILE="${S7_LOGFILE:-tutorials/s7plus/run_s7plus_fuzz.log}"

# S7CommPlus still uses the existing AFLNet S7 transport implementation.
# The response-state extractor in aflnet.c has a 0x72-specific branch.
exec tutorials/s7/run_s7comm_fuzz.sh "${1:-24h}" "${2:-fast}"
