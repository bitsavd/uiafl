#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

source tutorials/s7plus/vuln_repro/env.sh

dotnet build tutorials/s7plus/vuln_repro/poc_sources/harpos7/HarpoS7/HarpoS7.sln -c Release
