#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="$ROOT/aflnet-ui/targets/.cache"
mkdir -p "$CACHE/system"
python3 -m pip install -r "$ROOT/aflnet-ui/backend/requirements.txt"

fetch_package() {
  local package="$1"
  local tool="$2"
  if command -v "$tool" >/dev/null || [ -x "$CACHE/system/usr/sbin/$tool" ]; then
    return
  fi
  (cd "$CACHE" && apt-get download "$package")
  for archive in "$CACHE/${package}"_*.deb; do
    dpkg-deb -x "$archive" "$CACHE/system"
  done
}
fetch_package dnsmasq-base dnsmasq
fetch_package cups-ipp-utils ippeveprinter

if [ ! -d "$CACHE/tinydtls/.git" ]; then
  git clone https://github.com/assist-project/tinydtls-fuzz.git "$CACHE/tinydtls"
fi
git -C "$CACHE/tinydtls" checkout 06995d4
make -C "$CACHE/tinydtls" -j2 CC="$ROOT/afl-gcc"
make -C "$CACHE/tinydtls/tests" dtls-server CC="$ROOT/afl-gcc"

mkdir -p "$ROOT/tutorials/tinydtls/in-dtls"
cp "$ROOT/tutorials/tinydtls/handshake_captures/psk_handshake_client.raw" "$ROOT/tutorials/tinydtls/in-dtls/"
cp "$ROOT/tutorials/tinydtls/handshake_captures/ecc_handshake_client.raw" "$ROOT/tutorials/tinydtls/in-dtls/"
printf 'FTP, DNS, DICOM, IPP and DTLS reference targets are ready.\n'
