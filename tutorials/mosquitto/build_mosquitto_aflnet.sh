#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REPO="${MQTT_REPO:-https://github.com/eclipse/mosquitto.git}"
COMMIT="${MQTT_COMMIT:-2665705}"
BUILD_DIR="${MQTT_BUILD_DIR:-mosquitto}"
USE_ASAN="${MQTT_USE_ASAN:-0}"

if [ ! -d "$BUILD_DIR/.git" ]; then
  git clone "$REPO" "$BUILD_DIR"
fi

cd "$BUILD_DIR"
git fetch --all --tags
git checkout "$COMMIT"

if [ "$USE_ASAN" = "1" ]; then
  export AFL_USE_ASAN=1
  CFLAGS_VALUE="-g -O0 -fsanitize=address -fno-omit-frame-pointer"
  LDFLAGS_VALUE="-g -O0 -fsanitize=address -fno-omit-frame-pointer"
else
  unset AFL_USE_ASAN
  CFLAGS_VALUE="-g -O0 -fno-omit-frame-pointer"
  LDFLAGS_VALUE="-g -O0 -fno-omit-frame-pointer"
fi

CC="$ROOT_DIR/afl-gcc" \
CFLAGS="$CFLAGS_VALUE" \
LDFLAGS="$LDFLAGS_VALUE" \
make clean all \
  WITH_TLS=no \
  WITH_TLS_PSK=no \
  WITH_STATIC_LIBRARIES=yes \
  WITH_DOCS=no \
  WITH_CJSON=no \
  WITH_EPOLL=no
