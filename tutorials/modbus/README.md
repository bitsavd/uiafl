# Modbus/TCP

This directory contains Modbus/TCP seeds and a small instrumented target for local AFLNet smoke tests.

## Build the local target

```bash
tutorials/modbus/build_modbus_target.sh
```

The build script uses `afl-gcc` from the AFLNet root when available.

## Fuzz

```bash
tutorials/modbus/run_modbus_fuzz.sh 10m
```

Useful environment variables:

```bash
MODBUS_PORT=1503 MODBUS_OUT_DIR=tutorials/modbus/out-modbus-1503 tutorials/modbus/run_modbus_fuzz.sh 1h
```

For real devices or external targets, reuse `tutorials/modbus/in-modbus` and `tutorials/modbus/modbus.dict`, then replace the target command and `-N tcp://host/port` value.
