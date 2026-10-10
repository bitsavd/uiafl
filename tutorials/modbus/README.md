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

## Response states

Normal responses are grouped by function code. Exception responses are grouped
by exception code across all functions. Unit IDs and transaction IDs do not
create states. Undefined exception codes share one category. Invalid protocol
IDs, truncated frames and malformed exception responses are excluded.

Graph nodes remain compact discovery-order IDs, with node 0 as the initial
state. These represent response categories rather than internal device states.
Existing runs retain their original graphs; start a new run to use this rule.

The local target reads complete ADUs using the MBAP length, handles TCP
fragmentation and coalescing, and sends complete responses. Invalid ADU lengths
close the connection; an incomplete frame at EOF does not generate a response.

Coverage bitmap occupancy is not source-code coverage. New fuzz runs report
`bitmap_slots` (hit bitmap slots) and `bitmap_capacity` alongside `bitmap_cvg`.

Run the TCP stream regression tests:

```bash
python3 tutorials/modbus/test_tcp_stream.py -v
```

Run the parser regression checks from the repository root:

```bash
make aflnet.o
cc -O1 -g -I. tutorials/modbus/test_response_states.c aflnet.o -o /tmp/modbus-response-state-test -lgvc -lcgraph -lm
/tmp/modbus-response-state-test
```
