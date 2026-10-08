#!/usr/bin/env python3
from pathlib import Path
import struct

OUT = Path(__file__).resolve().parent / "in-modbus"


def adu(tid, unit, pdu, proto=0):
    return struct.pack(">HHHB", tid & 0xFFFF, proto & 0xFFFF, len(pdu) + 1, unit & 0xFF) + pdu


def req_read(fc, start, qty, tid):
    return adu(tid, 1, struct.pack(">BHH", fc, start, qty))


def req_write_single(fc, addr, value, tid):
    return adu(tid, 1, struct.pack(">BHH", fc, addr, value))


def req_write_many_coils(start, qty, payload, tid):
    return adu(tid, 1, struct.pack(">BHHB", 0x0F, start, qty, len(payload)) + payload)


def req_write_many_regs(start, values, tid):
    payload = b"".join(struct.pack(">H", value & 0xFFFF) for value in values)
    return adu(tid, 1, struct.pack(">BHHB", 0x10, start, len(values), len(payload)) + payload)


def req_mask_write(addr, and_mask, or_mask, tid):
    return adu(tid, 1, struct.pack(">BHHH", 0x16, addr, and_mask, or_mask))


def req_read_write(read_start, read_qty, write_start, values, tid):
    payload = b"".join(struct.pack(">H", value & 0xFFFF) for value in values)
    return adu(tid, 1, struct.pack(">BHHHHB", 0x17, read_start, read_qty, write_start, len(values), len(payload)) + payload)


def req_diagnostics(subfunc, data, tid):
    return adu(tid, 1, struct.pack(">BHH", 0x08, subfunc, data))


def req_device_id(tid):
    return adu(tid, 1, b"\x2b\x0e\x01\x00")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    seeds = [
        ("read_coils_min.raw", req_read(0x01, 0, 1, 1)),
        ("read_coils_byte_boundary.raw", req_read(0x01, 0, 8, 2)),
        ("read_coils_wide.raw", req_read(0x01, 19, 64, 3)),
        ("read_coils_max.raw", req_read(0x01, 0, 2000, 4)),
        ("read_discrete_inputs.raw", req_read(0x02, 0, 16, 5)),
        ("read_holding_registers_one.raw", req_read(0x03, 0, 1, 6)),
        ("read_holding_registers_block.raw", req_read(0x03, 10, 16, 7)),
        ("read_holding_registers_max.raw", req_read(0x03, 0, 125, 8)),
        ("read_input_registers.raw", req_read(0x04, 0, 8, 9)),
        ("write_single_coil_on.raw", req_write_single(0x05, 0, 0xFF00, 10)),
        ("write_single_coil_off.raw", req_write_single(0x05, 0, 0x0000, 11)),
        ("write_single_register_zero.raw", req_write_single(0x06, 0, 0x0000, 12)),
        ("write_single_register_max.raw", req_write_single(0x06, 1, 0xFFFF, 13)),
        ("write_multiple_coils_sparse.raw", req_write_many_coils(0, 10, b"\x55\x01", 14)),
        ("write_multiple_coils_dense.raw", req_write_many_coils(8, 16, b"\xff\x00", 15)),
        ("write_multiple_registers_pair.raw", req_write_many_regs(0, [0x0001, 0x7FFF], 16)),
        ("write_multiple_registers_pattern.raw", req_write_many_regs(4, [0x0000, 0xFFFF, 0x1234, 0xABCD], 17)),
        ("mask_write_register.raw", req_mask_write(2, 0x00F2, 0x0025, 18)),
        ("read_write_multiple_registers.raw", req_read_write(0, 4, 10, [0x1111, 0x2222], 19)),
        ("diagnostics_return_query.raw", req_diagnostics(0x0000, 0xA55A, 20)),
        ("device_identification.raw", req_device_id(21)),
        ("sequence_read_write_read.raw", req_read(0x03, 0, 2, 22) + req_write_single(0x06, 1, 0x1234, 23) + req_read(0x03, 0, 2, 24)),
        ("sequence_coils_registers.raw", req_read(0x01, 0, 8, 25) + req_write_many_regs(0, [1, 2, 3], 26) + req_read(0x04, 0, 3, 27)),
        ("invalid_function.raw", adu(28, 1, b"\x41\x00\x00\x00\x01")),
        ("invalid_zero_quantity.raw", req_read(0x03, 0, 0, 29)),
        ("invalid_single_coil_value.raw", req_write_single(0x05, 0, 0x1234, 30)),
        ("malformed_short_header.raw", b"\x00\x1f\x00\x00\x00"),
        ("malformed_length_too_large.raw", b"\x00\x20\x00\x00\x01\x20\x01\x03\x00\x00"),
    ]

    for name, data in seeds:
        (OUT / name).write_bytes(data)


if __name__ == "__main__":
    main()
