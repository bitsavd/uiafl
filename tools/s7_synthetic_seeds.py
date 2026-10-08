#!/usr/bin/env python3
import argparse
import shutil
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


AREA_INPUT = 0x81
AREA_OUTPUT = 0x82
AREA_MEMORY = 0x83
AREA_DB = 0x84
AREA_COUNTER = 0x1C
AREA_TIMER = 0x1D


@dataclass
class Candidate:
    name: str
    data: bytes
    slot: int
    dst_tsap: int
    description: str


@dataclass
class ProbeResult:
    ok: bool
    summary: str
    responses: List[bytes]


def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload


def cotp_cr(src_tsap: int, dst_tsap: int, tpdu_size: int = 0x0A) -> bytes:
    cotp = (
        b"\x11\xE0\x00\x00\x00\x01\x00"
        + b"\xC1\x02" + src_tsap.to_bytes(2, "big")
        + b"\xC2\x02" + dst_tsap.to_bytes(2, "big")
        + b"\xC0\x01" + bytes([tpdu_size])
    )
    return tpkt(cotp)


def cotp_data(payload: bytes) -> bytes:
    return tpkt(b"\x02\xF0\x80" + payload)


def s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    return (
        b"\x32"
        + bytes([rosctr])
        + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + data_len.to_bytes(2, "big")
    )


def setup_communication(pdu_ref: int = 1, max_amq: int = 1, pdu_len: int = 480) -> bytes:
    params = b"\xF0\x00" + max_amq.to_bytes(2, "big") + max_amq.to_bytes(2, "big") + pdu_len.to_bytes(2, "big")
    return cotp_data(s7_header(0x01, pdu_ref, len(params), 0) + params)


def read_var_item(area: int, db_number: int, byte_offset: int, size: int, transport_size: int = 0x02) -> bytes:
    bit_addr = byte_offset * 8
    return (
        b"\x12\x0A\x10"
        + bytes([transport_size])
        + size.to_bytes(2, "big")
        + db_number.to_bytes(2, "big")
        + bytes([area])
        + bit_addr.to_bytes(3, "big")
    )


def read_var_request(items: List[bytes], pdu_ref: int) -> bytes:
    params = b"\x04" + bytes([len(items)]) + b"".join(items)
    return cotp_data(s7_header(0x01, pdu_ref, len(params), 0) + params)


def write_var_request(item: bytes, payload: bytes, pdu_ref: int, transport_size: int = 0x04) -> bytes:
    params = b"\x05\x01" + item
    bit_len = len(payload) * 8
    data = b"\x00" + bytes([transport_size]) + bit_len.to_bytes(2, "big") + payload
    return cotp_data(s7_header(0x01, pdu_ref, len(params), len(data)) + params + data)


def raw_s7_job(params: bytes, data: bytes = b"", pdu_ref: int = 0x40) -> bytes:
    return cotp_data(s7_header(0x01, pdu_ref, len(params), len(data)) + params + data)


def split_tpkt_stream(data: bytes) -> List[bytes]:
    frames = []
    off = 0
    while off + 4 <= len(data):
        if data[off] != 0x03 or data[off + 1] != 0x00:
            break
        size = (data[off + 2] << 8) | data[off + 3]
        if size < 4 or off + size > len(data):
            break
        frames.append(data[off:off + size])
        off += size
    return frames


def dst_tsap_for_slot(slot: int, rack: int = 0, connection_type: int = 0x01) -> int:
    return (connection_type << 8) | ((rack << 5) | slot)


def build_candidates(slots: List[int], rack: int, src_tsap: int, include_writes: bool, include_aggressive: bool) -> List[Candidate]:
    candidates: List[Candidate] = []
    read_sets = [
        ("m0_byte", "read M0.0 byte", [read_var_item(AREA_MEMORY, 0, 0, 1)]),
        ("m0_4bytes", "read M0.0 four bytes", [read_var_item(AREA_MEMORY, 0, 0, 4)]),
        ("m10_16bytes", "read M10.0 sixteen bytes", [read_var_item(AREA_MEMORY, 0, 10, 16)]),
        ("i0_byte", "read I0.0 byte", [read_var_item(AREA_INPUT, 0, 0, 1)]),
        ("q0_byte", "read Q0.0 byte", [read_var_item(AREA_OUTPUT, 0, 0, 1)]),
        ("db1_byte", "read DB1.DBB0 byte", [read_var_item(AREA_DB, 1, 0, 1)]),
        ("db1_4bytes", "read DB1.DBB0 four bytes", [read_var_item(AREA_DB, 1, 0, 4)]),
        ("db1_far", "read DB1 far offset", [read_var_item(AREA_DB, 1, 4096, 4)]),
        ("db9999_byte", "read non-existing DB9999 byte", [read_var_item(AREA_DB, 9999, 0, 1)]),
        ("invalid_area", "read invalid area 0xff", [read_var_item(0xFF, 0, 0, 1)]),
        ("timer0", "read timer 0", [read_var_item(AREA_TIMER, 0, 0, 1, transport_size=0x1D)]),
        ("counter0", "read counter 0", [read_var_item(AREA_COUNTER, 0, 0, 1, transport_size=0x1C)]),
        (
            "multi_m_i_q",
            "read M/I/Q byte in one request",
            [
                read_var_item(AREA_MEMORY, 0, 0, 1),
                read_var_item(AREA_INPUT, 0, 0, 1),
                read_var_item(AREA_OUTPUT, 0, 0, 1),
            ],
        ),
    ]
    write_sets = [
        ("write_m0_zero", "write zero byte to M0", read_var_item(AREA_MEMORY, 0, 0, 1), b"\x00"),
        ("write_m0_ff", "write ff byte to M0", read_var_item(AREA_MEMORY, 0, 0, 1), b"\xFF"),
        ("write_q0_zero", "write zero byte to Q0", read_var_item(AREA_OUTPUT, 0, 0, 1), b"\x00"),
        ("write_db9999", "write byte to non-existing DB9999", read_var_item(AREA_DB, 9999, 0, 1), b"\x00"),
    ]
    aggressive_sets = [
        ("unknown_fn_00", "unknown/edge function 0x00", raw_s7_job(b"\x00\x00", pdu_ref=0x60)),
        ("unknown_fn_29", "unknown/edge function 0x29", raw_s7_job(b"\x29\x00", pdu_ref=0x61)),
        ("malformed_read_empty", "malformed read without items", raw_s7_job(b"\x04\x00", pdu_ref=0x62)),
        ("malformed_write_empty", "malformed write without items", raw_s7_job(b"\x05\x00", pdu_ref=0x63)),
        ("block_list_probe", "block list style probe", raw_s7_job(b"\x1A\x00", pdu_ref=0x64)),
        ("plc_control_probe", "PLC control style probe", raw_s7_job(b"\x28\x00\x00\x00", pdu_ref=0x65)),
    ]

    for slot in slots:
        dst_tsap = dst_tsap_for_slot(slot, rack)
        prefix = cotp_cr(src_tsap, dst_tsap) + setup_communication()
        for idx, (name, desc, items) in enumerate(read_sets, start=2):
            data = prefix + read_var_request(items, pdu_ref=idx)
            candidates.append(
                Candidate(
                    name=f"s7_slot{slot}_{name}.raw",
                    data=data,
                    slot=slot,
                    dst_tsap=dst_tsap,
                    description=desc,
                )
            )
        if include_writes:
            for idx, (name, desc, item, payload) in enumerate(write_sets, start=0x20):
                data = prefix + write_var_request(item, payload, pdu_ref=idx)
                candidates.append(
                    Candidate(
                        name=f"s7_slot{slot}_{name}.raw",
                        data=data,
                        slot=slot,
                        dst_tsap=dst_tsap,
                        description=desc,
                    )
                )
        if include_aggressive:
            for name, desc, frame in aggressive_sets:
                data = prefix + frame
                candidates.append(
                    Candidate(
                        name=f"s7_slot{slot}_{name}.raw",
                        data=data,
                        slot=slot,
                        dst_tsap=dst_tsap,
                        description=desc,
                    )
                )
    return candidates


def recv_tpkt(sock: socket.socket) -> Optional[bytes]:
    header = sock.recv(4)
    if len(header) < 4:
        return None
    if header[0] != 0x03 or header[1] != 0x00:
        return header
    size = (header[2] << 8) | header[3]
    if size < 4:
        return header
    payload = bytearray()
    while len(payload) < size - 4:
        chunk = sock.recv(size - 4 - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    return header + bytes(payload)


def describe_response(resp: Optional[bytes]) -> str:
    if not resp:
        return "no response"
    if len(resp) < 7 or resp[0] != 0x03:
        return f"non-tpkt len={len(resp)}"
    cotp_type = resp[5] & 0xF0
    if cotp_type == 0xD0:
        return "cotp-cc"
    if cotp_type == 0x80:
        return "cotp-dr"
    if resp[4:7] == b"\x02\xF0\x80" and len(resp) >= 17 and resp[7] == 0x32:
        rosctr = resp[8]
        header_len = 12 if rosctr in (0x03, 0x07) and len(resp) >= 19 else 10
        err = ""
        if header_len == 12:
            err = f" err={resp[17]:02x}/{resp[18]:02x}"
        param_start = 7 + header_len
        fn = resp[param_start] if param_start < len(resp) else None
        fn_text = f" fn={fn:02x}" if fn is not None else ""
        return f"s7 rosctr={rosctr:02x}{fn_text}{err} len={len(resp)}"
    return f"tpkt cotp={cotp_type:02x} len={len(resp)}"


def probe_candidate(host: str, port: int, candidate: Candidate, timeout: float) -> ProbeResult:
    frames = split_tpkt_stream(candidate.data)
    responses: List[bytes] = []
    summaries: List[str] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for frame in frames:
                sock.sendall(frame)
                resp = recv_tpkt(sock)
                if resp:
                    responses.append(resp)
                summaries.append(describe_response(resp))
    except (OSError, socket.timeout) as exc:
        return ProbeResult(False, f"socket-error: {exc}", responses)

    has_cc = any(s == "cotp-cc" for s in summaries)
    s7_count = sum(1 for s in summaries if s.startswith("s7 "))
    ok = has_cc and s7_count >= 2
    return ProbeResult(ok, "; ".join(summaries), responses)


def write_candidate(out_dir: Path, candidate: Candidate) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / candidate.name).write_bytes(candidate.data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and optionally probe synthetic S7COMM AFLNet seeds.")
    parser.add_argument("--target", default="192.168.0.13", help="PLC IP address")
    parser.add_argument("--port", type=int, default=102, help="PLC TCP port")
    parser.add_argument("--out", default="tutorials/s7/in", help="Output directory for valid seeds")
    parser.add_argument("--candidate-out", default="/tmp/s7_synthetic_candidates", help="Directory for all generated candidates")
    parser.add_argument("--slots", default="0,1,2,3", help="Comma-separated rack 0 slot list to try")
    parser.add_argument("--rack", type=int, default=0, help="PLC rack number")
    parser.add_argument("--src-tsap", default="0x0100", help="Source TSAP, decimal or hex")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--max-valid", type=int, default=8, help="Maximum probed-valid seeds to keep")
    parser.add_argument("--include-writes", action="store_true", help="Include Write Var candidates")
    parser.add_argument("--include-aggressive", action="store_true", help="Include malformed/control/block-style probe candidates")
    parser.add_argument("--generate-only", action="store_true", help="Only write candidates; do not connect to PLC")
    parser.add_argument("--replace", action="store_true", help="Replace output directory before writing valid seeds")
    args = parser.parse_args()

    slots = [int(x.strip(), 0) for x in args.slots.split(",") if x.strip()]
    src_tsap = int(args.src_tsap, 0)
    candidates = build_candidates(slots, args.rack, src_tsap, args.include_writes, args.include_aggressive)

    candidate_out = Path(args.candidate_out)
    if candidate_out.exists():
        shutil.rmtree(candidate_out)
    candidate_out.mkdir(parents=True, exist_ok=True)
    for candidate in candidates:
        write_candidate(candidate_out, candidate)

    print(f"[*] Generated {len(candidates)} candidate seeds in {candidate_out}")

    if args.generate_only:
        return

    out_dir = Path(args.out)
    if args.replace and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    kept = 0
    for candidate in candidates:
        if kept >= args.max_valid:
            break
        started = time.time()
        result = probe_candidate(args.target, args.port, candidate, args.timeout)
        elapsed_ms = int((time.time() - started) * 1000)
        status = "KEEP" if result.ok else "DROP"
        print(f"[{status}] {candidate.name} slot={candidate.slot} dst_tsap=0x{candidate.dst_tsap:04x} {elapsed_ms}ms :: {result.summary}")
        if result.ok:
            write_candidate(out_dir, candidate)
            kept += 1

    print(f"[*] Wrote {kept} probed-valid seeds to {out_dir}")
    if kept == 0:
        print("[!] No valid seeds found. Try another --slots list or check PLC access / rack-slot settings.")


if __name__ == "__main__":
    main()
