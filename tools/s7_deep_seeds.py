#!/usr/bin/env python3
import argparse
import json
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload


def cotp_cr(src_tsap: int = 0x0100, dst_tsap: int = 0x0100) -> bytes:
    return tpkt(
        b"\x11\xe0\x00\x00\x00\x01\x00"
        + b"\xc1\x02" + src_tsap.to_bytes(2, "big")
        + b"\xc2\x02" + dst_tsap.to_bytes(2, "big")
        + b"\xc0\x01\x0a"
    )


def cotp_data(payload: bytes) -> bytes:
    return tpkt(b"\x02\xf0\x80" + payload)


def s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    return (
        b"\x32"
        + bytes([rosctr])
        + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + data_len.to_bytes(2, "big")
    )


def setup_comm(pdu_ref: int = 1, max_amq: int = 1, pdu_len: int = 480) -> bytes:
    params = b"\xf0\x00" + max_amq.to_bytes(2, "big") + max_amq.to_bytes(2, "big") + pdu_len.to_bytes(2, "big")
    return cotp_data(s7_header(0x01, pdu_ref, len(params), 0) + params)


def raw_job(params: bytes, data: bytes = b"", pdu_ref: int = 0x40,
            declared_param_len: Optional[int] = None, declared_data_len: Optional[int] = None) -> bytes:
    param_len = len(params) if declared_param_len is None else declared_param_len
    data_len = len(data) if declared_data_len is None else declared_data_len
    return cotp_data(s7_header(0x01, pdu_ref, param_len, data_len) + params + data)


def read_var_item(area: int, db_number: int, byte_offset: int, size: int, transport_size: int = 0x02) -> bytes:
    bit_addr = byte_offset * 8
    return (
        b"\x12\x0a\x10"
        + bytes([transport_size])
        + size.to_bytes(2, "big")
        + db_number.to_bytes(2, "big")
        + bytes([area])
        + bit_addr.to_bytes(3, "big")
    )


def read_var(items: List[bytes], pdu_ref: int = 2) -> bytes:
    params = b"\x04" + bytes([len(items)]) + b"".join(items)
    return raw_job(params, pdu_ref=pdu_ref)


def write_var(item: bytes, payload: bytes, pdu_ref: int = 0x20, transport_size: int = 0x04,
              declared_data_len: Optional[int] = None) -> bytes:
    params = b"\x05\x01" + item
    data = b"\x00" + bytes([transport_size]) + (len(payload) * 8).to_bytes(2, "big") + payload
    return raw_job(params, data, pdu_ref=pdu_ref, declared_data_len=declared_data_len)


def read_var_declared(items: List[bytes], pdu_ref: int, declared_param_len: int) -> bytes:
    params = b"\x04" + bytes([len(items)]) + b"".join(items)
    return raw_job(params, pdu_ref=pdu_ref, declared_param_len=declared_param_len)


def read_var_count_mismatch(items: List[bytes], declared_count: int, pdu_ref: int) -> bytes:
    params = b"\x04" + bytes([declared_count & 0xFF]) + b"".join(items)
    return raw_job(params, pdu_ref=pdu_ref)


def block_name(block_type: bytes = b"OB", block_num: int = 1, suffix: bytes = b"A") -> bytes:
    # Common S7 block strings are ASCII-ish and parser-sensitive. Keep a family
    # of plausible names without assuming a specific PLC program layout.
    return b"_" + block_type[:2].ljust(2, b"X") + f"{block_num:05d}".encode("ascii") + suffix[:1]


@dataclass
class Seed:
    name: str
    frames: List[bytes]
    description: str

    @property
    def data(self) -> bytes:
        return b"".join(self.frames)


def base_prefix(slot: int, rack: int) -> List[bytes]:
    dst_tsap = 0x0100 | ((rack & 0x07) << 5) | (slot & 0x1F)
    return [cotp_cr(dst_tsap=dst_tsap), setup_comm()]


def build_deep_seeds(slot: int, rack: int) -> List[Seed]:
    prefix = base_prefix(slot, rack)
    seeds: List[Seed] = []

    # Baselines for comparison.
    seeds.append(Seed(
        "deep_baseline_db_read.raw",
        prefix + [read_var([read_var_item(0x84, 1, 0, 4)], pdu_ref=0x10)],
        "valid DB1 read baseline",
    ))
    seeds.append(Seed(
        "deep_write_len_mismatch.raw",
        prefix + [write_var(read_var_item(0x83, 0, 0, 1), b"\x41", pdu_ref=0x11, declared_data_len=0x20)],
        "Write Var with declared data length larger than payload",
    ))

    item_db1 = read_var_item(0x84, 1, 0, 4)
    item_inputs = read_var_item(0x81, 0, 0, 1)
    item_outputs = read_var_item(0x82, 0, 0, 1)
    item_flags = read_var_item(0x83, 0, 0, 1)
    length_cases = [
        ("read_plen_0000", [item_db1], 0x0000),
        ("read_plen_0001", [item_db1], 0x0001),
        ("read_plen_0002", [item_db1], 0x0002),
        ("read_plen_000d", [item_db1], 0x000D),
        ("read_plen_000f", [item_db1], 0x000F),
        ("read_plen_0010", [item_db1], 0x0010),
        ("read_plen_00ff", [item_db1], 0x00FF),
        ("read_plen_ff00", [item_db1], 0xFF00),
        ("read_plen_fff9", [item_db1], 0xFFF9),
        ("read_plen_fffe", [item_db1], 0xFFFE),
        ("read_plen_ffff", [item_db1], 0xFFFF),
        ("read_4items_plen_short", [item_db1, item_inputs, item_outputs, item_flags], 0x000E),
        ("read_4items_plen_long", [item_db1, item_inputs, item_outputs, item_flags], 0x0100),
    ]
    pdu = 0x18
    for name, items, declared_len in length_cases:
        seeds.append(Seed(
            f"deep_len_{name}.raw",
            prefix + [read_var_declared(items, pdu_ref=pdu, declared_param_len=declared_len)],
            f"Read Var with declared parameter length 0x{declared_len:04x}",
        ))
        pdu += 1

    for count in (0, 2, 3, 4, 8, 0x7F, 0xFF):
        seeds.append(Seed(
            f"deep_len_read_count_{count:02x}.raw",
            prefix + [read_var_count_mismatch([item_db1], count, pdu_ref=pdu)],
            f"Read Var item count declares {count} with one actual item",
        ))
        pdu += 1

    write_item = read_var_item(0x83, 0, 0, 1)
    for declared_data_len in (0, 1, 2, 3, 4, 5, 8, 0x10, 0x100, 0xFFFF):
        seeds.append(Seed(
            f"deep_len_write_dlen_{declared_data_len:04x}.raw",
            prefix + [write_var(write_item, b"\x41", pdu_ref=pdu, declared_data_len=declared_data_len)],
            f"Write Var with declared data length 0x{declared_data_len:04x}",
        ))
        pdu += 1

    pdu = max(pdu, 0x40)
    for fn in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
        seeds.append(Seed(
            f"deep_fn_{fn:02x}_empty.raw",
            prefix + [raw_job(bytes([fn, 0x00]), pdu_ref=pdu)],
            f"block/download/upload function 0x{fn:02x} minimal params",
        ))
        pdu += 1
        for btype in (b"OB", b"DB", b"FC"):
            name = block_name(btype, 1)
            seeds.append(Seed(
                f"deep_fn_{fn:02x}_{btype.decode().lower()}1_name.raw",
                prefix + [raw_job(bytes([fn, len(name)]) + name, pdu_ref=pdu)],
                f"function 0x{fn:02x} with block-like name {name.decode(errors='replace')}",
            ))
            pdu += 1
        seeds.append(Seed(
            f"deep_fn_{fn:02x}_plen_short.raw",
            prefix + [raw_job(bytes([fn, 0x08]) + b"ABCDEFGH", pdu_ref=pdu, declared_param_len=2)],
            f"function 0x{fn:02x} declared param length too short",
        ))
        pdu += 1
        seeds.append(Seed(
            f"deep_fn_{fn:02x}_plen_long.raw",
            prefix + [raw_job(bytes([fn, 0x01]) + b"A", pdu_ref=pdu, declared_param_len=0x40)],
            f"function 0x{fn:02x} declared param length too long",
        ))
        pdu += 1

    # Multi-step sequences that try to move past one request/response.
    for btype in (b"OB", b"DB", b"FC"):
        name = block_name(btype, 1)
        seeds.append(Seed(
            f"deep_download_seq_{btype.decode().lower()}1.raw",
            prefix + [
                raw_job(b"\x1a" + bytes([len(name)]) + name, pdu_ref=0x70),
                raw_job(b"\x1b\x00", b"\x00" * 16, pdu_ref=0x71),
                raw_job(b"\x1c\x00", pdu_ref=0x72),
            ],
            f"request-download/download/end sequence for {name.decode(errors='replace')}",
        ))
        seeds.append(Seed(
            f"deep_upload_seq_{btype.decode().lower()}1.raw",
            prefix + [
                raw_job(b"\x1d" + bytes([len(name)]) + name, pdu_ref=0x73),
                raw_job(b"\x1e\x00", pdu_ref=0x74),
                raw_job(b"\x1f\x00", pdu_ref=0x75),
            ],
            f"start-upload/upload/end sequence for {name.decode(errors='replace')}",
        ))

    control_payloads = [
        ("plc_control_empty", b"\x28\x00"),
        ("plc_control_pbc", b"\x28\x04P_BC"),
        ("plc_control_pi_service", b"\x28\x08P_PROGRAM"),
        ("plc_stop_empty", b"\x29\x00"),
        ("plc_stop_short", b"\x29\x02ST"),
        ("plc_stop_long", b"\x29\x10" + b"STOP" * 4),
    ]
    for name, params in control_payloads:
        seeds.append(Seed(
            f"deep_{name}.raw",
            prefix + [raw_job(params, pdu_ref=pdu)],
            name.replace("_", " "),
        ))
        pdu += 1

    # State-mixing sequences: valid deeper function followed by syntactically
    # malformed S7 data, not malformed COTP.
    seeds.append(Seed(
        "deep_download_then_s7_short_header.raw",
        prefix + [
            raw_job(b"\x1a\x00", pdu_ref=0x90),
            cotp_data(b"\x32\x01\x00"),
        ],
        "download request followed by short S7 header",
    ))
    seeds.append(Seed(
        "deep_setup_then_unknown_rosctr.raw",
        prefix + [cotp_data(b"\x32\x7f\x00\x00\x00\x91\x00\x02\x00\x00\x1a\x00")],
        "unknown ROSCTR with block-like function params",
    ))
    return seeds


def recv_tpkt(sock: socket.socket) -> Optional[bytes]:
    try:
        header = sock.recv(4)
    except socket.timeout:
        return None
    if len(header) < 4:
        return None
    if header[:2] != b"\x03\x00":
        return header
    size = int.from_bytes(header[2:4], "big")
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
        return "no_response"
    if len(resp) < 7 or resp[:2] != b"\x03\x00":
        return f"non_tpkt:{len(resp)}"
    cotp_type = resp[5] & 0xF0
    if cotp_type == 0xD0:
        return "cotp_cc"
    if cotp_type == 0x80:
        return "cotp_dr"
    if resp[4:7] == b"\x02\xf0\x80" and len(resp) >= 17 and resp[7] == 0x32:
        rosctr = resp[8]
        header_len = 12 if rosctr in (0x03, 0x07) and len(resp) >= 19 else 10
        err = ""
        if header_len == 12:
            err = f":err={resp[17]:02x}/{resp[18]:02x}"
        param_start = 7 + header_len
        fn = resp[param_start] if param_start < len(resp) else 0
        return f"s7:rosctr={rosctr:02x}:fn={fn:02x}{err}:len={len(resp)}"
    return f"tpkt:cotp={cotp_type:02x}:len={len(resp)}"


def probe(host: str, port: int, seed: Seed, timeout: float, delay: float) -> Dict[str, object]:
    responses = []
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for frame in seed.frames:
                sock.sendall(frame)
                responses.append(describe_response(recv_tpkt(sock)))
                if delay:
                    time.sleep(delay)
    except (OSError, socket.timeout) as exc:
        return {
            "name": seed.name,
            "ok": False,
            "kind": "io_error",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    sem = [r for r in responses if r.startswith("s7:") or r in ("cotp_cc", "cotp_dr")]
    return {
        "name": seed.name,
        "ok": responses[:2] and responses[0] == "cotp_cc" and responses[1].startswith("s7:"),
        "kind": "probed",
        "responses": responses,
        "semantic_responses": len(sem),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deeper S7 block/control focused seeds")
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--rack", type=int, default=0)
    parser.add_argument("--out", default="tutorials/s7/in_deep")
    parser.add_argument("--candidate-out", default="tutorials/s7/in_deep_candidates")
    parser.add_argument("--report", default="tutorials/s7/deep_seed_probe.json")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()

    seeds = build_deep_seeds(args.slot, args.rack)
    cand_dir = Path(args.candidate_out)
    if args.replace and cand_dir.exists():
        shutil.rmtree(cand_dir)
    cand_dir.mkdir(parents=True, exist_ok=True)
    for seed in seeds:
        (cand_dir / seed.name).write_bytes(seed.data)
    print(f"[*] Wrote {len(seeds)} candidates to {cand_dir}")

    if args.generate_only:
        return

    out_dir = Path(args.out)
    if args.replace and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    reports = []
    kept = 0
    for seed in seeds:
        result = probe(args.target, args.port, seed, args.timeout, args.delay)
        result["description"] = seed.description
        reports.append(result)
        keep = result.get("ok") and (
            result.get("kind") == "probed" or len(result.get("responses", [])) >= 2
        )
        if keep:
            (out_dir / seed.name).write_bytes(seed.data)
            kept += 1
        print(f"[{'KEEP' if keep else 'DROP'}] {seed.name}: {result.get('responses')} {result.get('detail', '')}")

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(reports, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[*] Kept {kept} seeds in {out_dir}")
    print(f"[*] Wrote probe report to {report_path}")


if __name__ == "__main__":
    main()
