#!/usr/bin/env python3
import argparse
import json
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


AREA_INPUT = 0x81
AREA_OUTPUT = 0x82
AREA_MEMORY = 0x83
AREA_DB = 0x84
AREA_COUNTER = 0x1C
AREA_TIMER = 0x1D


@dataclass
class Seed:
    name: str
    data: bytes
    category: str
    description: str
    risk: str = "medium"


def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload


def cotp_cr(src_tsap: int, dst_tsap: int, tpdu_size: int = 0x0A) -> bytes:
    return tpkt(
        b"\x11\xE0\x00\x00\x00\x01\x00"
        + b"\xC1\x02" + src_tsap.to_bytes(2, "big")
        + b"\xC2\x02" + dst_tsap.to_bytes(2, "big")
        + b"\xC0\x01" + bytes([tpdu_size])
    )


def cotp_data(payload: bytes) -> bytes:
    return tpkt(b"\x02\xF0\x80" + payload)


def s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    return (
        b"\x32" + bytes([rosctr]) + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + data_len.to_bytes(2, "big")
    )


def setup_communication(pdu_ref: int = 1, max_amq: int = 1, pdu_len: int = 480) -> bytes:
    params = b"\xF0\x00" + max_amq.to_bytes(2, "big") + max_amq.to_bytes(2, "big") + pdu_len.to_bytes(2, "big")
    return cotp_data(s7_header(0x01, pdu_ref, len(params), 0) + params)


def read_var_item(area: int, db_number: int, byte_offset: int, size: int, transport_size: int = 0x02) -> bytes:
    bit_addr = (byte_offset * 8) & 0xFFFFFF
    return (
        b"\x12\x0A\x10"
        + bytes([transport_size & 0xFF])
        + (size & 0xFFFF).to_bytes(2, "big")
        + (db_number & 0xFFFF).to_bytes(2, "big")
        + bytes([area & 0xFF])
        + bit_addr.to_bytes(3, "big")
    )


def read_var_request(items: List[bytes], pdu_ref: int, item_count: Optional[int] = None) -> bytes:
    count = len(items) if item_count is None else item_count & 0xFF
    params = b"\x04" + bytes([count]) + b"".join(items)
    return cotp_data(s7_header(0x01, pdu_ref, len(params), 0) + params)


def write_var_request(item: bytes, payload: bytes, pdu_ref: int,
                      transport_size: int = 0x04,
                      declared_bits: Optional[int] = None,
                      declared_data_len: Optional[int] = None) -> bytes:
    params = b"\x05\x01" + item
    bit_len = len(payload) * 8 if declared_bits is None else declared_bits & 0xFFFF
    data = b"\x00" + bytes([transport_size & 0xFF]) + bit_len.to_bytes(2, "big") + payload
    data_len = len(data) if declared_data_len is None else declared_data_len & 0xFFFF
    return cotp_data(s7_header(0x01, pdu_ref, len(params), data_len) + params + data)


def raw_s7_job(params: bytes, data: bytes = b"", pdu_ref: int = 0x40,
               declared_param_len: Optional[int] = None,
               declared_data_len: Optional[int] = None) -> bytes:
    param_len = len(params) if declared_param_len is None else declared_param_len & 0xFFFF
    data_len = len(data) if declared_data_len is None else declared_data_len & 0xFFFF
    return cotp_data(s7_header(0x01, pdu_ref, param_len, data_len) + params + data)


def patch_tpkt_length(frame: bytes, declared_len: int) -> bytes:
    if len(frame) < 4:
        return frame
    return frame[:2] + (declared_len & 0xFFFF).to_bytes(2, "big") + frame[4:]


def dst_tsap(rack: int, slot: int, connection_type: int) -> int:
    return ((connection_type & 0xFF) << 8) | (((rack & 0x07) << 5) | (slot & 0x1F))


def prefix(rack: int, slot: int, connection_type: int, pdu_len: int = 480,
           max_amq: int = 1, src_tsap: int = 0x0100, tpdu_size: int = 0x0A) -> bytes:
    return cotp_cr(src_tsap, dst_tsap(rack, slot, connection_type), tpdu_size) + setup_communication(1, max_amq, pdu_len)


def build_deep_seeds(rack: int, slot: int, src_tsap: int) -> List[Seed]:
    seeds: List[Seed] = []

    for conn_type, name in ((0x01, "pg"), (0x02, "op"), (0x03, "basic")):
        seeds.append(Seed(
            f"deep_tsap_{name}_read_m0.raw",
            prefix(rack, slot, conn_type, src_tsap=src_tsap) + read_var_request([read_var_item(AREA_MEMORY, 0, 0, 1)], 2),
            "tsap",
            f"read M0 using connection type {name}",
            "low",
        ))

    for pdu_len in (0x00F0, 0x01E0, 0x03C0, 0x0780, 0xFFFF):
        seeds.append(Seed(
            f"deep_setup_pdu_{pdu_len:04x}_then_read.raw",
            prefix(rack, slot, 0x01, pdu_len=pdu_len, src_tsap=src_tsap)
            + read_var_request([read_var_item(AREA_MEMORY, 0, 0, 1)], 3),
            "setup",
            f"negotiate PDU length 0x{pdu_len:04x} then read M0",
            "medium",
        ))

    for max_amq in (0, 1, 2, 8, 0xFFFF):
        seeds.append(Seed(
            f"deep_setup_amq_{max_amq:04x}_then_read.raw",
            prefix(rack, slot, 0x01, max_amq=max_amq, src_tsap=src_tsap)
            + read_var_request([read_var_item(AREA_MEMORY, 0, 0, 1)], 4),
            "setup",
            f"negotiate max AMQ 0x{max_amq:04x} then read M0",
            "medium",
        ))

    base = prefix(rack, slot, 0x01, src_tsap=src_tsap)
    boundary_reads = [
        ("m_bit_bool", AREA_MEMORY, 0, 0, 1, 0x01),
        ("m_size0", AREA_MEMORY, 0, 0, 0, 0x02),
        ("m_size240", AREA_MEMORY, 0, 0, 240, 0x02),
        ("m_offset255", AREA_MEMORY, 0, 255, 1, 0x02),
        ("m_offset256", AREA_MEMORY, 0, 256, 1, 0x02),
        ("m_offset65535", AREA_MEMORY, 0, 65535, 1, 0x02),
        ("m_offset24bit", AREA_MEMORY, 0, 0x1FFFFF, 1, 0x02),
        ("db0", AREA_DB, 0, 0, 1, 0x02),
        ("db1_offset65535", AREA_DB, 1, 65535, 1, 0x02),
        ("dbffff", AREA_DB, 0xFFFF, 0, 1, 0x02),
        ("area00", 0x00, 0, 0, 1, 0x02),
        ("areaff", 0xFF, 0, 0, 1, 0x02),
        ("counter_as_byte", AREA_COUNTER, 0, 0, 1, 0x02),
        ("timer_as_byte", AREA_TIMER, 0, 0, 1, 0x02),
    ]
    for idx, (name, area, db, off, size, tsize) in enumerate(boundary_reads, start=0x10):
        seeds.append(Seed(
            f"deep_read_{name}.raw",
            base + read_var_request([read_var_item(area, db, off, size, tsize)], idx),
            "read_boundary",
            f"Read Var boundary area=0x{area:02x} db={db} offset={off} size={size} tsize=0x{tsize:02x}",
            "medium",
        ))

    multi_sets = [
        ("multi_4_m", [read_var_item(AREA_MEMORY, 0, off, 1) for off in (0, 1, 2, 3)]),
        ("multi_8_m", [read_var_item(AREA_MEMORY, 0, off, 1) for off in range(8)]),
        ("multi_m_db_badarea", [
            read_var_item(AREA_MEMORY, 0, 0, 1),
            read_var_item(AREA_DB, 1, 0, 1),
            read_var_item(0xFF, 0, 0, 1),
        ]),
    ]
    for idx, (name, items) in enumerate(multi_sets, start=0x30):
        seeds.append(Seed(
            f"deep_read_{name}.raw",
            base + read_var_request(items, idx),
            "multi_item",
            f"Read Var with {len(items)} variable items",
            "medium",
        ))

    count_mismatch_item = read_var_item(AREA_MEMORY, 0, 0, 1)
    for declared_count in (0, 2, 0xFF):
        seeds.append(Seed(
            f"deep_read_item_count_{declared_count:02x}.raw",
            base + read_var_request([count_mismatch_item], 0x40 + declared_count % 16, item_count=declared_count),
            "length_mismatch",
            f"Read Var item count declares {declared_count} for one encoded item",
            "high",
        ))

    params = b"\x04\x01" + read_var_item(AREA_MEMORY, 0, 0, 1)
    for plen in (0, 1, 2, len(params) - 1, len(params) + 1, 0xFFFF):
        seeds.append(Seed(
            f"deep_read_param_len_{plen:04x}.raw",
            base + raw_s7_job(params, pdu_ref=0x50 + (plen & 0x0F), declared_param_len=plen),
            "length_mismatch",
            f"Read Var parameter length declared as 0x{plen:04x}",
            "high",
        ))

    write_item = read_var_item(AREA_MEMORY, 0, 0, 1)
    write_cases = [
        ("zero_payload", b"", None, None),
        ("decl_bits_0000", b"\x00", 0, None),
        ("decl_bits_0007", b"\x00", 7, None),
        ("decl_bits_ffff", b"\x00", 0xFFFF, None),
        ("decl_dlen_0000", b"\x00", None, 0),
        ("decl_dlen_0003", b"\x00", None, 3),
        ("decl_dlen_ffff", b"\x00", None, 0xFFFF),
    ]
    for idx, (name, payload, bits, data_len) in enumerate(write_cases, start=0x60):
        seeds.append(Seed(
            f"deep_write_m0_{name}.raw",
            base + write_var_request(write_item, payload, idx, declared_bits=bits, declared_data_len=data_len),
            "write_boundary",
            f"Write Var boundary/mismatch case {name}",
            "high",
        ))

    block_and_control = [
        ("cpu_service_empty", b"\x00"),
        ("mode_transition_empty", b"\x01"),
        ("request_download_empty", b"\x1A\x00"),
        ("download_block_empty", b"\x1B\x00"),
        ("download_ended_empty", b"\x1C\x00"),
        ("start_upload_empty", b"\x1D\x00"),
        ("upload_empty", b"\x1E\x00"),
        ("end_upload_empty", b"\x1F\x00"),
        ("pi_service_empty", b"\x28\x00"),
        ("plc_stop_empty", b"\x29\x00"),
    ]
    for idx, (name, params) in enumerate(block_and_control, start=0x80):
        seeds.append(Seed(
            f"deep_fn_{name}.raw",
            base + raw_s7_job(params, pdu_ref=idx),
            "block_control",
            f"Block/control function probe {name}",
            "high",
        ))

    normal = base + read_var_request([read_var_item(AREA_MEMORY, 0, 0, 1)], 0xA0)
    frames = split_tpkt_stream(normal)
    if frames:
        last = frames[-1]
        seeds.append(Seed(
            "deep_tpkt_declared_short.raw",
            b"".join(frames[:-1]) + patch_tpkt_length(last, max(4, len(last) - 1)),
            "transport_length",
            "TPKT declared length one byte shorter than actual S7 frame",
            "high",
        ))
        seeds.append(Seed(
            "deep_tpkt_declared_long.raw",
            b"".join(frames[:-1]) + patch_tpkt_length(last, len(last) + 1),
            "transport_length",
            "TPKT declared length one byte longer than actual S7 frame",
            "high",
        ))

    return seeds


def split_tpkt_stream(data: bytes) -> List[bytes]:
    frames: List[bytes] = []
    off = 0
    while off + 4 <= len(data):
        if data[off:off + 2] != b"\x03\x00":
            break
        size = int.from_bytes(data[off + 2:off + 4], "big")
        if size < 4 or off + size > len(data):
            break
        frames.append(data[off:off + size])
        off += size
    return frames


def recv_tpkt(sock: socket.socket) -> Optional[bytes]:
    header = sock.recv(4)
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
    if resp[4:7] == b"\x02\xF0\x80" and len(resp) >= 17 and resp[7] == 0x32:
        rosctr = resp[8]
        header_len = 12 if rosctr in (0x03, 0x07) and len(resp) >= 19 else 10
        err = ""
        if header_len == 12:
            err = f":err={resp[17]:02x}/{resp[18]:02x}"
        param_start = 7 + header_len
        fn = resp[param_start] if param_start < len(resp) else 0
        return f"s7:rosctr={rosctr:02x}:fn={fn:02x}{err}:len={len(resp)}"
    return f"tpkt:cotp={cotp_type:02x}:len={len(resp)}"


def probe_seed(host: str, port: int, seed: Seed, timeout: float) -> Dict[str, object]:
    frames = split_tpkt_stream(seed.data)
    responses: List[str] = []
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for frame in frames:
                sock.sendall(frame)
                try:
                    responses.append(describe_response(recv_tpkt(sock)))
                except socket.timeout:
                    responses.append("timeout")
                    break
    except OSError as exc:
        return {
            "ok": False,
            "name": seed.name,
            "category": seed.category,
            "risk": seed.risk,
            "description": seed.description,
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    s7_responses = [r for r in responses if r.startswith("s7:")]
    ok = any(r == "cotp_cc" for r in responses) and bool(s7_responses) and "timeout" not in responses
    abnormal = any(":err=" in r and ":err=00/00" not in r for r in s7_responses)
    return {
        "ok": ok,
        "abnormal": abnormal,
        "name": seed.name,
        "category": seed.category,
        "risk": seed.risk,
        "description": seed.description,
        "responses": responses,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def write_dictionary(path: Path) -> None:
    tokens = [
        b"\x03\x00", b"\x11\xE0", b"\x02\xF0\x80", b"\x32\x01",
        b"\x32\x03", b"\xF0\x00", b"\x04\x01", b"\x05\x01",
        b"\x12\x0A\x10", b"\x81", b"\x82", b"\x83", b"\x84",
        b"\x1C", b"\x1D", b"\x1A\x00", b"\x1B\x00", b"\x1C\x00",
        b"\x1D\x00", b"\x1E\x00", b"\x1F\x00", b"\x28\x00",
        b"\x29\x00", b"\x00\x00", b"\xFF\xFF", b"\x00\x01",
        b"\x01\xE0", b"\x03\xC0",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for idx, token in enumerate(sorted(set(tokens))):
        escaped = "".join(f"\\x{b:02x}" for b in token)
        lines.append(f's7_deep_{idx}="{escaped}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def selection_score(result: Dict[str, object]) -> int:
    score = 0
    category = str(result.get("category", ""))
    risk = str(result.get("risk", "medium"))
    responses = [str(r) for r in result.get("responses", [])]

    if risk == "high":
        score += 30
    elif risk == "medium":
        score += 15
    else:
        score += 5

    category_weights = {
        "length_mismatch": 45,
        "write_boundary": 40,
        "block_control": 38,
        "transport_length": 35,
        "multi_item": 30,
        "read_boundary": 25,
        "setup": 18,
        "tsap": 12,
    }
    score += category_weights.get(category, 10)

    if result.get("abnormal"):
        score += 35
    if any(":fn=85:" in r or ":fn=84:" in r or ":fn=81:" in r for r in responses):
        score += 25
    if any(":fn=05:" in r for r in responses):
        score += 15
    if any(":fn=04:" in r and ":len=25" in r for r in responses):
        score += 10
    return score


def main() -> None:
    parser = argparse.ArgumentParser(description="Build protocol-guided deep S7Comm seeds")
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--rack", type=int, default=0)
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--src-tsap", default="0x0100")
    parser.add_argument("--timeout", type=float, default=0.8)
    parser.add_argument("--out", type=Path, default=Path("tutorials/s7/in_deep_selected"))
    parser.add_argument("--candidate-out", type=Path, default=Path("tutorials/s7/in_deep_candidates"))
    parser.add_argument("--report", type=Path, default=Path("tutorials/s7/deep_seed_probe.json"))
    parser.add_argument("--dict-out", type=Path, default=Path("tutorials/s7/s7_deep.dict"))
    parser.add_argument("--max-selected", type=int, default=24)
    parser.add_argument("--generate-only", action="store_true")
    args = parser.parse_args()

    src_tsap = int(args.src_tsap, 0)
    seeds = build_deep_seeds(args.rack, args.slot, src_tsap)

    if args.candidate_out.exists():
        shutil.rmtree(args.candidate_out)
    if args.out.exists():
        shutil.rmtree(args.out)
    args.candidate_out.mkdir(parents=True, exist_ok=True)
    args.out.mkdir(parents=True, exist_ok=True)

    for seed in seeds:
        (args.candidate_out / seed.name).write_bytes(seed.data)

    report: Dict[str, object] = {
        "target": f"{args.target}:{args.port}",
        "candidate_dir": str(args.candidate_out),
        "selected_dir": str(args.out),
        "method": "protocol-guided S7Comm seed generation from public S7Comm structure references",
        "seeds": [],
    }

    results: List[Dict[str, object]] = []
    for seed in seeds:
        if args.generate_only:
            result = {
                "ok": True,
                "name": seed.name,
                "category": seed.category,
                "risk": seed.risk,
                "description": seed.description,
                "responses": [],
            }
        else:
            result = probe_seed(args.target, args.port, seed, args.timeout)
        report["seeds"].append(result)
        results.append(result)
        status = "OK" if result.get("ok") else "BAD"
        print(f"[{status}] {seed.name} :: {'; '.join(result.get('responses', []))} {result.get('detail', '')}")

    eligible = [result for result in results if result.get("ok")]
    eligible.sort(key=selection_score, reverse=True)

    selected_results: List[Dict[str, object]] = []
    category_counts: Dict[str, int] = {}

    # First pass: guarantee category diversity when possible.
    for result in eligible:
        category = str(result.get("category", "unknown"))
        if category_counts.get(category, 0) >= 3:
            continue
        selected_results.append(result)
        category_counts[category] = category_counts.get(category, 0) + 1
        if len(selected_results) >= args.max_selected:
            break

    # Second pass: fill remaining slots by score.
    selected_names = {str(result.get("name")) for result in selected_results}
    for result in eligible:
        if len(selected_results) >= args.max_selected:
            break
        name = str(result.get("name"))
        if name in selected_names:
            continue
        selected_results.append(result)
        selected_names.add(name)
        category = str(result.get("category", "unknown"))
        category_counts[category] = category_counts.get(category, 0) + 1

    for result in selected_results:
        name = str(result["name"])
        shutil.copy2(args.candidate_out / name, args.out / name)
        print(f"[KEEP] {name} score={selection_score(result)} category={result.get('category')}")

    report["selected_count"] = len(selected_results)
    report["selected_categories"] = category_counts
    report["selected_names"] = [str(result["name"]) for result in selected_results]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_dictionary(args.dict_out)

    print(f"wrote {len(seeds)} candidates to {args.candidate_out}")
    print(f"selected {len(selected_results)} seeds into {args.out}")
    print(f"wrote report {args.report}")
    print(f"wrote dictionary {args.dict_out}")


if __name__ == "__main__":
    main()
