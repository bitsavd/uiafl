#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


DEFAULT_SOURCE = Path(
    "tutorials/s7plus/vuln_repro/poc_sources/harpos7/HarpoS7/HarpoS7.PoC/Program.cs"
)


@dataclass
class Seed:
    name: str
    data: bytes
    description: str


def extract_csharp_byte_array(source: str, name: str) -> bytes:
    pattern = rf"{re.escape(name)}\s*=\s*new\s+byte\[\]\s*\{{(?P<body>.*?)\}};"
    match = re.search(pattern, source, re.DOTALL)
    if not match:
        raise ValueError(f"could not find byte array {name}")
    values = re.findall(r"0x[0-9a-fA-F]{1,2}", match.group("body"))
    if not values:
        raise ValueError(f"byte array {name} is empty")
    return bytes(int(value, 16) for value in values)


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


def fix_tpkt_len(frame: bytes) -> bytes:
    if len(frame) < 4:
        return frame
    return frame[:2] + len(frame).to_bytes(2, "big") + frame[4:]


def mutate_create_object(create_object: bytes) -> List[Seed]:
    seeds: List[Seed] = []

    # The generated mutations are intentionally conservative: they preserve
    # TPKT/COTP framing and S7CommPlus packet identity, but perturb fields that
    # influence object/session parsing and authorization state construction.
    variants: Dict[str, bytearray] = {
        "s7plus_create_msgclass_00.raw": bytearray(create_object),
        "s7plus_create_msgclass_03.raw": bytearray(create_object),
        "s7plus_create_opcode_30.raw": bytearray(create_object),
        "s7plus_create_opcode_32.raw": bytearray(create_object),
        "s7plus_create_seq_ff.raw": bytearray(create_object),
        "s7plus_create_declared_len_minus1.raw": bytearray(create_object),
        "s7plus_create_declared_len_plus1.raw": bytearray(create_object),
    }

    # TPKT(4) + COTP DT(3) + S7Plus starts at offset 7.
    s7p = 7
    if len(create_object) > s7p + 5:
        variants["s7plus_create_msgclass_00.raw"][s7p + 1] = 0x00
        variants["s7plus_create_msgclass_03.raw"][s7p + 1] = 0x03
        variants["s7plus_create_opcode_30.raw"][s7p + 4] = 0x30
        variants["s7plus_create_opcode_32.raw"][s7p + 4] = 0x32
        variants["s7plus_create_seq_ff.raw"][s7p + 3] = 0xFF

    declared = int.from_bytes(create_object[2:4], "big")
    if declared > 5:
        variants["s7plus_create_declared_len_minus1.raw"][2:4] = (declared - 1).to_bytes(2, "big")
    variants["s7plus_create_declared_len_plus1.raw"][2:4] = (declared + 1).to_bytes(2, "big")

    for name, data in variants.items():
        seeds.append(Seed(name=name, data=bytes(data), description="mutated S7CommPlus create-object request"))
    return seeds


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
    if resp[4:7] == b"\x02\xf0\x80":
        payload = resp[7:]
        if payload.startswith(b"\x72"):
            b1 = payload[1] if len(payload) > 1 else 0
            b2 = payload[2] if len(payload) > 2 else 0
            b3 = payload[3] if len(payload) > 3 else 0
            b4 = payload[4] if len(payload) > 4 else 0
            return f"s7plus:b1={b1:02x}:b2={b2:02x}:b3={b3:02x}:b4={b4:02x}:len={len(resp)}"
        if payload.startswith(b"\x32") and len(payload) >= 10:
            rosctr = payload[1]
            param_len = int.from_bytes(payload[6:8], "big")
            header_len = 12 if rosctr in (0x03, 0x07) and len(payload) >= 12 else 10
            fn = payload[header_len] if len(payload) > header_len and param_len else 0
            return f"s7:rosctr={rosctr:02x}:fn={fn:02x}:len={len(resp)}"
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
                    continue
    except OSError as exc:
        return {
            "ok": False,
            "name": seed.name,
            "description": seed.description,
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    interesting = any(r.startswith("s7plus:") for r in responses) and "timeout" not in responses
    return {
        "ok": interesting,
        "name": seed.name,
        "description": seed.description,
        "responses": responses,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def build_seeds(program_cs: Path) -> List[Seed]:
    source = program_cs.read_text(encoding="utf-8-sig")
    cotp = extract_csharp_byte_array(source, "cotpConnectionRequest")
    empty = extract_csharp_byte_array(source, "emptyDtData")
    create = extract_csharp_byte_array(source, "createObjectRequest")

    seeds = [
        Seed(
            "s7plus_session_create.raw",
            cotp + empty + create + empty,
            "HarpoS7 pre-auth session creation flow",
        ),
        Seed(
            "s7plus_session_create_no_tail_empty.raw",
            cotp + empty + create,
            "HarpoS7 session creation without final empty DT-Data",
        ),
        Seed(
            "s7plus_create_without_initial_empty.raw",
            cotp + create,
            "S7CommPlus create-object directly after COTP CR",
        ),
        Seed(
            "s7plus_empty_dt_only.raw",
            cotp + empty,
            "COTP CR followed by empty DT-Data",
        ),
    ]

    for variant in mutate_create_object(create):
        seeds.append(
            Seed(
                variant.name,
                cotp + variant.data,
                variant.description,
            )
        )

    # Also include single-frame versions for region-level mutation experiments.
    seeds.append(Seed("s7plus_frame_create_object.raw", create, "single S7CommPlus create-object frame"))
    seeds.append(Seed("s7plus_frame_empty_dt.raw", empty, "single empty COTP DT-Data frame"))
    return seeds


def main() -> None:
    parser = argparse.ArgumentParser(description="Build S7CommPlus AFLNet seeds from HarpoS7 PoC packets")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, default=Path("tutorials/s7plus/in_s7plus_candidates"))
    parser.add_argument("--select-out", type=Path, default=Path("tutorials/s7plus/in_s7plus"))
    parser.add_argument("--report", type=Path, default=Path("tutorials/s7plus/s7plus_seed_probe.json"))
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--probe", action="store_true", help="probe target PLC and copy responsive seeds to --select-out")
    args = parser.parse_args()

    seeds = build_seeds(args.source)
    args.out.mkdir(parents=True, exist_ok=True)
    args.select_out.mkdir(parents=True, exist_ok=True)

    for old in args.out.glob("*.raw"):
        old.unlink()
    for old in args.select_out.glob("*.raw"):
        old.unlink()

    for seed in seeds:
        (args.out / seed.name).write_bytes(seed.data)

    report = {
        "source": str(args.source),
        "candidate_dir": str(args.out),
        "selected_dir": str(args.select_out),
        "target": f"{args.target}:{args.port}",
        "seeds": [],
    }

    if args.probe:
        for seed in seeds:
            result = probe_seed(args.target, args.port, seed, args.timeout)
            report["seeds"].append(result)
            if result.get("ok"):
                shutil.copy2(args.out / seed.name, args.select_out / seed.name)
    else:
        for seed in seeds:
            report["seeds"].append({
                "ok": True,
                "name": seed.name,
                "description": seed.description,
                "responses": [],
            })
            shutil.copy2(args.out / seed.name, args.select_out / seed.name)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    selected = len(list(args.select_out.glob("*.raw")))
    print(f"wrote {len(seeds)} candidate seeds to {args.out}")
    print(f"selected {selected} seeds into {args.select_out}")
    print(f"report: {args.report}")


if __name__ == "__main__":
    main()
