#!/usr/bin/env python3
import argparse
import json
import shutil
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from s7_deep_seeds import (  # noqa: E402
    base_prefix,
    cotp_data,
    raw_job,
    read_var,
    read_var_count_mismatch,
    read_var_declared,
    read_var_item,
    setup_comm,
    write_var,
)


@dataclass
class Seed:
    name: str
    frames: List[bytes]
    description: str

    @property
    def data(self) -> bytes:
        return b"".join(self.frames)


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


def s7_short_payloads() -> List[bytes]:
    payloads = [
        b"\x32",
        b"\x32\x01",
        b"\x32\x01\x00",
        b"\x32\x01\x00\x00",
        b"\x32\x01\x00\x00\x00",
        b"\x32\x01\x00\x00\x00\x20",
        b"\x32\x01\x00\x00\x00\x20\x00",
        b"\x32\x01\x00\x00\x00\x20\x00\x00",
        b"\x32\x01\x00\x00\x00\x20\x00\x00\x00",
        b"\x32\x7f\x00\x00\x00\x20\x00\x00\x00",
        b"\x32\x01\x00\x00\x00\x20\xff\xff\x00\x00",
        b"\x32\x01\x00\x00\x00\x20\x00\x00\xff\xff",
    ]
    return payloads


def build_feedback_seeds(slot: int, rack: int) -> List[Seed]:
    prefix = base_prefix(slot, rack)
    valid_read = read_var([read_var_item(0x84, 1, 0, 4)], pdu_ref=0x33)
    valid_setup = setup_comm(pdu_ref=0x34)
    seeds: List[Seed] = []

    for idx, payload in enumerate(s7_short_payloads()):
        seeds.append(Seed(
            f"feedback_short_s7_{idx:02d}.raw",
            prefix + [cotp_data(payload)],
            "setup followed by a complete COTP Data frame carrying a short or length-corrupt S7 PDU",
        ))
        seeds.append(Seed(
            f"feedback_short_s7_{idx:02d}_then_read.raw",
            prefix + [cotp_data(payload), valid_read],
            "short or length-corrupt S7 PDU followed by a valid ReadVar probe on the same connection",
        ))
        seeds.append(Seed(
            f"feedback_short_s7_{idx:02d}_then_setup.raw",
            prefix + [cotp_data(payload), valid_setup],
            "short or length-corrupt S7 PDU followed by a second Setup Communication probe",
        ))

    item_db1 = read_var_item(0x84, 1, 0, 4)
    item_bad_db = read_var_item(0x84, 0xF201, 0, 4)
    item_bad_area = read_var_item(0x7F, 1, 0, 4)
    pdu_ref = 0x50
    for declared_len in (0, 1, 2, 3, 7, 8, 9, 13, 14, 15, 16, 31, 255, 0x7FFF, 0xFF00, 0xFFFF):
        seeds.append(Seed(
            f"feedback_read_plen_{declared_len:04x}.raw",
            prefix + [read_var_declared([item_db1], pdu_ref=pdu_ref, declared_param_len=declared_len)],
            f"ReadVar with complete COTP and declared S7 parameter length 0x{declared_len:04x}",
        ))
        pdu_ref += 1

    for count in (0, 1, 2, 3, 8, 15, 16, 31, 127, 128, 255):
        seeds.append(Seed(
            f"feedback_read_count_{count:02x}.raw",
            prefix + [read_var_count_mismatch([item_db1], count, pdu_ref=pdu_ref)],
            f"ReadVar declares item count {count} with one actual item",
        ))
        pdu_ref += 1

    for item_name, item in (("bad_db", item_bad_db), ("bad_area", item_bad_area)):
        seeds.append(Seed(
            f"feedback_read_{item_name}_then_short.raw",
            prefix + [read_var([item], pdu_ref=pdu_ref), cotp_data(b"\x32")],
            f"ReadVar {item_name} semantic response followed by short S7 PDU",
        ))
        pdu_ref += 1

    write_item = read_var_item(0x83, 0, 0, 1)
    for declared_data_len in (0, 1, 2, 3, 4, 5, 8, 16, 255, 0x7FFF, 0xFFFF):
        seeds.append(Seed(
            f"feedback_write_dlen_{declared_data_len:04x}.raw",
            prefix + [write_var(write_item, b"\x41", pdu_ref=pdu_ref, declared_data_len=declared_data_len)],
            f"WriteVar with declared S7 data length 0x{declared_data_len:04x}",
        ))
        pdu_ref += 1

    for fn in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29):
        seeds.append(Seed(
            f"feedback_fn_{fn:02x}_then_short.raw",
            prefix + [raw_job(bytes([fn, 0x00]), pdu_ref=pdu_ref), cotp_data(b"\x32")],
            f"deep S7 function 0x{fn:02x} followed by short S7 PDU to test error recovery",
        ))
        pdu_ref += 1

    return seeds


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
    except (ConnectionResetError, BrokenPipeError) as exc:
        return {
            "name": seed.name,
            "ok": False,
            "kind": "connection_reset",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except (OSError, socket.timeout) as exc:
        return {
            "name": seed.name,
            "ok": False,
            "kind": "io_error",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    return {
        "name": seed.name,
        "ok": True,
        "kind": "probed",
        "responses": responses,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def keep_seed(result: Dict[str, object]) -> bool:
    responses = result.get("responses", [])
    if len(responses) < 2:
        return False
    if responses[0] != "cotp_cc" or not str(responses[1]).startswith("s7:"):
        return False
    return any(str(response).startswith("s7:") for response in responses[2:]) or result.get("kind") == "connection_reset"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate feedback-driven S7COMM seeds from minimized findings")
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--rack", type=int, default=0)
    parser.add_argument("--out", default="tutorials/s7/in_feedback")
    parser.add_argument("--candidate-out", default="tutorials/s7/in_feedback_candidates")
    parser.add_argument("--report", default="tutorials/s7/feedback_seed_probe.json")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()

    seeds = build_feedback_seeds(args.slot, args.rack)
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
        keep = keep_seed(result)
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
