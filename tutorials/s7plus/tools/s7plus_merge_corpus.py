#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


@dataclass
class Candidate:
    path: Path
    data: bytes
    source: str
    name: str
    features: Dict[str, object]
    score: int = 0
    probe: Optional[Dict[str, object]] = None


def split_tpkt_stream(data: bytes) -> List[bytes]:
    frames: List[bytes] = []
    off = 0
    while off + 4 <= len(data):
        if data[off:off + 2] != b"\x03\x00":
            off += 1
            continue
        size = int.from_bytes(data[off + 2:off + 4], "big")
        if size < 4 or off + size > len(data):
            off += 1
            continue
        frames.append(data[off:off + size])
        off += size
    return frames


def describe_frame(frame: bytes) -> Dict[str, object]:
    desc: Dict[str, object] = {"len": len(frame), "kind": "unknown"}
    if len(frame) < 7 or frame[:2] != b"\x03\x00":
        return desc
    cotp_type = frame[5] & 0xF0
    desc["cotp_type"] = f"0x{cotp_type:02x}"
    if cotp_type == 0xE0:
        desc["kind"] = "cotp_cr"
        return desc
    if cotp_type == 0xD0:
        desc["kind"] = "cotp_cc"
        return desc
    if cotp_type == 0x80:
        desc["kind"] = "cotp_dr"
        return desc
    if frame[4:7] == b"\x02\xf0\x80":
        payload = frame[7:]
        if len(payload) >= 5 and payload[0] == 0x72:
            desc.update({
                "kind": "s7plus",
                "b1": payload[1],
                "b2": payload[2],
                "b3": payload[3],
                "b4": payload[4],
                "prefix5": payload[:5].hex(),
            })
        elif len(payload) >= 10 and payload[0] == 0x32:
            desc["kind"] = "s7comm"
        else:
            desc["kind"] = "cotp_dt_unknown"
    return desc


def analyze(data: bytes) -> Dict[str, object]:
    frames = split_tpkt_stream(data)
    frame_desc = [describe_frame(frame) for frame in frames]
    s7p = [item for item in frame_desc if item.get("kind") == "s7plus"]
    prefixes = sorted({str(item.get("prefix5")) for item in s7p if item.get("prefix5")})
    has_cr = any(item.get("kind") == "cotp_cr" for item in frame_desc)
    return {
        "len": len(data),
        "frames": len(frames),
        "has_cotp_cr": has_cr,
        "s7plus_frames": len(s7p),
        "s7plus_prefixes": prefixes,
        "frame_desc": frame_desc,
    }


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
        if len(payload) >= 5 and payload[0] == 0x72:
            return f"s7plus:b1={payload[1]:02x}:b2={payload[2]:02x}:b3={payload[3]:02x}:b4={payload[4]:02x}:len={len(resp)}"
        if len(payload) >= 10 and payload[0] == 0x32:
            return f"s7:rosctr={payload[1]:02x}:len={len(resp)}"
    return f"tpkt:cotp={cotp_type:02x}:len={len(resp)}"


def probe(host: str, port: int, data: bytes, timeout: float) -> Dict[str, object]:
    frames = split_tpkt_stream(data)
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
    except (OSError, socket.timeout) as exc:
        return {
            "ok": False,
            "kind": "io_error",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    ok = any(response.startswith("s7plus:") for response in responses)
    return {
        "ok": ok,
        "kind": "probed",
        "responses": responses,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def source_name(path: Path, roots: List[Path]) -> str:
    for root in roots:
        try:
            rel = path.relative_to(root)
            return root.name
        except ValueError:
            continue
    return path.parent.name


def load_candidates(paths: Iterable[Path]) -> List[Candidate]:
    roots = [path for path in paths if path.is_dir()]
    candidates: List[Candidate] = []
    files: List[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.raw")))
        elif path.is_file() and path.suffix == ".raw":
            files.append(path)
    for path in sorted(files):
        data = path.read_bytes()
        features = analyze(data)
        if features["s7plus_frames"] <= 0:
            continue
        candidates.append(Candidate(path, data, source_name(path, roots), path.name, features))
    return candidates


def dedup(candidates: List[Candidate]) -> List[Candidate]:
    seen = set()
    unique = []
    for cand in candidates:
        digest = hashlib.sha256(cand.data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unique.append(cand)
    return unique


def score_candidate(cand: Candidate) -> int:
    features = cand.features
    probe_info = cand.probe or {}
    score = 0
    if features.get("has_cotp_cr"):
        score += 20
    score += int(features.get("s7plus_frames", 0)) * 30
    score += len(features.get("s7plus_prefixes", [])) * 20
    length = int(features.get("len", 0))
    if length <= 128:
        score += 25
    elif length <= 320:
        score += 15
    else:
        score -= 15
    if probe_info.get("ok"):
        score += 50
    if "timeout" in probe_info.get("responses", []):
        score -= 20
    if probe_info.get("kind") == "io_error":
        score -= 10
    if "tia" in cand.source:
        score += 10
    if "in_s7plus" in cand.source:
        score += 8
    return score


def write_dictionary(path: Path) -> None:
    tokens = [
        b"\x03\x00", b"\x11\xe0", b"\x02\xf0\x80", b"\x72",
        b"\x72\x01", b"\x72\x02", b"\x72\x03", b"\x72\x01\x00",
        b"\x12\x31", b"\x00\x12\x31", b"\xf6\xf8", b"\x3c\x9e",
        b"\x08\xe8", b"\xd0\xe0", b"\x31\x00", b"\x70\x40",
        b"\x82\x32", b"\x8e\x26", b"\x8e\x09", b"\x8e\x0a",
        b"\x8e\x0b", b"\x8e\x0c", b"\x8e\x0d", b"\x00\x00",
        b"\x00\x01", b"\xff\xff",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for idx, token in enumerate(sorted(set(tokens))):
        escaped = "".join(f"\\x{b:02x}" for b in token)
        lines.append(f's7plus_{idx}="{escaped}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge and rank S7CommPlus seeds")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--candidate-out", type=Path, default=Path("tutorials/s7plus/in_s7plus_all_candidates"))
    parser.add_argument("--out", type=Path, default=Path("tutorials/s7plus/in_s7plus_final"))
    parser.add_argument("--report", type=Path, default=Path("tutorials/s7plus/s7plus_final_guidance.json"))
    parser.add_argument("--dict-out", type=Path, default=Path("tutorials/s7plus/s7plus_final.dict"))
    parser.add_argument("--top-n", type=int, default=16)
    args = parser.parse_args()

    for out_dir in (args.candidate_out, args.out):
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

    candidates = dedup(load_candidates(args.inputs))
    for cand in candidates:
        cand.probe = probe(args.target, args.port, cand.data, args.timeout)
        cand.score = score_candidate(cand)

    candidates.sort(key=lambda item: (item.score, -int(item.features["len"])), reverse=True)
    for idx, cand in enumerate(candidates):
        out_name = f"{idx:03d}_{cand.source}_{cand.name}"
        (args.candidate_out / out_name).write_bytes(cand.data)

    selected: List[Candidate] = []
    prefix_counts: Dict[tuple, int] = {}
    source_counts: Dict[str, int] = {}
    for cand in candidates:
        if len(selected) >= args.top_n:
            break
        if not (cand.probe or {}).get("ok"):
            continue
        prefixes = tuple(cand.features.get("s7plus_prefixes", []))
        prefix_count = prefix_counts.get(prefixes, 0)
        source_count = source_counts.get(cand.source, 0)
        if prefixes and prefix_count >= 3:
            continue
        if prefixes and prefix_count >= 2 and "tia" in cand.source and len(selected) >= 4:
            continue
        if source_count >= 4 and len(selected) >= 8:
            continue
        selected.append(cand)
        prefix_counts[prefixes] = prefix_count + 1
        source_counts[cand.source] = source_count + 1

    for cand in candidates:
        if len(selected) >= args.top_n:
            break
        if cand in selected or not (cand.probe or {}).get("ok"):
            continue
        selected.append(cand)

    for idx, cand in enumerate(selected):
        out_name = f"{idx:03d}_{cand.source}_{cand.name}"
        (args.out / out_name).write_bytes(cand.data)

    report = {
        "inputs": [str(path) for path in args.inputs],
        "candidate_count": len(candidates),
        "selected_count": len(selected),
        "candidate_dir": str(args.candidate_out),
        "selected_dir": str(args.out),
        "selected": [
            {
                "name": cand.name,
                "source": cand.source,
                "len": cand.features["len"],
                "frames": cand.features["frames"],
                "s7plus_frames": cand.features["s7plus_frames"],
                "s7plus_prefixes": cand.features["s7plus_prefixes"],
                "score": cand.score,
                "probe": cand.probe,
            }
            for cand in selected
        ],
        "candidates": [
            {
                "name": cand.name,
                "source": cand.source,
                "len": cand.features["len"],
                "score": cand.score,
                "probe": cand.probe,
                "features": cand.features,
            }
            for cand in candidates
        ],
    }
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_dictionary(args.dict_out)

    print(f"candidates: {len(candidates)}")
    print(f"selected: {len(selected)} -> {args.out}")
    print(f"dictionary: {args.dict_out}")
    print(f"report: {args.report}")
    for cand in selected:
        print(f"  {cand.source}/{cand.name} len={cand.features['len']} score={cand.score} responses={cand.probe.get('responses') if cand.probe else []}")


if __name__ == "__main__":
    main()
