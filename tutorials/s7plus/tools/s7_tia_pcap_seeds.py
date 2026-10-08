#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT_DIR / "tools"))

from extract_s7_seeds import extract_flows_from_pcap, reassemble_tcp_payloads


MAX_SEED_LEN = 512


@dataclass
class FrameInfo:
    frame: bytes
    kind: str
    fn: Optional[int]
    score: int
    desc: str


@dataclass
class Candidate:
    name: str
    data: bytes
    score: int
    source: str
    desc: str


def classify_frame(frame: bytes) -> FrameInfo:
    if len(frame) < 7 or frame[:2] != b"\x03\x00":
        return FrameInfo(frame, "non_tpkt", None, 0, "non TPKT")

    cotp_type = frame[5] & 0xF0
    if cotp_type == 0xE0:
        return FrameInfo(frame, "cotp_cr", None, 20, "COTP connection request")
    if cotp_type == 0xD0:
        return FrameInfo(frame, "cotp_cc", None, 0, "COTP connection confirm")
    if cotp_type == 0x80:
        return FrameInfo(frame, "cotp_dr", None, 5, "COTP disconnect")

    if frame[4:7] != b"\x02\xF0\x80":
        return FrameInfo(frame, "cotp_other", None, 2, f"COTP type 0x{cotp_type:02x}")

    payload = frame[7:]
    if len(payload) >= 10 and payload[0] == 0x32:
        rosctr = payload[1]
        header_len = 12 if rosctr in (0x03, 0x07) and len(payload) >= 12 else 10
        param_len = int.from_bytes(payload[6:8], "big")
        data_len = int.from_bytes(payload[8:10], "big")
        if header_len + param_len + data_len > len(payload):
            return FrameInfo(
                frame,
                "unknown_s7like",
                None,
                3,
                f"payload starts with 0x32 but declared lengths do not fit param_len={param_len} data_len={data_len}",
            )
        fn = payload[header_len] if len(payload) > header_len and param_len else None
        score = 20
        if fn == 0xF0:
            score += 15
        elif fn in (0x04, 0x05):
            score += 35
        elif fn in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29):
            score += 55
        elif fn is not None:
            score += 40
        if data_len:
            score += min(20, data_len // 8)
        if len(frame) > 256:
            score += 8
        return FrameInfo(
            frame,
            "s7comm",
            fn,
            score,
            f"S7Comm rosctr=0x{rosctr:02x} fn={fn_hex(fn)} param_len={param_len} data_len={data_len}",
        )

    if len(payload) >= 5 and payload[0] == 0x72:
        b1, b2, b3, b4 = payload[1], payload[2], payload[3], payload[4]
        score = 70 + min(30, len(frame) // 64)
        return FrameInfo(
            frame,
            "s7plus",
            None,
            score,
            f"S7CommPlus b1=0x{b1:02x} b2=0x{b2:02x} b3=0x{b3:02x} b4=0x{b4:02x}",
        )

    return FrameInfo(frame, "unknown_dt", None, 5, "COTP DT unknown payload")


def split_tpkt_scan(buf: bytes) -> List[bytes]:
    frames: List[bytes] = []
    off = 0
    while off + 7 <= len(buf):
        if buf[off:off + 2] != b"\x03\x00":
            off += 1
            continue
        size = int.from_bytes(buf[off + 2:off + 4], "big")
        if size < 7 or off + size > len(buf):
            off += 1
            continue
        frames.append(buf[off:off + size])
        off += size
    return frames


def fn_hex(fn: Optional[int]) -> str:
    return "none" if fn is None else f"0x{fn:02x}"


def dedup(candidates: Iterable[Candidate]) -> List[Candidate]:
    seen = set()
    out: List[Candidate] = []
    for cand in candidates:
        digest = hashlib.sha256(cand.data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        out.append(cand)
    return out


def safe_name(text: str) -> str:
    keep = []
    for ch in text:
        if ch.isalnum() or ch in ("-", "_"):
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep).strip("_")[:80]


def make_candidates_for_flow(source_name: str, flow_idx: int, frames: List[FrameInfo]) -> List[Candidate]:
    candidates: List[Candidate] = []
    cr = next((item.frame for item in frames if item.kind == "cotp_cr"), None)
    setup = next((item.frame for item in frames if item.kind == "s7comm" and item.fn == 0xF0), None)
    prefix = (cr or b"") + (setup or b"")

    app_frames = [item for item in frames if item.kind in ("s7comm", "s7plus") and item.fn != 0xF0]
    for idx, item in enumerate(app_frames):
        base = prefix + item.frame
        if cr and len(base) <= MAX_SEED_LEN:
            candidates.append(Candidate(
                name=f"{source_name}_flow{flow_idx:02d}_msg{idx:03d}_{item.kind}_{fn_hex(item.fn)}.raw",
                data=base,
                score=item.score + 25,
                source=source_name,
                desc=f"{item.desc}; with COTP/setup prefix",
            ))

        if cr and idx + 1 < len(app_frames):
            pair = prefix + item.frame + app_frames[idx + 1].frame
            if len(pair) <= MAX_SEED_LEN:
                candidates.append(Candidate(
                    name=f"{source_name}_flow{flow_idx:02d}_pair{idx:03d}_{item.kind}_{fn_hex(item.fn)}.raw",
                    data=pair,
                    score=item.score + app_frames[idx + 1].score + 15,
                    source=source_name,
                    desc=f"{item.desc}; followed by {app_frames[idx + 1].desc}",
                ))

        # Oversized real TIA messages are useful as templates, but not as-is for
        # PLC fuzzing. Keep their TPKT/COTP/S7 prefix as a boundary seed.
        if cr and len(base) > MAX_SEED_LEN:
            trimmed = prefix + item.frame[: min(len(item.frame), 220)]
            if len(trimmed) <= MAX_SEED_LEN:
                candidates.append(Candidate(
                    name=f"{source_name}_flow{flow_idx:02d}_trim{idx:03d}_{item.kind}_{fn_hex(item.fn)}.raw",
                    data=trimmed,
                    score=item.score - 5,
                    source=source_name,
                    desc=f"trimmed large TIA message prefix; {item.desc}",
                ))

    # Keep short authentic setup-only sessions as low-risk anchors.
    if cr and setup and len(prefix) <= MAX_SEED_LEN:
        candidates.append(Candidate(
            name=f"{source_name}_flow{flow_idx:02d}_setup_anchor.raw",
            data=prefix,
            score=30,
            source=source_name,
            desc="authentic TIA COTP + S7 setup anchor",
        ))

    return candidates


def process_pcap(path: Path) -> Tuple[List[Candidate], Dict[str, object]]:
    flows = extract_flows_from_pcap(str(path))
    report_flows = []
    candidates: List[Candidate] = []
    source_name = safe_name(path.stem)

    for flow_idx, (key, segments) in enumerate(sorted(flows.items())):
        stream = reassemble_tcp_payloads(segments)
        raw_frames = split_tpkt_scan(stream)
        infos = [classify_frame(frame) for frame in raw_frames]
        counts: Dict[str, int] = {}
        fns: Dict[str, int] = {}
        for info in infos:
            counts[info.kind] = counts.get(info.kind, 0) + 1
            if info.fn is not None:
                key_fn = f"0x{info.fn:02x}"
                fns[key_fn] = fns.get(key_fn, 0) + 1
        flow_candidates = make_candidates_for_flow(source_name, flow_idx, infos)
        candidates.extend(flow_candidates)
        report_flows.append({
            "flow_index": flow_idx,
            "key": key,
            "segments": len(segments),
            "stream_len": len(stream),
            "frames": len(infos),
            "frame_kinds": counts,
            "functions": fns,
            "candidates": len(flow_candidates),
        })

    report = {
        "pcap": str(path),
        "flows": report_flows,
        "candidate_count": len(candidates),
    }
    return candidates, report


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract compact protocol-guided seeds from TIA Portal S7 pcaps")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--candidate-out", type=Path, default=Path("tutorials/s7plus/in_tia_candidates"))
    parser.add_argument("--select-out", type=Path, default=Path("tutorials/s7plus/in_tia_selected"))
    parser.add_argument("--report", type=Path, default=Path("tutorials/s7plus/tia_pcap_seed_report.json"))
    parser.add_argument("--top-n", type=int, default=32)
    args = parser.parse_args()

    for out_dir in (args.candidate_out, args.select_out):
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

    all_candidates: List[Candidate] = []
    reports = []
    for input_path in args.inputs:
        paths = sorted(input_path.glob("*.pcap*")) if input_path.is_dir() else [input_path]
        for path in paths:
            cands, report = process_pcap(path)
            all_candidates.extend(cands)
            reports.append(report)

    unique = dedup(all_candidates)
    unique.sort(key=lambda item: (item.score, -len(item.data)), reverse=True)

    for cand in unique:
        (args.candidate_out / cand.name).write_bytes(cand.data)

    selected: List[Candidate] = []
    source_counts: Dict[str, int] = {}
    kind_quotas = {
        "s7plus": 6,
        "fn=0x1": 8,
        "fn=0x2": 8,
        "fn=0x4": 10,
        "fn=0x5": 8,
        "anchor": 2,
    }
    selected_names = set()
    for cand in unique:
        desc = cand.desc
        bucket = "anchor" if "anchor" in desc else "other"
        if "S7CommPlus" in desc:
            bucket = "s7plus"
        elif "fn=0x1" in desc:
            bucket = "fn=0x1"
        elif "fn=0x2" in desc:
            bucket = "fn=0x2"
        elif "fn=0x4" in desc:
            bucket = "fn=0x4"
        elif "fn=0x5" in desc:
            bucket = "fn=0x5"
        if bucket in kind_quotas and kind_quotas[bucket] <= 0:
            continue
        selected.append(cand)
        selected_names.add(cand.name)
        source_counts[cand.source] = source_counts.get(cand.source, 0) + 1
        if bucket in kind_quotas:
            kind_quotas[bucket] -= 1
        if len(selected) >= args.top_n:
            break

    for cand in unique:
        if len(selected) >= args.top_n:
            break
        if cand.name in selected_names:
            continue
        selected.append(cand)

    for cand in selected:
        (args.select_out / cand.name).write_bytes(cand.data)

    final_report = {
        "inputs": [str(p) for p in args.inputs],
        "candidate_dir": str(args.candidate_out),
        "selected_dir": str(args.select_out),
        "raw_candidates": len(all_candidates),
        "unique_candidates": len(unique),
        "selected_count": len(selected),
        "selected": [
            {
                "name": cand.name,
                "len": len(cand.data),
                "score": cand.score,
                "source": cand.source,
                "desc": cand.desc,
            }
            for cand in selected
        ],
        "pcaps": reports,
    }
    args.report.write_text(json.dumps(final_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"raw candidates: {len(all_candidates)}")
    print(f"unique candidates: {len(unique)}")
    print(f"selected: {len(selected)} -> {args.select_out}")
    print(f"report: {args.report}")
    for cand in selected[:20]:
        print(f"  {cand.name} len={len(cand.data)} score={cand.score} {cand.desc}")


if __name__ == "__main__":
    main()
