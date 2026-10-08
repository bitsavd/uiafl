#!/usr/bin/env python3
import argparse
import json
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def split_tpkt_stream(data: bytes) -> List[bytes]:
    frames = []
    off = 0
    while off + 4 <= len(data):
        if data[off:off + 2] != b"\x03\x00":
            off += 1
            continue
        size = int.from_bytes(data[off + 2:off + 4], "big")
        if size < 4 or off + size > len(data):
            break
        frames.append(data[off:off + size])
        off += size
    return frames


def fix_tpkt_len(frame: bytes) -> bytes:
    if len(frame) < 4 or frame[:2] != b"\x03\x00":
        return frame
    return frame[:2] + len(frame).to_bytes(2, "big") + frame[4:]


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


def replay_once(host: str, port: int, frames: List[bytes], timeout: float, delay: float) -> Dict[str, object]:
    responses = []
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for frame in frames:
                sock.sendall(frame)
                responses.append(describe_response(recv_tpkt(sock)))
                if delay:
                    time.sleep(delay)
    except (ConnectionResetError, BrokenPipeError) as exc:
        return {
            "ok": False,
            "reset": True,
            "kind": "connection_reset",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except (OSError, socket.timeout) as exc:
        return {
            "ok": False,
            "reset": False,
            "kind": "io_error",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    return {
        "ok": True,
        "reset": False,
        "kind": "replay_ok",
        "responses": responses,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def reset_reproduces(host: str, port: int, data: bytes, repeats: int, timeout: float,
                     delay: float, min_resets: int, min_response_count: int,
                     required_responses: List[str]) -> Tuple[bool, Dict[str, object]]:
    frames = split_tpkt_stream(data)
    if not frames:
        return False, {"error": "no_tpkt_frames", "size": len(data)}
    results = []
    reset_count = 0
    qualified_reset_count = 0
    for _ in range(repeats):
        result = replay_once(host, port, frames, timeout, delay)
        results.append(result)
        if result.get("reset"):
            reset_count += 1
            responses = result.get("responses", [])
            has_enough_responses = len(responses) >= min_response_count
            has_required = all(
                any(required in response for response in responses)
                for required in required_responses
            )
            if has_enough_responses and has_required:
                qualified_reset_count += 1
    ok = qualified_reset_count >= min_resets
    return ok, {
        "size": len(data),
        "frames": len(frames),
        "repeats": repeats,
        "reset_count": reset_count,
        "qualified_reset_count": qualified_reset_count,
        "min_resets": min_resets,
        "min_response_count": min_response_count,
        "required_responses": required_responses,
        "ok": ok,
        "results": results,
    }


def rebuild(frames: List[bytes]) -> bytes:
    return b"".join(fix_tpkt_len(frame) for frame in frames if frame)


def try_accept(label: str, candidate: bytes, current: bytes, args, history: List[Dict[str, object]]) -> bytes:
    if len(candidate) >= len(current) or candidate == current:
        return current
    ok, report = reset_reproduces(
        args.target,
        args.port,
        candidate,
        args.repeats,
        args.timeout,
        args.delay,
        args.min_resets,
        args.min_response_count,
        args.require_response,
    )
    history.append({"label": label, "accepted": ok, "report": report})
    if ok:
        print(f"[+] accepted {label}: {len(current)} -> {len(candidate)} bytes")
        return candidate
    print(f"[-] rejected {label}: {len(candidate)} bytes reset={report.get('reset_count')}/{report.get('repeats')}")
    return current


def remove_frames(data: bytes, args, history: List[Dict[str, object]]) -> bytes:
    changed = True
    current = data
    while changed:
        changed = False
        frames = split_tpkt_stream(current)
        if len(frames) <= 1:
            break
        for idx in range(len(frames)):
            cand_frames = frames[:idx] + frames[idx + 1:]
            candidate = rebuild(cand_frames)
            new_current = try_accept(f"remove_frame_{idx}", candidate, current, args, history)
            if new_current != current:
                current = new_current
                changed = True
                break
    return current


def trim_frame_suffixes(data: bytes, args, history: List[Dict[str, object]]) -> bytes:
    current = data
    changed = True
    while changed:
        changed = False
        frames = split_tpkt_stream(current)
        for idx, frame in enumerate(frames):
            if len(frame) <= 7:
                continue
            for cut in [128, 64, 32, 16, 8, 4, 2, 1]:
                if len(frame) - cut < 7:
                    continue
                cand_frames = list(frames)
                cand_frames[idx] = fix_tpkt_len(frame[:-cut])
                candidate = rebuild(cand_frames)
                new_current = try_accept(f"trim_frame_{idx}_suffix_{cut}", candidate, current, args, history)
                if new_current != current:
                    current = new_current
                    changed = True
                    break
            if changed:
                break
    return current


def delete_frame_chunks(data: bytes, args, history: List[Dict[str, object]]) -> bytes:
    current = data
    for chunk in [128, 64, 32, 16, 8, 4, 2, 1]:
        changed = True
        while changed:
            changed = False
            frames = split_tpkt_stream(current)
            for idx, frame in enumerate(frames):
                if len(frame) <= 7 + chunk:
                    continue
                # Keep TPKT and COTP data header intact when possible.
                start_min = 7 if frame[4:7] == b"\x02\xf0\x80" else 4
                pos = start_min
                while pos + chunk <= len(frame):
                    cand_frame = fix_tpkt_len(frame[:pos] + frame[pos + chunk:])
                    cand_frames = list(frames)
                    cand_frames[idx] = cand_frame
                    candidate = rebuild(cand_frames)
                    new_current = try_accept(f"delete_frame_{idx}_off_{pos}_len_{chunk}", candidate, current, args, history)
                    if new_current != current:
                        current = new_current
                        changed = True
                        break
                    pos += chunk
                if changed:
                    break
    return current


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimize S7 testcase while preserving connection reset behavior")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--min-resets", type=int, default=2)
    parser.add_argument("--min-response-count", type=int, default=0)
    parser.add_argument("--require-response", action="append", default=[])
    parser.add_argument("--report", type=Path)
    parser.add_argument("--skip-chunks", action="store_true")
    args = parser.parse_args()

    data = args.input.read_bytes()
    history: List[Dict[str, object]] = []
    ok, baseline = reset_reproduces(
        args.target,
        args.port,
        data,
        args.repeats,
        args.timeout,
        args.delay,
        args.min_resets,
        args.min_response_count,
        args.require_response,
    )
    if not ok:
        raise SystemExit(f"baseline does not satisfy reset predicate: {json.dumps(baseline, sort_keys=True)}")

    current = data
    print(f"[*] baseline accepted: {len(current)} bytes")
    current = remove_frames(current, args, history)
    current = trim_frame_suffixes(current, args, history)
    if not args.skip_chunks:
        current = delete_frame_chunks(current, args, history)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(current)
    ok, final_report = reset_reproduces(
        args.target,
        args.port,
        current,
        max(args.repeats, 5),
        args.timeout,
        args.delay,
        min(args.min_resets, max(args.repeats, 5)),
        args.min_response_count,
        args.require_response,
    )
    report = {
        "input": str(args.input),
        "output": str(args.output),
        "original_size": len(data),
        "minimized_size": len(current),
        "final_ok": ok,
        "final_report": final_report,
        "history": history,
    }
    report_path = args.report or args.output.with_suffix(args.output.suffix + ".minimize.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "input": str(args.input),
        "output": str(args.output),
        "original_size": len(data),
        "minimized_size": len(current),
        "final_ok": ok,
        "report": str(report_path),
    }, indent=2))


if __name__ == "__main__":
    main()
