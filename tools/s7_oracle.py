#!/usr/bin/env python3
import argparse
import json
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


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


def setup_comm() -> bytes:
    params = b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
    header = b"\x32\x01\x00\x00\x00\x01" + len(params).to_bytes(2, "big") + b"\x00\x00"
    return cotp_data(header + params)


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


def testcase_tags(data: bytes) -> List[str]:
    tags = []
    for frame in split_tpkt_stream(data):
        if len(frame) < 7:
            tags.append("short_tpkt_or_cotp")
            continue
        cotp_type = frame[5] & 0xF0
        if cotp_type == 0xE0 and len(frame) < 22:
            tags.append("truncated_cotp_cr")
        if frame[4:7] == b"\x02\xf0\x80":
            payload = frame[7:]
            if payload.startswith(b"\x32") and len(payload) < 10:
                tags.append("short_s7_header")
            if payload.startswith(b"\x32") and len(payload) >= 10:
                declared = int.from_bytes(payload[6:8], "big") + int.from_bytes(payload[8:10], "big")
                actual = len(payload) - 10
                if declared != actual:
                    tags.append("s7_declared_length_mismatch")
    return sorted(set(tags))


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
        if len(resp) >= 17 and resp[7] == 0x32:
            rosctr = resp[8]
            header_len = 12 if rosctr in (0x03, 0x07) and len(resp) >= 19 else 10
            err = ""
            if header_len == 12:
                err = f":err={resp[17]:02x}/{resp[18]:02x}"
            param_start = 7 + header_len
            fn = resp[param_start] if param_start < len(resp) else 0
            return f"s7:rosctr={rosctr:02x}:fn={fn:02x}{err}:len={len(resp)}"
        if len(resp) >= 12 and resp[7] == 0x72:
            b1 = resp[8]
            b2 = resp[9]
            b3 = resp[10]
            b4 = resp[11]
            return f"s7plus:b1={b1:02x}:b2={b2:02x}:b3={b3:02x}:b4={b4:02x}:len={len(resp)}"
    return f"tpkt:cotp={cotp_type:02x}:len={len(resp)}"


def is_abnormal_response(desc: str) -> bool:
    if desc in ("no_response",):
        return True
    if desc.startswith("cotp_dr"):
        return True
    if ":err=" in desc and ":err=00/00" not in desc:
        return True
    return False


def health_check(host: str, port: int, timeout: float, rack: int, slot: int) -> Dict[str, object]:
    dst_tsap = 0x0100 | ((rack & 0x07) << 5) | (slot & 0x1F)
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(cotp_cr(dst_tsap=dst_tsap))
            cr_resp = recv_tpkt(sock)
            sock.sendall(setup_comm())
            setup_resp = recv_tpkt(sock)
    except (OSError, socket.timeout) as exc:
        return {
            "ok": False,
            "kind": "connect_or_setup_failed",
            "detail": str(exc),
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    cr_desc = describe_response(cr_resp)
    setup_desc = describe_response(setup_resp)
    ok = cr_desc == "cotp_cc" and setup_desc.startswith("s7:")
    return {
        "ok": ok,
        "kind": "healthy" if ok else "bad_handshake",
        "cotp": cr_desc,
        "setup": setup_desc,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def replay_once(host: str, port: int, testcase: Path, timeout: float) -> Dict[str, object]:
    data = testcase.read_bytes()
    frames = split_tpkt_stream(data)
    started = time.time()
    responses = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for frame in frames:
                sock.sendall(frame)
                responses.append(describe_response(recv_tpkt(sock)))
    except (OSError, socket.timeout) as exc:
        return {
            "ok": False,
            "kind": "replay_io_error",
            "detail": str(exc),
            "responses": responses,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    abnormal = [r for r in responses if is_abnormal_response(r)]
    return {
        "ok": not abnormal,
        "kind": "abnormal_response" if abnormal else "replay_ok",
        "responses": responses,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def replay_case(host: str, port: int, testcase: Path, repeats: int, timeout: float,
                rack: int, slot: int, delay: float) -> Dict[str, object]:
    data = testcase.read_bytes()
    tags = testcase_tags(data)
    results = []
    pre = health_check(host, port, timeout, rack, slot)
    for _ in range(repeats):
        results.append(replay_once(host, port, testcase, timeout))
        if delay:
            time.sleep(delay)
    post = health_check(host, port, timeout, rack, slot)
    bad = [r for r in results if not r.get("ok")]
    reproducible = len(bad) >= max(1, (repeats + 1) // 2)
    severity = "high" if reproducible and post.get("ok") is False else "medium" if reproducible else "low"
    classification = "persistent_plc_fault" if severity == "high" else "normal_or_unreproducible"
    if reproducible and post.get("ok") is True:
        classification = "current_connection_reset"
        if "truncated_cotp_cr" in tags:
            severity = "low"
            classification = "transport_layer_current_connection_reset"
        elif "short_s7_header" in tags or "s7_declared_length_mismatch" in tags:
            classification = "s7_error_path_current_connection_reset"
    return {
        "testcase": str(testcase),
        "classification": classification,
        "testcase_tags": tags,
        "pre_health": pre,
        "post_health": post,
        "repeats": repeats,
        "bad_replays": len(bad),
        "reproducible": reproducible,
        "severity": severity,
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="S7 PLC health and replay oracle")
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--rack", type=int, default=0)
    parser.add_argument("--slot", type=int, default=0)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    replay = sub.add_parser("replay")
    replay.add_argument("testcase")
    replay.add_argument("--repeats", type=int, default=3)
    replay.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()

    if args.cmd == "health":
        result = health_check(args.target, args.port, args.timeout, args.rack, args.slot)
    else:
        result = replay_case(
            args.target,
            args.port,
            Path(args.testcase),
            args.repeats,
            args.timeout,
            args.rack,
            args.slot,
            args.delay,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
