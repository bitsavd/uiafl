#!/usr/bin/env python3
"""
Extract and generate S7COMM seeds for AFLNet.

This script supports:
  - extracting client->server S7COMM payload streams from pcap/pcapng files
  - cleaning and deduplicating S7 request sequences
  - splitting individual S7 requests into separate seed files
  - generating synthetic S7COMM candidate seeds from protocol templates

Usage examples:
  python3 tools/extract_s7_seeds.py /path/to/pcap_dir -o tutorials/s7/in --dedup --split-requests
  python3 tools/extract_s7_seeds.py --auto-gen 10 -o tutorials/s7/in
"""

import argparse
import hashlib
import importlib.util
import os
import random
import shutil
import sys
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from scapy.utils import RawPcapNgReader, RawPcapReader
except ImportError:  # pragma: no cover
    RawPcapNgReader = RawPcapReader = None


MIN_SEED_SIZE = 16
AUTO_GEN_TEMPLATES = 8


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_pcap(infile: str):
    if RawPcapNgReader is None or RawPcapReader is None:
        raise ImportError("scapy is required for pcap/pcapng extraction")
    try:
        return RawPcapNgReader(infile)
    except Exception:
        return RawPcapReader(infile)


def is_tpkt_frame(frame: bytes) -> bool:
    if len(frame) < 7 or frame[0] != 0x03 or frame[1] != 0x00:
        return False
    pkt_len = (frame[2] << 8) | frame[3]
    return pkt_len == len(frame)


def is_relevant_s7_tpkt_frame(frame: bytes) -> bool:
    if not is_tpkt_frame(frame):
        return False

    cotp_type = frame[5] & 0xF0
    if cotp_type in (0xE0, 0xD0, 0x80):  # CR, CC, DR
        return True

    return (
        frame[4] == 0x02
        and frame[5] == 0xF0
        and frame[6] == 0x80
        and len(frame) >= 18
        and frame[7] == 0x32
    )


def split_tpkt_stream(buf: bytes) -> List[bytes]:
    chunks = []
    offset = 0
    while offset + 4 <= len(buf):
        if buf[offset] != 0x03:
            break
        pkt_len = (buf[offset + 2] << 8) | buf[offset + 3]
        if pkt_len < 4 or offset + pkt_len > len(buf):
            break
        chunks.append(buf[offset : offset + pkt_len])
        offset += pkt_len
    if not chunks and buf:
        chunks.append(buf)
    return chunks


def _pkt_time(pkt) -> float:
    try:
        return float(pkt.time)
    except Exception:
        return 0.0


def parse_tcp_packet(frame: bytes) -> Optional[Tuple[str, int, str, int, int, bytes]]:
    if len(frame) < 14:
        return None

    eth_type = (frame[12] << 8) | frame[13]
    offset = 14
    if eth_type in (0x8100, 0x88A8) and len(frame) >= 18:
        eth_type = (frame[16] << 8) | frame[17]
        offset = 18

    if eth_type == 0x0800:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return None
        proto = frame[offset + 9]
        if proto != 6:
            return None
        total_len = (frame[offset + 2] << 8) | frame[offset + 3]
        ip_end = min(len(frame), offset + total_len) if total_len else len(frame)
        src = ".".join(str(b) for b in frame[offset + 12 : offset + 16])
        dst = ".".join(str(b) for b in frame[offset + 16 : offset + 20])
        tcp_off = offset + ihl
    elif eth_type == 0x86DD:
        if len(frame) < offset + 40:
            return None
        next_header = frame[offset + 6]
        if next_header != 6:
            return None
        payload_len = (frame[offset + 4] << 8) | frame[offset + 5]
        ip_end = min(len(frame), offset + 40 + payload_len)
        src = frame[offset + 8 : offset + 24].hex(":")
        dst = frame[offset + 24 : offset + 40].hex(":")
        tcp_off = offset + 40
    else:
        return None

    if len(frame) < tcp_off + 20 or ip_end < tcp_off + 20:
        return None

    sport = (frame[tcp_off] << 8) | frame[tcp_off + 1]
    dport = (frame[tcp_off + 2] << 8) | frame[tcp_off + 3]
    seq = int.from_bytes(frame[tcp_off + 4 : tcp_off + 8], "big")
    data_off = (frame[tcp_off + 12] >> 4) * 4
    if data_off < 20:
        return None
    payload_off = tcp_off + data_off
    if payload_off > ip_end:
        return None
    return src, sport, dst, dport, seq, frame[payload_off:ip_end]


def extract_flows_from_pcap(infile: str) -> Dict[Tuple[str, int, str, int], List[Tuple[int, float, bytes]]]:
    flows = {}
    rdr = read_pcap(infile)
    for idx, item in enumerate(rdr):
        frame = item[0] if isinstance(item, tuple) else item
        parsed = parse_tcp_packet(bytes(frame))
        if parsed is None:
            continue
        src, sport, dst, dport, seq, payload = parsed
        if dport != 102:
            continue
        if not payload:
            continue
        key = (src, sport, dst, dport)
        flows.setdefault(key, []).append((seq, float(idx), payload))
    return flows


def reassemble_tcp_payloads(segments: List[Tuple[int, float, bytes]]) -> bytes:
    if not segments:
        return b""

    ordered = sorted(segments, key=lambda x: (x[0], x[1]))
    stream = bytearray()
    next_seq: Optional[int] = None

    for seq, _ts, payload in ordered:
        if not payload:
            continue
        if next_seq is None:
            stream.extend(payload)
            next_seq = seq + len(payload)
            continue
        if seq < next_seq:
            overlap = next_seq - seq
            if overlap >= len(payload):
                continue
            payload = payload[overlap:]
        elif seq > next_seq:
            # A capture gap: keep the byte stream parseable by starting a new island.
            next_seq = seq
        stream.extend(payload)
        next_seq += len(payload)

    return bytes(stream)


def normalize_request_sequence(segments: List[Tuple[int, float, bytes]]) -> bytes:
    stream = reassemble_tcp_payloads(segments)
    cleaned = bytearray()
    for frame in split_tpkt_stream(stream):
        if is_relevant_s7_tpkt_frame(frame):
            cleaned.extend(frame)
    return bytes(cleaned)


def deduplicate_seeds(seeds: Iterable[bytes]) -> List[bytes]:
    seen = set()
    unique = []
    for seed in seeds:
        if len(seed) < MIN_SEED_SIZE:
            continue
        digest = hashlib.sha256(seed).hexdigest()
        if digest not in seen:
            seen.add(digest)
            unique.append(seed)
    return unique


def write_seed_file(outdir: str, name: str, data: bytes) -> str:
    outpath = os.path.join(outdir, name)
    with open(outpath, "wb") as f:
        f.write(data)
    return outpath


def build_s7_frame(payload: bytes) -> bytes:
    tpkt_len = 4 + len(payload)
    return b"\x03\x00" + tpkt_len.to_bytes(2, "big") + payload


def build_cotp_data(payload: bytes) -> bytes:
    return b"\x02\xF0\x80" + payload


def make_s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    return (
        b"\x32"
        + bytes([rosctr])
        + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + data_len.to_bytes(2, "big")
    )


def make_cotp_connect_request(src_tsap: int = 0x0100, dst_tsap: int = 0x0102, tpdu_size: int = 0x0A) -> bytes:
    cotp = (
        b"\x11\xE0\x00\x00\x00\x01\x00"
        + b"\xC1\x02" + src_tsap.to_bytes(2, "big")
        + b"\xC2\x02" + dst_tsap.to_bytes(2, "big")
        + b"\xC0\x01" + bytes([tpdu_size])
    )
    return build_s7_frame(cotp)


def make_setup_communication() -> bytes:
    params = b"\xF0\x00\x00\x01\x00\x01\x01\xE0"
    data = b""
    header = make_s7_header(0x01, 1, len(params), len(data))
    return build_s7_frame(build_cotp_data(header + params + data))


def make_read_var_request() -> bytes:
    params = b"\x04\x01\x12\x0A\x10\x02\x00\x01\x00\x01\x84\x00\x00\x00"
    data = b""
    header = make_s7_header(0x01, 2, len(params), len(data))
    return build_s7_frame(build_cotp_data(header + params + data))


def make_write_var_request() -> bytes:
    params = b"\x05\x01\x12\x0A\x10\x02\x00\x01\x00\x01\x84\x00\x00\x00"
    data = b"\x00\x04\x00\x08\x00"
    header = make_s7_header(0x01, 3, len(params), len(data))
    return build_s7_frame(build_cotp_data(header + params + data))


def make_diagnostic_request() -> bytes:
    params = b"\x04\x01\x12\x0A\x10\x02\x00\x01\x00\x00\x83\x00\x00\x00"
    data = b""
    header = make_s7_header(0x01, 4, len(params), len(data))
    return build_s7_frame(build_cotp_data(header + params + data))


def _load_quality_module():
    """Dynamically load tools/s7_seed_quality.py to access heuristic scoring."""
    mod_path = os.path.join(os.path.dirname(__file__), "s7_seed_quality.py")
    if not os.path.exists(mod_path):
        return None
    spec = importlib.util.spec_from_file_location("s7_seed_quality", mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_auto_generated_seeds(count: int = AUTO_GEN_TEMPLATES, include_writes: bool = False) -> List[bytes]:
    """Create a diverse set of S7COMM-like seeds using templates and mutations.

    Produces seeds with varied header fields, different PDU sizes and
    field-level randomization to increase chances of hitting stateful code.
    """
    templates = [
        make_setup_communication(),
        make_read_var_request(),
        make_diagnostic_request(),
    ]
    if include_writes:
        templates.append(make_write_var_request())
    seeds = []
    for i in range(count):
        base = bytearray(make_cotp_connect_request())
        base.extend(make_setup_communication())
        base.extend(random.choice(templates))

        # Randomly concatenate extra S7 frames (simulate multi-request packets)
        if random.random() < 0.4:
            extra = bytearray(random.choice(templates))
            base.extend(extra)

        # Field-level mutations: tweak rosctr, pdu_ref, and a few bytes
        if len(base) > 8:
            # mutate rosctr (byte at payload offset after cotp header)
            try:
                # find first S7 header byte (0x32) inside
                idx = base.index(0x32)
                # rosctr at idx+1, pdu_ref at idx+4..+5 in a standard 10-byte S7 header
                if idx + 1 < len(base):
                    base[idx + 1] = random.choice([0x01, 0x07, 0x03, base[idx + 1]])
                if idx + 5 < len(base):
                    base[idx + 4] = random.randint(0, 255)
                    base[idx + 5] = random.randint(0, 255)
            except ValueError:
                pass

        # Random payload blob injection sometimes to increase size
        if random.random() < 0.3:
            extra = bytearray(random.choice(templates))
            try:
                s7_idx = extra.index(0x32)
                params_len = (extra[s7_idx + 6] << 8) | extra[s7_idx + 7]
                params_start = s7_idx + 10
                insert_at = min(len(extra), params_start + params_len)
                extra[insert_at:insert_at] = os.urandom(random.randint(1, 4))
                new_len = len(extra)
                extra[2:4] = new_len.to_bytes(2, "big")
            except Exception:
                pass
            base.extend(extra)

        seeds.append(bytes(base))

    # deduplicate and return
    return deduplicate_seeds(seeds)


def process_pcap_file(infile: str, outdir: str, split_requests: bool = False) -> int:
    flows = extract_flows_from_pcap(infile)
    base = os.path.splitext(os.path.basename(infile))[0]
    written = 0
    for i, ((src, sport, dst, dport), segments) in enumerate(flows.items()):
        combined = normalize_request_sequence(segments)
        if combined and len(combined) >= MIN_SEED_SIZE:
            name = f"{base}_flow_{i}_to_{dport}.raw"
            write_seed_file(outdir, name, combined)
            written += 1
        if split_requests:
            for k, frame in enumerate(split_tpkt_stream(reassemble_tcp_payloads(segments))):
                if is_relevant_s7_tpkt_frame(frame) and len(frame) >= MIN_SEED_SIZE:
                    name = f"{base}_flow_{i}_pkt_{k}_to_{dport}.raw"
                    write_seed_file(outdir, name, frame)
                    written += 1
    if written == 0:
        fallback = bytearray()
        rdr2 = read_pcap(infile)
        for pkt in rdr2:
            if TCP in pkt:
                payload = bytes(pkt[TCP].payload)
                if payload:
                    fallback.extend(payload)
        if fallback:
            write_seed_file(outdir, f"{base}_fallback.raw", bytes(fallback))
            written = 1
    return written


def process_raw_file(infile: str, outdir: str, split_requests: bool = False) -> int:
    base = os.path.splitext(os.path.basename(infile))[0]
    with open(infile, "rb") as f:
        data = f.read()

    frames = [frame for frame in split_tpkt_stream(data) if is_relevant_s7_tpkt_frame(frame)]
    if not frames:
        return 0

    write_seed_file(outdir, f"{base}.raw", b"".join(frames))
    written = 1
    if split_requests:
        for i, frame in enumerate(frames):
            write_seed_file(outdir, f"{base}_pkt_{i}.raw", frame)
            written += 1
    return written


def parse_args():
    parser = argparse.ArgumentParser(description="Extract and generate S7COMM seeds.")
    parser.add_argument("input", nargs="?", default=None, help="PCAP file or directory to process")
    parser.add_argument("-o", "--out", default="tutorials/s7/in", help="Output directory for seed files")
    parser.add_argument("--auto-gen", type=int, default=0, help="Generate this many automatic S7 seeds")
    parser.add_argument("--dedup", action="store_true", help="Deduplicate generated seed outputs")
    parser.add_argument("--split-requests", action="store_true", help="Write individual S7 request frames as separate seed files")
    parser.add_argument("--include-writes", action="store_true", help="Include S7 Write Var templates in auto-generated seeds")
    parser.add_argument("--min-size", type=int, default=MIN_SEED_SIZE, help="Minimum seed size in bytes")
    parser.add_argument("--verbose", action="store_true", help="Print verbose progress")
    parser.add_argument("--keep-threshold", type=int, default=0, help="Score threshold (0-100) to keep seeds; lower-quality moved to low_quality/")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.input is None and args.auto_gen == 0:
        print("Please provide a pcap input path or use --auto-gen.")
        sys.exit(1)

    ensure_dir(args.out)
    total = 0
    # load quality module for optional filtering
    quality_mod = _load_quality_module()

    if args.auto_gen > 0:
        print(f"[*] Generating {args.auto_gen} automatic S7COMM seeds...")
        auto_seeds = make_auto_generated_seeds(args.auto_gen, include_writes=args.include_writes)
        for i, seed in enumerate(auto_seeds):
            if len(seed) < args.min_size:
                continue
            write_seed_file(args.out, f"auto_seed_{i}.raw", seed)
            total += 1
        print(f"[*] Wrote {len(auto_seeds)} auto-generated seeds to {args.out}")

    if args.input:
        inp = args.input
        files = []
        if os.path.isdir(inp):
            files = [os.path.join(inp, fn) for fn in os.listdir(inp) if fn.endswith((".pcap", ".pcapng", ".raw"))]
        elif os.path.isfile(inp):
            files = [inp]
        else:
            print("No pcap files found at", inp)
            sys.exit(1)

        for f in files:
            print("Processing", f)
            if f.endswith(".raw"):
                written = process_raw_file(f, args.out, split_requests=args.split_requests)
            else:
                written = process_pcap_file(f, args.out, split_requests=args.split_requests)
            print(f" -> wrote {written} extracted seed files for {os.path.basename(f)}")
            total += written

    if args.dedup:
        print("[*] Deduplicating seed files...")
        seeds = []
        names = []
        for fn in sorted(os.listdir(args.out)):
            path = os.path.join(args.out, fn)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    data = f.read()
                seeds.append(data)
                names.append(path)
        unique = deduplicate_seeds(seeds)
        if len(unique) != len(seeds):
            print(f"[*] Removing {len(seeds) - len(unique)} duplicate seeds")
            for fn in names:
                os.remove(fn)
            for i, seed in enumerate(unique):
                write_seed_file(args.out, f"deduped_seed_{i}.raw", seed)
            total = len(unique)

    # If a threshold is provided, classify existing seeds and move low quality
    if hasattr(args, 'keep_threshold') and args.keep_threshold and args.keep_threshold > 0:
        print(f"[*] Scoring seeds and keeping only those with score >= {args.keep_threshold}...")
        low_dir = os.path.join(os.path.dirname(args.out), os.path.basename(args.out) + '_low_quality')
        ensure_dir(low_dir)
        kept = 0
        moved = 0
        for fn in sorted(os.listdir(args.out)):
            path = os.path.join(args.out, fn)
            if os.path.isfile(path) and not fn.startswith(os.path.basename(low_dir)):
                with open(path, "rb") as f:
                    data = f.read()
                score = None
                if quality_mod is not None:
                    try:
                        res = quality_mod.heuristic_seed_score(data)
                        score = int(res.get('score', 0))
                    except Exception:
                        score = 0
                else:
                    if len(data) >= 4:
                        first_len = (data[2] << 8) | data[3]
                        score = 100 if is_relevant_s7_tpkt_frame(data[:first_len]) else 0
                    else:
                        score = 0
                if score < args.keep_threshold:
                    shutil.move(path, os.path.join(low_dir, fn))
                    moved += 1
                else:
                    kept += 1
        print(f"[*] Kept {kept} seeds; moved {moved} low-quality seeds to {low_dir}")

    print(f"Done. Total seed files written: {total}. Seeds located in: {args.out}")


if __name__ == '__main__':
    main()
