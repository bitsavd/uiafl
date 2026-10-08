#!/usr/bin/env python3
import argparse
from pathlib import Path


def split_tpkt_packets(data: bytes):
    packets = []
    offset = 0

    while offset + 4 <= len(data):
        if data[offset] != 0x03:
            offset += 1
            continue

        if offset + 4 > len(data):
            break

        pkt_len = (data[offset + 2] << 8) | data[offset + 3]
        if pkt_len < 4 or offset + pkt_len > len(data):
            break

        packets.append(data[offset:offset + pkt_len])
        offset += pkt_len

    return packets


def extract_function_code(packet: bytes):
    if len(packet) < 15:
        return None

    payload_off = 4
    if payload_off + 3 >= len(packet):
        return None

    s7_off = payload_off + 3
    if s7_off + 10 > len(packet) or packet[s7_off] != 0x32:
        return None

    rosctr = packet[s7_off + 1]
    header_len = 12 if rosctr in (0x03, 0x07) and s7_off + 12 <= len(packet) else 10
    params_start = s7_off + header_len
    if params_start >= len(packet):
        return None

    return packet[params_start]


def seed_name(base: str, index: int):
    return f"{base}_pkt_{index:02d}.raw"


def main():
    parser = argparse.ArgumentParser(description="Split and inspect S7COMM seeds.")
    parser.add_argument("--input-dir", default="tutorials/s7/in", help="Input directory with raw S7 seeds")
    parser.add_argument("--output-dir", default="tutorials/s7/in_split", help="Output directory for split packet seeds")
    parser.add_argument("--keep-original", action="store_true", help="Also retain original files in the output directory")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Scanning {input_dir} for raw seeds...")
    all_paths = sorted(input_dir.glob("*.raw"))
    if not all_paths:
        print(f"No .raw files found in {input_dir}")
        return

    total_packets = 0
    for path in all_paths:
        data = path.read_bytes()
        packets = split_tpkt_packets(data)
        if not packets:
            print(f"[SKIP] {path.name}: no TPKT packets found")
            continue

        base = path.stem
        for idx, pkt in enumerate(packets):
            out_path = output_dir / seed_name(base, idx)
            out_path.write_bytes(pkt)
            fn_code = extract_function_code(pkt)
            print(f"[SPLIT] {path.name} -> {out_path.name} len={len(pkt)} fn={fn_code}")
            total_packets += 1

        if args.keep_original:
            target = output_dir / path.name
            if not target.exists():
                target.write_bytes(data)

    print(f"Wrote {total_packets} split packet seeds to {output_dir}")


if __name__ == "__main__":
    main()
