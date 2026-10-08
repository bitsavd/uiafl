#!/usr/bin/env python3
"""
Convert raw concatenated TCP payloads into AFLNet replay format: each message
is stored as 4-byte little-endian size followed by the message bytes.

It splits by TPKT headers (version 0x03) using the 2-byte big-endian length at
offsets 2-3. If no TPKT headers found, it writes the whole raw file as a single
message.

Usage:
  python3 tools/convert_raw_to_aflnet_replay.py input_dir -o out_dir

"""
import os
import sys
import struct

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)


def split_tpkt_messages(data):
    msgs = []
    offset = 0
    N = len(data)
    while offset + 4 <= N:
        if data[offset] == 0x03:
            pkt_len = (data[offset+2] << 8) | data[offset+3]
            if pkt_len < 4:
                break
            if offset + pkt_len <= N:
                msgs.append(data[offset:offset+pkt_len])
                offset += pkt_len
                continue
            else:
                break
        else:
            break
    return msgs


def convert_file(inpath, outpath):
    with open(inpath, 'rb') as f:
        data = f.read()
    msgs = split_tpkt_messages(data)
    if not msgs:
        # fallback: single message with entire file
        msgs = [data]
    with open(outpath, 'wb') as f:
        for m in msgs:
            f.write(struct.pack('<I', len(m)))
            f.write(m)
    return len(msgs)


def main():
    if len(sys.argv) < 2:
        print("Usage: convert_raw_to_aflnet_replay.py input_dir -o out_dir")
        sys.exit(1)
    inp = sys.argv[1]
    outdir = None
    if "-o" in sys.argv:
        try:
            outdir = sys.argv[sys.argv.index("-o") + 1]
        except Exception:
            outdir = None
    if outdir is None:
        outdir = os.path.join(os.path.dirname(inp), "seeds_replay")

    ensure_dir(outdir)

    files = []
    if os.path.isdir(inp):
        for fn in os.listdir(inp):
            if fn.endswith('.raw'):
                files.append(os.path.join(inp, fn))
    elif os.path.isfile(inp):
        files = [inp]
    else:
        print("No raw files found at", inp)
        sys.exit(1)

    total = 0
    for f in files:
        base = os.path.splitext(os.path.basename(f))[0]
        outpath = os.path.join(outdir, base + '.pkt')
        n = convert_file(f, outpath)
        print(f"Converted {f} -> {outpath} ({n} messages)")
        total += 1
    print(f"Done. Wrote {total} files to {outdir}")

if __name__ == '__main__':
    main()
