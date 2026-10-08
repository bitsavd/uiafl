#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Dict, List


COTP_TYPES = {
    0xD0: "connection_confirm",
    0xE0: "connection_request",
    0x80: "disconnect",
    0xF0: "data",
}

S7_FUNCTIONS = {
    0x04: "read_var",
    0x05: "write_var",
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "plc_control",
    0x29: "plc_stop",
    0xF0: "setup_communication",
}

S7_AREAS = {
    0x81: "I",
    0x82: "Q",
    0x83: "M",
    0x84: "DB",
    0x1C: "counter",
    0x1D: "timer",
}


def split_tpkt_stream(data: bytes) -> List[Dict[str, object]]:
    frames = []
    off = 0
    while off + 4 <= len(data):
        if data[off:off + 2] != b"\x03\x00":
            off += 1
            continue
        declared = int.from_bytes(data[off + 2:off + 4], "big")
        if declared < 4:
            frames.append({
                "offset": off,
                "declared_len": declared,
                "actual_len": 4,
                "raw": data[off:off + 4],
                "error": "invalid_tpkt_len",
            })
            off += 1
            continue
        end = min(off + declared, len(data))
        frames.append({
            "offset": off,
            "declared_len": declared,
            "actual_len": end - off,
            "raw": data[off:end],
            "truncated": end < off + declared,
        })
        if end <= off:
            off += 1
        else:
            off = end
    return frames


def decode_cotp(frame: bytes) -> Dict[str, object]:
    out: Dict[str, object] = {}
    if len(frame) < 7:
        out["error"] = "short_cotp"
        return out
    cotp_len = frame[4]
    cotp_type = frame[5] & 0xF0
    out.update({
        "cotp_len": cotp_len,
        "cotp_type": f"0x{cotp_type:02x}",
        "cotp_name": COTP_TYPES.get(cotp_type, "unknown"),
        "cotp_raw_type": f"0x{frame[5]:02x}",
    })
    if cotp_type == 0xF0:
        out["eot"] = f"0x{frame[6]:02x}"
    return out


def decode_s7_items(params: bytes, data: bytes, fn: int) -> List[Dict[str, object]]:
    if len(params) < 2:
        return []
    count = params[1]
    items = []
    off = 2
    for idx in range(min(count, 32)):
        if off + 12 > len(params):
            items.append({"index": idx, "error": "truncated_item", "offset": off})
            break
        item = params[off:off + 12]
        syntax = item[0]
        var_spec_len = item[1]
        transport_size = item[3]
        amount = int.from_bytes(item[4:6], "big")
        db_number = int.from_bytes(item[6:8], "big")
        area = item[8]
        bit_address = int.from_bytes(item[9:12], "big")
        items.append({
            "index": idx,
            "syntax": f"0x{syntax:02x}",
            "var_spec_len": var_spec_len,
            "transport_size": f"0x{transport_size:02x}",
            "amount": amount,
            "db_number": db_number,
            "area": f"0x{area:02x}",
            "area_name": S7_AREAS.get(area, "unknown"),
            "bit_address": bit_address,
        })
        off += 12
    if fn == 0x05 and data:
        data_items = []
        doff = 0
        for idx in range(min(count, 32)):
            if doff + 4 > len(data):
                data_items.append({"index": idx, "error": "truncated_data_item", "offset": doff})
                break
            ret_or_reserved = data[doff]
            transport = data[doff + 1]
            bit_len = int.from_bytes(data[doff + 2:doff + 4], "big")
            byte_len = (bit_len + 7) // 8
            payload_start = doff + 4
            payload_end = min(payload_start + byte_len, len(data))
            data_items.append({
                "index": idx,
                "reserved": f"0x{ret_or_reserved:02x}",
                "transport_size": f"0x{transport:02x}",
                "bit_len": bit_len,
                "payload_len": payload_end - payload_start,
                "payload_prefix": data[payload_start:payload_end][:16].hex(),
            })
            doff = payload_end
            if bit_len % 8 and doff < len(data):
                doff += 1
        for item, data_item in zip(items, data_items):
            item["write_data"] = data_item
    return items


def decode_s7(frame: bytes) -> Dict[str, object]:
    out: Dict[str, object] = {}
    if len(frame) < 17 or frame[4:7] != b"\x02\xf0\x80":
        return out
    s7_off = 7
    if frame[s7_off] != 0x32:
        out["s7_error"] = "missing_protocol_id"
        return out
    if s7_off + 10 > len(frame):
        out["s7_error"] = "short_header"
        return out
    rosctr = frame[s7_off + 1]
    header_len = 10
    error_class = None
    error_code = None
    if rosctr in (0x03, 0x07) and s7_off + 12 <= len(frame):
        header_len = 12
        error_class = frame[s7_off + 10]
        error_code = frame[s7_off + 11]
    pdu_ref = int.from_bytes(frame[s7_off + 4:s7_off + 6], "big")
    param_len = int.from_bytes(frame[s7_off + 6:s7_off + 8], "big")
    data_len = int.from_bytes(frame[s7_off + 8:s7_off + 10], "big")
    params_start = s7_off + header_len
    data_start = params_start + param_len
    params = frame[params_start:min(data_start, len(frame))]
    s7_data = frame[data_start:min(data_start + data_len, len(frame))]
    fn = params[0] if params else None
    out.update({
        "s7_protocol": "0x32",
        "rosctr": f"0x{rosctr:02x}",
        "pdu_ref": pdu_ref,
        "param_len": param_len,
        "data_len": data_len,
        "header_len": header_len,
        "function": f"0x{fn:02x}" if fn is not None else None,
        "function_name": S7_FUNCTIONS.get(fn, "unknown") if fn is not None else None,
        "params_actual_len": len(params),
        "data_actual_len": len(s7_data),
        "params_hex": params[:64].hex(),
        "data_prefix": s7_data[:64].hex(),
    })
    if error_class is not None:
        out["error_class"] = f"0x{error_class:02x}"
        out["error_code"] = f"0x{error_code:02x}"
    if fn in (0x04, 0x05):
        out["item_count"] = params[1] if len(params) >= 2 else None
        out["items"] = decode_s7_items(params, s7_data, fn)
    return out


def decode_file(path: Path) -> Dict[str, object]:
    data = path.read_bytes()
    frames = []
    for idx, frame_info in enumerate(split_tpkt_stream(data)):
        raw = frame_info.pop("raw")
        decoded = {
            "index": idx,
            "offset": frame_info["offset"],
            "declared_len": frame_info["declared_len"],
            "actual_len": frame_info["actual_len"],
            "truncated": frame_info.get("truncated", False),
            "prefix": raw[:32].hex(),
        }
        decoded.update(decode_cotp(raw))
        decoded.update(decode_s7(raw))
        frames.append(decoded)
    return {
        "file": str(path),
        "size": len(data),
        "frame_count": len(frames),
        "frames": frames,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode S7COMM testcase frames")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    results = [decode_file(path) for path in args.files]
    if args.compact:
        for result in results:
            print(f"{result['file']} size={result['size']} frames={result['frame_count']}")
            for frame in result["frames"]:
                print(
                    f"  #{frame['index']} off={frame['offset']} len={frame['actual_len']}/"
                    f"{frame['declared_len']} cotp={frame.get('cotp_name')} "
                    f"rosctr={frame.get('rosctr')} fn={frame.get('function_name')} "
                    f"param_len={frame.get('param_len')} data_len={frame.get('data_len')}"
                )
                for item in frame.get("items", []):
                    print(
                        f"    item#{item.get('index')} area={item.get('area_name')}"
                        f" db={item.get('db_number')} amount={item.get('amount')}"
                        f" bit={item.get('bit_address')} ts={item.get('transport_size')}"
                    )
    else:
        print(json.dumps(results[0] if len(results) == 1 else results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
