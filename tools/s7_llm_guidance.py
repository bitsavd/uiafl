#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional


TOKEN_BYTES = {
    "tpkt": b"\x03\x00",
    "cotp_cr": b"\x11\xe0",
    "cotp_data": b"\x02\xf0\x80",
    "s7_protocol": b"\x32",
    "job": b"\x32\x01",
    "ack_data": b"\x32\x03",
    "setup_comm": b"\xf0\x00",
    "read_var": b"\x04\x01",
    "write_var": b"\x05\x01",
    "var_spec": b"\x12\x0a\x10",
    "area_i": b"\x81",
    "area_q": b"\x82",
    "area_m": b"\x83",
    "area_db": b"\x84",
    "area_counter": b"\x1c",
    "area_timer": b"\x1d",
    "block_list": b"\x1a\x00",
    "download_block": b"\x1b\x00",
    "download_ended": b"\x1c\x00",
    "start_upload": b"\x1d\x00",
    "upload": b"\x1e\x00",
    "end_upload": b"\x1f\x00",
    "plc_control": b"\x28\x00",
    "plc_stop": b"\x29\x00",
    "len_zero": b"\x00\x00",
    "len_one": b"\x00\x01",
    "len_ff": b"\xff\xff",
    "pdu_240": b"\x00\xf0",
    "pdu_480": b"\x01\xe0",
    "pdu_960": b"\x03\xc0",
}


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


def describe_frame(frame: bytes) -> Dict[str, object]:
    desc: Dict[str, object] = {"len": len(frame), "tpkt": frame[:2] == b"\x03\x00"}
    if len(frame) < 7:
        return desc
    desc["cotp_type"] = f"0x{frame[5] & 0xf0:02x}"
    if frame[4:7] != b"\x02\xf0\x80":
        return desc
    s7_off = 7
    if len(frame) < s7_off + 10 or frame[s7_off] != 0x32:
        return desc
    rosctr = frame[s7_off + 1]
    header_len = 12 if rosctr in (0x03, 0x07) and len(frame) >= s7_off + 12 else 10
    param_len = int.from_bytes(frame[s7_off + 6:s7_off + 8], "big")
    data_len = int.from_bytes(frame[s7_off + 8:s7_off + 10], "big")
    params_start = s7_off + header_len
    fn = frame[params_start] if params_start < len(frame) else None
    desc.update({
        "rosctr": f"0x{rosctr:02x}",
        "function": f"0x{fn:02x}" if fn is not None else None,
        "param_len": param_len,
        "data_len": data_len,
    })
    if fn in (0x04, 0x05) and params_start + 2 <= len(frame):
        item_count = frame[params_start + 1]
        areas = []
        dbs = []
        for i in range(min(item_count, 8)):
            item = params_start + 2 + i * 12
            if item + 12 > len(frame):
                break
            dbs.append(int.from_bytes(frame[item + 6:item + 8], "big"))
            areas.append(f"0x{frame[item + 8]:02x}")
        desc["item_count"] = item_count
        desc["areas"] = areas
        desc["db_numbers"] = dbs
    return desc


def analyze_seed(path: Path) -> Dict[str, object]:
    data = path.read_bytes()
    frames = split_tpkt_stream(data)
    frame_desc = [describe_frame(frame) for frame in frames]
    functions = [f.get("function") for f in frame_desc if f.get("function")]
    areas = sorted({area for f in frame_desc for area in f.get("areas", [])})
    score = 10 * len(frames) + 8 * len(set(functions)) + 5 * len(areas)
    if "0x05" in functions:
        score += 15
    if any(fn in functions for fn in ("0x1a", "0x1b", "0x1c", "0x1d", "0x1e", "0x1f", "0x28", "0x29")):
        score += 20
    if len(data) > 512:
        score -= 20
    return {
        "name": path.name,
        "path": str(path),
        "len": len(data),
        "frames": frame_desc,
        "functions": functions,
        "areas": areas,
        "heuristic_score": max(0, score),
    }


def build_llm_prompt(seed_infos: List[Dict[str, object]]) -> Dict[str, object]:
    return {
        "role": "s7comm_fuzzing_guidance",
        "goal": "Rank seeds and suggest mutation targets likely to expose S7COMM PLC protocol vulnerabilities, not just improve AFL metrics.",
        "constraints": [
            "Prefer valid stateful message sequences that pass COTP and S7 setup.",
            "Prioritize deep protocol functions, boundary lengths, item counts, invalid areas, DB edge cases, write/control/download-like functions.",
            "Avoid recommendations that only create random garbage or huge packets.",
        ],
        "return_json_schema": {
            "ranked_seed_names": ["seed.raw"],
            "mutation_targets": [
                {
                    "name": "short name",
                    "reason": "why it may expose a vulnerability",
                    "fields": ["function", "area", "length", "pdu_ref"],
                    "risk": "low|medium|high",
                }
            ],
            "dictionary_tokens_hex": ["0300", "02f080"],
        },
        "seeds": seed_infos,
    }


def call_llm(prompt: Dict[str, object]) -> Optional[Dict[str, object]]:
    cmd = os.environ.get("S7_LLM_CMD")
    if cmd:
        proc = subprocess.run(
            cmd,
            input=json.dumps(prompt),
            text=True,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=int(os.environ.get("S7_LLM_TIMEOUT", "120")),
        )
        if proc.returncode != 0:
            return {"error": "llm_command_failed", "stderr": proc.stderr.strip()}
        text = proc.stdout.strip()
        return parse_llm_json(text)

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if api_key:
        return call_deepseek(prompt, api_key)

    return None


def parse_llm_json(text: str) -> Dict[str, object]:
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start:end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": "llm_json_parse_failed", "raw": text}


def call_deepseek(prompt: Dict[str, object], api_key: str) -> Dict[str, object]:
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    timeout = int(os.environ.get("S7_LLM_TIMEOUT", "120"))
    temperature = float(os.environ.get("S7_LLM_TEMPERATURE", "0.2"))
    max_tokens = int(os.environ.get("S7_LLM_MAX_TOKENS", "4096"))

    request_body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are helping with authorized Siemens S7COMM PLC lab fuzzing. "
                    "Return only valid JSON matching the requested schema. "
                    "Do not include markdown fences or explanatory text."
                ),
            },
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }

    thinking = os.environ.get("DEEPSEEK_THINKING")
    if thinking:
        request_body["thinking"] = {"type": thinking}
        effort = os.environ.get("DEEPSEEK_REASONING_EFFORT")
        if effort:
            request_body["reasoning_effort"] = effort

    data = json.dumps(request_body).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {"error": "deepseek_http_error", "status": exc.code, "detail": detail}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"error": "deepseek_request_failed", "detail": str(exc)}

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"error": "deepseek_response_unexpected", "raw": payload}
    result = parse_llm_json(content)
    if "error" not in result:
        result["_llm_provider"] = "deepseek"
        result["_llm_model"] = model
    return result


def fallback_guidance(seed_infos: List[Dict[str, object]]) -> Dict[str, object]:
    ranked = sorted(seed_infos, key=lambda item: item["heuristic_score"], reverse=True)
    return {
        "ranked_seed_names": [item["name"] for item in ranked],
        "mutation_targets": [
            {
                "name": "var_item_boundary",
                "reason": "S7 variable item count, DB number, area and bit address are common parser boundary fields.",
                "fields": ["item_count", "area", "db_number", "bit_address", "transport_size"],
                "risk": "medium",
            },
            {
                "name": "write_data_length_mismatch",
                "reason": "Write Var has coupled parameter and data lengths; mismatches may expose parser bugs.",
                "fields": ["param_len", "data_len", "item_bit_length", "payload_length"],
                "risk": "high",
            },
            {
                "name": "control_and_block_functions",
                "reason": "PLC control and block-management functions tend to be stateful and privileged.",
                "fields": ["function", "rosctr", "param_len", "data_len"],
                "risk": "high",
            },
        ],
        "dictionary_tokens_hex": [token.hex() for token in TOKEN_BYTES.values()],
    }


def write_dictionary(path: Path, guidance: Dict[str, object]) -> None:
    tokens = set(TOKEN_BYTES.values())
    for token_hex in guidance.get("dictionary_tokens_hex", []):
        try:
            token = bytes.fromhex(str(token_hex))
        except ValueError:
            continue
        if 1 <= len(token) <= 32:
            tokens.add(token)
    lines = []
    for idx, token in enumerate(sorted(tokens)):
        escaped = "".join(f"\\x{b:02x}" for b in token)
        lines.append(f's7_{idx}="{escaped}"')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM/heuristic S7 seed ranking and mutation guidance")
    parser.add_argument("--input-dir", default="tutorials/s7/in")
    parser.add_argument("--output", default="tutorials/s7/llm_guidance.json")
    parser.add_argument("--dict-out", default="tutorials/s7/s7.dict")
    parser.add_argument("--select-out", help="Optional directory to receive top-ranked seeds")
    parser.add_argument("--top-n", type=int, default=16)
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    seeds = [analyze_seed(path) for path in sorted(input_dir.glob("*.raw"))]
    prompt = build_llm_prompt(seeds)
    llm_result = call_llm(prompt)
    guidance = fallback_guidance(seeds)
    if llm_result and "error" not in llm_result:
        guidance.update({k: v for k, v in llm_result.items() if v})
        guidance["llm_used"] = True
        guidance["llm_provider"] = llm_result.get("_llm_provider", "external_command")
        guidance["llm_model"] = llm_result.get("_llm_model", os.environ.get("DEEPSEEK_MODEL"))
    else:
        guidance["llm_used"] = False
        if llm_result:
            guidance["llm_error"] = llm_result
    guidance["seed_analysis"] = seeds
    guidance["prompt"] = prompt

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(guidance, indent=2, sort_keys=True) + "\n")
    write_dictionary(Path(args.dict_out), guidance)
    if args.select_out:
        select_dir = Path(args.select_out)
        if select_dir.exists():
            shutil.rmtree(select_dir)
        select_dir.mkdir(parents=True)
        seed_by_name = {Path(item["path"]).name: Path(item["path"]) for item in seeds}
        for name in guidance.get("ranked_seed_names", [])[:args.top_n]:
            src = seed_by_name.get(name)
            if src and src.exists():
                shutil.copy2(src, select_dir / src.name)
    print(f"wrote {output}")
    print(f"wrote {args.dict_out}")
    if args.select_out:
        print(f"wrote selected seeds to {args.select_out}")
    print("top seeds:")
    for name in guidance.get("ranked_seed_names", [])[:10]:
        print(f"  {name}")


if __name__ == "__main__":
    main()
