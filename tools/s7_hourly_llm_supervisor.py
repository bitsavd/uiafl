#!/usr/bin/env python3
import argparse
import json
import shutil
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from s7_llm_guidance import analyze_seed, call_llm, write_dictionary  # noqa: E402
from s7_oracle import testcase_tags  # noqa: E402


def parse_fuzzer_stats(path: Path) -> Dict[str, str]:
    stats = {}
    if not path.exists():
        return stats
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def event_counts(events_log: Path) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    if not events_log.exists():
        return {}
    for line in events_log.read_text(encoding="utf-8", errors="replace").splitlines():
        for field in line.split():
            if field.startswith("kind="):
                counts[field[5:]] += 1
    return dict(counts.most_common())


def iter_files(path: Path, limit: int = 0) -> Iterable[Path]:
    if not path.exists():
        return
    count = 0
    for child in sorted(path.iterdir()):
        if not child.is_file() or child.name.startswith("README"):
            continue
        yield child
        count += 1
        if limit and count >= limit:
            return


def collect_candidates(out_dir: Path, limit: int) -> List[Path]:
    candidates: List[Path] = []
    for subdir in ("replayable-new-ipsm-paths", "s7_events/cases", "queue"):
        for path in iter_files(out_dir / subdir, limit):
            candidates.append(path)
            if len(candidates) >= limit:
                return candidates
    return candidates


def safe_name(path: Path) -> str:
    return path.name.replace("/", "_").replace(":", "_").replace(",", "_")


def run_triage(args, candidates: List[Path], work_dir: Path) -> List[Dict[str, object]]:
    if not candidates:
        return []
    candidate_dir = work_dir / "triage_input"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for idx, path in enumerate(candidates):
        dst = candidate_dir / f"{idx:04d}_{safe_name(path)}"
        shutil.copy2(path, dst)
        copied.append(dst)

    triage_out = work_dir / "triage"
    cmd = [
        sys.executable,
        str(SCRIPT_DIR / "s7_triage_corpus.py"),
        str(candidate_dir),
        "--target",
        args.target,
        "--port",
        str(args.port),
        "--timeout",
        str(args.timeout),
        "--repeats",
        str(args.repeats),
        "--delay",
        str(args.delay),
        "--out",
        str(triage_out),
        "--limit",
        str(args.triage_limit),
    ]
    import subprocess

    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    (work_dir / "triage_stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (work_dir / "triage_stderr.txt").write_text(proc.stderr, encoding="utf-8")
    summary_path = triage_out / "summary.json"
    if proc.returncode != 0 or not summary_path.exists():
        return [{
            "classification": "triage_failed",
            "stderr": proc.stderr,
            "returncode": proc.returncode,
        }]
    return json.loads(summary_path.read_text(encoding="utf-8"))


def summarize_triage(triage: List[Dict[str, object]]) -> Dict[str, object]:
    buckets = Counter(item.get("bucket", "unknown") for item in triage)
    classes = Counter(item.get("classification", "unknown") for item in triage)
    tags = Counter(tag for item in triage for tag in item.get("tags", []))
    interesting = [
        item for item in triage
        if item.get("bucket") in ("high", "s7_reset") or item.get("classification") == "persistent_plc_fault"
    ][:20]
    return {
        "bucket_counts": dict(buckets.most_common()),
        "classification_counts": dict(classes.most_common()),
        "tag_counts": dict(tags.most_common()),
        "interesting": interesting,
    }


def analyze_candidates(candidates: List[Path], limit: int) -> List[Dict[str, object]]:
    analyses = []
    for path in candidates[:limit]:
        try:
            info = analyze_seed(path)
            info["tags"] = testcase_tags(path.read_bytes())
            analyses.append(info)
        except Exception as exc:  # keep the hourly loop alive on odd files
            analyses.append({"name": path.name, "path": str(path), "error": str(exc)})
    return analyses


def build_prompt(args, stats: Dict[str, str], counts: Dict[str, int],
                 triage_summary: Dict[str, object], candidates: List[Dict[str, object]],
                 previous: Optional[Dict[str, object]]) -> Dict[str, object]:
    return {
        "role": "llm_assisted_s7comm_state_modeling",
        "goal": (
            "Build or refine a semantic state machine for black-box Siemens S7COMM fuzzing "
            "and propose the next mutation/corpus strategy. Optimize for reproducible "
            "vulnerability discovery, not pretty AFL metrics."
        ),
        "feedback_window": "about one fuzzing hour or the current available AFLNet output",
        "constraints": [
            "Do not prioritize malformed or truncated COTP unless it leads to persistent PLC health failure.",
            "Prefer complete COTP Data frames with malformed S7 header, param, data, item count, area, DB, and block/control fields.",
            "Treat current-connection reset with healthy post-check as low priority unless it occurs after a deep S7 semantic response.",
            "Recommend bounded, replayable, PLC-lab-safe mutations rather than huge random packets.",
            "Return only JSON.",
        ],
        "return_json_schema": {
            "state_model": {
                "states": [{"name": "setup_ok", "evidence": ["response signature"], "priority": 1}],
                "transitions": [{"from": "setup_ok", "to": "s7_error_85", "trigger": "short S7 header"}],
                "noise_states": ["transport_layer_current_connection_reset"],
            },
            "next_strategy": {
                "summary": "short plan",
                "target_states": ["s7_error_85"],
                "mutation_hotspots": [
                    {"field": "param_len", "values": ["0000", "ffff"], "reason": "parser boundary"}
                ],
                "seed_selection": ["seed name or testcase name"],
                "dictionary_tokens_hex": ["3201", "0401"],
                "afl_env": {"S7_HARNESS_S7_ONLY_COVERAGE": "1"},
            },
            "stop_or_continue": "continue|enough_for_24h|needs_new_seed_family",
        },
        "fuzzer_stats": stats,
        "event_counts": counts,
        "triage_summary": triage_summary,
        "candidate_samples": candidates,
        "previous_guidance": previous,
    }


def fallback_guidance(stats: Dict[str, str], counts: Dict[str, int],
                      triage_summary: Dict[str, object],
                      candidates: List[Dict[str, object]]) -> Dict[str, object]:
    ranked = sorted(
        candidates,
        key=lambda item: (
            "s7_declared_length_mismatch" in item.get("tags", []),
            "short_s7_header" in item.get("tags", []),
            item.get("heuristic_score", 0),
        ),
        reverse=True,
    )
    target_states = ["s7_error_85", "s7_error_84", "read_ack_data", "block_control_error_81"]
    if triage_summary.get("bucket_counts", {}).get("high"):
        target_states.insert(0, "persistent_plc_fault")
    return {
        "state_model": {
            "states": [
                {"name": "cotp_connected", "evidence": ["cotp_cc"], "priority": 1},
                {"name": "setup_ok", "evidence": ["fn=f0 err=00/00"], "priority": 2},
                {"name": "read_ack_data", "evidence": ["rosctr=03 fn=04"], "priority": 3},
                {"name": "s7_error_84", "evidence": ["rosctr=02 fn=84"], "priority": 4},
                {"name": "s7_error_85", "evidence": ["rosctr=02 fn=85"], "priority": 5},
                {"name": "block_control_error_81", "evidence": ["rosctr=02 fn=81"], "priority": 4},
            ],
            "transitions": [
                {"from": "setup_ok", "to": "s7_error_85", "trigger": "length mismatch or short S7 header"},
                {"from": "setup_ok", "to": "s7_error_84", "trigger": "Read Var count/item mismatch"},
                {"from": "setup_ok", "to": "block_control_error_81", "trigger": "download/upload/control-like functions"},
            ],
            "noise_states": ["transport_layer_current_connection_reset", "truncated_cotp_cr"],
        },
        "next_strategy": {
            "summary": "Keep COTP complete and focus mutations on S7 length, item, DB, area and block/control parameters.",
            "target_states": target_states,
            "mutation_hotspots": [
                {"field": "param_len", "values": ["0000", "0001", "000d", "000e", "00ff", "ff00", "ffff"], "reason": "S7 parser boundary"},
                {"field": "data_len", "values": ["0000", "0001", "0005", "0010", "0100", "ffff"], "reason": "Write/Data coupling boundary"},
                {"field": "read_item_count", "values": ["00", "02", "03", "08", "7f", "ff"], "reason": "declared item count mismatch"},
                {"field": "area_db_number", "values": ["81", "82", "83", "84", "1c", "1d"], "reason": "memory-area parser diversity"},
                {"field": "block_control_fn", "values": ["1a", "1b", "1c", "1d", "1e", "1f", "28", "29"], "reason": "deep stateful functions"},
            ],
            "seed_selection": [item.get("name") for item in ranked[:16]],
            "dictionary_tokens_hex": [
                "3201", "3203", "3202", "f000", "0401", "0501", "120a10",
                "81", "82", "83", "84", "1a", "1b", "1c", "1d", "1e", "1f", "28", "29",
                "0000", "0001", "0005", "000d", "00ff", "ff00", "ffff",
            ],
            "afl_env": {"S7_HARNESS_S7_ONLY_COVERAGE": "1", "S7_STATE_STRICT": "1"},
        },
        "stop_or_continue": "continue",
        "llm_used": False,
        "fuzzer_stats_snapshot": stats,
        "event_counts_snapshot": counts,
        "triage_summary_snapshot": triage_summary,
    }


def copy_selected(guidance: Dict[str, object], candidates: List[Path], select_out: Path, top_n: int) -> None:
    if select_out.exists():
        shutil.rmtree(select_out)
    select_out.mkdir(parents=True, exist_ok=True)
    by_name = {path.name: path for path in candidates}
    selected = guidance.get("next_strategy", {}).get("seed_selection", [])
    copied = 0
    for name in selected:
        src = by_name.get(str(name))
        if src and src.exists():
            shutil.copy2(src, select_out / safe_name(src))
            copied += 1
            if copied >= top_n:
                return
    for path in candidates:
        dst = select_out / safe_name(path)
        if not dst.exists():
            shutil.copy2(path, dst)
            copied += 1
            if copied >= top_n:
                return


def run_once(args) -> Path:
    out_dir = Path(args.out_dir)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work_dir = Path(args.guidance_dir) / stamp
    work_dir.mkdir(parents=True, exist_ok=True)

    stats = parse_fuzzer_stats(out_dir / "fuzzer_stats")
    counts = event_counts(out_dir / "s7_events" / "events.log")
    candidates = collect_candidates(out_dir, args.candidate_limit)
    triage = run_triage(args, candidates[:args.triage_limit], work_dir) if args.triage else []
    triage_summary = summarize_triage(triage)
    candidate_analysis = analyze_candidates(candidates, args.prompt_sample_limit)
    previous = None
    if args.previous and Path(args.previous).exists():
        previous = json.loads(Path(args.previous).read_text(encoding="utf-8"))

    prompt = build_prompt(args, stats, counts, triage_summary, candidate_analysis, previous)
    prompt_path = work_dir / "prompt.json"
    prompt_path.write_text(json.dumps(prompt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    guidance = fallback_guidance(stats, counts, triage_summary, candidate_analysis)
    llm_result = call_llm(prompt)
    if llm_result and "error" not in llm_result:
        guidance.update({k: v for k, v in llm_result.items() if v})
        guidance["llm_used"] = True
        guidance["llm_provider"] = llm_result.get("_llm_provider", "external_command")
        guidance["llm_model"] = llm_result.get("_llm_model")
    elif llm_result:
        guidance["llm_error"] = llm_result

    guidance["source_out_dir"] = str(out_dir)
    guidance["generated_at"] = stamp
    guidance["prompt_path"] = str(prompt_path)
    guidance["triage_summary"] = triage_summary
    guidance["candidate_count"] = len(candidates)
    guidance_path = work_dir / "guidance.json"
    guidance_path.write_text(json.dumps(guidance, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.dict_out:
        write_dictionary(Path(args.dict_out), guidance.get("next_strategy", guidance))
    if args.select_out:
        copy_selected(guidance, candidates, Path(args.select_out), args.top_n)

    print(f"wrote {guidance_path}")
    print(f"llm_used={guidance.get('llm_used', False)} stop_or_continue={guidance.get('stop_or_continue')}")
    print("triage:", json.dumps(triage_summary.get("bucket_counts", {}), sort_keys=True))
    return guidance_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Hourly LLM-guided S7COMM fuzzing supervisor")
    parser.add_argument("--out-dir", default="tutorials/s7/out_deep_len_24h", help="AFLNet output directory to analyze")
    parser.add_argument("--guidance-dir", default="tutorials/s7/llm_hourly", help="Where hourly prompts/guidance are written")
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--candidate-limit", type=int, default=80)
    parser.add_argument("--prompt-sample-limit", type=int, default=40)
    parser.add_argument("--triage-limit", type=int, default=30)
    parser.add_argument("--no-triage", dest="triage", action="store_false")
    parser.add_argument("--dict-out", default="", help="Optional dictionary path to write next-round tokens")
    parser.add_argument("--select-out", default="", help="Optional next-round corpus directory")
    parser.add_argument("--top-n", type=int, default=24)
    parser.add_argument("--previous", default="", help="Previous guidance.json to include as context")
    parser.add_argument("--watch", action="store_true", help="Run forever and analyze every interval")
    parser.add_argument("--interval", type=int, default=3600, help="Watch interval in seconds")
    args = parser.parse_args()

    if args.watch:
        previous = args.previous
        while True:
            path = run_once(args)
            args.previous = str(path)
            previous = str(path)
            time.sleep(args.interval)
    else:
        run_once(args)


if __name__ == "__main__":
    main()
