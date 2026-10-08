#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List


def iter_cases(paths: List[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file():
            yield path
        elif path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and not child.name.startswith("README"):
                    yield child


def safe_name(path: Path) -> str:
    return path.name.replace("/", "_").replace(":", "_").replace(",", "_")


def run_oracle(args, testcase: Path, report: Path) -> dict:
    cmd = [
        "python3",
        "tools/s7_oracle.py",
        "--target",
        args.target,
        "--port",
        str(args.port),
        "--timeout",
        str(args.timeout),
        "replay",
        str(testcase),
        "--repeats",
        str(args.repeats),
        "--delay",
        str(args.delay),
    ]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        data = {
            "testcase": str(testcase),
            "classification": "oracle_failed",
            "severity": "unknown",
            "stderr": proc.stderr,
        }
    else:
        data = json.loads(proc.stdout)
    report.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay and classify S7 fuzz candidates")
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories to triage")
    parser.add_argument("--target", default="192.168.0.13")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--out", default="tutorials/s7/vuln_analysis/triage_latest")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    (out / "reports").mkdir(parents=True, exist_ok=True)
    for name in ("high", "s7_reset", "transport_reset", "normal", "oracle_failed"):
        (out / name).mkdir(parents=True, exist_ok=True)

    summary = []
    for idx, testcase in enumerate(iter_cases(args.paths)):
        if args.limit and idx >= args.limit:
            break
        report_path = out / "reports" / f"{idx:04d}_{safe_name(testcase)}.json"
        result = run_oracle(args, testcase, report_path)
        classification = result.get("classification", "oracle_failed")
        severity = result.get("severity", "unknown")
        if severity == "high":
            bucket = "high"
        elif classification == "s7_error_path_current_connection_reset":
            bucket = "s7_reset"
        elif classification == "transport_layer_current_connection_reset":
            bucket = "transport_reset"
        elif classification == "oracle_failed":
            bucket = "oracle_failed"
        else:
            bucket = "normal"
        shutil.copy2(testcase, out / bucket / safe_name(testcase))
        summary.append({
            "bucket": bucket,
            "classification": classification,
            "severity": severity,
            "testcase": str(testcase),
            "report": str(report_path),
            "tags": result.get("testcase_tags", []),
        })
        print(f"[{bucket}] {testcase} severity={severity} class={classification}")

    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    counts = {}
    for item in summary:
        counts[item["bucket"]] = counts.get(item["bucket"], 0) + 1
    print(json.dumps({"out": str(out), "counts": counts}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
