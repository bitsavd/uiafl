"""Replay saved inputs locally and rebuild state graphs with the current C parser."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "aflnet-ui/backend"))
from app.store import (load_tasks, normalize_path, replay_target_command, runtime_env,
                       task_work_dir, terminate_process_group, wait_for_port)


def samples_in(directory: Path) -> list[Path]:
    candidates = [p for group in ("replayable-queue", "replayable-new-ipsm-paths",
                                  "replayable-crashes", "replayable-hangs")
                  for p in (directory / group).glob("id:*") if p.is_file()]
    candidates.sort(key=lambda p: ("orig:" not in p.name, p.name, str(p)))
    unique = {}
    for path in candidates:
        data = path.read_bytes()
        offset = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
            size = struct.unpack_from("=I", data, offset)[0]
            if not size or size > len(data) - offset - 4:
                break
            offset += 4 + size
        if data and offset == len(data):
            unique.setdefault(hashlib.sha256(data).hexdigest(), path)
    return list(unique.values())


def trimmed_path(states: list[int]) -> tuple[int, ...]:
    return tuple(value for i, value in enumerate(states)
                 if i < 2 or value != states[i - 1] or value != states[i - 2])


def graph_data(results: list[dict]) -> tuple[str, dict]:
    nodes, edges, paths = {0: "blue"}, {}, set()
    for result in results:
        states = result.get("states", [])
        if not result.get("response_bytes") or not states:
            continue
        paths.add(trimmed_path(states))
        color = "blue" if result["initial_seed"] else "red"
        for state in states:
            nodes.setdefault(state, color)
        for edge in zip(states, states[1:]):
            edges.setdefault(edge, color)
    lines = ["digraph g {", 'node [color=black];', 'edge [color=black];']
    lines += [f'{state} [color={color}];' for state, color in sorted(nodes.items())]
    lines += [f'{a} -> {b} [color={color}];' for (a, b), color in sorted(edges.items())]
    return "\n".join([*lines, "}", ""]), {
        "state_nodes": len(nodes), "state_edges": len(edges), "state_paths": len(paths)}


def build_tools(temp: Path) -> tuple[Path, Path]:
    replay, parser = temp / "replay", temp / "parse"
    common = ["-I", str(ROOT), str(ROOT / "aflnet.c"), "-lgvc", "-lcgraph", "-lm"]
    for source, output in ((ROOT / "aflnet-replay.c", replay),
                           (Path(__file__).with_name("parse_state_responses.c"), parser)):
        subprocess.run(["cc", "-O1", "-w", str(source), *common, "-o", str(output)], check=True)
    return replay, parser


def rebuild(task: dict, replay: Path, parser: Path, port: int) -> dict:
    source = Path(normalize_path(task["output_dir"], ROOT))
    stats_file = source / "fuzzer_stats"
    source_digest = hashlib.sha256(stats_file.read_bytes() if stats_file.exists() else b"").hexdigest()
    samples = samples_in(source)
    if not samples:
        raise RuntimeError(f"No replayable samples: {task['id']}")
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
    target_command = replay_target_command(task["target_command"], port)
    if task.get("target_profile") == "external" or task["protocol"] not in {"MQTT", "MODBUS"}:
        raise ValueError("Only managed local MQTT/Modbus targets are supported")
    destination = source / "state-reanalysis"
    # A completed reconstruction is immutable; a rerun must use a separate directory.
    if destination.exists():
        raise FileExistsError(destination)
    destination.mkdir()
    capture_dir = destination / "responses"
    capture_dir.mkdir()
    results = []
    for index, sample in enumerate(samples):
        capture = capture_dir / f"{index:06d}.bin"
        result = {"sample": str(sample.relative_to(source)), "initial_seed": "orig:" in sample.name,
                  "input_sha256": hashlib.sha256(sample.read_bytes()).hexdigest()}
        target = subprocess.Popen(target_command, cwd=task_work_dir(task), env=runtime_env(),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        try:
            if not wait_for_port("127.0.0.1", port, "tcp", timeout=3):
                raise RuntimeError("Local replay target failed to start")
            env = runtime_env()
            env["AFLNET_REPLAY_RESPONSE_FILE"] = str(capture)
            try:
                completed = subprocess.run([str(replay), str(sample), task["protocol"], str(port),
                                            "10", "1000", "127.0.0.1", "tcp"],
                                           cwd=ROOT, env=env, capture_output=True, timeout=5)
                result["returncode"] = completed.returncode
                if completed.returncode:
                    result["error"] = completed.stderr.decode(errors="replace")[-1000:]
            except subprocess.TimeoutExpired:
                result["error"] = "Replay timed out after 5 seconds"
            result["target_returncode"] = target.poll()
        finally:
            terminate_process_group(target)
        if not capture.exists():
            capture.write_bytes(b"")
        result["response_bytes"] = capture.stat().st_size
        result["response_sha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
        results.append(result)
        if (index + 1) % 25 == 0 or index + 1 == len(samples):
            print(f"{task['id']}: {index + 1}/{len(samples)}", flush=True)
    inputs = "".join(str(capture_dir / f"{i:06d}.bin") + "\n" for i in range(len(results)))
    parsed = subprocess.run([str(parser), task["protocol"]], input=inputs, text=True,
                            capture_output=True, check=True, timeout=30)
    sequences = [json.loads(line) for line in parsed.stdout.splitlines()]
    if len(sequences) != len(results):
        raise RuntimeError("Parser result count does not match captured samples")
    for result, states in zip(results, sequences):
        result["states"] = states
    dot, metrics = graph_data(results)
    if not any(result["response_bytes"] for result in results):
        raise RuntimeError("No responses captured; reconstruction was not published")
    (destination / "ipsm.dot").write_text(dot)
    subprocess.run(["dot", "-Tsvg", str(destination / "ipsm.dot"), "-o",
                    str(destination / "ipsm.svg")], check=True, timeout=20)
    if hashlib.sha256(stats_file.read_bytes() if stats_file.exists() else b"").hexdigest() != source_digest:
        raise RuntimeError("Source statistics changed during replay; reconstruction was not published")
    summary = {"version": 1, "method": "saved-input-replay", "task_id": task["id"],
               "protocol": task["protocol"], "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
               "parser_sha256": hashlib.sha256((ROOT / "aflnet.c").read_bytes()).hexdigest(),
               "source_stats_sha256": source_digest,
               "target_sha256": hashlib.sha256((ROOT / target_command[0]).read_bytes()).hexdigest(),
               "sample_count": len(results),
               "responding_samples": sum(bool(r["response_bytes"]) for r in results),
               "failed_samples": sum(bool(r.get("error")) for r in results), **metrics}
    (destination / "samples.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    # Publish the manifest last so interrupted runs never replace the historical graph.
    (destination / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return summary


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--task", action="append", required=True)
    args.add_argument("--port", type=int, default=28885)
    options = args.parse_args()
    tasks = {task["id"]: task for task in load_tasks()}
    with TemporaryDirectory(prefix="state-history-") as directory:
        replay, parser = build_tools(Path(directory))
        for task_id in options.task:
            task = tasks[task_id]
            if task.get("status") == "running":
                raise RuntimeError(f"Refusing to reprocess a running task: {task_id}")
            rebuild(task, replay, parser, options.port)


if __name__ == "__main__":
    main()
