from __future__ import annotations

import gzip
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .protocols import protocol_meta

ROOT = Path(__file__).resolve().parents[3]
_lock = threading.Lock()
_build_slot = threading.Semaphore(1)
_jobs: dict[str, tuple[bool, float]] = {}


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_json(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def line_metrics(output: Path) -> dict[str, Any]:
    data = read_json(output / "line_coverage.json")
    covered, total = data.get("lines_covered"), data.get("lines_total")
    if not isinstance(covered, int) or not isinstance(total, int) or not 0 <= covered <= total or total <= 0:
        return {"line_coverage_available": False}
    return {"line_coverage_available": True, "line_coverage_pct": round(covered * 100 / total, 2),
            "line_coverage": f"{covered * 100 / total:.2f}%", "lines_covered": covered, "lines_total": total}


def schedule_collection(task: dict[str, Any], output: Path) -> None:
    if not task.get("line_coverage_enabled") or task.get("target_profile") == "external":
        return
    key = str(output)
    with _lock:
        busy, last = _jobs.get(key, (False, 0))
        if busy or time.monotonic() - last < 15:
            return
        _jobs[key] = (True, last)

    def work() -> None:
        try:
            with _build_slot:
                collect(task, output)
        except Exception as error:
            output.mkdir(parents=True, exist_ok=True)
            (output / "line_coverage_error.log").write_text(str(error), encoding="utf-8")
        finally:
            with _lock:
                _jobs[key] = (False, time.monotonic())

    threading.Thread(target=work, daemon=True, name="line-coverage").start()


def _run(command: list[str], cwd: Path, log: Any) -> None:
    subprocess.run(command, cwd=cwd, stdout=log, stderr=log, check=True, timeout=180)


def _build(task: dict[str, Any], base: Path) -> tuple[list[str], Path, Path]:
    builder = protocol_meta(task["protocol"]).get("coverage_builder")
    source = base / "source"
    source.mkdir(parents=True, exist_ok=True)
    ready = base / "build.json"
    with open(base / "build.log", "ab") as log:
        if builder == "modbus":
            target = source / "server"
            if not ready.exists():
                shutil.copyfile(ROOT / "tutorials/modbus/modbus_tcp_server.c", source / "modbus_tcp_server.c")
                hook = base / "coverage_shutdown.h"
                hook.write_text("#include <signal.h>\n#include <stdlib.h>\nstatic void coverage_shutdown(int signo) { exit(0); }\n__attribute__((constructor)) static void coverage_signals(void) { signal(SIGTERM, coverage_shutdown); }\n", encoding="ascii")
                _run(["gcc", "-O0", "-g", "--coverage", "-include", str(hook), "modbus_tcp_server.c", "-o", str(target)], source, log)
            command, cwd = [str(target), "{port}"], source
        elif builder == "mosquitto":
            target = source / "src/mosquitto"
            if not ready.exists():
                shutil.copytree(ROOT / "mosquitto", source, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns(".git", "*.o", "*.so*", "*.a", "*.gcda", "*.gcno", "out*", "mosquitto", "*.log"))
                _run(["make", "-C", "src", "-j2", "CC=gcc", "CFLAGS=-O0 -g", "WITH_COVERAGE=yes"], source, log)
            command, cwd = [str(target), "-p", "{port}"], source
        elif builder == "live555":
            target = source / "testProgs/testOnDemandRTSPServer"
            if not ready.exists():
                original = (ROOT / protocol_meta(task["protocol"])["work_dir"]).resolve().parent
                shutil.copytree(original, source, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("*.o", "*.a", "*.gcda", "*.gcno", ".git", "*.log"))
                hook = base / "coverage_shutdown.h"
                hook.write_text("#include <signal.h>\n#include <stdlib.h>\nstatic void coverage_shutdown(int signo) { exit(0); }\n__attribute__((constructor)) static void coverage_signals(void) { signal(SIGTERM, coverage_shutdown); }\n", encoding="ascii")
                options = ["-j2", "C_COMPILER=gcc", "CPLUSPLUS_COMPILER=g++", "LINK=g++ -o",
                           f"C_FLAGS=$(COMPILE_OPTS) -O0 -g --coverage -include {hook}",
                           f"CPLUSPLUS_FLAGS=$(COMPILE_OPTS) -O0 -g -DBSD=1 --coverage -include {hook}",
                           "LINK_OPTS=-L. --coverage"]
                for directory in ("UsageEnvironment", "BasicUsageEnvironment", "groupsock", "liveMedia"):
                    _run(["make", "-C", directory, *options], source, log)
                _run(["make", "-C", "testProgs", "-B", "testOnDemandRTSPServer", *options], source, log)
            command, cwd = [str(target), "{port}"], source / "testProgs"
        else:
            raise ValueError("No source coverage builder for this target")
    save_json(ready, {"builder": builder})
    return command, cwd, source


def replay_sample(command: list[str], cwd: Path, sample: Path, protocol: str) -> bool:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen([item.format(port=port) for item in command], cwd=cwd,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    break
            except OSError:
                time.sleep(.02)
        else:
            return False
        result = subprocess.run([str(ROOT / "aflnet-replay"), str(sample), protocol, str(port), "10", "1000"],
                                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def aggregate_gcov(documents: list[dict[str, Any]], source: Path) -> tuple[int, int]:
    lines: dict[tuple[str, int], bool] = {}
    source = source.resolve()
    for document in documents:
        cwd = Path(document.get("current_working_directory") or source)
        for item in document.get("files", []):
            path = Path(item["file"])
            if not path.is_absolute():
                path = cwd / path
            path = path.resolve()
            if not path.is_relative_to(source):
                continue
            for line in item.get("lines", []):
                key = (str(path), line["line_number"])
                lines[key] = lines.get(key, False) or line.get("count", 0) > 0
    return sum(lines.values()), len(lines)


def collect(task: dict[str, Any], output: Path, batch_size: int = 16) -> dict[str, Any]:
    base = output / "line-coverage"
    base.mkdir(parents=True, exist_ok=True)
    state_file = base / "collection.json"
    state = read_json(state_file)
    processed = set(state.get("processed", []))
    samples = sorted((output / "replayable-queue").glob("id:*"))
    pending = [sample for sample in samples if sample.name not in processed][:batch_size]
    if not pending:
        return line_metrics(output)
    command, cwd, source = _build(task, base)
    completed = []
    for sample in pending:
        if replay_sample(command, cwd, sample, task["protocol"]):
            processed.add(sample.name)
            completed.append(sample)
    if not completed:
        raise ValueError("No detection samples could be replayed for line coverage")
    if not list(source.rglob("*.gcda")):
        raise ValueError("The coverage target did not write execution counters")
    documents = []
    # Separate output directories prevent equal object names from overwriting JSON.
    with tempfile.TemporaryDirectory(dir=base, prefix="gcov-") as directory, open(base / "gcov.log", "ab") as log:
        for index, notes in enumerate(source.rglob("*.gcno")):
            destination = Path(directory) / str(index)
            destination.mkdir()
            subprocess.run(["gcov", "--json-format", str(notes)], cwd=destination, stdout=log, stderr=log, check=True, timeout=15)
            for path in destination.glob("*.gcov.json.gz"):
                with gzip.open(path, "rt", encoding="utf-8") as file:
                    documents.append(json.load(file))
    covered, total = aggregate_gcov(documents, source)
    if not total:
        raise ValueError("No executable source lines were reported by gcov")
    timestamp = int(time.time())
    snapshot = {"lines_covered": covered, "lines_total": total, "method": "gcov", "samples": len(processed), "updated_at": timestamp}
    save_json(output / "line_coverage.json", snapshot)
    save_json(state_file, {"processed": sorted(processed)})
    history_file = output / "line_coverage_plot.json"
    history = read_json(history_file).get("rows", [])
    history.append({"unix_time": int(max(sample.stat().st_mtime for sample in completed)), "line_coverage_pct": round(covered * 100 / total, 2)})
    save_json(history_file, {"rows": history})
    return line_metrics(output)


def merge_coverage_plot(output: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    history = read_json(output / "line_coverage_plot.json").get("rows", [])
    if not history:
        return rows
    history = sorted(history, key=lambda row: row["unix_time"])
    result = []
    index = 0
    coverage = None
    # Keep the engine's sampling grid; coverage-only events must not move its origin.
    for row in sorted(rows, key=lambda row: row["unix_time"]):
        while index < len(history) and history[index]["unix_time"] <= row["unix_time"]:
            coverage = history[index].get("line_coverage_pct")
            index += 1
        point = dict(row)
        if coverage is not None:
            point["line_coverage_pct"] = coverage
        result.append(point)
    return result
