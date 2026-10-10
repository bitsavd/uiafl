from __future__ import annotations

import json
import os
import signal
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
APP_ROOT = ROOT / "aflnet-ui"
DATA_DIR = APP_ROOT / "backend" / "data"
TASKS_FILE = DATA_DIR / "tasks.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
RUNS_DIR = APP_ROOT / "runs"
DEMO_RUN_ENV = "PROTOCOL_DETECTOR_DEMO_RUN"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if not TASKS_FILE.exists():
        save_tasks(seed_tasks())


def seed_tasks() -> list[dict[str, Any]]:
    demo_run = demo_run_path()
    if not demo_run.exists():
        return []
    return [
        {
            "id": "history_mqtt_builtin_20260730",
            "name": "MQTT 原始种子历史记录 6h",
            "category": "industrial",
            "protocol": "MQTT",
            "netinfo": "tcp://127.0.0.1/1886",
            "input_dir": "tutorials/mosquitto/in-mqtt",
            "output_dir": str(demo_run),
            "dictionary": "",
            "target_command": "mosquitto/src/mosquitto -p 1886",
            "cleanup_script": "",
            "duration": "6h",
            "aflnet_options": {**default_options(), "startup_delay_us": 10000, "timeout": "1000+"},
            "status": "completed",
            "pid": None,
            "created_at": "2026-07-30T09:08:00+08:00",
            "readonly": True,
            "hidden": False,
        }
    ]


def demo_run_path() -> Path:
    configured = os.environ.get(DEMO_RUN_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    return APP_ROOT / "demo" / "mqtt_builtin_20260730" / "out"


def migrate_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    changed = False
    for task in tasks:
        if "hidden" not in task:
            task["hidden"] = False
            changed = True
    if any(task.get("id") == "demo_mqtt_20260724" for task in tasks):
        tasks = [task for task in tasks if task.get("id") != "demo_mqtt_20260724"]
        for task in reversed(seed_tasks()):
            if not any(item.get("id") == task["id"] for item in tasks):
                tasks.insert(0, task)
        changed = True
    if not any(task.get("id") == "history_mqtt_builtin_20260730" for task in tasks):
        for task in reversed(seed_tasks()):
            tasks.insert(0, task)
        changed = True
    if changed:
        save_tasks(tasks)
    return tasks


def default_options() -> dict[str, Any]:
    return {
        "state_aware": True,
        "region_mutation": True,
        "false_negative_reduction": False,
        "terminate_server": True,
        "state_selection": 3,
        "seed_selection": 3,
        "startup_delay_us": 20000,
        "timeout": "2000+",
        "memory_limit": "none",
        "skip_deterministic": True,
    }


def default_settings() -> dict[str, Any]:
    return {
        "execution": {
            "max_parallel_tasks": 1,
            "default_duration": "10m",
            "default_timeout_ms": "2000+",
            "startup_delay_us": 20000,
        },
        "limits": {
            "max_replay_seconds": 30,
        },
    }


def load_settings() -> dict[str, Any]:
    ensure_dirs()
    if not SETTINGS_FILE.exists():
        save_settings(default_settings())
    try:
        stored = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        stored = {}
    return normalize_settings(stored)


def save_settings(settings: dict[str, Any]) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    merged = normalize_settings(settings)
    SETTINGS_FILE.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return merged


def normalize_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Keep only settings that have an active effect in the application."""
    defaults = default_settings()
    return {
        section: {
            key: settings.get(section, {}).get(key, value)
            for key, value in values.items()
        }
        for section, values in defaults.items()
    }


def merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def load_tasks() -> list[dict[str, Any]]:
    ensure_dirs()
    try:
        return migrate_tasks(json.loads(TASKS_FILE.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return []


def save_tasks(tasks: list[dict[str, Any]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    TASKS_FILE.write_text(json.dumps(tasks, ensure_ascii=False, indent=2), encoding="utf-8")


def get_task(task_id: str) -> dict[str, Any] | None:
    return next((task for task in load_tasks() if task["id"] == task_id), None)


def upsert_task(task: dict[str, Any]) -> dict[str, Any]:
    tasks = load_tasks()
    for idx, item in enumerate(tasks):
        if item["id"] == task["id"]:
            tasks[idx] = task
            save_tasks(tasks)
            return task
    tasks.insert(0, task)
    save_tasks(tasks)
    return task


def hide_task(task_id: str) -> bool:
    tasks = load_tasks()
    for task in tasks:
        if task.get("id") == task_id:
            task["hidden"] = True
            save_tasks(tasks)
            return True
    return False


def normalize_path(path: str | None, base: Path = ROOT) -> str:
    if not path:
        return ""
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = base / p
    return str(p.resolve())


def is_process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        parts = stat_path.read_text(errors="ignore").split()
        if len(parts) > 2 and parts[2] == "Z":
            return False
    except OSError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def refresh_task_status(task: dict[str, Any]) -> dict[str, Any]:
    if task.get("status") == "running" and not is_process_alive(task.get("pid")):
        task["status"] = "stopped"
        task["pid"] = None
        upsert_task(task)
    return task


def parse_stats(output_dir: str) -> dict[str, Any]:
    path = Path(output_dir) / "fuzzer_stats"
    data: dict[str, Any] = {}
    if not path.exists():
        return data
    for line in path.read_text(errors="ignore").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    start = _to_int(data.get("start_time"))
    last = _to_int(data.get("last_update"))
    if start and last and last >= start:
        data["run_seconds"] = last - start
        data["run_time"] = format_duration(last - start)
    return data


def parse_plot(output_dir: str) -> list[dict[str, Any]]:
    path = Path(output_dir) / "plot_data"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip().rstrip("%") for part in line.split(",")]
        if len(parts) < 13:
            continue
        rows.append(
            {
                "unix_time": _to_float(parts[0]),
                "cycles_done": _to_float(parts[1]),
                "cur_path": _to_float(parts[2]),
                "paths_total": _to_float(parts[3]),
                "pending_total": _to_float(parts[4]),
                "pending_favs": _to_float(parts[5]),
                "map_size": _to_float(parts[6]),
                "unique_crashes": _to_float(parts[7]),
                "unique_hangs": _to_float(parts[8]),
                "max_depth": _to_float(parts[9]),
                "execs_per_sec": _to_float(parts[10]),
                "n_nodes": _to_float(parts[11]),
                "n_edges": _to_float(parts[12]),
            }
        )
    return rows


def render_state_machine(output_dir: str) -> Path | None:
    out_dir = Path(output_dir)
    dot_path = out_dir / "ipsm.dot"
    if not dot_path.exists():
        return None
    svg_path = out_dir / "ipsm.svg"
    subprocess.run(["dot", "-Tsvg", str(dot_path), "-o", str(svg_path)], check=True, timeout=20)
    return svg_path


def list_findings(output_dir: str) -> dict[str, list[dict[str, Any]]]:
    out_dir = Path(output_dir)
    result: dict[str, list[dict[str, Any]]] = {}
    for name in ["replayable-crashes", "replayable-hangs", "replayable-queue", "replayable-new-ipsm-paths"]:
        folder = out_dir / name
        items = []
        if folder.exists():
            for item in sorted(folder.iterdir()):
                if item.is_file() and is_replayable_sample(item):
                    stat = item.stat()
                    items.append({"name": item.name, "group": name, "size": stat.st_size, "modified": stat.st_mtime})
        result[name] = items
    return result


def is_replayable_sample(path: Path) -> bool:
    name = path.name
    if name.startswith("."):
        return False
    if name.lower() in {"readme", "readme.txt"}:
        return False
    return name.startswith("id:") or name.startswith("seed")


def resolve_finding(output_dir: str, group: str, name: str) -> Path:
    allowed = {"replayable-crashes", "replayable-hangs", "replayable-queue", "replayable-new-ipsm-paths"}
    if group not in allowed:
        raise FileNotFoundError(group)
    base = (Path(output_dir) / group).resolve()
    path = (base / name).resolve()
    if base not in path.parents:
        raise FileNotFoundError(name)
    if not path.exists() or not path.is_file() or not is_replayable_sample(path):
        raise FileNotFoundError(name)
    return path


def build_aflnet_command(task: dict[str, Any]) -> list[str]:
    opts = {**default_options(), **task.get("aflnet_options", {})}
    command = [str(ROOT / "afl-fuzz")]
    if opts.get("skip_deterministic"):
        command.append("-d")
    command += [
        "-i",
        normalize_path(task.get("input_dir")),
        "-o",
        normalize_path(task.get("output_dir")),
        "-m",
        str(opts.get("memory_limit") or "none"),
        "-t",
        str(opts.get("timeout") or "2000+"),
        "-N",
        task["netinfo"],
        "-P",
        task["protocol"],
        "-D",
        str(opts.get("startup_delay_us") or 10000),
        "-q",
        str(opts.get("state_selection") or 3),
        "-s",
        str(opts.get("seed_selection") or 3),
    ]
    if task.get("dictionary"):
        command += ["-x", normalize_path(task["dictionary"])]
    if task.get("cleanup_script"):
        command += ["-c", normalize_path(task["cleanup_script"])]
    if opts.get("state_aware"):
        command.append("-E")
    if opts.get("region_mutation"):
        command.append("-R")
    if opts.get("false_negative_reduction"):
        command.append("-F")
    if opts.get("terminate_server"):
        command.append("-K")
    command.append("--")
    command += shlex.split(task["target_command"])
    duration = (task.get("duration") or "").strip()
    if duration:
        command = ["timeout", "-k", "30s", duration] + command
    return command


def start_task(task: dict[str, Any]) -> dict[str, Any]:
    output_dir = Path(normalize_path(task["output_dir"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    prepare_task_environment(task)
    stdout = open(output_dir / "afl_stdout.log", "ab", buffering=0)
    stderr = open(output_dir / "afl_stderr.log", "ab", buffering=0)
    env = runtime_env()
    command = build_aflnet_command(task)
    proc = subprocess.Popen(command, cwd=task_work_dir(task), stdout=stdout, stderr=stderr, env=env, start_new_session=True)
    task["pid"] = proc.pid
    task["status"] = "running"
    task["command_line"] = " ".join(command)
    upsert_task(task)
    return task


def stop_task(task: dict[str, Any]) -> dict[str, Any]:
    pid = task.get("pid")
    if pid and is_process_alive(pid):
        os.killpg(pid, signal.SIGTERM)
        time.sleep(0.5)
        if is_process_alive(pid):
            os.killpg(pid, signal.SIGKILL)
    task["pid"] = None
    task["status"] = "stopped"
    upsert_task(task)
    return task


def replay_sample(sample_path: str, protocol: str, port: int, timeout: int = 30) -> dict[str, Any]:
    path = Path(sample_path)
    if not path.exists():
        raise FileNotFoundError(sample_path)
    started = time.time()
    proc = subprocess.run(
        [str(ROOT / "aflnet-replay"), str(path), protocol, str(port)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "elapsed_ms": round((time.time() - started) * 1000),
    }


def replay_sample_with_target(sample_path: str, task: dict[str, Any], port: int, timeout: int = 30) -> dict[str, Any]:
    if task.get("target_profile") == "external" or is_tcp_port_open("127.0.0.1", port):
        result = replay_sample(sample_path, task["protocol"], port, timeout)
        result["target_started"] = False
        return result

    prepare_task_environment(task)
    command = replay_target_command(task.get("target_command") or "", port)
    if not command:
        result = replay_sample(sample_path, task["protocol"], port, timeout)
        result["target_started"] = False
        return result

    proc = subprocess.Popen(
        command,
        cwd=task_work_dir(task),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=runtime_env(),
        start_new_session=True,
    )
    target_ready = wait_for_tcp_port("127.0.0.1", port, timeout=3.0)
    try:
        result = replay_sample(sample_path, task["protocol"], port, timeout)
        result["target_started"] = True
        result["target_ready"] = target_ready
        return result
    finally:
        terminate_process_group(proc)


def runtime_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
    env.setdefault("AFL_SKIP_CPUFREQ", "1")
    lib_paths = [str(ROOT / "mosquitto" / "lib")]
    current = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = ":".join([*lib_paths, current]) if current else ":".join(lib_paths)
    return env


def task_work_dir(task: dict[str, Any]) -> str:
    return normalize_path(task.get("work_dir") or ".", ROOT)


def prepare_task_environment(task: dict[str, Any]) -> None:
    if task.get("protocol") != "RTSP":
        return
    target_dir = Path(task_work_dir(task))
    source_dir = ROOT / "tutorials" / "live555" / "sample_media_sources"
    if not target_dir.exists() or not source_dir.exists():
        return
    for item in source_dir.iterdir():
        if item.is_file():
            shutil.copy2(item, target_dir / item.name)


def replay_target_command(target_command: str, port: int) -> list[str]:
    command = shlex.split(target_command)
    if not command:
        return command
    for idx, part in enumerate(command[:-1]):
        if part in {"-p", "--port"} and command[idx + 1].isdigit():
            command[idx + 1] = str(port)
            return command
    if command[-1].isdigit():
        command[-1] = str(port)
    return command


def is_tcp_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def wait_for_tcp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_tcp_port_open(host, port):
            return True
        time.sleep(0.08)
    return False


def terminate_process_group(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=1)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass


def format_duration(seconds: int) -> str:
    hours, rem = divmod(seconds, 3600)
    minutes, sec = divmod(rem, 60)
    if hours:
        return f"{hours}时{minutes:02d}分"
    return f"{minutes}分{sec:02d}秒"


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None
