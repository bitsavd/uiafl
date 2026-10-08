from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .protocols import PROTOCOL_GROUPS, protocol_ids, protocol_meta
from .store import (
    APP_ROOT,
    ROOT,
    build_aflnet_command,
    default_options,
    get_task,
    hide_task,
    list_findings,
    load_settings,
    load_tasks,
    normalize_path,
    parse_plot,
    parse_stats,
    refresh_task_status,
    render_state_machine,
    replay_sample_with_target,
    resolve_finding,
    save_settings,
    start_task,
    stop_task,
    upsert_task,
)

app = FastAPI(title="Protocol Anomaly Detection API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TaskCreate(BaseModel):
    name: str
    category: str = "network"
    protocol: str
    netinfo: str
    target_profile: str = "standard"
    input_dir: str = ""
    output_dir: str | None = None
    dictionary: str = ""
    target_command: str = ""
    cleanup_script: str = ""
    duration: str = ""
    aflnet_options: dict[str, Any] = Field(default_factory=default_options)


class ReplayRequest(BaseModel):
    sample_group: str
    sample_name: str
    port: int


class SettingsUpdate(BaseModel):
    execution: dict[str, Any] = Field(default_factory=dict)
    policies: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/protocols")
def protocols() -> list[dict[str, Any]]:
    return PROTOCOL_GROUPS


@app.get("/api/settings")
def settings() -> dict[str, Any]:
    return load_settings()


@app.put("/api/settings")
def update_settings(payload: SettingsUpdate) -> dict[str, Any]:
    return save_settings(payload.model_dump())


@app.get("/api/tasks")
def tasks() -> list[dict[str, Any]]:
    return [with_summary(refresh_task_status(task)) for task in load_tasks() if not task.get("hidden")]


@app.post("/api/tasks")
def create_task(payload: TaskCreate) -> dict[str, Any]:
    if payload.protocol not in protocol_ids():
        raise HTTPException(400, "协议不在当前支持列表中")
    settings_data = load_settings()
    template = protocol_meta(payload.protocol)
    port = parse_netinfo_port(payload.netinfo) or template.get("default_port") or 0
    input_dir = payload.input_dir or template.get("input_dir") or ""
    dictionary = payload.dictionary or template.get("dictionary") or ""
    if payload.target_profile == "external":
        target_command = payload.target_command or "sleep 86400"
    else:
        target_command = payload.target_command or template.get("target_command", "").format(port=port)
    work_dir = template.get("work_dir", ".")
    cleanup_script = payload.cleanup_script or template.get("cleanup_script") or ""
    if not input_dir or not target_command:
        raise HTTPException(400, "当前协议模板需要补充目标接入配置")
    options = {
        **default_options(),
        "startup_delay_us": settings_data["execution"]["startup_delay_us"],
        "timeout": settings_data["execution"]["default_timeout_ms"],
        **payload.aflnet_options,
    }
    if payload.target_profile == "external":
        options["terminate_server"] = False
    task_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}_{payload.protocol.lower()}"
    output_dir = payload.output_dir or str(APP_ROOT / "runs" / task_id)
    task = {
        "id": task_id,
        "name": payload.name,
        "category": payload.category,
        "protocol": payload.protocol,
        "netinfo": payload.netinfo,
        "target_profile": payload.target_profile,
        "input_dir": input_dir,
        "output_dir": output_dir,
        "dictionary": dictionary,
        "target_command": target_command,
        "work_dir": work_dir,
        "cleanup_script": cleanup_script,
        "duration": payload.duration or settings_data["execution"]["default_duration"],
        "aflnet_options": options,
        "status": "created",
        "pid": None,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "readonly": False,
    }
    task["command_line"] = " ".join(build_aflnet_command(task))
    return with_summary(upsert_task(task))


@app.get("/api/tasks/{task_id}")
def task_detail(task_id: str) -> dict[str, Any]:
    task = get_task_or_404(task_id)
    return with_summary(refresh_task_status(task), include_plot=True)


@app.post("/api/tasks/{task_id}/start")
def start(task_id: str) -> dict[str, Any]:
    task = get_task_or_404(task_id)
    if task.get("readonly"):
        raise HTTPException(400, "历史样例任务不能启动")
    if task.get("status") == "running":
        return with_summary(task)
    max_parallel = int(load_settings().get("execution", {}).get("max_parallel_tasks", 1))
    running_count = sum(1 for item in load_tasks() if not item.get("hidden") and refresh_task_status(item).get("status") == "running")
    if running_count >= max_parallel:
        raise HTTPException(400, f"当前并行任务已达到上限：{max_parallel}")
    return with_summary(start_task(task))


@app.post("/api/tasks/{task_id}/stop")
def stop(task_id: str) -> dict[str, Any]:
    task = get_task_or_404(task_id)
    if task.get("readonly"):
        raise HTTPException(400, "历史样例任务不能停止")
    return with_summary(stop_task(task))


@app.delete("/api/tasks/{task_id}")
def remove_task(task_id: str) -> dict[str, str]:
    task = get_task_or_404(task_id)
    if task.get("status") == "running":
        raise HTTPException(400, "运行中的任务不能移除记录")
    if not hide_task(task_id):
        raise HTTPException(404, "任务不存在")
    return {"status": "removed"}


@app.get("/api/tasks/{task_id}/findings")
def findings(task_id: str) -> dict[str, list[dict[str, Any]]]:
    task = get_task_or_404(task_id)
    return list_findings(normalize_path(task["output_dir"], ROOT))


@app.get("/api/tasks/{task_id}/state-machine")
def state_machine(task_id: str) -> FileResponse:
    task = get_task_or_404(task_id)
    try:
        svg = render_state_machine(normalize_path(task["output_dir"], ROOT))
    except Exception as exc:
        raise HTTPException(500, f"状态机渲染失败: {exc}") from exc
    if not svg:
        raise HTTPException(404, "当前任务还没有 ipsm.dot")
    return FileResponse(svg, media_type="image/svg+xml")


@app.post("/api/tasks/{task_id}/replay")
def replay(task_id: str, payload: ReplayRequest) -> dict[str, Any]:
    task = get_task_or_404(task_id)
    try:
        sample = resolve_finding(normalize_path(task["output_dir"], ROOT), payload.sample_group, payload.sample_name)
        timeout = int(load_settings().get("limits", {}).get("max_replay_seconds", 30))
        return replay_sample_with_target(str(sample), task, payload.port, timeout)
    except FileNotFoundError as exc:
        raise HTTPException(404, "样本文件不存在") from exc
    except Exception as exc:
        raise HTTPException(500, f"回放失败: {exc}") from exc


@app.get("/api/tasks/{task_id}/report.md", response_class=PlainTextResponse)
def report_markdown(task_id: str) -> str:
    task = with_summary(get_task_or_404(task_id), include_plot=True)
    findings = list_findings(normalize_path(get_task(task_id)["output_dir"], ROOT))
    stats = task.get("stats", {})
    lines = [
        f"# {task['name']} 检测报告",
        "",
        "## 任务摘要",
        "",
        f"- 检测协议：{task['protocol']}",
        f"- 目标地址：{task['netinfo']}",
        f"- 运行时长：{task.get('duration') or '手动停止'}",
        f"- 任务状态：{task.get('status')}",
        "",
        "## 核心指标",
        "",
        f"- 执行次数：{stats.get('execs_done', '未采集')}",
        f"- 执行速度：{stats.get('execs_per_sec', '未采集')}",
        f"- 路径总数：{stats.get('paths_total', '未采集')}",
        f"- 覆盖反馈：{stats.get('bitmap_cvg', '未采集')}",
        f"- 崩溃样本：{len(findings.get('replayable-crashes', []))}",
        f"- 超时样本：{len(findings.get('replayable-hangs', []))}",
        "",
        "## 状态机",
        "",
        f"- 状态机：{'已生成' if task.get('has_state_machine') else '未生成'}",
        f"- 状态节点：{latest_plot_value(task.get('plot', []), 'n_nodes')}",
        f"- 状态边：{latest_plot_value(task.get('plot', []), 'n_edges')}",
        "",
        "## 异常样本",
        "",
    ]
    for group, label in [("replayable-crashes", "崩溃"), ("replayable-hangs", "超时")]:
        samples = findings.get(group, [])
        lines.append(f"### {label}样本")
        lines.append("")
        if not samples:
            lines.append("- 暂无记录")
        else:
            for sample in samples[:20]:
                lines.append(f"- {sample['name']}（{sample['size']} 字节）")
        lines.append("")
    return "\n".join(lines)


def get_task_or_404(task_id: str) -> dict[str, Any]:
    task = get_task(task_id)
    if not task or task.get("hidden"):
        raise HTTPException(404, "任务不存在")
    return task


def with_summary(task: dict[str, Any], include_plot: bool = False) -> dict[str, Any]:
    output_dir = normalize_path(task.get("output_dir"), ROOT)
    stats = parse_stats(output_dir)
    plot = parse_plot(output_dir)
    hidden_fields = {"input_dir", "output_dir", "dictionary", "target_command", "work_dir", "cleanup_script", "command_line", "aflnet_options"}
    public_task = {key: value for key, value in task.items() if key not in hidden_fields}
    hidden_stats = {"command_line", "afl_banner", "afl_version", "target_mode"}
    public_stats = {key: value for key, value in stats.items() if key not in hidden_stats}
    result = {**public_task, "stats": public_stats, "plot_tail": plot[-120:], "has_state_machine": (Path(output_dir) / "ipsm.dot").exists()}
    if include_plot:
        result["plot"] = plot
    return result


def parse_netinfo_port(netinfo: str) -> int | None:
    try:
        return int(netinfo.rsplit("/", 1)[1])
    except (IndexError, ValueError):
        return None


def latest_plot_value(plot: list[dict[str, Any]], key: str) -> Any:
    for row in reversed(plot):
        value = row.get(key)
        if value not in (None, ""):
            return value
    return "未采集"
