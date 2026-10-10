from __future__ import annotations

import os
import importlib.util
import shlex
import shutil
import socket
import ssl
import struct
import time
from pathlib import Path
from typing import Any

from .protocols import PROTOCOL_GROUPS, protocol_meta
from .store import ROOT, normalize_path


def preflight(protocol: str, host: str, port: int, transport: str) -> dict[str, Any]:
    started = time.monotonic()
    items: list[dict[str, str]] = []

    def add(name: str, status: str, message: str) -> None:
        items.append({"name": name, "status": status, "message": message})

    meta = protocol_meta(protocol)
    entry = next(item for group in PROTOCOL_GROUPS for item in group["protocols"] if item["id"] == protocol)
    local = host.lower() in {"127.0.0.1", "localhost", "::1"}
    executable = ROOT / "afl-fuzz"
    add("检测引擎", "pass" if os.access(executable, os.X_OK) else "fail", "检测程序可执行" if os.access(executable, os.X_OK) else "检测程序缺失或不可执行，请先编译检测引擎。")
    compatible = transport.upper() in entry["transport"].split("/")
    add("传输协议", "pass" if compatible else "fail", f"{protocol} / {transport.upper()}" if compatible else f"所选协议使用 {entry['transport']}，请调整传输协议。")
    seed_dir = Path(normalize_path(meta.get("input_dir"))) if meta.get("input_dir") else None
    seeds = [p for p in seed_dir.iterdir() if p.is_file() and not p.name.startswith('.') and p.stat().st_size and os.access(p, os.R_OK)] if seed_dir and seed_dir.is_dir() else []
    add("测试种子", "pass" if seeds else "fail", f"发现 {len(seeds)} 个可读种子" if seeds else "当前协议未配置可读取的测试种子。")
    if meta.get("dictionary"):
        dictionary = Path(normalize_path(meta["dictionary"]))
        valid = dictionary.is_file() and os.access(dictionary, os.R_OK)
        add("变异字典", "pass" if valid else "fail", "字典可读取" if valid else "协议字典缺失或不可读取。")

    if local:
        command = shlex.split(meta.get("target_command", "").format(port=port))
        work_dir = Path(normalize_path(meta.get("work_dir", ".")))
        target = Path(shutil.which(command[0]) or normalize_path(command[0], work_dir)) if command else None
        valid = bool(target and target.is_file() and os.access(target, os.X_OK) and work_dir.is_dir())
        for module in meta.get("python_dependencies", []):
            valid = valid and importlib.util.find_spec(module) is not None
        tool = meta.get("target_tool")
        if tool:
            valid = valid and bool(shutil.which(tool[0]) or os.access(normalize_path(tool[1]), os.X_OK))
        add("本地目标程序", "pass" if valid else "fail", "启动配置可用，任务启动时自动启动目标服务。" if valid else "本地目标程序或启动配置缺失。")
    else:
        add("目标接入", "pass", "本机向指定设备发包，目标服务需由设备提供。")
        add("覆盖率观测", "warning", "远端设备的代码覆盖率与崩溃信息需要额外执行反馈，端口响应不能证明这些数据可采集。")

    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM)
        add("目标地址", "pass", "地址解析成功")
    except OSError:
        add("目标地址", "fail", "地址无法解析，请检查目标主机。")
        return result(items, started)

    if local:
        family, kind, proto, _, address = addresses[0]
        try:
            with socket.socket(family, kind, proto) as check:
                check.bind(address)
            add("本地端口", "pass", "端口可用，目标服务尚未启动属于正常情况。")
        except OSError:
            add("本地端口", "fail", "端口被占用或无法绑定，请更换端口或停止占用服务。")
        add("协议响应", "warning", "本地服务将在任务启动时运行，当前未验证协议响应。")
        return result(items, started)

    if not compatible:
        add("协议响应", "warning", "传输协议不匹配，未执行协议探测。")
        return result(items, started)

    if transport == "tcp":
        try:
            with socket.create_connection((host, port), timeout=2) as connection:
                connection.settimeout(2)
                add("目标连接", "pass", "TCP 连接成功")
                status, message = probe_tcp(connection, protocol, host)
                add("协议响应", status, message)
        except OSError:
            if not any(item['name'] == '目标连接' for item in items):
                add("目标连接", "fail", "TCP 连接失败，请检查设备服务、端口及网络。")
            else:
                add("协议响应", "warning", "未收到有效协议响应，可能需要认证或特定请求参数。")
    else:
        add("目标连接", "warning", "UDP 无连接握手，需根据协议响应确认目标。")
        status, message = probe_udp(addresses, protocol)
        add("协议响应", status, message)
    return result(items, started)


def result(items: list[dict[str, str]], started: float) -> dict[str, Any]:
    blocked = any(item["status"] == "fail" for item in items)
    return {"ok": not blocked, "status": "fail" if blocked else "warning" if any(item["status"] == "warning" for item in items) else "pass", "checks": items, "elapsed_ms": round((time.monotonic() - started) * 1000)}


def receive(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def probe_tcp(connection: socket.socket, protocol: str, host: str) -> tuple[str, str]:
    valid = False
    if protocol == "MODBUS":
        connection.sendall(bytes.fromhex("000100000006010300000001"))
        header = receive(connection, 7)
        if len(header) == 7 and header[:4] == bytes.fromhex("00010000") and header[6] == 1:
            length = int.from_bytes(header[4:6], "big")
            if 2 <= length <= 254:
                body = receive(connection, length - 1)
                valid = (len(body) == length - 1 and (body[:2] == b'\x03\x02' and len(body) == 4 or body[:1] == b'\x83' and len(body) == 2))
    elif protocol == "MQTT":
        client_id = b'preflight'
        body = b'\x00\x04MQTT\x04\x02\x00\x05' + struct.pack('!H', len(client_id)) + client_id
        connection.sendall(b'\x10' + bytes([len(body)]) + body)
        reply = receive(connection, 4)
        valid = len(reply) == 4 and reply[:2] == b'\x20\x02' and reply[2] in (0, 1) and reply[3] <= 5
    elif protocol in {"HTTP", "IPP", "RTSP", "SIP"}:
        version = 'RTSP/1.0' if protocol == 'RTSP' else 'SIP/2.0' if protocol == 'SIP' else 'HTTP/1.1'
        request = f'OPTIONS * {version}\r\nHost: {host}\r\nCSeq: 1\r\nConnection: close\r\n\r\n'
        if protocol == 'SIP':
            return 'warning', 'SIP 探测需要目标 URI 与会话参数，当前仅验证 TCP 连接。'
        connection.sendall(request.encode('ascii'))
        reply = connection.recv(4096)
        valid = reply.startswith(version.encode() + b' ') and len(reply.split(b' ', 2)) >= 2 and reply.split(b' ', 2)[1].isdigit()
        if protocol == 'IPP' and valid:
            return 'warning', '已收到 HTTP 响应；IPP 需要打印机 URI，尚未验证 IPP 层响应。'
    elif protocol in {'FTP', 'SMTP', 'SSH'}:
        reply = connection.recv(4096)
        valid = reply.startswith(b'SSH-') if protocol == 'SSH' else reply.startswith(b'220 ') or reply.startswith(b'220-')
        if protocol in {'FTP', 'SMTP'} and valid:
            connection.sendall(b'FEAT\r\n' if protocol == 'FTP' else b'EHLO preflight.local\r\n')
            reply = connection.recv(4096)
            valid = reply.startswith(b'211') if protocol == 'FTP' else reply.startswith(b'250')
    elif protocol == 'TLS':
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(connection, server_hostname=host) as secured:
            valid = bool(secured.version())
    else:
        return 'warning', 'TCP 连接可用；该协议握手需要会话或设备参数，尚未验证协议响应。'
    return ('pass', '收到有效协议响应（不代表检测覆盖率或崩溃反馈可用）。') if valid else ('warning', '收到的响应未能确认所选协议，请检查服务类型或认证要求。')


def probe_udp(addresses: list[Any], protocol: str) -> tuple[str, str]:
    if protocol == 'DNS':
        request = b'\x71\x23\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'
        valid = lambda data: len(data) >= 12 and data[:2] == request[:2] and bool(data[2] & 0x80)
    elif protocol in {'NTP', 'SNTP'}:
        request = b'\x23' + b'\x00' * 39 + struct.pack('!Q', int((time.time() + 2208988800) * 2**32))
        valid = lambda data: len(data) >= 48 and data[0] & 7 == 4 and data[24:32] == request[40:48]
    elif protocol == 'TFTP':
        request = b'\x00\x01preflight-nonexistent\x00octet\x00'
        valid = lambda data: len(data) >= 4 and (data[:2] == b'\x00\x05' or data[:4] == b'\x00\x03\x00\x01')
    else:
        return 'warning', '协议探测需要认证、会话或设备参数，当前未确认 UDP 服务响应。'
    family, kind, proto, _, address = addresses[0]
    try:
        with socket.socket(family, kind, proto) as connection:
            connection.settimeout(2)
            connection.sendto(request, address)
            data, source = connection.recvfrom(4096)
            if source[0] != address[0] or (protocol != 'TFTP' and source[1] != address[1]):
                return 'warning', '响应来源与目标不匹配，未确认目标协议。'
        return ('pass', '收到有效协议响应。') if valid(data) else ('warning', '响应格式与所选协议不匹配。')
    except OSError:
        return 'warning', '未收到协议响应，可能受网络、服务或认证配置影响。'
