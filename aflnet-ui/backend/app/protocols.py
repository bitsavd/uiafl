PROTOCOL_TEMPLATES = {
    "MQTT": {
        "coverage_builder": "mosquitto",
        "default_port": 18885,
        "transport": "TCP",
        "input_dir": "tutorials/mosquitto/in-mqtt",
        "dictionary": "",
        "target_command": "mosquitto/src/mosquitto -p {port}",
        "work_dir": ".",
        "cleanup_script": "",
        "profile": "standard",
        "capabilities": ["state_feedback", "region_mutation", "replay", "trend"],
    },
    "RTSP": {
        "coverage_builder": "live555",
        "default_port": 8554,
        "transport": "TCP",
        "input_dir": "tutorials/live555/in-rtsp",
        "dictionary": "tutorials/live555/rtsp.dict",
        "target_command": "./testOnDemandRTSPServer {port}",
        "work_dir": "../live555/testProgs",
        "cleanup_script": "",
        "profile": "standard",
        "capabilities": ["state_feedback", "region_mutation", "replay", "trend"],
    },
    "MODBUS": {
        "coverage_builder": "modbus",
        "default_port": 1502,
        "transport": "TCP",
        "input_dir": "tutorials/modbus/in-modbus",
        "dictionary": "tutorials/modbus/modbus.dict",
        "target_command": "tutorials/modbus/modbus_tcp_server {port}",
        "work_dir": ".",
        "cleanup_script": "",
        "profile": "standard",
        "capabilities": ["state_feedback", "region_mutation", "replay", "trend"],
    },
    "FTP": {
        "default_port": 2200, "transport": "TCP", "input_dir": "tutorials/lightftp/in-ftp",
        "dictionary": "tutorials/lightftp/ftp.dict", "instrumented": False, "startup_delay_us": 750000,
        "target_command": "python3 aflnet-ui/targets/reference_servers.py FTP {port}", "work_dir": ".",
        "python_dependencies": ["pyftpdlib"],
    },
    "DNS": {
        "default_port": 15353, "transport": "UDP", "input_dir": "tutorials/dnsmasq/in-dns",
        "instrumented": False, "startup_delay_us": 1000000, "poll_timeout_ms": 30,
        "target_command": "python3 aflnet-ui/targets/reference_servers.py DNS {port}", "work_dir": ".",
        "target_tool": ["dnsmasq", "aflnet-ui/targets/.cache/system/usr/sbin/dnsmasq"],
    },
    "DICOM": {
        "default_port": 5158, "transport": "TCP", "input_dir": "tutorials/dcmqrscp/in-dicom",
        "instrumented": False, "startup_delay_us": 1500000, "default_timeout_ms": "5000+",
        "target_command": "python3 aflnet-ui/targets/reference_servers.py DICOM {port}", "work_dir": ".", "poll_timeout_ms": 100,
        "python_dependencies": ["pynetdicom"],
    },
    "IPP": {
        "default_port": 8631, "transport": "TCP", "input_dir": "tutorials/ippsample/in-ipp",
        "dictionary": "tutorials/ippsample/ipp.dict", "instrumented": False, "startup_delay_us": 1000000, "poll_timeout_ms": 50,
        "target_command": "python3 aflnet-ui/targets/reference_servers.py IPP {port}", "work_dir": ".",
        "target_tool": ["ippeveprinter", "aflnet-ui/targets/.cache/system/usr/sbin/ippeveprinter"],
    },
    "DTLS12": {
        "default_port": 20220, "transport": "UDP", "input_dir": "tutorials/tinydtls/in-dtls",
        "startup_delay_us": 20000,
        "target_command": "aflnet-ui/targets/.cache/tinydtls/tests/dtls-server -A ::ffff:127.0.0.1 -p {port}",
        "work_dir": ".", "poll_timeout_ms": 30,
    },
}


def protocol_meta(protocol_id: str) -> dict:
    return PROTOCOL_TEMPLATES.get(protocol_id, {})


def public_protocol(item: dict) -> dict:
    meta = protocol_meta(item["id"])
    return {
        **item,
        "default_port": meta.get("default_port", item.get("default_port")),
        "profile": meta.get("profile", "standard"),
        "capabilities": meta.get("capabilities", ["state_feedback", "region_mutation", "replay", "trend"] if meta else ["state_feedback", "region_mutation"]),
        "startup_delay_us": meta.get("startup_delay_us", 20000),
        "default_timeout_ms": meta.get("default_timeout_ms"),
    }


PROTOCOL_GROUPS = [
    {
        "id": "industrial",
        "name": "工控协议",
        "description": "工业、物联网和设备侧常见协议。",
        "protocols": [
            public_protocol({"id": "MQTT", "name": "MQTT", "transport": "TCP"}),
            public_protocol({"id": "MODBUS", "name": "Modbus", "transport": "TCP"}),
            public_protocol({"id": "DICOM", "name": "DICOM", "transport": "TCP"}),
            public_protocol({"id": "IPP", "name": "IPP", "transport": "TCP"}),
            public_protocol({"id": "SNMP", "name": "SNMP", "transport": "UDP"}),
            public_protocol({"id": "NTP", "name": "NTP", "transport": "UDP"}),
            public_protocol({"id": "SNTP", "name": "SNTP", "transport": "UDP"}),
            public_protocol({"id": "DHCP", "name": "DHCP", "transport": "UDP"}),
            public_protocol({"id": "TFTP", "name": "TFTP", "transport": "UDP"}),
        ],
    },
    {
        "id": "network",
        "name": "网络协议",
        "description": "通用网络服务协议和应用层协议。",
        "protocols": [
            public_protocol({"id": "RTSP", "name": "RTSP", "transport": "TCP"}),
            public_protocol({"id": "FTP", "name": "FTP", "transport": "TCP"}),
            public_protocol({"id": "DNS", "name": "DNS", "transport": "UDP"}),
            public_protocol({"id": "SMTP", "name": "SMTP", "transport": "TCP"}),
            public_protocol({"id": "SSH", "name": "SSH", "transport": "TCP"}),
            public_protocol({"id": "TLS", "name": "TLS", "transport": "TCP"}),
            public_protocol({"id": "DTLS12", "name": "DTLS 1.2", "transport": "UDP"}),
            public_protocol({"id": "SIP", "name": "SIP", "transport": "UDP/TCP"}),
            public_protocol({"id": "HTTP", "name": "HTTP", "transport": "TCP"}),
        ],
    },
]


def protocol_ids() -> set[str]:
    return {item["id"] for group in PROTOCOL_GROUPS for item in group["protocols"]}
