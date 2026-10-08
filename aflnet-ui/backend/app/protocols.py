PROTOCOL_TEMPLATES = {
    "MQTT": {
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
    "FTP": {"default_port": 2200, "transport": "TCP", "profile": "standard", "capabilities": ["state_feedback", "region_mutation", "replay"]},
    "DNS": {"default_port": 5353, "transport": "UDP", "profile": "standard", "capabilities": ["state_feedback", "region_mutation", "replay"]},
}


def protocol_meta(protocol_id: str) -> dict:
    return PROTOCOL_TEMPLATES.get(protocol_id, {})


def public_protocol(item: dict) -> dict:
    meta = protocol_meta(item["id"])
    return {
        **item,
        "default_port": meta.get("default_port", item.get("default_port")),
        "profile": meta.get("profile", "standard"),
        "capabilities": meta.get("capabilities", ["state_feedback", "region_mutation"]),
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
