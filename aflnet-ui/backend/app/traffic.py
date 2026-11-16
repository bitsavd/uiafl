"""Read a bounded tail of genuine fuzzer send/receive events."""
from functools import lru_cache
import json
from pathlib import Path
import re

KINDS = {'case_begin', 'send', 'receive', 'skip', 'case_end'}
MAX_READ = 2 * 1024 * 1024


@lru_cache(maxsize=4)
def _read_file(path: str, inode: int, modified_ns: int, size: int) -> tuple[dict, ...]:
    try:
        with open(path, 'rb') as stream:
            offset = max(0, size - MAX_READ)
            stream.seek(offset)
            if offset:
                stream.readline()
            lines = stream.read(MAX_READ).splitlines()
    except OSError:
        return ()
    events = []
    for line in lines:
        if len(line) > 8192:
            continue
        try:
            event = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(event, dict) or event.get('kind') not in KINDS:
            continue
        if any(type(event.get(key)) is not int or event[key] < 1 for key in ('seq', 'case_id', 'timestamp_ms')):
            continue
        payload = event.get('data_hex', '')
        if not isinstance(payload, str) or len(payload) > 1024 or len(payload) % 2 or not re.fullmatch('[0-9a-fA-F]*', payload):
            continue
        events.append(event)
    return tuple(events)


def read_traffic(output_dir: str, after: int = 0, limit: int = 200) -> dict:
    directory = Path(output_dir)
    events, available = {}, False
    for name in ('packet_trace.previous.jsonl', 'packet_trace.jsonl'):
        path = directory / name
        try:
            info = path.stat()
        except OSError:
            continue
        available = True
        for event in _read_file(str(path), info.st_ino, info.st_mtime_ns, info.st_size):
            events[event['seq']] = event
    ordered = sorted(events.values(), key=lambda event: event['seq'])
    latest = ordered[-1]['seq'] if ordered else 0
    oldest = ordered[0]['seq'] if ordered else 0
    reset = bool(after and latest and after > latest)
    matches = [event for event in ordered if event['seq'] > (0 if reset else after)]
    selected = matches[-limit:]
    skipped = max(0, len(matches) - limit) if after and not reset else 0
    if after and oldest > after + 1 and not reset:
        skipped += oldest - after - 1
    return {'events': selected, 'cursor': latest, 'available': available,
            'reset': reset, 'skipped': skipped, 'preview_bytes': 512}
