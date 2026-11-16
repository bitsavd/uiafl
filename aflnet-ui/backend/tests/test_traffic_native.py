"""RUN_TRAFFIC_SMOKE=1 python3 -m unittest discover -s tests -p test_traffic_native.py"""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

from app.protocols import protocol_meta
from app.store import ROOT, build_aflnet_command, default_options, runtime_env
from app.traffic import read_traffic


@unittest.skipUnless(os.environ.get('RUN_TRAFFIC_SMOKE') == '1', 'Explicit opt-in for native traffic tests')
class NativeTrafficTests(unittest.TestCase):
    def test_tcp_and_udp_capture_actual_packets_and_results(self):
        for protocol in ('MQTT', 'MODBUS', 'DTLS12'):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory(prefix='aflnet-traffic-') as directory:
                meta = protocol_meta(protocol)
                with socket.socket(type=socket.SOCK_DGRAM if meta['transport'] == 'UDP' else socket.SOCK_STREAM) as reserve:
                    reserve.bind(('127.0.0.1', 0))
                    port = reserve.getsockname()[1]
                task = {**meta, 'protocol': protocol, 'target_profile': 'standard',
                        'netinfo': f"{meta['transport'].lower()}://127.0.0.1/{port}",
                        'output_dir': directory, 'target_command': meta['target_command'].format(port=port),
                        'duration': '12s', 'aflnet_options': {**default_options(), 'startup_delay_us': 20000}}
                result = subprocess.run(build_aflnet_command(task), cwd=ROOT, env=runtime_env(task),
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=35)
                self.assertIn(result.returncode, (0, 124), result.stdout[-3000:])
                events = read_traffic(directory, limit=100000)['events']
                self.assertTrue({'case_begin', 'send', 'receive', 'case_end'} <= {item['kind'] for item in events})
                seeds = list((ROOT / meta['input_dir']).iterdir())
                first_send = next(item for item in events if item['kind'] == 'send')
                self.assertTrue(any(bytes.fromhex(first_send['data_hex']) in seed.read_bytes() for seed in seeds))
                cases = {item['case_id'] for item in events if item['kind'] == 'case_begin'}
                for item in events:
                    self.assertIn(item['case_id'], cases)
                    if item['kind'] in ('send', 'receive'):
                        self.assertEqual(len(item['data_hex']) // 2, min(item['length'], 512))
                        self.assertEqual(item['truncated'], item['length'] > 512)
                outcomes = [item for item in events if item['kind'] == 'case_end']
                self.assertTrue(any(item['response_bytes'] > 0 and item['states'] for item in outcomes))
                self.assertLess(sum(path.stat().st_size for path in Path(directory).glob('packet_trace*.jsonl')), 2 * 1024 * 1024 + 8192)
                print(protocol, len(events), 'events;', len(outcomes), 'completed cases', flush=True)
