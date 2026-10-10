"""RUN_PROTOCOL_SMOKE=1 python3 -m unittest discover -s tests -p test_protocol_smoke.py"""
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.protocols import protocol_meta
from app.store import (ROOT, build_aflnet_command, default_options, parse_stats,
                       replay_sample_with_target, runtime_env)


@unittest.skipUnless(os.environ.get('RUN_PROTOCOL_SMOKE') == '1', 'Explicit opt-in for native fuzzing smoke tests')
class ProtocolSmokeTests(unittest.TestCase):
    def test_no_response_exits_without_spinning(self):
        with tempfile.TemporaryDirectory(prefix='protocol-no-response-') as directory:
            meta = protocol_meta('DNS')
            task = {**meta, 'protocol': 'DNS', 'target_profile': 'external',
                    'netinfo': 'udp://127.0.0.2/59999', 'output_dir': directory,
                    'target_command': 'sleep 86400', 'duration': '8s',
                    'aflnet_options': {**default_options(), 'startup_delay_us': 10000}}
            result = subprocess.run(build_aflnet_command(task), cwd=ROOT, env=runtime_env(),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
            self.assertNotEqual(result.returncode, 124)
            self.assertIn(b'No seeds reached a protocol state', result.stdout)

    def test_bundled_protocols_detect_and_replay(self):
        for protocol in ('FTP', 'DNS', 'DICOM', 'IPP', 'DTLS12'):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory(prefix='protocol-smoke-') as directory:
                meta = protocol_meta(protocol)
                with socket.socket(type=socket.SOCK_DGRAM if meta['transport'] == 'UDP' else socket.SOCK_STREAM) as reserve:
                    reserve.bind(('127.0.0.1', 0))
                    port = reserve.getsockname()[1]
                task = {**meta, 'protocol': protocol, 'target_profile': 'standard',
                        'netinfo': f"{meta['transport'].lower()}://127.0.0.1/{port}",
                        'output_dir': directory, 'target_command': meta['target_command'].format(port=port),
                        'duration': '60s' if protocol == 'DICOM' else '30s',
                        'aflnet_options': {**default_options(), 'startup_delay_us': meta['startup_delay_us'],
                                           'timeout': meta.get('default_timeout_ms', '2000+')}}
                result = subprocess.run(build_aflnet_command(task), cwd=ROOT, env=runtime_env(),
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=100)
                log = result.stdout.decode(errors='replace')
                self.assertIn(result.returncode, (0, 124), log[-3000:])
                stats = parse_stats(directory)
                self.assertGreater(int(stats.get('execs_done', 0)), 0, log[-3000:])
                self.assertGreater(int(stats.get('state_edges', 0)), 0, log[-3000:])
                if meta.get('instrumented') is False:
                    self.assertEqual(int(stats['code_feedback']), 0)
                originals = list((Path(directory) / 'replayable-queue').glob('id*,orig:*'))
                self.assertEqual(len(originals), len(list((ROOT / meta['input_dir']).iterdir())))
                for sample in originals:
                    replay = replay_sample_with_target(str(sample), task, port)
                    self.assertEqual(replay['returncode'], 0, replay)
                    responses = replay['stderr'].split('Responses from server:', 1)[1].splitlines()[0]
                    self.assertGreater(len(responses.split('-')), 2, replay)
                print(protocol, {key: stats.get(key) for key in ('execs_done', 'paths_total', 'state_nodes', 'state_edges', 'code_feedback')}, flush=True)


if __name__ == '__main__':
    unittest.main()
