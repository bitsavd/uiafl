import tempfile
import socket
import struct
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app.main import TaskCreate, create_task
from app.protocols import protocol_meta
from app.store import ROOT, build_aflnet_command, default_options, replay_sample


class ProtocolTemplateTests(unittest.TestCase):
    def test_bundled_corpora(self):
        for protocol, count in {'FTP': 2, 'DNS': 1, 'DICOM': 4, 'IPP': 4, 'DTLS12': 2}.items():
            with self.subTest(protocol=protocol):
                meta = protocol_meta(protocol)
                seeds = list((ROOT / meta['input_dir']).iterdir())
                self.assertEqual(len(seeds), count)
                self.assertTrue(all(seed.is_file() and seed.stat().st_size for seed in seeds))
                if meta.get('dictionary'):
                    self.assertTrue((ROOT / meta['dictionary']).is_file())
                if protocol == 'DTLS12':
                    self.assertTrue(all('client' in seed.name for seed in seeds))

    def task(self, protocol, external=False):
        meta = protocol_meta(protocol)
        return {**meta, 'protocol': protocol, 'target_profile': 'external' if external else 'standard',
                'netinfo': f"{meta['transport'].lower()}://127.0.0.1/{meta['default_port']}",
                'output_dir': '/tmp/protocol-test-output', 'target_command': 'sleep 86400' if external else meta['target_command'].format(port=meta['default_port']),
                'aflnet_options': default_options()}

    def test_local_noninstrumented_targets_use_protocol_feedback(self):
        for protocol in ('FTP', 'DNS', 'DICOM', 'IPP'):
            command = build_aflnet_command(self.task(protocol))
            self.assertIn('-n', command)
            self.assertEqual(command[command.index('-b') + 1], '2')
        self.assertNotIn('-n', build_aflnet_command(self.task('MQTT')))
        self.assertNotIn('-n', build_aflnet_command(self.task('DTLS12')))

    def test_external_placeholder_is_terminated_even_without_cleanup_option(self):
        task = self.task('DNS', external=True)
        task['aflnet_options']['terminate_server'] = False
        command = build_aflnet_command(task)
        self.assertIn('-n', command)
        self.assertIn('-K', command)
        self.assertEqual(command[-2:], ['sleep', '86400'])

    def test_creation_uses_protocol_startup_default(self):
        with patch('app.main.upsert_task') as save, patch('app.main.load_settings', return_value={'execution': {'startup_delay_us': 20000, 'default_timeout_ms': '2000+', 'default_duration': '10m'}}):
            for protocol in ('FTP', 'DNS', 'DICOM', 'IPP', 'DTLS12'):
                meta = protocol_meta(protocol)
                create_task(TaskCreate(name='test', protocol=protocol, netinfo=f"{meta['transport'].lower()}://127.0.0.1/{meta['default_port']}"))
                task = save.call_args.args[0]
                self.assertEqual(task['aflnet_options']['startup_delay_us'], meta['startup_delay_us'])

    def test_replay_passes_host_transport_and_binary_safe_decoding(self):
        with tempfile.NamedTemporaryFile() as seed, patch('app.store.subprocess.run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ''
            run.return_value.stderr = ''
            replay_sample(seed.name, 'DNS', 5353, host='127.0.0.2')
            self.assertEqual(run.call_args.args[0][-2:], ['127.0.0.2', 'udp'])
            self.assertEqual(run.call_args.kwargs['errors'], 'replace')

    @unittest.skipUnless((ROOT / 'aflnet-replay').is_file(), 'Native replay needs compilation')
    def test_native_udp_replay_reaches_requested_host(self):
        request = bytes.fromhex('7123010000010000000000000000020001')
        errors = []
        with socket.socket(type=socket.SOCK_DGRAM) as server, tempfile.NamedTemporaryFile() as sample:
            server.bind(('127.0.0.2', 0))
            server.settimeout(3)
            sample.write(struct.pack('=I', len(request)) + request)
            sample.flush()

            def respond():
                try:
                    data, address = server.recvfrom(4096)
                    self.assertEqual(data, request)
                    server.sendto(data[:2] + b'\x81\x85' + data[4:], address)
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=respond)
            worker.start()
            result = replay_sample(sample.name, 'DNS', server.getsockname()[1], host='127.0.0.2')
            worker.join(4)
            self.assertFalse(errors)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result['returncode'], 0)
            self.assertIn('\\x81', result['stderr'])
            self.assertIn('Responses from server:0-', result['stderr'])


if __name__ == '__main__':
    unittest.main()
