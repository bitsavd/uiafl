import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from app.protocols import protocol_meta
from app.store import (default_options, is_process_alive, parse_stats, start_task, stop_task)


@unittest.skipUnless(os.environ.get('RUN_DICOM_SMOKE') == '1', 'Opt in to the DICOM forkserver integration test')
class DicomForkserverTests(unittest.TestCase):
    def test_backend_launches_isolated_forkserver_and_disallows_restart(self):
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        meta = protocol_meta('DICOM')
        with tempfile.TemporaryDirectory(prefix='dicom-forkserver-') as directory:
            task = {**meta, 'id': 'dicom-integration', 'status': 'created', 'protocol': 'DICOM',
                    'target_profile': 'standard', 'netinfo': f'tcp://127.0.0.1/{port}',
                    'target_command': meta['target_command'].format(port=port), 'output_dir': directory,
                    'duration': '30s', 'aflnet_options': {**default_options(),
                        'startup_delay_us': meta['startup_delay_us'], 'timeout': meta['default_timeout_ms']}}
            with patch('app.store.upsert_task'), patch.dict(os.environ, {'AFL_FAST_CAL': '1', 'AFL_NO_UI': '1'}):
                start_task(task)
                self.assertTrue(task.get('started_at'))
                pid = task['pid']
                try:
                    deadline = time.monotonic() + 45
                    while is_process_alive(pid) and time.monotonic() < deadline:
                        time.sleep(.1)
                    self.assertFalse(is_process_alive(pid), 'DICOM integration timed out')
                finally:
                    stop_task(task)
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
                with self.assertRaises(ValueError):
                    start_task(task)
            stats = parse_stats(directory)
            log = (Path(directory) / 'afl_stdout.log').read_text(errors='replace')
            self.assertIn('fork server is up', log)
            self.assertEqual(len(list((Path(directory) / 'replayable-queue').glob('id*,orig:*'))), 4, log[-3000:])
            self.assertGreater(int(stats.get('state_edges', 0)), 0, log[-3000:])
            self.assertEqual(stats.get('code_feedback'), '0')
            print('DICOM backend integration:', {key: stats.get(key) for key in ('execs_done', 'execs_per_sec', 'state_edges', 'unique_hangs')}, flush=True)
