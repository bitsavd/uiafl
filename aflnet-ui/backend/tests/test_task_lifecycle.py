from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from app.main import start, stop, create_task, TaskCreate
from app.store import can_start_task, can_stop_task, start_task


class TaskLifecycleTests(unittest.TestCase):
    def test_only_unused_created_tasks_can_start(self):
        with tempfile.TemporaryDirectory() as directory:
            task = {'id': 'fresh', 'status': 'created', 'output_dir': directory}
            self.assertTrue(can_start_task(task))
            for update in ({'status': 'stopped'}, {'status': 'completed'}, {'status': 'running'},
                           {'readonly': True}, {'started_at': '2026-11-16'}, {'pid': 123}):
                self.assertFalse(can_start_task({**task, **update}), update)
            (Path(directory) / 'fuzzer_stats').write_text('old experiment')
            self.assertFalse(can_start_task(task))
            with patch('app.store.subprocess.Popen') as launch:
                with self.assertRaises(ValueError):
                    start_task(task)
            launch.assert_not_called()
            self.assertEqual((Path(directory) / 'fuzzer_stats').read_text(), 'old experiment')

    def test_new_task_with_prepared_command_is_startable(self):
        with tempfile.TemporaryDirectory() as directory, patch('app.main.upsert_task', side_effect=lambda t: t):
            task = create_task(TaskCreate(name='new DICOM', category='industrial', protocol='DICOM',
                                         netinfo='tcp://127.0.0.1/5158', output_dir=directory))
            self.assertTrue(task['can_start'])
            self.assertFalse(task['can_stop'])

    def test_stop_requires_running_mutable_task(self):
        self.assertTrue(can_stop_task({'status': 'running'}))
        for task in ({'status': 'created'}, {'status': 'stopped'}, {'status': 'running', 'readonly': True}):
            self.assertFalse(can_stop_task(task))
            with patch('app.main.get_task_or_404', return_value=task), patch('app.main.refresh_task_status', side_effect=lambda t: t), patch('app.main.stop_task') as halt:
                with self.assertRaises(HTTPException) as error:
                    stop('test')
                self.assertEqual(error.exception.status_code, 409)
                halt.assert_not_called()

    def test_concurrent_start_requests_launch_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            shared = {'id': 'test', 'status': 'created', 'output_dir': directory}

            def launch(task):
                shared.update(status='running', started_at='2026-11-16')
                return dict(shared)

            def request():
                try:
                    start('test')
                    return 200
                except HTTPException as error:
                    return error.status_code

            with patch('app.main.get_task_or_404', side_effect=lambda _: dict(shared)), patch('app.main.refresh_task_status', side_effect=lambda t: t), patch('app.main.load_tasks', return_value=[]), patch('app.main.load_settings', return_value={}), patch('app.main.with_summary', side_effect=lambda t: t), patch('app.main.start_task', side_effect=launch) as spawn:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    statuses = list(executor.map(lambda _: request(), range(2)))
                self.assertEqual(sorted(statuses), [200, 409])
                self.assertEqual(spawn.call_count, 1)
