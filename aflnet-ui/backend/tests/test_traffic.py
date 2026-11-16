import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.main import task_traffic
from app.traffic import read_traffic
from app.store import runtime_env


def event(seq, **fields):
    return {'seq': seq, 'case_id': 1, 'timestamp_ms': 1700000000000,
            'kind': 'send', 'data_hex': '10020000', **fields}


class TrafficTests(unittest.TestCase):
    def test_missing_historical_records_are_not_fabricated(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(read_traffic(directory)['events'], [])
            self.assertFalse(read_traffic(directory)['available'])

    def test_cursor_limits_rotation_and_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'packet_trace.previous.jsonl').write_text('\n'.join(json.dumps(event(i)) for i in range(10, 16)) + '\n')
            (root / 'packet_trace.jsonl').write_text('\n'.join(json.dumps(event(i)) for i in range(15, 21)) + '\n')
            result = read_traffic(directory, after=5, limit=3)
            self.assertEqual([item['seq'] for item in result['events']], [18, 19, 20])
            self.assertEqual(result['skipped'], 12)
            self.assertEqual(result['cursor'], 20)
            self.assertEqual(read_traffic(directory, after=20)['events'], [])
            self.assertTrue(read_traffic(directory, after=100)['reset'])

    def test_invalid_and_partial_records_and_append(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'packet_trace.jsonl'
            invalid = [[], event(True), event(2, data_hex='xyz'), event(3, data_hex='00' * 513), event(4, kind='unknown')]
            path.write_text('\n'.join(json.dumps(item) for item in invalid) + '\n' + json.dumps(event(5)) + '\n{"seq":')
            self.assertEqual([item['seq'] for item in read_traffic(directory)['events']], [5])
            with path.open('a') as stream:
                stream.write('6,"case_id":1,"timestamp_ms":1700000000000,"kind":"case_end"}\n')
            self.assertEqual([item['seq'] for item in read_traffic(directory, after=5)['events']], [6])

    def test_api_uses_task_output_and_runtime_enables_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            task = {'id': 'capture', 'status': 'running', 'output_dir': directory}
            with patch('app.main.get_task_or_404', return_value=task), patch('app.main.refresh_task_status', side_effect=lambda item: item):
                result = task_traffic('capture', after=0, limit=10)
            self.assertEqual(result['task_id'], 'capture')
            self.assertFalse(result['available'])
            self.assertEqual(runtime_env(task)['AFLNET_UI_TRACE'], '1')


if __name__ == '__main__':
    unittest.main()
