import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from app.line_coverage import ROOT, aggregate_gcov, collect, line_metrics, merge_coverage_plot
from app.main import build_report_markdown
from app.store import detection_metrics


class LineCoverageTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('gcc') and shutil.which('gcov') and (ROOT / 'aflnet-replay').exists(), 'Requires coverage toolchain and replay binary')
    def test_modbus_real_collection_accumulates_source_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            queue = output / 'replayable-queue'
            queue.mkdir()
            packet = bytes.fromhex('000100000006010100000001')
            (queue / 'id:000000').write_bytes(struct.pack('I', len(packet)) + packet)
            first = collect({'protocol': 'MODBUS'}, output)
            self.assertGreater(first['lines_covered'], 0)
            packet = bytes.fromhex('000200000006010300000002')
            (queue / 'id:000001').write_bytes(struct.pack('I', len(packet)) + packet)
            second = collect({'protocol': 'MODBUS'}, output)
            self.assertGreaterEqual(second['lines_covered'], first['lines_covered'])
            self.assertEqual(second['lines_total'], first['lines_total'])
            self.assertEqual(second['line_coverage_pct'], round(second['lines_covered'] * 100 / second['lines_total'], 2))
            self.assertEqual(collect({'protocol': 'MODBUS'}, output), second)

    def test_unique_source_lines_exclude_system_headers(self):
        source = Path('/tmp/coverage-source')
        documents = [{'current_working_directory': str(source), 'files': [
            {'file': 'server.c', 'lines': [{'line_number': 1, 'count': 2}, {'line_number': 2, 'count': 0}]},
            {'file': 'server.c', 'lines': [{'line_number': 2, 'count': 1}]},
            {'file': '/usr/include/stdio.h', 'lines': [{'line_number': 4, 'count': 1}]},
        ]}]
        self.assertEqual(aggregate_gcov(documents, source), (2, 2))

    def test_real_line_data_required_for_display_and_export(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertFalse(line_metrics(output)['line_coverage_available'])
            (output / 'line_coverage.json').write_text(json.dumps({'lines_covered': 30, 'lines_total': 100}))
            result = detection_metrics({}, {'target_mode': 'default', 'bitmap_cvg': '0.4%'}, directory)
            self.assertEqual(result['line_coverage'], '30.00%')
            self.assertNotIn('bitmap_cvg', result)
            task = {'name': 'test', 'protocol': 'MODBUS', 'netinfo': 'tcp://localhost/502', 'stats': result}
            report = build_report_markdown(task, {})
            self.assertIn('代码行覆盖率：30.00%', report)
            self.assertNotIn('0.4%', report)
            external = detection_metrics({'target_profile': 'external'}, {'target_mode': 'default', 'bitmap_cvg': '0.4%'}, directory)
            self.assertFalse(external['line_coverage_available'])

    def test_invalid_denominator_not_displayed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / 'line_coverage.json').write_text(json.dumps({'lines_covered': 0, 'lines_total': 0}))
            self.assertFalse(line_metrics(output)['line_coverage_available'])

    def test_history_does_not_invent_early_zero_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / 'line_coverage_plot.json').write_text(json.dumps({'rows': [{'unix_time': 20, 'line_coverage_pct': 30}]}))
            rows = merge_coverage_plot(output, [{'unix_time': 10, 'paths_total': 4}, {'unix_time': 30, 'paths_total': 8}])
            self.assertNotIn('line_coverage_pct', rows[0])
            self.assertEqual(rows[-1]['line_coverage_pct'], 30)
            self.assertEqual(rows[1]['paths_total'], 8)
            self.assertEqual([row['unix_time'] for row in rows], [10, 30])

    def test_earlier_coverage_does_not_shift_engine_time_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / 'line_coverage_plot.json').write_text(json.dumps({'rows': [
                {'unix_time': 5, 'line_coverage_pct': 70},
                {'unix_time': 15, 'line_coverage_pct': 90},
                {'unix_time': 40, 'line_coverage_pct': 95},
            ]}))
            raw = [{'unix_time': 10, 'paths_total': 4, 'execs_per_sec': 20},
                   {'unix_time': 20, 'paths_total': 8, 'execs_per_sec': 25}]
            rows = merge_coverage_plot(output, raw)
            self.assertEqual([row['unix_time'] for row in rows], [10, 20])
            self.assertEqual([row['line_coverage_pct'] for row in rows], [70, 90])
            self.assertEqual(rows[0]['paths_total'], 4)
            self.assertEqual(rows[0]['execs_per_sec'], 20)
            self.assertNotIn('line_coverage_pct', raw[0])
            self.assertEqual(merge_coverage_plot(output, []), [])
