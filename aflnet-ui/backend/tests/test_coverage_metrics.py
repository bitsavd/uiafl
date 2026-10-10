import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.main import build_report_markdown, with_summary
from app.store import detection_metrics


class CoverageMetricsTests(unittest.TestCase):
    def test_bitmap_is_not_relabelled_as_line_coverage(self):
        result = detection_metrics({}, {"target_mode": "default", "bitmap_cvg": "4.87%"}, "/tmp/absent")
        self.assertFalse(result["line_coverage_available"])
        self.assertNotIn("bitmap_cvg", result)

    def test_state_feedback_is_not_code_coverage(self):
        for stats, task in [
            ({"target_mode": "dumb", "bitmap_cvg": "3%"}, {}),
            ({"target_mode": "default", "bitmap_cvg": "3%", "code_feedback": "0"}, {}),
            ({"target_mode": "default", "bitmap_cvg": "3%", "command_line": "afl-fuzz -b 2 -- target"}, {}),
            ({"target_mode": "default", "bitmap_cvg": "3%"}, {"target_profile": "external"}),
            ({"bitmap_cvg": "3%"}, {}),
        ]:
            result = detection_metrics(task, stats, "/tmp/absent")
            self.assertFalse(result["line_coverage_available"])
            self.assertNotIn("bitmap_cvg", result)

    def test_state_paths_do_not_use_queue_count(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = Path(directory) / "replayable-new-ipsm-paths"
            paths.mkdir()
            (paths / "id:0-1:seed").touch()
            (paths / "id:0-1-2:new").touch()
            (paths / "README.txt").touch()
            result = detection_metrics({}, {"paths_total": "73"}, directory)
            self.assertEqual(result["state_paths"], 2)
            self.assertEqual(result["paths_total"], "73")

    def test_summary_and_export_hide_blackbox_coverage(self):
        task = {"id": "test", "name": "test", "protocol": "MQTT", "netinfo": "tcp://localhost/1883", "target_profile": "external"}
        rows = [{"unix_time": 1, "paths_total": 73, "map_size": 4.87, "n_nodes": 3, "n_edges": 2}]
        with patch("app.main.parse_stats", return_value={"bitmap_cvg": "4.87%", "state_paths": "5", "target_mode": "default"}), \
                patch("app.main.parse_plot", return_value=rows):
            summary = with_summary(task, include_plot=True)
        self.assertNotIn("map_size", summary["plot"][0])
        self.assertEqual(summary["stats"]["state_nodes"], 3)
        report = build_report_markdown(summary, {})
        self.assertNotIn("代码行覆盖率", report)
        self.assertIn("状态路径数：5", report)


if __name__ == "__main__":
    unittest.main()
