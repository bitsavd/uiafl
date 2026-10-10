import unittest
from unittest.mock import patch

from app.main import task_stats


class LiveStatsTests(unittest.TestCase):
    def snapshot(self, status):
        task = {"id": "test", "status": status, "output_dir": "/tmp/unused"}
        stats = {"start_time": "100", "last_update": "120", "run_seconds": 20,
                 "run_time": "0分20秒", "execs_done": "42", "command_line": "private"}
        with patch("app.main.get_task_or_404", return_value=task), \
                patch("app.main.refresh_task_status", return_value=task), \
                patch("app.main.parse_stats", return_value=stats), \
                patch("app.main.time.time", return_value=130):
            return task_stats("test")

    def test_running_duration_uses_live_clock(self):
        result = self.snapshot("running")
        self.assertEqual(result["stats"]["run_seconds"], 30)
        self.assertEqual(result["stats"]["execs_done"], "42")
        self.assertNotIn("command_line", result["stats"])
        self.assertNotIn("plot", result)

    def test_stopped_duration_does_not_advance(self):
        self.assertEqual(self.snapshot("stopped")["stats"]["run_seconds"], 20)


if __name__ == "__main__":
    unittest.main()
