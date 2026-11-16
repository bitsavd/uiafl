import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.main import chart_time_label, render_trend_chart


class ChartTimeTests(unittest.TestCase):
    def test_integer_hours_minutes_seconds(self):
        for seconds, expected in [(0, '00:00:00'), (5, '00:00:05'), (90, '00:01:30'),
                                  (3600, '01:00:00'), (3661, '01:01:01'), (86400, '24:00:00'),
                                  (-1, '00:00:00'), (59.5, '00:01:00')]:
            with self.subTest(seconds=seconds):
                self.assertEqual(chart_time_label(seconds), expected)

    def test_trend_only_plots_paths_and_speed(self):
        figure, axis = MagicMock(), MagicMock()
        rows = [{"unix_time": 1, "paths_total": 1, "execs_per_sec": 2, "line_coverage_pct": 20},
                {"unix_time": 2, "paths_total": 2, "execs_per_sec": 3, "line_coverage_pct": 21}]
        with patch("app.main.plt.subplots", return_value=(figure, axis)), patch("app.main.plt.close"):
            self.assertTrue(render_trend_chart(rows, Path("/tmp/chart-test.png")))
        self.assertEqual([call.kwargs["label"] for call in axis.plot.call_args_list], ["Paths", "Execs/sec"])
