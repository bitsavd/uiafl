import unittest

from app.main import chart_time_label


class ChartTimeTests(unittest.TestCase):
    def test_integer_hours_minutes_seconds(self):
        for seconds, expected in [(0, '00:00:00'), (5, '00:00:05'), (90, '00:01:30'),
                                  (3600, '01:00:00'), (3661, '01:01:01'), (86400, '24:00:00'),
                                  (-1, '00:00:00'), (59.5, '00:01:00')]:
            with self.subTest(seconds=seconds):
                self.assertEqual(chart_time_label(seconds), expected)
