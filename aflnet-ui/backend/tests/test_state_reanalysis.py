import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from app.store import detection_metrics, state_graph_path, state_reanalysis

spec = importlib.util.spec_from_file_location("rebuild_state_history", Path(__file__).resolve().parents[2] / "tools/rebuild_state_history.py")
rebuild = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rebuild)


class StateReanalysisTests(unittest.TestCase):
    def test_global_sequences_build_edges_and_trim_repetitions(self):
        dot, metrics = rebuild.graph_data([
            {"states": [0, 1, 2, 2, 2], "initial_seed": True, "response_bytes": 12},
            {"states": [0, 1, 2, 2], "initial_seed": False, "response_bytes": 12},
            {"states": [0, 2], "initial_seed": False, "response_bytes": 4},
            {"states": [0], "initial_seed": False, "response_bytes": 0},
        ])
        self.assertEqual(metrics, {"state_nodes": 3, "state_edges": 4, "state_paths": 2})
        self.assertIn("0 -> 2 [color=red]", dot)
        self.assertIn("1 -> 2 [color=blue]", dot)

    def test_invalid_and_duplicate_samples_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            samples = root / "replayable-queue"
            samples.mkdir()
            payload = b"\x02\x00\x00\x00\xc0\x00"
            (samples / "id:0,orig:seed").write_bytes(payload)
            (samples / "id:1").write_bytes(payload)
            (samples / "id:2").write_bytes(b"\xff\xff\xff\xffx")
            self.assertEqual(rebuild.samples_in(root), [samples / "id:0,orig:seed"])

    def test_rebuilt_graph_is_separate_and_stale_results_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzzer_stats").write_text("historical")
            original = root / "ipsm.dot"
            original.write_text("original")
            rebuilt = root / "state-reanalysis"
            rebuilt.mkdir()
            (rebuilt / "ipsm.dot").write_text("rebuilt")
            manifest = {"version": 1, "method": "saved-input-replay", "state_nodes": 3,
                        "state_edges": 4, "state_paths": 2, "sample_count": 8, "failed_samples": 0,
                        "source_stats_sha256": hashlib.sha256(b"historical").hexdigest()}
            (rebuilt / "summary.json").write_text(json.dumps(manifest))
            self.assertEqual(state_graph_path(directory), rebuilt / "ipsm.dot")
            metrics = detection_metrics({"status": "completed"}, {"paths_total": "73"}, directory)
            self.assertEqual(metrics["state_edges"], 4)
            self.assertEqual(metrics["paths_total"], "73")
            self.assertNotIn("state_graph_source", detection_metrics({"status": "running"}, {}, directory))
            self.assertEqual(original.read_text(), "original")
            (root / "fuzzer_stats").unlink()
            manifest["source_stats_sha256"] = hashlib.sha256(b"").hexdigest()
            (rebuilt / "summary.json").write_text(json.dumps(manifest))
            self.assertEqual(state_graph_path(directory), rebuilt / "ipsm.dot")
            (root / "fuzzer_stats").write_text("resumed")
            self.assertIsNone(state_reanalysis(directory))
            self.assertEqual(state_graph_path(directory), original)
            (rebuilt / "summary.json").write_text("{")
            self.assertIsNone(state_reanalysis(directory))


if __name__ == "__main__":
    unittest.main()
