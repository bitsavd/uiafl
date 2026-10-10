import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class BlackboxFeedbackTests(unittest.TestCase):
    def test_uninstrumented_target_produces_state_metrics(self):
        with tempfile.TemporaryDirectory(prefix="aflnet-blackbox-test-") as directory:
            base = Path(directory)
            target = base / "server"
            seeds = base / "seeds"
            seeds.mkdir()
            shutil.copyfile(ROOT / "tutorials/modbus/in-modbus/read_coils_min.raw", seeds / "read.raw")
            subprocess.run(["cc", str(ROOT / "tutorials/modbus/modbus_tcp_server.c"), "-o", str(target)], check=True)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            output = base / "out"
            command = ["timeout", "-k", "2s", "5s", str(ROOT / "afl-fuzz"),
                       "-d", "-n", "-b", "2", "-i", str(seeds), "-o", str(output),
                       "-m", "none", "-t", "100", "-N", f"tcp://127.0.0.1/{port}",
                       "-P", "MODBUS", "-D", "20000", "-q", "3", "-s", "3", "-E", "-R", "-K",
                       "--", str(target), str(port)]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=10,
                                    env={**os.environ, "AFL_SKIP_CPUFREQ": "1",
                                         "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_NO_UI": "1"})
            stats_file = output / "fuzzer_stats"
            self.assertTrue(stats_file.exists(), (result.stdout + result.stderr).decode(errors="replace"))
            stats = dict(line.split(":", 1) for line in stats_file.read_text().splitlines() if ":" in line)
            stats = {key.strip(): value.strip() for key, value in stats.items()}
            self.assertEqual(stats["code_feedback"], "0")
            self.assertGreater(int(stats["execs_done"]), 0)
            self.assertGreater(int(stats["state_paths"]), 0)
            self.assertGreater(int(stats["state_edges"]), 0)
            print({key: stats[key] for key in ("execs_done", "state_paths", "state_nodes", "state_edges", "code_feedback")})


if __name__ == "__main__":
    unittest.main()
