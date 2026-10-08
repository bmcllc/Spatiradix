"""Synthetic guard tests; NEVER launch cargo or change real thermal hardware."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import guarded_cqr_build as guarded


class GuardedCQRBuildTests(unittest.TestCase):
    def test_adaptive_duty_never_relaxes_thermal_ceiling(self):
        self.assertEqual(guarded.MAX_C, 75.0)
        self.assertEqual(guarded.START_MAX_C, 70.0)
        self.assertEqual(guarded.MAX_RUNTIME_SECONDS, 900)
        self.assertEqual(guarded.duty_cycle(52, False), (0.12, 0.08))
        self.assertEqual(guarded.duty_cycle(63, False), (0.10, 0.16))
        self.assertEqual(guarded.duty_cycle(67, False), (0.06, 0.24))
        self.assertEqual(guarded.duty_cycle(70, False), (0.0, 0.25))
        self.assertEqual(guarded.duty_cycle(60, True), (0.0, 0.25))

    def test_mock_thermal_alarm_kills_private_process_group(self):
        child = Mock()
        child.poll.return_value = None
        child.pid = 123456
        with tempfile.TemporaryDirectory() as td, \
             patch.object(guarded, "cpu_thermal_paths", return_value=[Path("/fake/temp")]), \
             patch.object(guarded, "temperature", side_effect=[52.0, 52.0, 76.0]), \
             patch.object(guarded.os, "sched_getaffinity", return_value={3}), \
             patch.object(guarded, "LOGFILE", Path(td) / "fake-alarm.log"), \
             patch.object(guarded.subprocess, "Popen", return_value=child), \
             patch.object(guarded.os, "killpg") as killed, \
             patch.object(guarded.time, "sleep"):
            self.assertEqual(guarded.run(), 3)
        killed.assert_any_call(child.pid, guarded.signal.SIGTERM)
        self.assertGreaterEqual(killed.call_count, 2)

    def test_hot_start_never_launches_cargo(self):
        with patch.object(guarded, "cpu_thermal_paths", return_value=[Path("/fake/temp")]), \
             patch.object(guarded, "temperature", return_value=79.0), \
             patch.object(guarded.subprocess, "Popen") as launch:
            self.assertEqual(guarded.run(), 3)
            launch.assert_not_called()

    def test_missing_cpu_telemetry_fails_closed(self):
        with patch.object(guarded.Path, "glob", return_value=[]):
            with self.assertRaises(RuntimeError):
                guarded.cpu_thermal_paths()

    def test_lost_sensor_raises_instead_of_inventing_zero(self):
        with tempfile.TemporaryDirectory() as td:
            thermal = Path(td) / "missing_hwmon"
            with patch.object(guarded.Path, "glob", return_value=[]):
                with self.assertRaises(RuntimeError):
                    guarded.temperature([thermal])

    def test_mock_success_uses_single_cpu_and_one_build_job(self):
        child = Mock()
        child.poll.return_value = 0
        child.returncode = 0
        with tempfile.TemporaryDirectory() as td, \
             patch.object(guarded, "cpu_thermal_paths", return_value=[Path("/fake/temp")]), \
             patch.object(guarded, "temperature", return_value=58.0), \
             patch.object(guarded.os, "sched_getaffinity", return_value={2, 3}), \
             patch.object(guarded, "LOGFILE", Path(td) / "fake-test-only.log"), \
             patch.object(guarded.subprocess, "Popen", return_value=child) as launch:
            self.assertEqual(guarded.run(), 0)
            launch.assert_called_once()
            args = launch.call_args.args[0]
            self.assertEqual(args[:3], ["taskset", "-c", "2"])
            self.assertEqual(args[-2:], ["-j", "1"])


if __name__ == "__main__":
    unittest.main()
