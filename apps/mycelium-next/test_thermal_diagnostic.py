"""Pure synthetic thermal diagnostic tests (no hardware manipulation)."""
import unittest
from unittest.mock import patch
import thermal_diagnostic as diagnosis


class ThermalBaselineTests(unittest.TestCase):
    def test_series_measures_real_values_without_simulated_compute_claim(self):
        reads = [
            {"time_unix_s": 1_000, "cpu_package_c": 60.0,
             "maximum_sensor_c": 63.0, "cpu0_freq_mhz": 1400,
             "sensor_error_count": 0, "sensor_valid": True},
            {"time_unix_s": 1_001, "cpu_package_c": 78.0,
             "maximum_sensor_c": 79.0, "cpu0_freq_mhz": 4300,
             "sensor_error_count": 0, "sensor_valid": True},
            {"time_unix_s": 1_002, "cpu_package_c": 61.0,
             "maximum_sensor_c": 65.0, "cpu0_freq_mhz": 1200,
             "sensor_error_count": 0, "sensor_valid": True},
        ]
        with patch.object(diagnosis, "snapshot", side_effect=reads) as sampler:
            result = diagnosis.series(3, 0.25, sleeper=lambda _: None)
        self.assertEqual(sampler.call_count, 3)
        self.assertEqual(result["cpu_package_min_c"], 60.0)
        self.assertEqual(result["cpu_package_median_c"], 61.0)
        self.assertEqual(result["cpu_package_max_c"], 78.0)
        self.assertEqual(result["over_75c_samples"], 1)
        self.assertFalse(result["cqr_executed"])
        self.assertIsNone(result["verified_nev"])

    def test_failed_sensor_invalidates_report(self):
        invalid = {"time_unix_s": 1_000, "cpu_package_c": None,
                   "maximum_sensor_c": None, "cpu0_freq_mhz": None,
                   "sensor_error_count": 2, "sensor_valid": False}
        with patch.object(diagnosis, "snapshot", return_value=invalid):
            report = diagnosis.series(1, 0.25, sleeper=lambda _: None)
        self.assertFalse(report["all_sensors_valid"])
        self.assertIsNone(report["cpu_package_max_c"])
        self.assertIsNone(report["all_sensor_max_c"])

    def test_bounded_samples_and_intervals(self):
        for count, interval in ((0, 0.25), (81, 0.25),
                                (1, 0.1), (1, 3.0)):
            with self.subTest(count=count, interval=interval):
                with self.assertRaises(ValueError):
                    diagnosis.series(count, interval, sleeper=lambda _: None)

    def test_snapshot_never_substitutes_zone_for_missing_cpu_package(self):
        with patch.object(diagnosis, "temperatures", return_value={
                "samples": [{"source": "acpi", "celsius": 40.0}],
                "errors": []}), \
             patch.object(diagnosis, "cpu_package", return_value=(
                None, ["cpu_coretemp_package_missing"])), \
             patch.object(diagnosis, "read_optional_number", return_value=800.0):
            snap = diagnosis.snapshot(clock=lambda: 1000.0)
        self.assertIsNone(snap["cpu_package_c"])
        self.assertFalse(snap["sensor_valid"])
        self.assertEqual(snap["sensor_error_count"], 1)


if __name__ == "__main__":
    unittest.main()
