"""AEM passive bridge tests; synthetic sensors and no blockchain/worker calls."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import mycelium_next as app
from aem_bridge import decide_from_gate, public_advice
from aem_shadow import ControllerMemory


class AEMBridgeTests(unittest.TestCase):
    NOW = 1000.0

    def gate(self, **overrides):
        data = {
            "allowed": True,
            "reason": "ready",
            "maximum_celsius": 68.0,
            "provenance": {"sampled_at_unix_s": self.NOW},
            "s1_mupp": {"allowed": True, "provenance": {"timestamp_unix": self.NOW}},
        }
        data.update(overrides)
        return data

    def assert_no_money(self, result):
        for key in ("trade_authorized", "mint_authorized",
                    "reinvestment_authorized"):
            self.assertFalse(result[key])

    def test_both_authorities_required(self):
        result = decide_from_gate(self.gate(allowed=False, reason="s1_blocked"),
                                  ControllerMemory(False), self.NOW)
        self.assertEqual(result.state, "MUPP_LOCK")
        self.assert_no_money(public_advice(result, self.NOW)["decision"])

    def test_future_mupp_timestamp_is_not_accepted(self):
        gate = self.gate()
        gate["s1_mupp"]["provenance"]["timestamp_unix"] = self.NOW + 1
        result = decide_from_gate(gate, ControllerMemory(False), self.NOW)
        self.assertEqual(result.state, "SENSOR_LOCK")

    def test_malformed_and_missing_provenance_refuse(self):
        for gate in (None, {}, self.gate(s1_mupp={}),
                     self.gate(provenance={}),
                     self.gate(maximum_celsius=None)):
            with self.subTest(gate=gate):
                self.assertEqual(decide_from_gate(gate, ControllerMemory(False),
                                                  self.NOW).state, "SENSOR_LOCK")

    def test_hard_stop_and_hysteresis(self):
        data = self.gate(allowed=False, reason="cooldown", maximum_celsius=92)
        blocked = decide_from_gate(data, ControllerMemory(False), self.NOW)
        self.assertEqual(blocked.state, "THERMAL_LOCK")
        self.assertTrue(blocked.next_memory.thermal_latched)
        data = self.gate(maximum_celsius=73)
        still_blocked = decide_from_gate(data, blocked.next_memory, self.NOW)
        self.assertEqual(still_blocked.state, "THERMAL_LOCK")
        cleared = decide_from_gate(self.gate(maximum_celsius=69),
                                   blocked.next_memory, self.NOW)
        self.assertEqual(cleared.state, "LOW_POWER_DISCOVERY")

    def test_read_only_financial_evidence_unavailable(self):
        d = decide_from_gate(self.gate(), ControllerMemory(False), self.NOW)
        out = public_advice(d, self.NOW)
        self.assertEqual(out["evidence"]["no_edge"],
                         "not_connected_to_discovery")
        self.assertIsNone(out["evidence"]["realized_revenue"])
        self.assert_no_money(out["decision"])


class SensorCoverageTests(unittest.TestCase):
    def test_hwmon_hottest_package_wins_even_if_acpi_cool(self):
        zone = Mock()
        zone.__str__ = Mock(return_value="/sys/class/thermal/thermal_zone0/temp")
        zone.read_text.return_value = "57000"
        cpu = Mock()
        cpu.__str__ = Mock(return_value="/sys/class/hwmon/hwmon6/temp1_input")
        cpu.read_text.return_value = "91000"
        thermal_root = Mock()
        thermal_root.glob.return_value = [zone]
        hwmon_root = Mock()
        hwmon_root.glob.return_value = [cpu]
        with patch.object(app, "Path", side_effect=lambda path: {
                "/sys/class/thermal": thermal_root,
                "/sys/class/hwmon": hwmon_root,
            }[path]):
            values = app.temperatures()
        self.assertEqual(max(s["celsius"] for s in values["samples"]), 91)
        self.assertEqual(values["errors"], [])
        self.assertTrue(any("/sys/class/hwmon/" in s["source"] for s in values["samples"]))

    def test_unreadable_hwmon_is_reported_fail_closed(self):
        zone = Mock()
        zone.__str__ = Mock(return_value="/sys/class/thermal/thermal_zone0/temp")
        zone.read_text.return_value = "40000"
        cpu = Mock()
        cpu.__str__ = Mock(return_value="/sys/class/hwmon/hwmon6/temp1_input")
        cpu.read_text.side_effect = PermissionError("sensor denied")
        thermal_root = Mock()
        thermal_root.glob.return_value = [zone]
        hwmon_root = Mock()
        hwmon_root.glob.return_value = [cpu]
        with patch.object(app, "Path", side_effect=lambda path: {
                "/sys/class/thermal": thermal_root,
                "/sys/class/hwmon": hwmon_root,
            }[path]):
            values = app.temperatures()
        self.assertEqual(len(values["samples"]), 1)
        self.assertEqual(values["errors"], ["/sys/class/hwmon/hwmon6/temp1_input"])


class EngineAEMIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.now = 1000.0
        self.temperature = 69
        self.state = Path(temp.name) / "state"
        self.kwargs = dict(
            state=self.state, backend=Path(temp.name) / "never-connect.sock",
            thermal_source=self.sensor, mupp_source=self.mupp,
            clock=lambda: self.now,
        )
        self.engine = app.Engine(**self.kwargs)

    def sensor(self):
        return {"samples": [{"celsius": self.temperature, "source": "synthetic:test"}],
                "errors": [], "sampled_at_unix_s": self.now}

    def mupp(self):
        return {"schema_version": 1, "mode": "MUPP_LOCAL_CONTROL",
                "timestamp_unix": self.now, "phase": "REGULATED", "regime": "SAFE",
                "sensor_ok": True, "sensor_warmup_complete": True,
                "allow_execution": True, "T": self.temperature, "H": 20.0,
                "RecoveryDebt": 0.0, "queue": 0}

    def test_real_engine_gate_persists_shadow_no_job(self):
        self.assertTrue(self.engine.gate()["allowed"])
        snap = self.engine.status()["aem_eco"]
        self.assertEqual(snap["decision"]["state"], "LOW_POWER_DISCOVERY")
        self.assertFalse(snap["decision"]["trade_authorized"])
        self.assertEqual(self.engine.status()["counts"], {})
        self.assertTrue(self.engine.verify_journal()["valid"])

    def test_hot_cooldown_survives_restart(self):
        self.temperature = 96
        self.assertFalse(self.engine.gate()["allowed"])
        self.assertEqual(self.engine.status()["aem_eco"]["decision"]["state"],
                         "THERMAL_LOCK")
        self.temperature = 73
        restarted = app.Engine(**self.kwargs)
        self.assertFalse(restarted.gate()["allowed"])
        self.assertEqual(restarted.status()["aem_eco"]["decision"]["state"],
                         "THERMAL_LOCK")
        self.temperature = 69
        self.assertTrue(restarted.gate()["allowed"])
        self.assertEqual(restarted.status()["aem_eco"]["decision"]["state"],
                         "LOW_POWER_DISCOVERY")

    def test_s1_unavailable_does_not_produce_positive_advice(self):
        self.engine.mupp_source = lambda: (_ for _ in ()).throw(
            FileNotFoundError("no S1 state"))
        self.assertFalse(self.engine.gate()["allowed"])
        self.assertEqual(self.engine.status()["aem_eco"]["decision"]["state"],
                         "MUPP_LOCK")

    def test_corrupt_persistent_memory_fails_closed(self):
        with self.engine.db() as conn:
            conn.execute("INSERT INTO settings VALUES (?,?)",
                         ("aem_shadow_memory", '{"thermal_latched":"yes"}'))
        self.engine.gate()
        self.assertEqual(self.engine.status()["aem_eco"]["decision"]["state"],
                         "SENSOR_LOCK")

    def test_status_never_treats_stale_snapshot_as_fresh(self):
        self.engine.gate()
        self.now += 31
        self.assertEqual(self.engine.status()["aem_eco"]["state"],
                         "STALE_TELEMETRY")

    def test_absent_snapshot_is_explicit(self):
        self.assertEqual(self.engine.status()["aem_eco"]["state"], "NOT_SAMPLED")

    def test_preflight_hot_does_not_consume_or_execute(self):
        job_id = self.engine.submit("pending-health")
        self.temperature = 93
        report = self.engine.preflight()
        self.assertFalse(report["can_execute_existing_jobs"])
        self.assertEqual(report["aem_eco"]["decision"]["state"], "THERMAL_LOCK")
        self.assertFalse(report["cqr_backend"]["connected"])
        self.assertFalse(report["financial_execution"]["enabled"])
        self.assertIsNone(report["external_revenue"]["verified"])
        with self.engine.db() as db:
            job = db.execute("SELECT state,attempts FROM jobs WHERE id=?",
                             (job_id,)).fetchone()
            self.assertEqual((job["state"], job["attempts"]), ("queued", 0))

    def test_preflight_good_gate_does_not_fabricate_cqr_or_nev(self):
        report = self.engine.preflight()
        self.assertTrue(report["can_execute_existing_jobs"])
        self.assertFalse(report["cqr_backend"]["connected"])
        self.assertIsNone(report["external_revenue"]["verified"])
        self.assertFalse(report["aem_eco"]["decision"]["trade_authorized"])
        self.assertEqual(self.engine.status()["counts"], {})

    def test_preflight_without_s1_fails_closed(self):
        self.engine.mupp_source = lambda: (_ for _ in ()).throw(
            FileNotFoundError("not running"))
        report = self.engine.preflight()
        self.assertFalse(report["can_execute_existing_jobs"])
        self.assertEqual(report["aem_eco"]["decision"]["state"], "MUPP_LOCK")


if __name__ == "__main__":
    unittest.main()
