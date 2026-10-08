"""Bounded native CQR adapter contract tests, WITHOUT executing native physics."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cqr_runner as cqr
import mycelium_next as app


def synthetic_job():
    """Protocol fixture only: input hash is fabricated, not a real CQR hash."""
    return {
        "spec": {
            "schema_version": 1,
            "job_id": "synthetic-contract-only",
            "model_id": "coupled_oscillators_64",
            "model_version": "1.0.0",
            "compute_level": "c0_classical_symplectic",
            "initial_state_hash": "a" * 64,
            "classical_spec": {"oscillator_count": 64, "mass": 1.0,
                               "spring_constant": 2.0, "periodic_boundary": True},
            "integrator_spec": "velocity_verlet",
            "precision_policy": "float64_strict",
            "tolerance_policy": {"absolute_tolerance": 1e-9,
                                 "relative_tolerance": 1e-7,
                                 "max_energy_drift_fraction": 1e-5},
            "step_count": 45,
            "time_step": 0.005,
            "seed": None,
            "resource_budget": {"max_cpu_time_ms": 10000,
                                "max_wall_time_ms": 30000,
                                "max_memory_bytes": 512 * 1024 * 1024,
                                "thermal_ceiling_celsius": 75},
            "expected_observables": ["energy"],
            "validation_suite": ["symplectic_conservation"],
        },
        "initial_state": {"q": [0.0] * 64, "p": [0.0] * 64},
    }


def synthetic_native_output(job):
    """Contract fixture, never evidence of real execution or revenue."""
    spec = job["spec"]
    digest = "b" * 64
    h = "c" * 64
    return {"scope": "LOCAL_CQR_C0_SCIENTIFIC_VALIDATION_NOT_EXTERNAL_SETTLEMENT",
            "job_id": spec["job_id"], "job_hash": h,
            "result_digest": digest, "validation_passed": True,
            "validation_report": {"numerical_valid": True,
                                  "physical_known_answer_valid": True,
                                  "bitwise_reproducible": True},
            "result": {"job_id": spec["job_id"], "job_hash": h,
                       "result_digest": digest, "validation_passed": True},
            "maximum_thermal_c": 67,
            "received_revenue": False, "verified_nev": None,
            "wallet_signing": False, "onchain_execution": False}


class StrictCQRAdapterTests(unittest.TestCase):
    def test_bounded_fixture_schema(self):
        self.assertLess(len(cqr.validate_request(synthetic_job())), cqr.MAX_REQUEST)

    def test_reject_invalid_input(self):
        changes = [
            ("spec", "compute_level", "c5_quantum_geometry_research"),
            ("spec", "schema_version", 2),
            ("spec", "model_id", "different_physics"),
            ("spec", "model_version", "2.0.0"),
            ("spec", "integrator_spec", "runge_kutta4_non_symplectic"),
            ("spec", "precision_policy", "float32_standard"),
            ("spec", "expected_observables", ["energy", "unknown"]),
            ("spec", "validation_suite", ["unimplemented"]),
            ("spec", "classical_spec", {
                "oscillator_count": 64, "mass": 1.0,
                "spring_constant": 2.0, "periodic_boundary": False,
            }),
            ("spec", "step_count", 0),
            ("spec", "step_count", 5001),
            ("spec", "time_step", float("nan")),
            ("spec", "initial_state_hash", "not-a-real-hash"),
            ("spec", "resource_budget", {}),
            ("initial_state", "q", [float("inf")] * 64),
            ("initial_state", "p", [1.0]),
        ]
        for group, key, value in changes:
            with self.subTest(group=group, key=key):
                payload = synthetic_job()
                payload[group][key] = value
                with self.assertRaises(ValueError):
                    cqr.validate_request(payload)

    def test_missing_or_wrong_binary_refuses_without_launch(self):
        with self.assertRaises(OSError):
            cqr.run_cqr(synthetic_job(), "/definitely/not/a/worker")

    def test_no_external_revenue_can_be_claimed_by_native_output(self):
        data = synthetic_job()
        with tempfile.TemporaryDirectory() as td:
            fake_binary = Path(td) / "mock-native"
            fake_binary.write_text("mock only")
            fake_binary.chmod(0o700)
            for updates in ({"received_revenue": True},
                            {"verified_nev": 123},
                            {"wallet_signing": True},
                            {"maximum_thermal_c": 95},
                            {"validation_passed": False}):
                with self.subTest(updates=updates):
                    report = synthetic_native_output(data)
                    report.update(updates)
                    fake_result = subprocess.CompletedProcess(
                        [str(fake_binary)], 0,
                        json.dumps(report).encode(), b"")
                    with patch.object(cqr.subprocess, "run", return_value=fake_result):
                        with self.assertRaises(ValueError):
                            cqr.run_cqr(data, fake_binary)

    def test_timeout_is_bounded_failure_not_supervisor_crash(self):
        with tempfile.TemporaryDirectory() as td:
            mock = Path(td) / "mock-only"
            mock.write_text("mock only")
            mock.chmod(0o700)
            with patch.object(cqr.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                    "mycelium-cqr-worker", 10)):
                with self.assertRaises(OSError):
                    cqr.run_cqr(synthetic_job(), mock)

    def test_valid_mock_contract_still_not_revenue(self):
        data = synthetic_job()
        report = synthetic_native_output(data)
        with tempfile.TemporaryDirectory() as td:
            mock = Path(td) / "mock-only"
            mock.write_text("mock only")
            mock.chmod(0o700)
            fake_result = subprocess.CompletedProcess(
                [str(mock)], 0, json.dumps(report).encode(), b"")
            with patch.object(cqr.subprocess, "run", return_value=fake_result):
                self.assertEqual(cqr.run_cqr(data, mock)["received_revenue"], False)


class CQRQueueSafetyTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.now = 1000
        self.temp = 69.0
        self.engine = app.Engine(
            Path(td.name) / "state", Path(td.name) / "backend.sock",
            thermal_source=lambda: {
                "samples": [{"source": "synthetic:test", "celsius": self.temp}],
                "errors": [], "sampled_at_unix_s": self.now,
            },
            clock=lambda: self.now,
            mupp_source=lambda: {
                "schema_version": 1, "timestamp_unix": self.now,
                "mode": "MUPP_LOCAL_CONTROL",
                "phase": "REGULATED", "regime": "SAFE", "sensor_ok": True,
                "sensor_warmup_complete": True, "allow_execution": True,
                "T": self.temp, "H": 20.0, "RecoveryDebt": 0.0, "queue": 0,
            },
        )

    def test_hot_queue_stays_queued_and_runner_not_invoked(self):
        jid = self.engine.submit("cqr-hot", "cqr_c0", synthetic_job())
        self.temp = 91
        with patch.object(app, "run_cqr") as native:
            res = self.engine.run_once()
        native.assert_not_called()
        self.assertEqual(res["state"], "thermal_blocked")
        self.assertEqual(self.engine.status()["jobs"][0]["attempts"], 0)
        self.assertEqual(self.engine.status()["jobs"][0]["state"], "queued")
        self.assertEqual(jid, 1)

    def test_native_absent_never_accepts(self):
        self.engine.submit("cqr-unavailable", "cqr_c0", synthetic_job())
        with patch.object(app, "run_cqr", side_effect=OSError("no binary")):
            result = self.engine.run_once()
        self.assertEqual(result["state"], "queued")
        self.assertEqual(result["result"]["received_revenue"], False)

    def test_synthetic_native_result_never_economic_income(self):
        self.engine.submit("cqr-fixture", "cqr_c0", synthetic_job())
        with patch.object(app, "run_cqr", return_value=synthetic_native_output(synthetic_job())):
            result = self.engine.run_once()
        self.assertEqual(result["state"], "accepted")
        self.assertEqual(result["result"]["scope"],
                         "LOCAL_CQR_C0_SCIENTIFIC_VALIDATION_NOT_EXTERNAL_SETTLEMENT")
        self.assertFalse(result["result"]["received_revenue"])
        self.assertTrue(self.engine.verify_journal()["valid"])

    def test_gate_changed_after_mock_native_discards_result(self):
        self.engine.submit("cqr-unsafe-after", "cqr_c0", synthetic_job())

        def fake_native(_):
            self.temp = 80
            return synthetic_native_output(synthetic_job())

        with patch.object(app, "run_cqr", side_effect=fake_native):
            result = self.engine.run_once()
        self.assertEqual(result["state"], "queued")
        self.assertEqual(result["result"]["reason"], "gate_changed")
        self.assertEqual(self.engine.status()["jobs"][0]["attempts"], 0)

    def test_idempotency_cannot_swap_cqr_payload(self):
        self.engine.submit("cqr-same", "cqr_c0", synthetic_job())
        second = synthetic_job()
        second["spec"]["step_count"] = 99
        with self.assertRaises(ValueError):
            self.engine.submit("cqr-same", "cqr_c0", second)


if __name__ == "__main__":
    unittest.main()
