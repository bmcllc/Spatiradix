"""Isolated tests of AEM ECO shadow policy: no hardware access."""
import unittest

from aem_shadow import ControllerMemory, Observation, evaluate


NOW = 1_900_000_000.0


def obs(**overrides):
    data = {
        "sensor_unix": NOW, "package_c": 69.0,
        "mupp_unix": NOW, "mupp_allow": True
    }
    data.update(overrides)
    return Observation.parse(data)


class AEMShadowTests(unittest.TestCase):
    def test_safe_scan_is_never_financial_authority(self):
        decision = evaluate(obs(), ControllerMemory(), NOW)
        self.assertEqual(decision.state, "LOW_POWER_DISCOVERY")
        self.assertFalse(decision.trade_authorized)
        self.assertFalse(decision.mint_authorized)
        self.assertFalse(decision.reinvestment_authorized)

    def test_hot_temperature_hard_locks(self):
        self.assertEqual(evaluate(obs(package_c=80), ControllerMemory(False), NOW).state,
                         "THERMAL_LOCK")

    def test_hysteresis_needs_cooldown(self):
        self.assertEqual(evaluate(obs(package_c=72), ControllerMemory(True), NOW).state,
                         "THERMAL_LOCK")
        self.assertEqual(evaluate(obs(package_c=70), ControllerMemory(True), NOW).state,
                         "LOW_POWER_DISCOVERY")

    def test_missing_sensor_is_not_zero_celsius(self):
        self.assertEqual(evaluate(obs(package_c=None), ControllerMemory(False), NOW).state,
                         "SENSOR_LOCK")

    def test_future_sensor_fails_closed(self):
        self.assertEqual(evaluate(obs(sensor_unix=NOW + 1), ControllerMemory(False), NOW).state,
                         "SENSOR_LOCK")

    def test_stale_mupp_fails_closed(self):
        self.assertEqual(evaluate(obs(mupp_unix=NOW - 31), ControllerMemory(False), NOW).state,
                         "SENSOR_LOCK")

    def test_mupp_denied_cannot_be_overridden(self):
        self.assertEqual(evaluate(obs(mupp_allow=False), ControllerMemory(False), NOW).state,
                         "MUPP_LOCK")

    def test_no_edge_cold_and_backoff(self):
        d = evaluate(obs(no_edge=True), ControllerMemory(False, 3), NOW)
        self.assertEqual(d.state, "COLD_DISCOVERY")
        self.assertEqual(d.next_check_seconds, 480)
        self.assertEqual(d.next_memory.no_edge_streak, 4)

    def test_rotates_only_when_an_adapter_is_supported(self):
        d = evaluate(obs(no_edge=True, alternative_class_supported=True),
                     ControllerMemory(False), NOW)
        self.assertEqual(d.state, "ROTATE_CLASS")

    def test_paid_job_observation_does_not_mint(self):
        d = evaluate(obs(paid_job_observed=True), ControllerMemory(False), NOW)
        self.assertEqual(d.state, "VERIFY_JOB_SHADOW")
        self.assertFalse(d.mint_authorized)

    def test_reject_string_boolean_and_contradiction(self):
        with self.assertRaises(ValueError):
            obs(mupp_allow="false")
        with self.assertRaises(ValueError):
            obs(no_edge=True, candidate_observed=True)

    def test_never_goes_to_trade(self):
        for situation in [
            obs(), obs(no_edge=True), obs(candidate_observed=True),
            obs(paid_job_observed=True), obs(package_c=91),
            obs(mupp_allow=False),
        ]:
            d = evaluate(situation, ControllerMemory(False), NOW)
            self.assertFalse(d.trade_authorized)
            self.assertFalse(d.mint_authorized)
            self.assertFalse(d.reinvestment_authorized)


if __name__ == "__main__":
    unittest.main()
