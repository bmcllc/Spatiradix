"""Economic boundary tests with synthetic quotes and mock gates, no hardware."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, replace
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aem_economics import (
    BudgetSnapshot, Costs, Forecast, MAX_INPUT_BYTES, Policy, Quote,
    energy_cost_upper_micros, evaluate_quote, main, reject_constant, strict_object,
)
from aem_shadow import ControllerMemory, Observation, evaluate


NOW = 1_900_000_000.0
DAY = datetime.fromtimestamp(NOW, timezone.utc).date().isoformat()


def mock_observation(**overrides):
    values = dict(sensor_unix=NOW, package_c=50.0, mupp_unix=NOW,
                  mupp_allow=True, paid_job_observed=True)
    values.update(overrides)
    return Observation.parse(values)


class EconomicAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.quote = Quote("synthetic-job", "USDC", NOW + 60, 1_000_000,
                           Costs(20_000, 50_000, 10_000, 10_000, 10_000),
                           True, True, True, False, 2_000, 10_000)
        self.policy = Policy(100_000, 50_000, 500_000, 2_000_000, 10_000, 30_000)
        self.budget = BudgetSnapshot(NOW, DAY, 0, 0)
        self.gate = evaluate(mock_observation(), ControllerMemory(), NOW)

    def forecast(self, quote=None, policy=None, budget=None, gate=None):
        return evaluate_quote(quote or self.quote, policy or self.policy,
                              budget or self.budget, gate or self.gate, NOW)

    def test_forecast_includes_all_costs_and_risk_without_authorizing(self):
        result = self.forecast()
        self.assertEqual(result.state, "READY_FOR_VERIFICATION_SHADOW")
        self.assertEqual(result.cost_upper_micros, 100_000)
        self.assertEqual(result.required_reservation_micros, 150_000)
        self.assertEqual(result.net_lower_micros, 850_000)
        self.assertIsNone(result.verified_nev)
        for name in ("execution_authorized", "trade_authorized", "mint_authorized",
                     "reinvestment_authorized"):
            self.assertFalse(getattr(result, name))
            with self.assertRaises(TypeError):
                Forecast("READY", "synthetic", "VERIFY_JOB_SHADOW", **{name: True})

    def test_each_unknown_cost_blocks_instead_of_becoming_zero(self):
        for name in asdict(self.quote.costs_upper_micros):
            with self.subTest(cost=name):
                costs = replace(self.quote.costs_upper_micros, **{name: None})
                result = self.forecast(quote=replace(self.quote, costs_upper_micros=costs))
                self.assertEqual(result.state, "MEASURE_COST_SHADOW")
                self.assertIsNone(result.net_lower_micros)
                self.assertIn(name, result.reason)

    def test_unknown_payment_is_unpriced(self):
        self.assertEqual(self.forecast(quote=replace(self.quote, payment_lower_micros=None)).state,
                         "UNPRICED_JOB")

    def test_internal_unfunded_and_unsupported_jobs_do_not_advance(self):
        for name, state in (("external_payer_declared", "INTERNAL_WORK"),
                            ("funding_evidence_declared", "UNFUNDED_JOB"),
                            ("adapter_implemented_declared", "UNSUPPORTED_SERVICE")):
            with self.subTest(name=name):
                self.assertEqual(self.forecast(quote=replace(self.quote, **{name: False})).state,
                                 state)

    def test_gpu_and_resource_overruns_block(self):
        for changes in ({"gpu_required": True}, {"total_cpu_ms": 10_001},
                        {"total_wall_ms": 30_001}):
            with self.subTest(changes=changes):
                self.assertEqual(self.forecast(quote=replace(self.quote, **changes)).state,
                                 "RESOURCE_LOCK")

    def test_exact_resource_limits_can_be_forecast(self):
        result = self.forecast(quote=replace(self.quote, total_cpu_ms=10_000, total_wall_ms=30_000))
        self.assertEqual(result.state, "READY_FOR_VERIFICATION_SHADOW")

    def test_thermal_sensor_mupp_and_no_edge_advice_remain_blocking(self):
        for changes in ({"package_c": 75}, {"package_c": None},
                        {"sensor_unix": NOW - 31}, {"sensor_unix": NOW + 1},
                        {"mupp_allow": False}, {"mupp_unix": NOW - 31},
                        {"no_edge": True}, {"paid_job_observed": False}):
            with self.subTest(changes=changes):
                gate = evaluate(mock_observation(**changes), ControllerMemory(), NOW)
                self.assertEqual(self.forecast(gate=gate).state, "GATE_BLOCKED")

    def test_profit_floor_is_inclusive_and_does_not_relax_after_no_edge(self):
        exact = replace(self.quote, payment_lower_micros=250_000)
        self.assertEqual(self.forecast(quote=exact).state, "READY_FOR_VERIFICATION_SHADOW")
        below = replace(exact, payment_lower_micros=249_999)
        result = self.forecast(quote=below)
        self.assertEqual(result.state, "NO_EDGE_QUOTE")
        self.assertEqual(result.net_lower_micros, 99_999)
        self.assertEqual(self.policy.min_profit_micros, 100_000)

    def test_negative_edge_is_reported_without_execution(self):
        result = self.forecast(quote=replace(self.quote, payment_lower_micros=0))
        self.assertEqual(result.state, "NO_EDGE_QUOTE")
        self.assertEqual(result.net_lower_micros, -150_000)
        self.assertFalse(result.execution_authorized)

    def test_expiration_is_inclusive(self):
        self.assertEqual(self.forecast(quote=replace(self.quote, expires_unix=NOW)).state,
                         "EXPIRED_QUOTE")

    def test_job_cap_counts_risk_reserve(self):
        exact = replace(self.policy, max_job_exposure_micros=150_000)
        self.assertEqual(self.forecast(policy=exact).state, "READY_FOR_VERIFICATION_SHADOW")
        self.assertEqual(self.forecast(policy=replace(exact, max_job_exposure_micros=149_999)).state,
                         "BUDGET_LOCK")

    def test_daily_cap_counts_spent_and_existing_reservations(self):
        exact = replace(self.budget, spent_micros=1_000_000, reserved_micros=850_000)
        self.assertEqual(self.forecast(budget=exact).state, "READY_FOR_VERIFICATION_SHADOW")
        self.assertEqual(self.forecast(budget=replace(exact, reserved_micros=850_001)).state,
                         "BUDGET_LOCK")

    def test_disabled_or_overspent_budget_blocks(self):
        self.assertEqual(self.forecast(policy=replace(self.policy, daily_exposure_limit_micros=0)).state,
                         "BUDGET_LOCK")
        self.assertEqual(self.forecast(budget=replace(self.budget, spent_micros=2_000_001)).state,
                         "BUDGET_LOCK")

    def test_budget_freshness_and_utc_day_fail_closed(self):
        for changes in ({"sampled_unix": NOW - 31}, {"sampled_unix": NOW + 1},
                        {"day_utc": "2000-01-01"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.forecast(budget=replace(self.budget, **changes)).state,
                                 "BUDGET_LOCK")
        self.assertEqual(self.forecast(budget=replace(self.budget, sampled_unix=NOW - 30)).state,
                         "READY_FOR_VERIFICATION_SHADOW")

    def test_policy_rejects_zero_profit_negative_boolean_and_large_limits(self):
        for changes in ({"min_profit_micros": 0}, {"risk_reserve_micros": -1},
                        {"max_job_exposure_micros": True}, {"max_cpu_ms": 10_001},
                        {"max_wall_ms": 30_001}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.policy, **changes)

    def test_quotes_reject_ambiguous_types_currency_and_missing_costs(self):
        for changes in ({"payment_lower_micros": 1.5}, {"external_payer_declared": "true"},
                        {"currency": "BRL"}, {"total_cpu_ms": 0},
                        {"expires_unix": float("nan")}, {"expires_unix": 10 ** 1000}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.quote, **changes)
        raw = asdict(self.quote)
        del raw["costs_upper_micros"]["wear"]
        with self.assertRaises(TypeError):
            Quote.parse(raw)
        with self.assertRaises(TypeError):
            Quote.parse(dict(asdict(self.quote), execution_authorized=True))

    def test_energy_conversion_rounds_up_without_temperature_or_float_money(self):
        self.assertEqual(energy_cost_upper_micros(3_600_000, 250_000), 250_000)
        self.assertEqual(energy_cost_upper_micros(1, 250_000), 1)
        self.assertEqual(energy_cost_upper_micros(0, 250_000), 0)
        with self.assertRaises(ValueError):
            energy_cost_upper_micros(50.0, 250_000)
        with self.assertRaises(ValueError):
            energy_cost_upper_micros(1, True)

    def test_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for payload in ('{"payment":1,"payment":2}', '{"payment":NaN}', '{"payment":Infinity}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                json.loads(payload, object_pairs_hook=strict_object, parse_constant=reject_constant)

    def call_cli(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-proposal.json"
            path.write_bytes(payload)
            output, errors = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["aem_economics", "--proposal", str(path)]), \
                    patch("aem_economics.time.time", return_value=NOW), \
                    redirect_stdout(output), redirect_stderr(errors):
                main()
            return output.getvalue()

    def test_cli_reports_shadow_and_never_financial_authority(self):
        raw = dict(quote=asdict(self.quote), policy=asdict(self.policy),
                   budget=asdict(self.budget), observation=asdict(mock_observation()))
        result = json.loads(self.call_cli(json.dumps(raw).encode()))
        self.assertEqual(result["forecast"]["scope"], "SHADOW_QUOTE")
        self.assertFalse(result["forecast"]["execution_authorized"])
        self.assertIsNone(result["forecast"]["verified_nev"])

    def test_cli_rejects_nonobject_sections_and_oversized_input(self):
        raw = dict(quote=asdict(self.quote), policy=asdict(self.policy),
                   budget=asdict(self.budget), observation=[])
        for payload in (json.dumps(raw).encode(), b" " * (MAX_INPUT_BYTES + 1)):
            with self.subTest(size=len(payload)), self.assertRaises(SystemExit) as raised:
                self.call_cli(payload)
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
