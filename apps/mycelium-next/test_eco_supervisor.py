"""Synthetic safety and recovery tests; no network, wallet or native mining."""
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

import mycelium_next as app
from eco_supervisor import (EcoConfig, EcoSupervisor, NativeFailure, NativeRunner,
                            scheduler_deadline, verified_paid_demand)


def scheduler(deadline=0, thermal=0):
    return {'version': 1, 'wait_cycle_seconds': 60, 'next_attempt_unix': deadline,
            'thermal_cooldown_until_unix': thermal}


def dashboard(now=1000):
    return {'timestamp_unix': now,
            'trust': {'trust_mode': 'provider_pinned', 'provider_identity_verified': True,
                      'outcome_policy': {'validated': True}},
            'invariants': {key: False for key in (
                'internal_volume_is_revenue', 'myc_emission_is_revenue',
                'bot_service_spend_is_external_value', 'terr_can_authorize_capital',
                'stored_proof_verified_is_authority')},
            'revenue_validation': {'paid_demand_musd': 1.25}}


class FakeNative:
    def __init__(self, now):
        self.now, self.calls, self.failures = now, [], {}
        self.status = {'scheduler': scheduler()}
        self.result = {'observation': {}, 'state_name': 'NO_EDGE',
                       'action_name': 'BACKOFF', 'scheduler': scheduler(1120)}
        self.revenue = dashboard()

    def run(self, command, arguments=(), stop_event=None):
        self.calls.append((command, list(arguments)))
        if command in self.failures:
            raise self.failures[command]
        if command == 'discovery-status':
            return self.status
        if command == 'discovery-run':
            return self.result
        return self.revenue


class EcoSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.now, self.temperature, self.mupp_valid = 1000.0, 50.0, True
        self.engine = self.make_engine()
        self.config = EcoConfig(self.root / 'native', self.root / 'eco',
                                self.root / 'source.json', self.root / 'mupp.json',
                                'test-agent', 10000, 60)
        self.native = FakeNative(lambda: self.now)
        self.supervisor = EcoSupervisor(self.engine, self.config, self.native)
        self.write_source({'report': 1})

    def make_engine(self):
        return app.Engine(self.root / 'state', self.root / 'backend.sock',
                          thermal_source=lambda: {
                              'samples': [{'celsius': self.temperature, 'source': 'synthetic:test'}],
                              'errors': [], 'sampled_at_unix_s': self.now},
                          clock=lambda: self.now, mupp_source=self.mupp_reading)

    def mupp_reading(self):
        if not self.mupp_valid:
            return {}
        return {'schema_version': 1, 'mode': 'MUPP_LOCAL_CONTROL',
                'timestamp_unix': self.now, 'phase': 'REGULATED', 'regime': 'SAFE',
                'sensor_ok': True, 'sensor_warmup_complete': True,
                'allow_execution': True, 'T': 50.0, 'H': 20.0,
                'RecoveryDebt': 0.0, 'queue': 0}

    def write_source(self, value):
        self.config.source_report.write_text(json.dumps(value), encoding='utf-8')
        os.utime(self.config.source_report, (self.now, self.now))

    def report_state(self):
        with self.supervisor.db() as db:
            return db.execute('SELECT state FROM reports').fetchone()[0]

    def test_thermal_and_mupp_blocks_do_not_start_native_processes(self):
        self.temperature = 75
        self.assertEqual(self.supervisor.run_once()['state'], 'GATE_BLOCKED')
        self.temperature = 50
        self.mupp_valid = False
        self.assertEqual(self.supervisor.run_once()['state'], 'GATE_BLOCKED')
        self.assertEqual(self.native.calls, [])
        self.assertFalse(self.config.native_home.exists())

    def test_fresh_source_and_scheduler_are_required(self):
        for raw, expected in ((b'{"a":1,"a":2}', 'SOURCE_INVALID'),
                              (b'{"a":NaN}', 'SOURCE_INVALID'),
                              (b'[]', 'SOURCE_INVALID'), (b'', 'SOURCE_INVALID')):
            with self.subTest(raw=raw):
                self.config.source_report.write_bytes(raw)
                os.utime(self.config.source_report, (self.now, self.now))
                self.assertEqual(self.supervisor.run_once()['state'], expected)
        self.write_source({'report': 1})
        self.now += 31
        self.assertEqual(self.supervisor.run_once()['state'], 'SOURCE_STALE')
        self.config.source_report.unlink()
        self.assertEqual(self.supervisor.run_once()['state'], 'SOURCE_UNAVAILABLE')
        self.assertEqual(self.native.calls, [])

    def test_normalized_source_also_has_size_limit(self):
        self.config.source_report.write_text('{"a":"' + 'é' * 23000 + '"}', encoding='utf-8')
        os.utime(self.config.source_report, (self.now, self.now))
        self.assertLess(self.config.source_report.stat().st_size, 131072)
        self.assertEqual(self.supervisor.run_once()['state'], 'SOURCE_INVALID')
        self.assertEqual(self.native.calls, [])

    def test_old_native_binary_cannot_mutate_discovery(self):
        self.native.status = {'state_name': 'NO_EDGE'}
        self.assertEqual(self.supervisor.run_once()['state'], 'NATIVE_UPGRADE_REQUIRED')
        self.assertEqual([item[0] for item in self.native.calls], ['discovery-status'])

    def test_native_backoff_does_not_fabricate_a_search(self):
        self.native.status = {'scheduler': scheduler(1120)}
        self.assertEqual(self.supervisor.run_once()['state'], 'BACKOFF')
        self.now = 1119
        self.write_source({'report': 2})
        self.assertEqual(self.supervisor.run_once()['state'], 'BACKOFF')
        self.assertEqual([item[0] for item in self.native.calls], ['discovery-status'])

    def test_backoff_restart_dedup_and_new_report_resume_automatically(self):
        first = self.supervisor.run_once()
        self.assertEqual(first['state'], 'OBSERVED')
        self.assertEqual(first['verified_paid_demand_musd'], 1.25)
        self.assertFalse(first['financial_authority'])
        self.assertEqual(self.report_state(), 'consumed')
        frozen = self.native.calls[1][1][0]
        self.assertEqual(frozen.read_bytes(), b'{"report":1}')
        self.assertEqual(self.native.calls[1][1][2], '0.010000')
        self.assertEqual(frozen.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.native_home.stat().st_mode & 0o777, 0o700)
        restarted = EcoSupervisor(self.make_engine(), self.config, self.native)
        self.now = 1119
        self.assertEqual(restarted.run_once()['state'], 'BACKOFF')
        self.now = 1120
        self.write_source({'report': 1})
        self.config.source_report.write_text(' { "report" : 1 } ')
        os.utime(self.config.source_report, (self.now, self.now))
        self.assertEqual(restarted.run_once()['state'], 'WAITING_FOR_NEW_REPORT')
        self.assertEqual(len(self.native.calls), 3)
        self.write_source({'report': 2})
        self.native.result['scheduler'] = scheduler(1240)
        self.assertEqual(restarted.run_once()['state'], 'OBSERVED')
        self.assertEqual(len(self.native.calls), 6)

    def test_started_failure_blocks_all_replays_even_with_new_reports(self):
        self.native.failures['discovery-run'] = NativeFailure('NATIVE_TIMEOUT', True)
        self.assertEqual(self.supervisor.run_once()['state'], 'NEEDS_RECONCILIATION')
        self.now += 500
        self.write_source({'report': 2})
        restarted = EcoSupervisor(self.make_engine(), self.config, self.native)
        self.assertEqual(restarted.run_once()['state'], 'NEEDS_RECONCILIATION')
        self.assertEqual([c[0] for c in self.native.calls], ['discovery-status', 'discovery-run'])

    def test_process_crash_checkpoint_blocks_a_retry(self):
        self.native.status = {'scheduler': scheduler(1120)}
        self.supervisor.run_once()
        with self.supervisor.db() as db:
            db.execute("INSERT INTO reports VALUES('interrupted','processing',NULL)")
        self.assertEqual(self.supervisor.run_once()['state'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.report_state(), 'needs_reconciliation')
        self.assertEqual(len(self.native.calls), 1)

    def test_presend_failure_is_retryable_after_poll_wait(self):
        self.native.failures['discovery-run'] = NativeFailure('GATE_BLOCKED')
        self.assertEqual(self.supervisor.run_once()['state'], 'GATE_BLOCKED')
        self.assertEqual(self.report_state(), 'pending')
        self.assertEqual(self.supervisor.run_once()['state'], 'BACKOFF')
        self.now += 30
        self.write_source({'report': 1})
        del self.native.failures['discovery-run']
        self.assertEqual(self.supervisor.run_once()['state'], 'OBSERVED')

    def test_native_denial_does_not_consume_the_report(self):
        self.native.result = {'completed': False, 'denied': {'state': 'thermal'},
                              'scheduler': scheduler(1060)}
        self.assertEqual(self.supervisor.run_once()['state'], 'BACKOFF')
        self.assertEqual(self.report_state(), 'pending')
        self.assertEqual(len(self.native.calls), 2)
        self.now = 1060
        self.write_source({'report': 1})
        self.native.result = {'observation': {}, 'scheduler': scheduler()}
        self.assertEqual(self.supervisor.run_once()['state'], 'OBSERVED')

    def test_invalid_mutating_response_requires_reconciliation(self):
        self.native.result = {'completed': True, 'scheduler': scheduler()}
        self.assertEqual(self.supervisor.run_once()['state'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.report_state(), 'needs_reconciliation')

    def test_missing_post_mutation_scheduler_requires_reconciliation(self):
        self.native.result = {'observation': {}}
        self.assertEqual(self.supervisor.run_once()['state'], 'NEEDS_RECONCILIATION')

    def test_revenue_read_failure_does_not_replay_consumed_search(self):
        self.native.failures['economy-dashboard'] = NativeFailure('NATIVE_FAILED', True)
        result = self.supervisor.run_once()
        self.assertEqual(result['state'], 'OBSERVED')
        self.assertIsNone(result['verified_paid_demand_musd'])
        self.assertEqual(self.report_state(), 'consumed')

    def test_lock_prevents_competing_supervisors(self):
        self.config.native_home.mkdir()
        with (self.config.native_home / '.mycelium-next-eco.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.supervisor.run_once()['state'], 'SUPERVISOR_BUSY')
        self.assertEqual(self.native.calls, [])

    def test_status_is_passive_and_expires_revenue(self):
        self.supervisor.run_once()
        self.assertEqual(self.engine.status()['mycelium_eco']['state'], 'OBSERVED')
        self.now += 61
        status = self.engine.status()['mycelium_eco']
        self.assertEqual(status['state'], 'STALE_TELEMETRY')
        self.assertIsNone(status['verified_paid_demand_musd'])
        self.assertFalse(status['financial_authority'])
        self.assertEqual(len(self.native.calls), 3)


class ContractTests(unittest.TestCase):
    def test_scheduler_requires_real_wall_clock_contract(self):
        self.assertEqual(scheduler_deadline(scheduler(1120, 1180)), 1180)
        self.assertEqual(scheduler_deadline(scheduler(None, None)), 0)
        for value in (None, {}, scheduler(True), scheduler(-1), scheduler(2**63),
                      {**scheduler(), 'version': True},
                      {**scheduler(), 'wait_cycle_seconds': 1}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scheduler_deadline(value)

    def test_untrusted_internal_or_stale_revenue_is_unknown(self):
        self.assertEqual(verified_paid_demand(dashboard(), 1000), 1.25)
        self.assertIsNone(verified_paid_demand(dashboard(), 1006))
        self.assertIsNone(verified_paid_demand(dashboard(), 999))
        for key, value in (('trust_mode', 'unverified'),
                           ('provider_identity_verified', False),
                           ('outcome_policy', {'validated': False})):
            data = dashboard()
            data['trust'][key] = value
            self.assertIsNone(verified_paid_demand(data, 1000))
        for key in dashboard()['invariants']:
            data = dashboard()
            data['invariants'][key] = True
            self.assertIsNone(verified_paid_demand(data, 1000))
        for value in (True, -1, float('nan'), float('inf'), '1.25'):
            data = dashboard()
            data['revenue_validation']['paid_demand_musd'] = value
            self.assertIsNone(verified_paid_demand(data, 1000))

    def test_config_paths_limits_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'config.json'
            valid = {'binary': 'binary', 'native_home': 'home', 'source_report': 'source',
                     'mupp_state': '/tmp/s1-mupp-state.json', 'agent_id': 'test',
                     'estimated_job_cost_musd_micros': 10000, 'ttl_seconds': 60}
            path.write_text(json.dumps(valid))
            config = EcoConfig.load(path)
            self.assertEqual(config.binary, Path(root) / 'binary')
            self.assertEqual(config.poll_seconds, 30)
            for key, value in (('poll_seconds', 1), ('ttl_seconds', True),
                               ('estimated_job_cost_musd_micros', 0),
                               ('agent_id', ''), ('unknown', 1), ('mupp_policy', 'policy')):
                with self.subTest(key=key):
                    path.write_text(json.dumps({**valid, key: value}))
                    with self.assertRaises(ValueError):
                        EcoConfig.load(path)


class NativeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.binary = self.root / 'native'
        self.config = EcoConfig(self.binary, self.root / 'home', self.root / 'source',
                                self.root / 'mupp', 'test', 1, 60)
        self.runner = NativeRunner(self.config, lambda: {'allowed': True})

    def script(self, code):
        self.binary.write_text('#!' + sys.executable + '\n' + code + '\n')
        self.binary.chmod(0o700)

    def test_limits_are_applied_before_exec(self):
        self.script('import json, os, resource\n'
                    'print(json.dumps({"cpu": resource.getrlimit(resource.RLIMIT_CPU), '
                    '"memory": resource.getrlimit(resource.RLIMIT_AS), '
                    '"cores": len(os.sched_getaffinity(0)), "nice": os.nice(0)}))')
        result = self.runner.run('discovery-status')
        self.assertEqual(result['cpu'], [2, 3])
        self.assertEqual(result['memory'], [256 * 1024 * 1024] * 2)
        self.assertEqual(result['cores'], 1)
        self.assertGreaterEqual(result['nice'], 15)

    def test_financial_commands_are_rejected_before_launch(self):
        with self.assertRaises(NativeFailure) as failure:
            self.runner.run('transfer')
        self.assertEqual(failure.exception.code, 'COMMAND_NOT_ALLOWED')
        self.assertFalse(failure.exception.started)

    def test_stop_and_gate_blocks_are_presend(self):
        stop = threading.Event()
        stop.set()
        with self.assertRaises(NativeFailure) as failure:
            self.runner.run('discovery-run', stop_event=stop)
        self.assertFalse(failure.exception.started)
        self.runner.gate = lambda: {'allowed': False}
        with self.assertRaises(NativeFailure) as failure:
            self.runner.run('discovery-status')
        self.assertEqual(failure.exception.code, 'GATE_BLOCKED')

    def test_invalid_json_and_excess_output_are_uncertain(self):
        for code, expected in (('print("[]")', 'NATIVE_INVALID_RESPONSE'),
                               ('print("x" * 300000)', 'NATIVE_OUTPUT_LIMIT')):
            with self.subTest(expected=expected):
                self.script(code)
                with self.assertRaises(NativeFailure) as failure:
                    self.runner.run('discovery-run')
                self.assertEqual(failure.exception.code, expected)
                self.assertTrue(failure.exception.started)

    def test_gate_is_monitored_after_worker_closes_output(self):
        self.script('import os, time\nos.close(1)\nos.close(2)\ntime.sleep(5)')
        calls = 0

        def gate():
            nonlocal calls
            calls += 1
            return {'allowed': calls < 4}

        self.runner.gate = gate
        with self.assertRaises(NativeFailure) as failure:
            self.runner.run('discovery-run')
        self.assertEqual(failure.exception.code, 'GATE_BLOCKED')
        self.assertTrue(failure.exception.started)


if __name__ == '__main__':
    unittest.main()
