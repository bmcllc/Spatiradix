import concurrent.futures
import fcntl
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import mycelium_next as app
from mycelium_backend import ControlClient, MutationUncertain, ProtocolError, task_leaves


class MemoryBackend:
    def __init__(self):
        self.repositories = {}
        self.publications = []
        self.fail_publication = None
        self.fail_clone = None

    def publish(self, leaves, message):
        self.publications.append(message)
        if self.fail_publication == len(self.publications):
            raise OSError('synthetic pre-send failure')
        cid = f'{len(self.publications):064x}'
        self.repositories[cid] = json.loads(json.dumps(leaves))
        return cid

    def clone(self, cid):
        if self.fail_clone == cid:
            self.fail_clone = None
            raise OSError('synthetic transient clone failure')
        return json.loads(json.dumps(self.repositories[cid]))


class EngineTests(unittest.TestCase):
    def artifact_job(self, backend=None):
        self.engine.client = backend or MemoryBackend()
        return self.engine.submit('artifact-test', 'artifact_verify',
                                  {'leaves': task_leaves(b'local public sample', 'sample.txt')})

    def test_native_artifact_round_trip_and_receipt(self):
        self.artifact_job()
        self.assertEqual(self.engine.run_once()['state'], 'accepted')
        row = self.job()
        self.assertEqual(row['result']['scope'], 'native_mycelium_artifact_verify')
        self.assertFalse(row['result']['received_revenue'])
        self.assertEqual(len(self.engine.client.publications), 2)
        self.assertIsNone(row['metrics']['energy_joules'])
        self.assertIsNone(row['metrics']['cost_amount'])
        self.assertTrue(self.engine.verify_journal()['valid'])

    def test_imported_corrupt_artifact_is_terminal(self):
        backend = MemoryBackend()
        cid = 'a' * 64
        backend.repositories[cid] = task_leaves(b'original', 'sample.txt')
        backend.repositories[cid][1]['content'] = list(b'tampered')
        self.engine.client = backend
        self.engine.import_task('corrupt-task', cid)
        self.assertEqual(self.engine.run_once()['state'], 'failed')
        self.assertEqual(backend.publications, [])

    def test_lost_publication_ack_needs_reconciliation(self):
        backend = MemoryBackend()
        self.artifact_job(backend)
        with patch.object(backend, 'publish', side_effect=MutationUncertain('ack lost')) as publish:
            self.assertEqual(self.engine.run_once()['state'], 'needs_reconciliation')
            self.now += 600
            self.engine.run_once()
            self.assertEqual(publish.call_count, 1)

    def test_interrupted_mutation_is_never_blindly_republished(self):
        job_id = self.artifact_job()
        with self.engine.db() as db:
            db.execute("UPDATE jobs SET state='running', attempts=1, mutation_started=1 WHERE id=?", (job_id,))
        self.engine.run_once()
        self.assertEqual(self.job()['state'], 'needs_reconciliation')
        self.assertEqual(self.engine.client.publications, [])

    def test_presend_receipt_failure_reuses_task_checkpoint(self):
        backend = MemoryBackend()
        backend.fail_publication = 2
        self.artifact_job(backend)
        self.assertEqual(self.engine.run_once()['state'], 'queued')
        self.assertIsNotNone(self.job()['task_cid'])
        self.now += 30
        backend.fail_publication = None
        self.assertEqual(self.engine.run_once()['state'], 'accepted')
        self.assertEqual(len(backend.publications), 3)
        self.assertEqual(len(backend.repositories), 2)

    def test_receipt_read_failure_reuses_both_checkpoints(self):
        backend = MemoryBackend()
        backend.fail_clone = f'{2:064x}'
        self.artifact_job(backend)
        self.assertEqual(self.engine.run_once()['state'], 'queued')
        self.assertIsNotNone(self.job()['receipt_cid'])
        self.now += 30
        self.assertEqual(self.engine.run_once()['state'], 'accepted')
        self.assertEqual(len(backend.publications), 2)

    def test_gate_change_before_publication_does_not_consume_attempt(self):
        self.artifact_job()
        original = self.engine.gate
        calls = 0

        def changing_gate():
            nonlocal calls
            calls += 1
            if calls > 1:
                self.temperature = 80
            return original()

        with patch.object(self.engine, 'gate', side_effect=changing_gate):
            self.assertEqual(self.engine.run_once()['state'], 'queued')
        self.assertEqual(self.job()['attempts'], 0)
        self.assertEqual(self.engine.client.publications, [])

    def test_invalid_or_stale_s1_blocks_without_attempt(self):
        self.artifact_job()
        for changes in ({'timestamp_unix': self.now - 6}, {'timestamp_unix': self.now + 1},
                        {'schema_version': True}, {'sensor_ok': 1},
                        {'allow_execution': False}, {'sensor_warmup_complete': False},
                        {'RecoveryDebt': -1}, {'queue': True},
                        {'cpu_temp_c': float('nan')}, {'phase': 'COOLDOWN'},
                        {'T': -1}, {'T': 151},
                        {'cpu_temp_c': -1}, {'cpu_temp_c': 151},
                        {'gpu_temp_c': -1}, {'gpu_temp_c': 151},
                        {'cpu_util_pct': -1}, {'cpu_util_pct': 101},
                        {'gpu_util_pct': -1}, {'gpu_util_pct': 101}):
            with self.subTest(changes=changes):
                state = self.mupp_reading()
                state.update(changes)
                self.engine.mupp_source = lambda: state
                self.assertEqual(self.engine.run_once()['state'], 'thermal_blocked')
                self.assertEqual(self.job()['attempts'], 0)
                self.assertEqual(self.engine.client.publications, [])

    def test_dedup_key_cannot_change_task_payload(self):
        self.artifact_job()
        with self.assertRaises(ValueError):
            self.engine.submit('artifact-test', 'artifact_verify',
                               {'leaves': task_leaves(b'different', 'sample.txt')})

    def test_artifact_bounds_and_cid_validation(self):
        for name in ('../private', '', '.', 'a/b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                task_leaves(b'public', name)
        with self.assertRaises(ValueError):
            task_leaves(b'x' * (128 * 1024 + 1), 'large.bin')
        with self.assertRaises(ValueError):
            self.engine.import_task('bad-cid', 'not-a-native-cid')

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = 1000.0
        self.temperature = 50.0
        self.engine = app.Engine(Path(self.directory.name) / 'state',
                                 Path(self.directory.name) / 'backend.sock',
                                 thermal_source=self.reading, clock=lambda: self.now,
                                 mupp_source=self.mupp_reading)

    def mupp_reading(self):
        return {'schema_version': 1, 'mode': 'MUPP_LOCAL_CONTROL',
                'timestamp_unix': self.now, 'phase': 'REGULATED', 'regime': 'SAFE',
                'sensor_ok': True, 'sensor_warmup_complete': True,
                'allow_execution': True, 'T': 50.0, 'H': 20.0,
                'RecoveryDebt': 0.0, 'queue': 0}

    def reading(self):
        return {'samples': [{'celsius': self.temperature, 'source': 'synthetic:test'}],
                'errors': [], 'sampled_at_unix_s': self.now}

    def job(self):
        return self.engine.status()['jobs'][0]

    def test_hysteresis_survives_restart(self):
        self.assertTrue(self.engine.gate()['allowed'])
        self.temperature = 75
        self.assertFalse(self.engine.gate()['allowed'])
        self.temperature = 72
        restarted = app.Engine(self.engine.state, self.engine.backend,
                               thermal_source=self.reading, clock=lambda: self.now,
                               mupp_source=self.mupp_reading)
        self.assertFalse(restarted.gate()['allowed'])
        self.temperature = 70
        self.assertTrue(restarted.gate()['allowed'])

    def test_invalid_reports_fail_closed_without_attempts(self):
        self.engine.submit('thermal-test')
        reports = [None, [], {}, {'samples': []},
                   {**self.reading(), 'sampled_at_unix_s': self.now - 6},
                   {**self.reading(), 'sampled_at_unix_s': self.now + 1},
                   {**self.reading(), 'sampled_at_unix_s': True},
                   {**self.reading(), 'samples': [None]},
                   {**self.reading(), 'samples': [{'celsius': float('nan'), 'source': 'test'}]},
                   {**self.reading(), 'samples': [{'celsius': 50, 'source': ''}]},
                   {**self.reading(), 'errors': ['unreadable sensor']}]
        for report in reports:
            with self.subTest(report=report):
                self.engine.thermal_source = lambda report=report: report
                self.assertEqual(self.engine.run_once()['state'], 'thermal_blocked')
                self.assertEqual(self.job()['attempts'], 0)
        records = self.engine.verify_journal()['records']
        self.engine.run_once()
        self.assertEqual(self.engine.verify_journal()['records'], records)

    def test_sensor_exception_fails_closed(self):
        self.engine.thermal_source = lambda: (_ for _ in ()).throw(OSError('sensor gone'))
        self.assertFalse(self.engine.gate()['allowed'])

    def test_concurrent_submission_is_idempotent(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(lambda _: self.engine.submit('same-task'), range(12)))
        self.assertEqual(len(self.engine.status()['jobs']), 1)
        self.assertTrue(all(value == ids[0] for value in ids))

    def test_accepted_task_has_units_and_unknown_cost(self):
        self.engine.submit('healthy')
        backend = {'node_id': 'test', 'peer_id': 'test', 'neighbors': 0,
                   'messages_in': 0, 'messages_out': 0, 'atp': 0}
        with patch.object(app, 'backend_status', return_value=backend):
            self.engine.run_once()
        job = self.job()
        self.assertEqual(job['state'], 'accepted')
        self.assertFalse(job['result']['received_revenue'])
        metrics = job['metrics']
        self.assertGreaterEqual(metrics['duration_ms'], 0)
        self.assertGreaterEqual(metrics['process_cpu_ms'], 0)
        self.assertGreater(metrics['process_peak_rss_kib'], 0)
        self.assertIsNone(metrics['energy_joules'])
        self.assertIsNone(metrics['cost_amount'])
        self.assertTrue(self.engine.verify_journal()['valid'])

    def test_backoff_and_terminal_failure(self):
        self.engine.submit('unavailable')
        with patch.object(app, 'backend_status', side_effect=OSError('offline')):
            for attempt in range(1, 4):
                self.engine.run_once()
                self.assertEqual(self.job()['attempts'], attempt)
                if attempt < 3:
                    self.engine.run_once()
                    self.assertEqual(self.job()['attempts'], attempt)
                    self.now += 30 * 2 ** (attempt - 1)
            self.assertEqual(self.job()['state'], 'failed')
            self.now += 1000
            self.engine.run_once()
            self.assertEqual(self.job()['attempts'], 3)

    def test_interrupted_job_recovers_with_delay(self):
        self.engine.submit('interrupted')
        with self.engine.db() as conn:
            conn.execute("UPDATE jobs SET state='running', attempts=1")
        with patch.object(app, 'backend_status') as backend:
            self.engine.run_once()
            backend.assert_not_called()
        self.assertEqual(self.job()['state'], 'queued')
        self.assertEqual(self.job()['next_at'], self.now + 30)

    def test_interrupted_exhausted_job_is_terminal(self):
        self.engine.submit('exhausted')
        with self.engine.db() as conn:
            conn.execute("UPDATE jobs SET state='running', attempts=3")
        with patch.object(app, 'backend_status') as backend:
            self.engine.run_once()
            backend.assert_not_called()
        self.assertEqual(self.job()['state'], 'failed')

    def test_exclusive_worker(self):
        with open(self.engine.state / 'worker.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.engine.run_once()['state'], 'worker_busy')

    def test_audit_detects_modified_event(self):
        self.engine.submit('audit')
        with self.engine.db() as conn:
            conn.execute("UPDATE journal SET payload='{}' WHERE id=1")
        self.assertFalse(self.engine.verify_journal()['valid'])

    def test_unknown_task_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.submit('unsupported', kind='payment')


class UnixBackendTests(unittest.TestCase):
    def exchange(self, response, operation, expected, token='test-token'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'backend.sock'
            received = []
            errors = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                server.listen(1)
                server.settimeout(5)
                def reply():
                    try:
                        with server.accept()[0] as client:
                            client.settimeout(5)
                            frame = b''
                            while b'\n' not in frame:
                                frame += client.recv(4096)
                                if len(frame) > 1024 * 1024:
                                    raise ValueError('request too large')
                            received.append(json.loads(frame))
                            client.sendall(response)
                    except Exception as error:
                        errors.append(error)
                thread = threading.Thread(target=reply)
                thread.start()
                try:
                    with patch.dict('os.environ', {'MYCELIUM_CONTROL_TOKEN': token}):
                        result = operation(path)
                finally:
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])
                    self.assertEqual(received, [expected])
            return result

    def query(self, response, token='test-token'):
        return self.exchange(response, app.backend_status,
                             {'cmd': 'status', 'auth': 'test-token'}, token)

    def publish(self, response):
        leaves = task_leaves(b'public sample', 'sample.txt')
        expected = {'cmd': 'repo_publish', 'repository': None, 'branch': None,
                    'expected_previous_cid': None, 'message': 'test artifact',
                    'leaves': leaves, 'auth': 'test-token'}
        return self.exchange(response,
                             lambda path: ControlClient(path).publish(leaves, 'test artifact'),
                             expected)

    def acknowledgement(self, **changes):
        leaves = task_leaves(b'public sample', 'sample.txt')
        frame = {'status': 'repo_published', 'cid': 'a' * 64,
                 'leaves': len(leaves), 'bytes': sum(len(leaf['content']) for leaf in leaves)}
        frame.update(changes)
        return json.dumps(frame).encode() + b'\n'

    def frame(self, **changes):
        value = {'status': 'status', 'node_id': 'node', 'peer_id': 'peer', 'home': '/private',
                 'neighbors': 0, 'messages_in': 1, 'messages_out': 2, 'atp': 3}
        value.update(changes)
        return json.dumps(value).encode() + b'\n'

    def test_unix_status_auth_and_private_field_filter(self):
        result = self.query(self.frame())
        self.assertEqual(result['messages_in'], 1)
        self.assertNotIn('home', result)
        self.assertNotIn('auth', result)

    def test_invalid_backend_counter(self):
        with self.assertRaises(ValueError):
            self.query(self.frame(neighbors=True))

    def test_unterminated_frame(self):
        with self.assertRaises(ValueError):
            self.query(self.frame().rstrip(b'\n'))

    def test_publish_wire_protocol(self):
        self.assertEqual(self.publish(self.acknowledgement()), 'a' * 64)

    def test_clone_wire_protocol(self):
        leaves = task_leaves(b'public sample', 'sample.txt')
        response = json.dumps({'status': 'repo_clone_result', 'leaves': leaves,
                               'message': 'test artifact'}).encode() + b'\n'
        result = self.exchange(response, lambda path: ControlClient(path).clone('a' * 64),
                               {'cmd': 'repo_clone', 'cid': 'a' * 64, 'auth': 'test-token'})
        self.assertEqual(result, leaves)

    def test_boolean_acknowledgement_count_is_uncertain(self):
        with self.assertRaises(MutationUncertain):
            self.publish(self.acknowledgement(leaves=True))

    def test_invalid_acknowledgement_cid_is_uncertain(self):
        with self.assertRaises(MutationUncertain):
            self.publish(self.acknowledgement(cid='invalid'))

    def test_lost_acknowledgement_is_uncertain(self):
        with self.assertRaises(MutationUncertain):
            self.publish(b'')

    def test_token_whitespace_is_trimmed(self):
        self.assertEqual(self.query(self.frame(), token=' test-token \n')['messages_in'], 1)


if __name__ == '__main__':
    unittest.main()
