#!/usr/bin/env python3
"""Local Mycelium supervisor with thermal gates; no financial execution."""
import argparse
import contextlib
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import resource
import sys
import sqlite3
import threading
import time
from mycelium_backend import (ControlClient, MutationUncertain, ProtocolError,
                              canonical as artifact_canonical, leaf, task_leaves,
                              valid_cid, verify_task, MAX_ARTIFACT)
from s1_gate import evaluate as evaluate_s1, read_state as read_s1_state
from aem_shadow import ControllerMemory
from aem_bridge import decide_from_gate, denied as aem_denied, public_advice
from cqr_runner import run_cqr, validate_request as validate_cqr_request, MAX_REQUEST as MAX_CQR_REQUEST, WORKER as CQR_WORKER
from eco_supervisor import EcoConfig, EcoSupervisor

VERSION = '0.1.0'
MAX_ATTEMPTS = 3
DEFAULT_SOCKET = Path.home() / '.local/share/mycelium/mycelium.sock'
DEFAULT_STATE = Path(__file__).resolve().parent / 'var'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def temperatures():
    """Fresh sysfs sample; never substitute missing measurements with zero."""
    samples = []
    errors = []
    # Both ACPI thermal zones and Linux hwmon are necessary. On this host
    # coretemp CPU package values in hwmon may be hotter than the ACPI zones.
    # If any probed sensor cannot be read, the existing gate fails closed.
    paths = (sorted(Path('/sys/class/thermal').glob('thermal_zone*/temp'))
             + sorted(Path('/sys/class/hwmon').glob('hwmon*/temp*_input')))
    for path in paths:
        try:
            value = float(path.read_text().strip()) / 1000
            if not math.isfinite(value) or not -20 <= value <= 150:
                raise ValueError('invalid temperature')
            samples.append({'celsius': value, 'source': str(path)})
        except (OSError, ValueError):
            errors.append(str(path))
    return {'samples': samples, 'errors': errors, 'sampled_at_unix_s': time.time()}


def backend_status(path):
    """Only the authenticated, read-only status command is allowed here."""
    response = ControlClient(path).request({'cmd': 'status'})
    if not isinstance(response, dict) or response.get('status') != 'status':
        raise ValueError('backend rejected status query')
    for field in ('node_id', 'peer_id', 'home'):
        if not isinstance(response.get(field), str) or not response[field]:
            raise ValueError('invalid backend identity')
    for field in ('neighbors', 'messages_in', 'messages_out', 'atp'):
        value = response.get(field)
        if type(value) is not int or value < 0:
            raise ValueError('invalid backend counter')
    return {key: response[key] for key in ('node_id', 'peer_id', 'neighbors',
                                         'messages_in', 'messages_out', 'atp')}


class GateBlocked(RuntimeError):
    pass


class Engine:
    def _now(self):
        value = self.clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('invalid engine clock')
        return value

    def __init__(self, state=DEFAULT_STATE, backend=DEFAULT_SOCKET,
                 thermal_source=temperatures, clock=time.time,
                 mupp_source=read_s1_state, client=None):
        self.state = Path(state).resolve()
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        self.backend = Path(backend)
        self.thermal_source = thermal_source
        self.clock = clock
        self.mupp_source = mupp_source
        self.client = client or ControlClient(self.backend)
        with self.db() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL,
                    kind TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL, result TEXT, metrics TEXT);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS journal (
                    id INTEGER PRIMARY KEY, payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
            ''')
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(jobs)')}
            for name, declaration in (('payload', 'TEXT'), ('mutation_started', 'INTEGER NOT NULL DEFAULT 0'),
                                      ('task_cid', 'TEXT'), ('receipt_cid', 'TEXT')):
                if name not in columns:
                    conn.execute(f'ALTER TABLE jobs ADD COLUMN {name} {declaration}')

    @contextlib.contextmanager
    def db(self):
        conn = sqlite3.connect(self.state / 'engine.sqlite3', timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def event(self, conn, kind, data):
        previous = conn.execute('SELECT hash FROM journal ORDER BY id DESC LIMIT 1').fetchone()
        previous_hash = previous[0] if previous else '0' * 64
        payload = canonical({'at_unix_s': self._now(), 'kind': kind, 'data': data})
        digest = hashlib.sha256((previous_hash + '\n' + payload).encode()).hexdigest()
        conn.execute('INSERT INTO journal(payload,previous_hash,hash) VALUES(?,?,?)',
                     (payload, previous_hash, digest))

    def submit(self, key, kind='backend_health', payload=None):
        if kind not in ('backend_health', 'artifact_verify', 'cqr_c0'):
            raise ValueError('unsupported job class')
        if kind == 'backend_health' and payload is not None:
            raise ValueError('health task does not accept a payload')
        if kind == 'artifact_verify':
            if not isinstance(payload, dict):
                raise ValueError('artifact task requires a payload')
            if set(payload) == {'task_cid'}:
                if not valid_cid(payload['task_cid']):
                    raise ValueError('invalid Mycelium task CID')
            elif set(payload) == {'leaves'}:
                verify_task(payload['leaves'])
            else:
                raise ValueError('invalid artifact task payload')
        if kind == 'cqr_c0':
            # Only a bounded explicit scientific input; no automatic discovery.
            validate_cqr_request(payload)
        encoded = canonical(payload) if payload is not None else None
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError('idempotency key must have 1..128 characters')
        with self.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            old = conn.execute('SELECT id,kind,payload FROM jobs WHERE idempotency_key=?', (key,)).fetchone()
            if old:
                if old['kind'] != kind or old['payload'] != encoded:
                    raise ValueError('idempotency key already belongs to a different task')
                return old['id']
            task_cid = payload.get('task_cid') if payload is not None else None
            job_id = conn.execute('INSERT INTO jobs(idempotency_key,kind,created_at,payload,task_cid) VALUES(?,?,?,?,?)',
                                  (key, kind, self._now(), encoded, task_cid)).lastrowid
            self.event(conn, 'submitted', {'job_id': job_id, 'kind': kind})
            return job_id

    def submit_artifact(self, key, public_file):
        path = Path(public_file)
        with path.open('rb') as stream:
            data = stream.read(MAX_ARTIFACT + 1)
        return self.submit(key, 'artifact_verify', {'leaves': task_leaves(data, path.name)})

    def import_task(self, key, cid):
        return self.submit(key, 'artifact_verify', {'task_cid': cid})

    def submit_cqr(self, key, source_file):
        path = Path(source_file)
        with path.open('rb') as stream:
            data = stream.read(MAX_CQR_REQUEST + 1)
        if len(data) > MAX_CQR_REQUEST:
            raise ValueError('CQR job source exceeds 64 KiB')
        payload = json.loads(data)
        validate_cqr_request(payload)
        return self.submit(key, 'cqr_c0', payload)

    def gate(self):
        try:
            reading = self.thermal_source()
            # Reject non-JSON/non-finite sensor reports before journaling them.
            reading = json.loads(canonical(reading))
        except Exception as error:
            reading = {'sensor_error': type(error).__name__}
        if not isinstance(reading, dict):
            reading = {'sensor_error': 'invalid_report_type'}
        samples = reading.get('samples', [])
        now = self._now()
        measured_at = reading.get('sampled_at_unix_s')
        valid = (type(measured_at) in (int, float) and math.isfinite(measured_at)
                 and 0 <= now - measured_at <= 5
                 and isinstance(samples, list) and bool(samples)
                 and isinstance(reading.get('errors'), list) and not reading['errors'])
        valid = valid and all(isinstance(s, dict) and type(s.get('celsius')) in (int, float)
                              and math.isfinite(s['celsius']) and -20 <= s['celsius'] <= 150
                              and isinstance(s.get('source'), str) and bool(s['source']) for s in samples)
        maximum = max(s['celsius'] for s in samples) if valid else None
        s1 = evaluate_s1(self.mupp_source, now=now)
        with self.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            old = conn.execute("SELECT value FROM settings WHERE key='thermal_paused'").fetchone()
            paused = old is not None and old[0] == 'true'
            paused = not valid or maximum >= 75 or (paused and maximum > 70)
            conn.execute("INSERT OR REPLACE INTO settings VALUES('thermal_paused',?)",
                         ('true' if paused else 'false',))
            report = {'allowed': not paused and s1['allowed'], 'maximum_celsius': maximum,
                      'reason': 'unknown_or_invalid_sensor' if not valid else
                                ('cooldown' if paused else
                                 ('ready' if s1['allowed'] else s1['reason'])),
                      'pause_celsius': 75, 'resume_celsius': 70,
                      'provenance': reading, 's1_mupp': s1}
            # Passive AEM advice shares the already-taken thermal/MUPP sample.
            # Never authorizes work, tokens, trades or reinvestment.
            old_memory = conn.execute(
                "SELECT value FROM settings WHERE key='aem_shadow_memory'").fetchone()
            try:
                memory = (ControllerMemory.parse(json.loads(old_memory[0]))
                          if old_memory else ControllerMemory())
                advice = decide_from_gate(report, memory, now)
            except (ValueError, TypeError, OverflowError, KeyError):
                advice = aem_denied("SENSOR_LOCK", "invalid_persisted_aem_memory",
                                    ControllerMemory())
            snapshot = public_advice(advice, now)
            conn.execute("INSERT OR REPLACE INTO settings VALUES('aem_shadow_memory',?)",
                         (canonical(vars(advice.next_memory)),))
            conn.execute("INSERT OR REPLACE INTO settings VALUES('aem_shadow_last',?)",
                         (canonical(snapshot),))
            reason_old = conn.execute("SELECT value FROM settings WHERE key='gate_reason'").fetchone()
            if not reason_old or reason_old[0] != report['reason']:
                self.event(conn, 'thermal_transition', report)
                conn.execute("INSERT OR REPLACE INTO settings VALUES('gate_reason',?)", (report['reason'],))
            return report

    def preflight(self):
        """Observe live safety conditions; NEVER select, submit or execute a job."""
        gate = self.gate()
        aem = self.status()["aem_eco"]
        return {
            "mode": "AEM_ECO_PREFLIGHT_READ_ONLY_NO_JOB_EXECUTION",
            "execution_gate": gate,
            "aem_eco": aem,
            "can_execute_existing_jobs": gate["allowed"],
            "cqr_backend": {
                "connected": False,
                "binary_available": CQR_WORKER.is_file() and bool(CQR_WORKER.stat().st_mode & 0o111),
                "reason": "Python queue bridge implemented; native binary unverified until a real gated CQR run",
            },
            "financial_execution": {
                "enabled": False, "reason": "no executor or capital permission from preflight",
            },
            "external_revenue": {
                "verified": None,
                "reason": "verified_view/provider-pinned settlement not consulted",
            },
        }

    def _publish(self, job_id, leaves, message, column):
        # The checkpoint must survive a crash before any native mutation starts.
        if not self.gate()['allowed']:
            raise GateBlocked()
        with self.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('UPDATE jobs SET mutation_started=1 WHERE id=?', (job_id,))
            self.event(conn, 'publication_started', {'job_id': job_id, 'artifact': column})
        try:
            cid = self.client.publish(leaves, message)
        except MutationUncertain:
            raise
        except (OSError, ValueError, TypeError, UnicodeError):
            # The client only raises these when it knows no mutation was sent.
            with self.db() as conn:
                conn.execute('UPDATE jobs SET mutation_started=0 WHERE id=?', (job_id,))
            raise
        if not valid_cid(cid):
            raise MutationUncertain('invalid publication content ID')
        with self.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute(f'UPDATE jobs SET {column}=?,mutation_started=0 WHERE id=?', (cid, job_id))
            self.event(conn, 'publication_confirmed', {'job_id': job_id, 'artifact': column, 'cid': cid})
        return cid

    def _artifact(self, row):
        task_cid = row['task_cid']
        if task_cid is None:
            payload = json.loads(row['payload'])
            task_cid = self._publish(row['id'], payload['leaves'],
                                     'Mycelium local artifact verification task', 'task_cid')
        receipt = verify_task(self.client.clone(task_cid))
        receipt.update(task_cid=task_cid, idempotency_key=row['idempotency_key'])
        receipt_cid = row['receipt_cid']
        if receipt_cid is None:
            receipt_cid = self._publish(row['id'], [leaf('receipt.json', artifact_canonical(receipt).encode())],
                                        'Mycelium local artifact verification receipt', 'receipt_cid')
        # Acceptance requires reading the receipt back through the native store.
        if self.client.clone(receipt_cid) != [leaf('receipt.json', artifact_canonical(receipt).encode())]:
            raise ProtocolError('native receipt read-back differs from publication')
        return {'scope': 'native_mycelium_artifact_verify', 'task_cid': task_cid,
                'receipt_cid': receipt_cid, 'receipt': receipt, 'received_revenue': False}

    def _cqr(self, row):
        # One gate already ran in run_once; check again immediately before
        # native computation. Worker repeats independent live MUPP/thermal checks.
        if not self.gate()['allowed']:
            raise GateBlocked()
        payload = json.loads(row['payload'])
        result = run_cqr(payload)
        # Recheck after native validation. Discard if S1 went stale/hot.
        if not self.gate()['allowed']:
            raise GateBlocked()
        return result

    def run_once(self):
        with (self.state / 'worker.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'state': 'worker_busy'}
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                # The lock proves no other supervisor owns these interrupted jobs.
                for row in conn.execute("SELECT id,attempts,mutation_started FROM jobs WHERE state='running'").fetchall():
                    state = ('needs_reconciliation' if row['mutation_started'] else
                             ('failed' if row['attempts'] >= MAX_ATTEMPTS else 'queued'))
                    conn.execute('UPDATE jobs SET state=?,next_at=? WHERE id=?',
                                 (state, self._now() + 30, row['id']))
                    self.event(conn, 'interrupted', {'job_id': row['id'], 'state': state})
            gate = self.gate()
            if not gate['allowed']:
                return {'state': 'thermal_blocked', 'gate': gate}
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                row = conn.execute("SELECT * FROM jobs WHERE state='queued' AND next_at<=? ORDER BY id LIMIT 1",
                                   (self._now(),)).fetchone()
                if not row:
                    return {'state': 'idle'}
                attempts = row['attempts'] + 1
                conn.execute("UPDATE jobs SET state='running',attempts=? WHERE id=?", (attempts, row['id']))
                self.event(conn, 'started', {'job_id': row['id'], 'attempt': attempts})
            before = resource.getrusage(resource.RUSAGE_SELF)
            child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.monotonic()
            try:
                if row['kind'] == 'artifact_verify':
                    result = self._artifact(row)
                elif row['kind'] == 'cqr_c0':
                    result = self._cqr(row)
                elif row['kind'] == 'backend_health':
                    result = {'backend': backend_status(self.backend),
                              'scope': 'read_only_backend_health', 'received_revenue': False}
                else:
                    raise ValueError('unsupported stored job kind')
                state = 'accepted'
            except GateBlocked:
                result = {'reason': 'gate_changed', 'received_revenue': False}
                state = 'queued'
                attempts -= 1
            except MutationUncertain:
                result = {'reason': 'native_publication_acknowledgement_unknown',
                          'received_revenue': False}
                state = 'needs_reconciliation'
            except ProtocolError as error:
                result = {'error_type': type(error).__name__, 'scope': row['kind'],
                          'received_revenue': False}
                state = 'failed'
            except (OSError, ValueError, TypeError, UnicodeError) as error:
                # Do not persist raw server errors or authentication material.
                result = {'error_type': type(error).__name__, 'scope': row['kind'],
                          'received_revenue': False}
                state = 'failed' if attempts >= MAX_ATTEMPTS else 'queued'
            after = resource.getrusage(resource.RUSAGE_SELF)
            child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            metrics = {
                'duration_ms': (time.monotonic() - started) * 1000,
                'duration_source': 'time.monotonic; backend request and validation',
                'process_cpu_ms': ((after.ru_utime + after.ru_stime) -
                                   (before.ru_utime + before.ru_stime)) * 1000,
                'cpu_source': 'getrusage(RUSAGE_SELF) delta; excludes Rust child',
                'child_cpu_ms': ((child_after.ru_utime + child_after.ru_stime) -
                                 (child_before.ru_utime + child_before.ru_stime)) * 1000,
                'child_cpu_source': 'getrusage(RUSAGE_CHILDREN) delta; process-wide, not isolated to one job',
                'process_peak_rss_kib': after.ru_maxrss,
                'rss_source': 'Linux getrusage(RUSAGE_SELF); lifetime process high-water mark',
                'energy_joules': None, 'energy_source': 'not measured',
                'cost_currency': None, 'cost_amount': None, 'cost_source': 'not measured',
                'accepted': state == 'accepted', 'backend_socket': str(self.backend),
                'thermal_before': gate,
                'task_class': row['kind'],
            }
            next_at = self._now() + min(300, 30 * 2 ** (max(1, attempts) - 1))
            with self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute('UPDATE jobs SET state=?,attempts=?,next_at=?,result=?,metrics=? WHERE id=?',
                             (state, attempts, next_at, canonical(result), canonical(metrics), row['id']))
                self.event(conn, 'attempt_finished', {'job_id': row['id'], 'attempt': attempts,
                                                     'state': state, 'result': result, 'metrics': metrics})
            return {'job_id': row['id'], 'state': state, 'result': result, 'metrics': metrics}

    def verify_journal(self):
        previous = '0' * 64
        with self.db() as conn:
            rows = conn.execute('SELECT * FROM journal ORDER BY id').fetchall()
        for index, row in enumerate(rows, 1):
            digest = hashlib.sha256((previous + '\n' + row['payload']).encode()).hexdigest()
            if row['id'] != index or row['previous_hash'] != previous or row['hash'] != digest:
                return {'valid': False, 'failed_record': row['id']}
            previous = digest
        return {'valid': True, 'records': len(rows), 'head': previous,
                'scope': 'local audit integrity; no consensus or external checkpoint'}

    def status(self):
        with self.db() as conn:
            rows = conn.execute('SELECT * FROM jobs ORDER BY id DESC LIMIT 50').fetchall()
            counts = {row[0]: row[1] for row in conn.execute('SELECT state,count(*) FROM jobs GROUP BY state')}
            gate = conn.execute("SELECT value FROM settings WHERE key='gate_reason'").fetchone()
            last_aem = conn.execute(
                "SELECT value FROM settings WHERE key='aem_shadow_last'").fetchone()
            last_eco = conn.execute(
                "SELECT value FROM settings WHERE key='eco_supervisor_last'").fetchone()
        aem = {"scope": "AEM_ECO_SHADOW_NO_EXECUTION_AUTHORITY",
               "state": "NOT_SAMPLED", "financial_authority": False}
        if last_aem:
            try:
                aem = json.loads(last_aem[0])
                age = self._now() - aem["observed_unix_s"]
                if type(age) not in (int, float) or not math.isfinite(age) or age < 0 or age > 30:
                    aem = {"scope": "AEM_ECO_SHADOW_NO_EXECUTION_AUTHORITY",
                           "state": "STALE_TELEMETRY", "financial_authority": False}
            except (ValueError, TypeError, KeyError, OverflowError):
                aem = {"scope": "AEM_ECO_SHADOW_NO_EXECUTION_AUTHORITY",
                       "state": "INVALID_TELEMETRY", "financial_authority": False}
        eco = {"scope": "MYCELIUM_ECO_NATIVE_DISCOVERY", "state": "DISABLED",
               "financial_authority": False, "verified_paid_demand_musd": None}
        if last_eco:
            try:
                eco = json.loads(last_eco[0])
                age = self._now() - eco['observed_unix_s']
                if not math.isfinite(age) or not 0 <= age <= max(60, eco['poll_seconds'] * 2):
                    eco = {**eco, 'state': 'STALE_TELEMETRY',
                           'verified_paid_demand_musd': None}
            except (ValueError, TypeError, KeyError, OverflowError):
                eco = {"scope": "MYCELIUM_ECO_NATIVE_DISCOVERY", "state": "INVALID_TELEMETRY",
                       "financial_authority": False, "verified_paid_demand_musd": None}
        jobs = []
        for row in rows:
            value = dict(row)
            value.pop('payload', None)
            for key in ('result', 'metrics'):
                value[key] = json.loads(value[key]) if value[key] else None
            jobs.append(value)
        completed = counts.get('accepted', 0) + counts.get('failed', 0)
        return {'version': VERSION, 'state_directory': str(self.state), 'backend_socket': str(self.backend),
                'thermal_state': gate[0] if gate else 'not_sampled', 'counts': counts, 'jobs': jobs,
                'aem_eco': aem,
                'mycelium_eco': eco,
                'acceptance_fraction': counts.get('accepted', 0) / completed if completed else None,
                'acceptance_denominator': 'terminal jobs (accepted + failed), excludes queued/running/needs_reconciliation',
                'wallet': {'mode': 'planned_capability_inventory', 'balances': None,
                           'signing': False, 'stablecoin': 'planned_evm_erc20_adapter',
                           'lightning': 'planned_lnd_regtest_adapter', 'received_revenue': None},
                'chain': {'mode': 'local_hash_linked_audit_journal', 'consensus': False},
                'journal': self.verify_journal()}


PAGE = '''<!doctype html><html lang="pt-BR"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mycelium Next · Local</title><style>
body{font:16px system-ui;background:#101a18;color:#e2f0e9;margin:0;padding:32px;max-width:1050px}
h1{font-size:32px}small{color:#a6bbae}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
article{background:#1b2a25;border:1px solid #385347;border-radius:16px;padding:20px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}b{color:#94dfb0}</style>
<h1>Mycelium Next <small>Local</small></h1><p>Robôs com fila persistente e proteção automática.</p>
<div class="cards"><article><h2>Execução</h2><b id="thermal">Conectando…</b><pre id="counts"></pre></article>
<article><h2>Wallet planejada</h2><p>Integração e assinatura ainda indisponíveis.</p><small>Saldo desconhecido · sem transações</small></article>
<article><h2>Registro</h2><b id="audit"></b><p>Auditoria local verificável. Consenso ainda indisponível.</p></article>
<article><h2>AEM-ECO (somente observação)</h2><b id="aem-state">Sem leitura</b>
<pre id="aem-detail"></pre><small>Não executa trades, emite moedas ou investe.</small></article>
<article><h2>Mycelium-ECO</h2><b id="eco-state">Desativado</b><pre id="eco-detail"></pre>
<small>Demanda paga verificada não representa saldo ou lucro.</small></article></div>
<h2>Últimas tarefas</h2><pre id="jobs"></pre><small id="connection"></small>
<script>async function refresh(){try{const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw Error();
const s=await r.json();document.getElementById('thermal').textContent=s.thermal_state;
document.getElementById('counts').textContent=JSON.stringify(s.counts,null,2);
document.getElementById('audit').textContent=s.journal.valid?'Registro consistente':'Falha de integridade';
const aem=s.aem_eco||{};const mode=aem.decision||{};
document.getElementById('aem-state').textContent=mode.state||aem.state||'NOT_SAMPLED';
document.getElementById('aem-detail').textContent=mode.reason||aem.scope||'Aguardando telemetria real';
const eco=s.mycelium_eco||{};
document.getElementById('eco-state').textContent=eco.state||'DISABLED';
document.getElementById('eco-detail').textContent=(eco.reason||eco.native_state||'Aguardando fonte externa')+
String.fromCharCode(10)+'Demanda paga acumulada (MUSD): '+(eco.verified_paid_demand_musd??'desconhecida')+
(eco.next_attempt_unix?String.fromCharCode(10)+'Próxima avaliação: '+new Date(eco.next_attempt_unix*1000).toLocaleString():'');
document.getElementById('jobs').textContent=JSON.stringify(s.jobs,null,2);
document.getElementById('connection').textContent='Atualizado '+new Date().toLocaleTimeString();
}catch(e){document.getElementById('connection').textContent='Painel desconectado; dados podem estar desatualizados.'}}
refresh();setInterval(refresh,3000)</script></html>'''


def serve(engine, port, eco_supervisor=None):
    stop = threading.Event()
    failures = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Prevent another website from using the loopback server through DNS rebinding.
            if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
                self.send_error(403)
                return
            if self.path == '/':
                body, mime = PAGE.encode(), 'text/html; charset=utf-8'
            elif self.path == '/api/status':
                body, mime = canonical(engine.status()).encode(), 'application/json'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    def supervisor():
        while not stop.is_set():
            try:
                engine.run_once()
                if eco_supervisor and not stop.is_set():
                    eco_supervisor.run_once(stop_event=stop)
            except Exception as error:
                # Fail visibly and stop; never silently retry a broken supervisor.
                failures.append(type(error).__name__)
                print(f'Supervisor stopped: {type(error).__name__}', file=sys.stderr, flush=True)
                stop.set()
                server.shutdown()
                return
            stop.wait(30)

    with ThreadingHTTPServer(('127.0.0.1', port), Handler) as server:
        thread = threading.Thread(target=supervisor, daemon=True)
        thread.start()
        print(f'Mycelium Next: http://127.0.0.1:{server.server_port}', flush=True)
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            thread.join(timeout=5)
    if failures:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=DEFAULT_STATE)
    parser.add_argument('--socket', type=Path, default=DEFAULT_SOCKET)
    commands = parser.add_subparsers(dest='command', required=True)
    start = commands.add_parser('start')
    start.add_argument('--port', type=int, default=8787)
    start.add_argument('--eco-config', type=Path)
    eco_once = commands.add_parser('eco-run-once')
    eco_once.add_argument('--config', required=True, type=Path)
    submit = commands.add_parser('submit')
    submit.add_argument('--key', required=True)
    artifact = commands.add_parser('submit-artifact')
    artifact.add_argument('--key', required=True)
    artifact.add_argument('--public-file', required=True, type=Path)
    imported = commands.add_parser('import-task')
    imported.add_argument('--key', required=True)
    imported.add_argument('--cid', required=True)
    cqr = commands.add_parser('submit-cqr')
    cqr.add_argument('--key', required=True)
    cqr.add_argument('--job-file', required=True, type=Path)
    for command in ('status', 'preflight', 'run-once', 'verify-journal'):
        commands.add_parser(command)
    args = parser.parse_args()
    config_path = getattr(args, 'eco_config', None) or getattr(args, 'config', None)
    config = EcoConfig.load(config_path) if config_path else None
    engine = Engine(args.state, args.socket, **(
        {'mupp_source': lambda: read_s1_state(config.mupp_state)} if config else {}))
    eco = EcoSupervisor(engine, config) if config else None
    if args.command == 'start':
        serve(engine, args.port, eco)
    elif args.command == 'eco-run-once':
        print(canonical(eco.run_once()))
    elif args.command == 'submit':
        print(canonical({'job_id': engine.submit(args.key)}))
    elif args.command == 'submit-artifact':
        print(canonical({'job_id': engine.submit_artifact(args.key, args.public_file)}))
    elif args.command == 'import-task':
        print(canonical({'job_id': engine.import_task(args.key, args.cid)}))
    elif args.command == 'submit-cqr':
        print(canonical({'job_id': engine.submit_cqr(args.key, args.job_file)}))
    else:
        print(canonical(getattr(engine, args.command.replace('-', '_'))()))


if __name__ == '__main__':
    main()
