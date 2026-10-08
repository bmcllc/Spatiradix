"""Bounded Mycelium-ECO discovery supervisor; no trading or payment commands."""
import contextlib
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def parse_json(raw):
    def reject_constant(value):
        raise ValueError('non-finite JSON number')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique_pairs)
    if not isinstance(value, dict):
        raise ValueError('JSON object required')
    return value


@dataclass(frozen=True)
class EcoConfig:
    binary: Path
    native_home: Path
    source_report: Path
    mupp_state: Path
    agent_id: str
    estimated_job_cost_musd_micros: int
    ttl_seconds: int
    poll_seconds: int = 30
    max_source_age_seconds: int = 30
    search_policy: Path | None = None
    mupp_policy: Path | None = None

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        if path.stat().st_size > 16_384:
            raise ValueError('ECO configuration too large')
        with path.open('rb') as stream:
            raw = stream.read(16_385)
        if len(raw) > 16_384:
            raise ValueError('ECO configuration too large')
        data = parse_json(raw)
        required = {'binary', 'native_home', 'source_report', 'mupp_state', 'agent_id',
                    'estimated_job_cost_musd_micros', 'ttl_seconds'}
        optional = {'poll_seconds', 'max_source_age_seconds', 'search_policy', 'mupp_policy'}
        if not required <= data.keys() or data.keys() - required - optional:
            raise ValueError('invalid ECO configuration fields')
        for key in ('binary', 'native_home', 'source_report', 'mupp_state',
                    'search_policy', 'mupp_policy'):
            if key in data:
                if not isinstance(data[key], str) or not data[key] or '\x00' in data[key]:
                    raise ValueError('invalid ECO path')
                data[key] = (path.parent / data[key]).resolve()
        if (not isinstance(data['agent_id'], str) or not 1 <= len(data['agent_id']) <= 128
                or any(ord(char) < 32 for char in data['agent_id'])):
            raise ValueError('invalid ECO agent')
        for key, default, lower, upper in (
                ('estimated_job_cost_musd_micros', None, 1, 10**12),
                ('ttl_seconds', None, 1, 300), ('poll_seconds', 30, 30, 3600),
                ('max_source_age_seconds', 30, 5, 300)):
            value = data.get(key, default)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError('invalid ECO limit: ' + key)
        if 'mupp_policy' in data and 'search_policy' not in data:
            raise ValueError('mupp_policy requires search_policy')
        return cls(**data)


class NativeFailure(RuntimeError):
    def __init__(self, code, started=False):
        super().__init__(code)
        self.code, self.started = code, started


# Apply limits in a separate interpreter before exec: preexec_fn is unsafe in
# the HTTP server's threaded process. No shell or arbitrary command arguments.
LAUNCHER = '''import os, resource, sys
resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024,) * 2)
os.nice(15)
os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
os.execv(sys.argv[1], sys.argv[1:])
'''


class NativeRunner:
    def __init__(self, config, gate):
        self.config, self.gate = config, gate

    def run(self, command, arguments=(), stop_event=None):
        if command not in {'discovery-status', 'discovery-run', 'economy-dashboard'}:
            raise NativeFailure('COMMAND_NOT_ALLOWED')
        if not self.gate()['allowed'] or (stop_event and stop_event.is_set()):
            raise NativeFailure('GATE_BLOCKED')
        if not self.config.binary.is_file() or not os.access(self.config.binary, os.X_OK):
            raise NativeFailure('NATIVE_UNAVAILABLE')
        argv = [sys.executable, '-c', LAUNCHER, str(self.config.binary),
                '--home', str(self.config.native_home), command, *map(str, arguments)]
        try:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
        except OSError:
            raise NativeFailure('NATIVE_UNAVAILABLE') from None
        deadline = time.monotonic() + (15 if command == 'discovery-run' else 5)
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        try:
            with selectors.DefaultSelector() as selector:
                for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map():
                    if stop_event and stop_event.is_set():
                        raise NativeFailure('STOP_REQUESTED', True)
                    if not self.gate()['allowed']:
                        raise NativeFailure('GATE_BLOCKED', True)
                    if time.monotonic() >= deadline:
                        raise NativeFailure('NATIVE_TIMEOUT', True)
                    for key, _ in selector.select(timeout=0.25):
                        chunk = os.read(key.fd, 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output[key.data].extend(chunk)
                            if sum(map(len, output.values())) > 262_144:
                                raise NativeFailure('NATIVE_OUTPUT_LIMIT', True)
            # Closing both pipes must not bypass thermal monitoring.
            while process.poll() is None:
                if stop_event and stop_event.is_set():
                    raise NativeFailure('STOP_REQUESTED', True)
                if not self.gate()['allowed']:
                    raise NativeFailure('GATE_BLOCKED', True)
                if time.monotonic() >= deadline:
                    raise NativeFailure('NATIVE_TIMEOUT', True)
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass
            code = process.returncode
            if code != 0:
                raise NativeFailure('NATIVE_FAILED', True)
            if not self.gate()['allowed']:
                raise NativeFailure('GATE_BLOCKED', True)
            try:
                return parse_json(output['stdout'])
            except (ValueError, UnicodeError):
                raise NativeFailure('NATIVE_INVALID_RESPONSE', True) from None
        finally:
            # Also terminate descendants if a malformed worker closed its pipes.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()


def scheduler_deadline(value):
    if (not isinstance(value, dict) or type(value.get('version')) is not int
            or value['version'] != 1 or type(value.get('wait_cycle_seconds')) is not int
            or value['wait_cycle_seconds'] != 60):
        raise ValueError('native wall-clock scheduler required')
    deadlines = []
    for key in ('next_attempt_unix', 'thermal_cooldown_until_unix'):
        if key not in value:
            raise ValueError('missing native deadline')
        deadline = value[key]
        if deadline is not None:
            if type(deadline) is not int or not 0 <= deadline <= 2**63 - 1:
                raise ValueError('invalid native deadline')
            deadlines.append(deadline)
    return max(deadlines, default=0)


def verified_paid_demand(dashboard, now):
    """Cumulative verified paid demand is neither wallet balance nor profit."""
    try:
        stamp = dashboard['timestamp_unix']
        if type(stamp) is not int or not 0 <= now - stamp <= 5:
            return None
        trust = dashboard['trust']
        if (trust['trust_mode'] != 'provider_pinned'
                or trust['provider_identity_verified'] is not True
                or trust['outcome_policy']['validated'] is not True):
            return None
        invariants = dashboard['invariants']
        for key in ('internal_volume_is_revenue', 'myc_emission_is_revenue',
                    'bot_service_spend_is_external_value', 'terr_can_authorize_capital',
                    'stored_proof_verified_is_authority'):
            if invariants[key] is not False:
                return None
        value = dashboard['revenue_validation']['paid_demand_musd']
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            return None
        return value
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


class EcoSupervisor:
    def __init__(self, engine, config, runner=None):
        self.engine, self.config = engine, config
        self.runner = runner or NativeRunner(config, engine.gate)

    @contextlib.contextmanager
    def db(self):
        connection = sqlite3.connect(self.config.native_home / 'mycelium-next-eco.sqlite3', timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA synchronous=FULL')
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def snapshot(self, state, **details):
        value = {'scope': 'MYCELIUM_ECO_NATIVE_DISCOVERY', 'state': state,
                 'financial_authority': False, 'verified_paid_demand_musd': None,
                 'observed_unix_s': self.engine._now(), 'poll_seconds': self.config.poll_seconds,
                 **details}
        with self.engine.db() as db:
            old = db.execute("SELECT value FROM settings WHERE key='eco_supervisor_last'").fetchone()
            previous = json.loads(old[0]) if old else {}
            # Polls do not flood the audit log with unchanged observations.
            if {k: v for k, v in previous.items() if k != 'observed_unix_s'} != {
                    k: v for k, v in value.items() if k != 'observed_unix_s'}:
                self.engine.event(db, 'eco_supervisor_transition', value)
            db.execute("INSERT OR REPLACE INTO settings VALUES('eco_supervisor_last',?)",
                       (canonical(value),))
        return value

    def next_at(self, deadline):
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES('next_at',?)", (str(deadline),))

    def source(self, now):
        path = self.config.source_report
        before = path.stat()
        if not path.is_file() or not 0 < before.st_size <= 131_072:
            raise ValueError('SOURCE_INVALID')
        if not 0 <= now - before.st_mtime <= self.config.max_source_age_seconds:
            raise ValueError('SOURCE_STALE')
        with path.open('rb') as stream:
            raw = stream.read(131_073)
        after = path.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) > 131_072:
            raise ValueError('SOURCE_CHANGED')
        # Changes to JSON whitespace or key order do not create a new report.
        normalized = canonical(parse_json(raw)).encode()
        if len(normalized) > 131_072:
            raise ValueError('SOURCE_INVALID')
        return hashlib.sha256(normalized).hexdigest(), normalized

    def run_once(self, stop_event=None):
        gate = self.engine.gate()
        if not gate['allowed']:
            return self.snapshot('GATE_BLOCKED', reason=gate['reason'])
        home = self.config.native_home
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(home, 0o700)
        with (home / '.mycelium-next-eco.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return self.snapshot('SUPERVISOR_BUSY')
            return self._run_locked(stop_event)

    def _run_locked(self, stop_event):
        now = self.engine._now()
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS reports (
                digest TEXT PRIMARY KEY, state TEXT NOT NULL, result TEXT);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);''')
            db.execute("UPDATE reports SET state='needs_reconciliation' WHERE state='processing'")
            uncertain = db.execute("SELECT digest FROM reports WHERE state='needs_reconciliation' LIMIT 1").fetchone()
            deadline = db.execute("SELECT value FROM settings WHERE key='next_at'").fetchone()
        if uncertain:
            return self.snapshot('NEEDS_RECONCILIATION', report_digest=uncertain[0])
        if deadline and now < float(deadline[0]):
            return self.snapshot('BACKOFF', next_attempt_unix=float(deadline[0]))
        try:
            digest, raw = self.source(now)
        except OSError:
            return self.snapshot('SOURCE_UNAVAILABLE')
        except (ValueError, UnicodeError) as error:
            reason = str(error)
            return self.snapshot(reason if reason.startswith('SOURCE_') else 'SOURCE_INVALID')
        with self.db() as db:
            row = db.execute('SELECT state FROM reports WHERE digest=?', (digest,)).fetchone()
        if row and row[0] == 'consumed':
            return self.snapshot('WAITING_FOR_NEW_REPORT', report_digest=digest)
        status_args = [self.config.search_policy] if self.config.search_policy else []
        try:
            status = self.runner.run('discovery-status', status_args, stop_event)
            deadline = scheduler_deadline(status.get('scheduler'))
        except ValueError:
            self.next_at(now + self.config.poll_seconds)
            return self.snapshot('NATIVE_UPGRADE_REQUIRED')
        except NativeFailure as error:
            self.next_at(now + self.config.poll_seconds)
            return self.snapshot(error.code)
        if deadline > now:
            self.next_at(deadline)
            return self.snapshot('BACKOFF', next_attempt_unix=deadline)
        spool = self.config.native_home / 'eco-report-spool'
        spool.mkdir(mode=0o700, exist_ok=True)
        os.chmod(spool, 0o700)
        frozen = spool / (digest + '.json')
        # Rewrite from the bytes just hashed, even if an earlier spool was changed.
        with frozen.open('wb') as stream:
            os.chmod(frozen, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO reports VALUES(?,'processing',NULL)", (digest,))
        cost = self.config.estimated_job_cost_musd_micros
        arguments = [frozen, self.config.agent_id, f'{cost // 1_000_000}.{cost % 1_000_000:06d}',
                     self.config.ttl_seconds, self.config.mupp_state, *status_args]
        if self.config.mupp_policy:
            arguments.append(self.config.mupp_policy)
        try:
            result = self.runner.run('discovery-run', arguments, stop_event)
            deadline = scheduler_deadline(result.get('scheduler'))
            consumed = isinstance(result.get('observation'), dict)
            if not consumed and not (result.get('completed') is False and 'denied' in result):
                raise NativeFailure('NATIVE_INVALID_RESPONSE', True)
        except (NativeFailure, ValueError) as error:
            uncertain = not isinstance(error, NativeFailure) or error.started
            with self.db() as db:
                db.execute('UPDATE reports SET state=? WHERE digest=?',
                           ('needs_reconciliation' if uncertain else 'pending', digest))
            self.next_at(now + self.config.poll_seconds)
            return self.snapshot('NEEDS_RECONCILIATION' if uncertain else error.code,
                                 report_digest=digest)
        with self.db() as db:
            db.execute('UPDATE reports SET state=?,result=? WHERE digest=?',
                       ('consumed' if consumed else 'pending', canonical(result), digest))
        deadline = max(deadline, self.engine._now() + self.config.poll_seconds)
        self.next_at(deadline)
        paid, revenue_reason = None, 'native verification unavailable'
        if consumed:
            try:
                dashboard = self.runner.run('economy-dashboard', (), stop_event)
                paid = verified_paid_demand(dashboard, self.engine._now())
                revenue_reason = 'verified cumulative paid demand' if paid is not None else 'native trust incomplete'
            except NativeFailure as error:
                revenue_reason = error.code
        return self.snapshot('OBSERVED' if consumed else 'BACKOFF', report_digest=digest,
                             native_state=result.get('state_name'), native_action=result.get('action_name'),
                             next_attempt_unix=deadline, verified_paid_demand_musd=paid,
                             revenue_reason=revenue_reason)
