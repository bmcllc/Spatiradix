"""Read the S1-MUPP controller state without manufacturing sensor data."""
import json
import math
from pathlib import Path
import time


DEFAULT_STATE = Path('/tmp/s1-mupp-state.json')


def read_state(path=DEFAULT_STATE):
    with Path(path).open('rb') as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        raise ValueError('S1 state exceeds 16 KiB')
    return json.loads(data)


def evaluate(source=read_state, now=None):
    now = time.time() if now is None else now
    source_label = str(DEFAULT_STATE) if source is read_state else "injected_s1_state_source"
    try:
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError("invalid clock")
        state = source()
        if not isinstance(state, dict):
            raise ValueError('invalid S1 state')
        def number(key):
            value = state.get(key)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError('invalid S1 number')
            return value
        timestamp = number('timestamp_unix')
        if type(state.get('schema_version')) is not int or state['schema_version'] != 1:
            raise ValueError('unsupported S1 schema')
        if state.get('mode') != 'MUPP_LOCAL_CONTROL':
            raise ValueError('invalid S1 mode')
        if not isinstance(state.get('phase'), str) or not state['phase']:
            raise ValueError('invalid S1 phase')
        if not isinstance(state.get('regime'), str) or not state['regime']:
            raise ValueError('invalid S1 regime')
        for key in ('sensor_ok', 'sensor_warmup_complete', 'allow_execution'):
            if type(state.get(key)) is not bool:
                raise ValueError('invalid S1 flag')
        for key in ('T', 'H', 'RecoveryDebt'):
            number(key)
        if not 0 <= state['T'] <= 150:
            raise ValueError('invalid S1 temperature')
        if state['RecoveryDebt'] < 0 or type(state.get('queue')) is not int or state['queue'] < 0:
            raise ValueError('invalid S1 resource state')
        for key in ('cpu_temp_c', 'gpu_temp_c'):
            if state.get(key) is not None:
                if not 0 <= number(key) <= 150:
                    raise ValueError('invalid S1 temperature')
        for key in ('cpu_util_pct', 'gpu_util_pct'):
            if state.get(key) is not None:
                if not 0 <= number(key) <= 100:
                    raise ValueError('invalid S1 utilization')
        if timestamp < 0 or not 0 <= now - timestamp <= 5:
            return {'allowed': False, 'reason': 's1_stale', 'source': source_label}
        allowed = (state['sensor_ok'] and state['sensor_warmup_complete']
                   and state['allow_execution'] and state['H'] > 0
                   and state['phase'] not in ('COLLAPSE', 'COOLDOWN'))
        return {'allowed': allowed, 'reason': 's1_ready' if allowed else 's1_blocked',
                'headroom_fraction': max(0.0, min(1.0, state['H'] / 20)),
                'source': source_label, 'provenance': {key: state[key] for key in (
                    'schema_version', 'timestamp_unix', 'mode', 'phase', 'regime',
                    'sensor_ok', 'sensor_warmup_complete', 'allow_execution',
                    'T', 'H', 'RecoveryDebt', 'queue', 'cpu_temp_c', 'gpu_temp_c',
                    'cpu_util_pct', 'gpu_util_pct') if key in state}}
    except (OSError, ValueError, TypeError, OverflowError) as error:
        return {'allowed': False, 'reason': 's1_unavailable_or_invalid',
                'source': source_label, 'error_type': type(error).__name__}
