"""Reproduce existing offline tests in a full checkout, without historical logs."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import runpy
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
FOCUSED = [f'tests/test_harness_alignment_{name}.py' for name in
           ('models', 'hardening', 'judge', 'casebook', 'gateway')]
NATIVE = ['tests/test_mcp_gateway.py', 'tests/test_tool_policy_three_state.py',
          'tests/test_surface_conformance.py']
SELECTION = ('call_forwarded_on_allow or call_blocked_pre_forward or engine_error_fails_closed '
             'or call_step_up or call_modify or gateway_end_to_end_real_engine '
             'or three_state or surface_conformance')
STEPS = ('focused', 'native', 'boundary', 'dry-run', 'packaging')


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()


def snapshot():
    """Hash tracked checkout bytes plus the explicitly proposed packaging files."""
    proposed = (ROOT / 'candidate_files.txt').read_text().splitlines()
    names = set(git('ls-files', '-z').split('\0')) | set(proposed)
    files = {}
    for name in sorted(names - {''}):
        path = REPO / name
        files[name] = (digest(os.readlink(path).encode()) if path.is_symlink() else
                       digest(path.read_bytes()) if path.is_file() else None)
    return {'head': git('rev-parse', 'HEAD'), 'branch': git('branch', '--show-current'),
            'tracked_diff': git('diff', '--name-only', 'HEAD'),
            'proposed_files': proposed, 'files': files,
            'content_sha256': digest(json.dumps(files, sort_keys=True).encode()),
            'identity_note': 'HEAD plus actual file hashes; uncommitted overlays are not an immutable commit'}


def junit(path):
    if not path.exists():
        return None
    root = ET.parse(path).getroot()
    cases = list(root.iter('testcase'))
    skips = [{'test': c.get('classname', '') + '::' + c.get('name', ''),
              'reason': c.find('skipped').get('message', '')} for c in cases if c.find('skipped') is not None]
    failures = sum(c.find('failure') is not None for c in cases)
    errors = sum(c.find('error') is not None for c in cases)
    return {'tests': len(cases), 'passed': len(cases) - len(skips) - failures - errors,
            'failed': failures, 'errors': errors, 'skipped': len(skips), 'skips': skips,
            'hardening_checks': sum('test_harness_alignment_hardening' in c.get('classname', '') for c in cases)}


def observations(rows):
    def total(values):
        return sum(values) if values and all(type(v) is int for v in values) else None
    return {'rows': len(rows), 'statuses': dict(Counter(r.get('status', 'unknown') for r in rows)),
            'forwarded_calls': total([(r.get('actual_forwarding') or {}).get('tools_call_count') for r in rows if r.get('status') != 'unsupported']),
            'scripted_calls': total([r.get('scripted_call_count') for r in rows if r.get('status') != 'unsupported']),
            'model_calls': total([r.get('model_call_count') for r in rows if r.get('status') != 'unsupported']),
            'approval_outcomes': dict(Counter(r['approval_outcome']['status'] for r in rows if r.get('approval_outcome'))),
            'unknown_forwarding_rows': sum(r.get('status') != 'unsupported' and (r.get('actual_forwarding') or {}).get('tools_call_count') is None for r in rows)}


def child_environment(state):
    state.mkdir(parents=True, exist_ok=True)
    for name in ('home', 'config', 'cache', 'prismor', 'secrets', 'tmp'):
        (state / name).mkdir(exist_ok=True)
    # Construct, never serialize or inherit, the owner's credential-bearing environment.
    return {'PATH': str(Path(sys.executable).parent) + os.pathsep + os.defpath,
            'HOME': str(state / 'home'), 'XDG_CONFIG_HOME': str(state / 'config'),
            'XDG_CACHE_HOME': str(state / 'cache'), 'PRISMOR_HOME': str(state / 'prismor'),
            'PRISMOR_SECRETS_DIR': str(state / 'secrets'), 'PRISMOR_NO_UPDATE_CHECK': '1',
            'TMPDIR': str(state / 'tmp'), 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1', 'LANG': 'C.UTF-8'}


def step_command(step, output):
    if step == 'dry-run':
        return ['research.harness_alignment.comparison', '--mode', 'dry-run',
                '--output', str(output / 'native-dry-run')]
    paths = (FOCUSED if step == 'focused' else NATIVE if step == 'native' else
             ['tests/test_harness_alignment_gateway.py'] if step == 'boundary' else
             ['tests/test_harness_alignment_reproduce.py'])
    return ['pytest', *paths, '-q', '-s', '-rs', '-p', 'no:cacheprovider',
            '--junitxml=' + str(output / (step + '.xml'))] + (['-k', SELECTION] if step == 'native' else [])


def worker(step, output):
    """A fresh interpreter per command; audit hooks detect even swallowed socket errors."""
    attempts = []
    def audit(event, args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.sendto'):
            attempts.append(event)  # Never record addresses, headers or credentials.
            raise RuntimeError('offline reproduction forbids outbound network')
    sys.addaudithook(audit)
    rc = 1
    try:
        from prismor.runtime import mcp_gateway
        if not Path(mcp_gateway.__file__).resolve().is_relative_to(REPO):
            raise RuntimeError('Prismor import did not resolve to this checkout')
        write(output / (step + '-environment.json'), {
            'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
            'prismor_import': str(Path(mcp_gateway.__file__).resolve()),
            'dependencies': {d.metadata['Name']: d.version for d in metadata.distributions()},
            'user_site_disabled': sys.flags.no_user_site == 1})
        command = step_command(step, output)
        sys.argv = command
        try:
            runpy.run_module(command[0], run_name='__main__', alter_sys=True)
            rc = 0
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else int(exc.code is not None)
    finally:
        write(output / (step + '-network.json'), {'blocked_attempts': attempts,
              'scope': 'Python worker socket audit plus existing research fixture service guards; not a kernel sandbox'})
    return 1 if attempts else rc


def complete_dry_run(data, rows):
    """Require one observation per source case and the matching offline manifest."""
    expected = {case['evaluator']['id'] for case in json.loads((ROOT / 'casebook.json').read_text())['cases']}
    ids = [row.get('case_id') for row in rows]
    manifest_path = data / 'manifest.json'
    if not manifest_path.is_file():
        return False
    manifest = json.loads(manifest_path.read_text())
    return (len(ids) == len(expected) and set(ids) == expected
            and all(row.get('status') in ('ok', 'unsupported') for row in rows)
            and manifest.get('casebook_sha256') == digest((ROOT / 'casebook.json').read_bytes())
            and manifest.get('mode') == 'dry-run'
            and manifest.get('effective_live_model_run') is False
            and manifest.get('effective_max_real_requests') == 0)


def summarize(output, records):
    result = {'steps': records, 'test_groups': {}, 'boundary': None, 'native': None,
              'real_external_inference_requests': None, 'historical_reference': {
                  'focused_passed': 107, 'hardening_checks': 25, 'native_passed': 33,
                  'native_skipped': 1, 'native_deselected': 48, 'boundary_calls': [1, 0, 0, 1]},
              'note': 'Historical reference is not a target; groups overlap. Packaging checks are separate.'}
    for step in ('focused', 'native', 'boundary', 'packaging'):
        result['test_groups'][step] = junit(output / (step + '.xml'))
        matches = re.findall(r'(\d+) deselected', (output / (step + '.log')).read_text())
        if result['test_groups'][step] is not None:
            result['test_groups'][step]['deselected'] = int(matches[-1]) if matches else 0
    boundary = []
    for line in (output / 'boundary.log').read_text().splitlines():
        start = line.find('{"approval_outcome"')
        if start >= 0:
            boundary.append(json.JSONDecoder().raw_decode(line[start:])[0])
    if boundary:
        result['boundary'] = boundary
    data = output / 'native-dry-run'
    rows = []
    if (data / 'native_observations.jsonl').exists():
        rows = [json.loads(line) for line in (data / 'native_observations.jsonl').read_text().splitlines() if line.strip()]
        result['native'] = observations(rows)
    if (data / 'pilot.json').exists():
        result['real_external_inference_requests'] = json.loads((data / 'pilot.json').read_text()).get('actual_real_requests')
    result['success'] = (all(r['returncode'] == 0 for r in records)
                         and all(result['test_groups'].values()) and len(boundary) == 4
                         and complete_dry_run(data, rows)
                         and not result['native']['statuses'].get('failed', 0)
                         and result['real_external_inference_requests'] == 0)
    return result


def run(output):
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    records = []
    write(output / 'summary.json', {'success': False, 'state': 'started', 'real_external_inference_requests': None})
    try:
        settings = json.loads((ROOT / 'live_settings.json').read_text())
        if settings.get('LIVE_MODEL_RUN') is not False or settings.get('MAX_REAL_REQUESTS') != 0:
            raise ValueError('offline reproduction requires unchanged false/zero live settings')
        write(output / 'source_snapshot.json', snapshot())
        for step in STEPS:
            command = [sys.executable, '-m', 'research.harness_alignment.reproduce',
                       '--worker', step, '--output', str(output)]
            record = {'step': step, 'command': command,
                      'inner_command': [sys.executable, '-m', *step_command(step, output)],
                      'returncode': None}
            records.append(record); write(output / 'commands.json', records)
            start = time.monotonic()
            with (output / (step + '.log')).open('w') as log:
                proc = subprocess.run(command, cwd=REPO,
                                      env=child_environment(output / '_state' / step),
                                      stdout=log, stderr=subprocess.STDOUT)
            record.update(returncode=proc.returncode, elapsed_seconds=time.monotonic() - start)
            write(output / 'commands.json', records)
            print(json.dumps({'step': step, 'returncode': proc.returncode}), flush=True)
        result = summarize(output, records)
        write(output / 'summary.json', result)
        return 0 if result['success'] else 1
    except Exception as exc:
        write(output / 'summary.json', {'success': False, 'error_type': type(exc).__name__,
                                       'steps': records, 'real_external_inference_requests': None})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', choices=STEPS, help=argparse.SUPPRESS)
    args = parser.parse_args()
    return worker(args.worker, args.output) if args.worker else run(args.output)


if __name__ == '__main__':
    raise SystemExit(main())
