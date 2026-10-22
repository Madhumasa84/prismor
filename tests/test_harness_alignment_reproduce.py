"""Packaging invariants; separate from the historical 107 focused checks."""
import io
import json
import tarfile
from pathlib import Path

import pytest

from research.harness_alignment import reproduce as r
from research.harness_alignment import evidence_package as p


def test_junit_failure_and_skip_are_not_passes(tmp_path):
    path = tmp_path / 'run.xml'
    path.write_text('<testsuites><testsuite tests="3" failures="1" errors="0" skipped="1">'
                    '<testcase name="pass"/><testcase name="failure"><failure/></testcase>'
                    '<testcase name="skip"><skipped message="demo missing"/></testcase>'
                    '</testsuite></testsuites>')
    assert r.junit(path)['passed'] == 1
    assert r.junit(path)['skips'][0]['reason'] == 'demo missing'
    assert r.junit(tmp_path / 'missing') is None


def test_unknown_calls_are_not_zero():
    assert r.observations([{'status': 'failed', 'actual_forwarding': None}])['forwarded_calls'] is None
    assert r.observations([{'status': 'ok', 'actual_forwarding': {'tools_call_count': 0},
                            'model_call_count': 0, 'scripted_call_count': 0}])['forwarded_calls'] == 0


def test_existing_output_refused_before_running(tmp_path):
    with pytest.raises(FileExistsError):
        r.run(tmp_path)


def test_child_environment_excludes_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('SECRET_API_KEY', 'synthetic-test-value')
    monkeypatch.setenv('PYTHONPATH', '/not/the/checkout')
    env = r.child_environment(tmp_path)
    assert 'SECRET_API_KEY' not in env and 'PYTHONPATH' not in env
    assert env['HOME'] == str(tmp_path / 'home')
    assert env['PYTHONNOUSERSITE'] == '1'


def test_archive_roundtrip_and_tamper(tmp_path):
    source = tmp_path / 'source'; source.mkdir()
    (source / 'record.json').write_text('{"fixture": true}')
    archive = tmp_path / 'evidence.tar.gz'
    p.pack(source, ['record.json'], archive, {'table': ['record.json']})
    extracted = tmp_path / 'extracted'
    p.verify(archive, extracted)
    assert (extracted / 'record.json').read_text() == '{"fixture": true}'
    with pytest.raises(FileExistsError):
        p.verify(archive, extracted)
    with tarfile.open(archive, 'r:gz') as t:
        payload = {m.name: t.extractfile(m).read() for m in t}
    payload['record.json'] = b'changed'
    corrupt = tmp_path / 'corrupt.tar.gz'
    with tarfile.open(corrupt, 'w:gz') as t:
        for name,data in payload.items():
            m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
    with pytest.raises(ValueError):p.verify(corrupt, tmp_path / 'bad')
    assert not (tmp_path / 'bad').exists()


@pytest.mark.parametrize('name,link', [('../escape', False),('/absolute', False),('link', True),('a/../b', False)])
def test_unsafe_archive_rejected_before_extraction(tmp_path, name, link):
    archive=tmp_path/'bad.tar.gz'
    with tarfile.open(archive,'w:gz') as t:
        m=tarfile.TarInfo(name)
        if link:m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd'
        t.addfile(m,io.BytesIO(b''))
    with pytest.raises(ValueError):p.verify(archive,tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_unlisted_and_sensitive_input_rejected(tmp_path):
    (tmp_path/'.env').write_text('synthetic fixture')
    with pytest.raises(ValueError):p.pack(tmp_path,['.env'],tmp_path/'x.tar.gz',{})
    (tmp_path/'record.json').write_text('https://name:password@example.invalid')
    with pytest.raises(ValueError):p.pack(tmp_path,['record.json'],tmp_path/'x.tar.gz',{})


@pytest.mark.parametrize('mutation', ['extra', 'missing', 'duplicate'])
def test_archive_must_match_exact_allowlist(tmp_path, mutation):
    source=tmp_path/'source';source.mkdir();(source/'record.json').write_text('{}')
    archive=tmp_path/'original.tar.gz'
    p.pack(source,['record.json'],archive,{})
    with tarfile.open(archive,'r:gz') as t:
        items=[(m.name,t.extractfile(m).read()) for m in t]
    if mutation=='extra':items.append(('extra.json',b'{}'))
    elif mutation=='missing':items=[item for item in items if item[0]!='record.json']
    else:items.append(('record.json',b'{}'))
    bad=tmp_path/'bad.tar.gz'
    with tarfile.open(bad,'w:gz') as t:
        for name,data in items:
            m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
    with pytest.raises(ValueError):p.verify(bad,tmp_path/'out')
    assert not (tmp_path/'out').exists()


@pytest.mark.parametrize('mutation', ['none', 'empty', 'missing', 'duplicate', 'no_manifest', 'wrong_hash'])
def test_dry_run_requires_complete_case_coverage(tmp_path, mutation):
    cases = json.loads((r.ROOT / 'casebook.json').read_text())['cases']
    rows = [{'case_id': c['evaluator']['id'], 'status': 'ok'} for c in cases]
    manifest = {'casebook_sha256': r.digest((r.ROOT / 'casebook.json').read_bytes()),
                'mode': 'dry-run', 'effective_live_model_run': False,
                'effective_max_real_requests': 0}
    if mutation == 'empty': rows = []
    elif mutation == 'missing': rows.pop()
    elif mutation == 'duplicate': rows[-1] = rows[0]
    elif mutation == 'wrong_hash': manifest['casebook_sha256'] = 'incorrect'
    if mutation != 'no_manifest':
        (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    assert r.complete_dry_run(tmp_path, rows) is (mutation == 'none')
