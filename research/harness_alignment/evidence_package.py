"""Allowlisted historical evidence packaging; hashes prove consistency, not inference."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '\\' in name
            or ':' in name or str(path) != name or name in ('.', 'MANIFEST.json')):
        raise ValueError('unsafe or reserved evidence path')
    return name


def screen(name, data):
    parts = PurePosixPath(name).parts
    if (any(p.startswith('.env') for p in parts) or
            Path(name).suffix.lower() in ('.pem', '.key', '.bin', '.pt', '.pth', '.safetensors')):
        raise ValueError('forbidden evidence file type')
    patterns = (rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                rb'gh[pousr]_[A-Za-z0-9]{30,}', rb'AKIA[A-Z0-9]{16}',
                rb'sk-[A-Za-z0-9_-]{32,}', rb'https?://[^\s/"<>]+:[^\s/"<>]+@')
    if any(re.search(p, data) for p in patterns):
        raise ValueError('potential credential in allowlisted evidence: ' + name)


def pack(root, names, archive, mapping):
    root = root.resolve()
    sidecar = archive.with_suffix(archive.suffix + '.manifest.json')
    if archive.exists() or sidecar.exists():
        raise FileExistsError(archive)
    if len(names) != len(set(names)):
        raise ValueError('duplicate allowlist path')
    payload = {}
    for name in names:
        safe_name(name)
        path = root / name
        if (not path.resolve().is_relative_to(root) or not path.is_file()
                or any(p.is_symlink() for p in [path, *path.parents] if p != root)):
            raise ValueError('missing, linked or escaping evidence path: ' + name)
        data = path.read_bytes()
        if len(data) > MAX_FILE:
            raise ValueError('evidence file too large')
        screen(name, data)
        payload[name] = data
    if sum(map(len, payload.values())) > MAX_TOTAL:
        raise ValueError('evidence package too large')
    manifest = {'version': 1, 'files': {n: hashlib.sha256(d).hexdigest() for n, d in payload.items()},
                'mapping': mapping, 'redaction': 'none; originals copied byte-for-byte',
                'trust': 'Consistency only; not remote inference authentication.'}
    payload['MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open('xb') as target:
        with tarfile.open(fileobj=target, mode='w:gz') as tar:
            for name, data in payload.items():
                member = tarfile.TarInfo(name)
                member.size = len(data); member.mode = 0o600
                tar.addfile(member, io.BytesIO(data))
    archive.chmod(0o600)
    # Same manifest beside the archive supports inspection without extraction.
    sidecar = archive.with_suffix(archive.suffix + '.manifest.json')
    with sidecar.open('x') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    sidecar.chmod(0o600)
    return manifest


def verify(archive, output=None):
    if output is not None and output.exists():
        raise FileExistsError(output)
    payload = {}
    total = 0
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            if member.name != 'MANIFEST.json':
                safe_name(member.name)
            if (not member.isfile() or member.name in payload or member.size > MAX_FILE
                    or member.size < 0):
                raise ValueError('unsafe, duplicate or oversized archive entry')
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError('archive too large')
            payload[member.name] = tar.extractfile(member).read()
    try:
        manifest = json.loads(payload.pop('MANIFEST.json'))
        expected = manifest['files']
        if manifest['version'] != 1 or set(expected) != set(payload):
            raise ValueError('archive is not exactly its manifest allowlist')
        for name, data in payload.items():
            screen(name, data)
            if hashlib.sha256(data).hexdigest() != expected[name]:
                raise ValueError('checksum mismatch: ' + name)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError('missing or invalid manifest') from exc
    if output is not None:
        output.mkdir(parents=True, exist_ok=False); output.chmod(0o700)
        # Never use extractall: validated regular files only, created in a new directory.
        for name, data in payload.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as f:f.write(data)
            path.chmod(0o600)
        (output / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        for name, expected_hash in expected.items():
            if hashlib.sha256((output / name).read_bytes()).hexdigest() != expected_hash:
                raise ValueError('extracted checksum mismatch')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build')
    build.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('archive', type=Path)
    check.add_argument('--extract', type=Path)
    args = parser.parse_args()
    if args.command == 'build':
        selection = json.loads((ROOT / 'historical_evidence.json').read_text())
        result = pack(REPO, selection['files'], args.output, selection['mapping'])
    else:
        result = verify(args.archive, args.extract)
    print(json.dumps({'verified_files': len(result['files']), 'redaction': result['redaction']}))


if __name__ == '__main__':
    main()
