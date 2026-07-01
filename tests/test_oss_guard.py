"""Tests for the OSS-safety guard (scripts/check_oss_safe.py)."""
import importlib.util
from pathlib import Path

_GUARD = Path(__file__).resolve().parent.parent / "scripts" / "check_oss_safe.py"
_spec = importlib.util.spec_from_file_location("check_oss_safe", _GUARD)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def test_clean_files_pass(tmp_path: Path):
    # A normal source file with no secrets and an allowed path → no violations.
    assert guard.scan(["warden/sinks.py"]) == []


def test_public_key_is_allowed():
    # The verify-only public key is meant to ship — must not be flagged.
    assert guard._path_violations(["keys/public.pub"]) == []


def test_private_pem_path_blocked():
    v = guard._path_violations(["keys/private.pem"])
    assert v and "private.pem" in v[0]


def test_pem_and_key_suffixes_blocked():
    v = guard._path_violations(["foo/server.pem", "secrets/app.key", "home/.env"])
    assert len(v) == 3


def test_pem_private_key_content_detected(tmp_path: Path):
    f = tmp_path / "leak.txt"
    f.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
    # Point the guard at a temp tree by faking REPO_ROOT for the read.
    orig = guard.REPO_ROOT
    guard.REPO_ROOT = tmp_path
    try:
        v = guard._content_violations(["leak.txt"])
    finally:
        guard.REPO_ROOT = orig
    assert v and "PEM private key" in v[0]


def test_aws_and_github_secrets_detected(tmp_path: Path):
    f = tmp_path / "creds.txt"
    f.write_text("AKIAIOSFODNN7EXAMPLE\nghp_0123456789abcdefghijklmnopqrstuvwxyz\n")
    orig = guard.REPO_ROOT
    guard.REPO_ROOT = tmp_path
    try:
        v = guard._content_violations(["creds.txt"])
    finally:
        guard.REPO_ROOT = orig
    assert len(v) >= 2


def test_guard_does_not_flag_itself():
    # The guard file contains the signature regexes; it must be exempt.
    assert guard._content_violations([guard.SELF]) == []


def test_repo_is_currently_clean():
    # The live public repo (all git-tracked files) must pass — this is the real
    # CI assertion and guards against a regression sneaking a secret in.
    assert guard.scan([]) == []
