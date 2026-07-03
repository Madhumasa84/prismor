"""Tests for admin-granted, repo-scoped policy exemptions.

Invariants:
  * An exemption matching the workspace's repo relaxes a NON-floor rule.
  * An exemption can NEVER disable a core/floor rule (reinforced).
  * A non-matching repo gets no exemption.
  * An expired exemption is ignored.
  * The active exemption is recorded so telemetry can show the repo is relaxed.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime.enterprise import identity
    identity.save_identity({"device_id": "d", "org_id": "o", "user_id": "u",
                            "device_key": "prism_dev_x", "api_base": "http://x"})
    yield


def _git(tmp_path, url):
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    (ws / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {url}\n', encoding="utf-8")
    return ws


# A remote (org) bundle: an org rule that blocks curl|sh, a repo exemption that
# disables it for acme/sandbox, AND an (illegal) attempt to disable the core
# destructive-command rule via the exemption.
def _bundle(exemption_pattern="github.com/acme/sandbox", expires=None, disable_core=False):
    overlay = {"rules": [{"id": "org-no-curl-pipe-sh", "enabled": False}]}
    if disable_core:
        overlay["rules"].append({"id": "destructive-command", "enabled": False})
    return {
        "rules": [{
            "id": "org-no-curl-pipe-sh", "enabled": True, "severity": "HIGH",
            "category": "tool_call_abuse", "title": "no curl|sh", "event_types": ["shell"],
            "fields": ["command"], "action": "block", "patterns": ["curl.*\\|.*sh"],
        }],
        "settings": {
            "repo_exemptions": [{
                "id": "exm_test1", "pattern": exemption_pattern, "reason": "deploy uses curl|sh",
                **({"expires": expires} if expires else {}),
                "overlay": overlay,
            }],
        },
        "_remote_meta": {"version": 3},
    }


def _engine(tmp_path, monkeypatch, url, bundle):
    from prismor.runtime.enterprise import workspace_scope, remote_policy
    from prismor.runtime.policy_engine import PolicyEngine
    monkeypatch.setattr(workspace_scope, "is_managed", lambda ws: True)
    monkeypatch.setattr(workspace_scope, "org_managed_patterns", lambda: ["github.com/acme/*"])
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: dict(bundle))
    return PolicyEngine(workspace=_git(tmp_path, url))


def test_exemption_relaxes_non_core_rule_for_matching_repo(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch, "https://github.com/acme/sandbox", _bundle())
    rules = {r.id: r for r in e.rules}
    assert e.active_exemption and e.active_exemption["id"] == "exm_test1"
    # The org rule was disabled for this repo by the exemption.
    assert "org-no-curl-pipe-sh" not in rules or getattr(rules.get("org-no-curl-pipe-sh"), "enabled", True) is False


def test_exemption_cannot_disable_core_floor(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch, "https://github.com/acme/sandbox",
                _bundle(disable_core=True))
    rule_ids = {r.id for r in e.rules}
    # Even though the exemption tried to disable destructive-command, the floor wins.
    assert "destructive-command" in rule_ids, "exemption must NOT be able to weaken the floor"


def test_non_matching_repo_gets_no_exemption(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch, "https://github.com/acme/production", _bundle())
    assert e.active_exemption is None
    # The org rule stays enforced for a repo without an exemption.
    assert "org-no-curl-pipe-sh" in {r.id for r in e.rules}


def test_expired_exemption_ignored(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch, "https://github.com/acme/sandbox",
                _bundle(expires="2000-01-01T00:00:00Z"))
    assert e.active_exemption is None
    assert "org-no-curl-pipe-sh" in {r.id for r in e.rules}


def test_telemetry_record_tags_policy_scope(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import telemetry
    rec = telemetry.build_record(
        {"severity": "high", "category": "x", "ruleId": "r", "action": "warn", "title": "t"},
        {"type": "shell", "command": "x"},
        extra={"repo": "github.com/acme/sandbox", "policy_scope": "repo_exemption:exm_test1"},
    )
    assert rec["repo"] == "github.com/acme/sandbox"
    assert rec["policy_scope"] == "repo_exemption:exm_test1"
    telemetry.assert_redacted(rec)  # repo/scope are not sensitive free text
