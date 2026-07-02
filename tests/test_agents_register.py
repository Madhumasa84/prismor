"""Tests for record_seen's control-plane fleet registration (warden/agents.py).

Invariants:
  * Registration fires once per process per agent, only when enrolled AND the
    workspace is org-managed; personal workspaces never report.
  * The on-disk debounce suppresses re-registration across processes (<1h).
  * The POST carries {name, framework} with '' for unnamed agents, bearer-authed.
  * Failures never raise into the caller (hook hot path).
"""
from __future__ import annotations

import json

import pytest

from warden import agents


class _SyncThread:
    """Run thread targets inline so tests are deterministic."""

    def __init__(self, target=None, args=(), daemon=None):
        self._target, self._args = target, args

    def start(self):
        self._target(*self._args)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    agents._SEEN_THIS_PROCESS.clear()
    agents._CONFIG_CACHE.clear()
    monkeypatch.setattr(agents.threading, "Thread", _SyncThread)
    yield


def _enroll():
    from warden.enterprise import identity
    identity.save_identity({
        "device_id": "d1", "org_id": "o1", "user_id": "u1",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })


@pytest.fixture
def posts(monkeypatch):
    calls = []
    monkeypatch.setattr(agents, "_post_registration", lambda ident, payload: calls.append((ident, payload)))
    return calls


def test_registers_named_agent_when_enrolled_and_managed(tmp_path, monkeypatch, posts):
    _enroll()
    monkeypatch.setattr("warden.enterprise.workspace_scope.is_managed", lambda ws: True)
    agents.record_seen("checkout-bot", framework="openai-agents", workspace=tmp_path)
    assert len(posts) == 1
    _, payload = posts[0]
    assert payload == {"agents": [{"name": "checkout-bot", "framework": "openai-agents"}]}
    # Local registry still written alongside.
    assert (tmp_path / ".prismor-warden" / "agents.yaml").exists()


def test_unnamed_agent_registers_with_empty_name(tmp_path, monkeypatch, posts):
    _enroll()
    monkeypatch.setattr("warden.enterprise.workspace_scope.is_managed", lambda ws: True)
    # record_seen is called with name == framework for unnamed agents.
    agents.record_seen("claude", framework="claude", workspace=tmp_path)
    assert posts[0][1] == {"agents": [{"name": "", "framework": "claude"}]}


def test_noop_when_not_enrolled(tmp_path, monkeypatch, posts):
    monkeypatch.setattr("warden.enterprise.workspace_scope.is_managed", lambda ws: True)
    agents.record_seen("bot", framework="langchain", workspace=tmp_path)
    assert posts == []


def test_noop_on_personal_workspace(tmp_path, monkeypatch, posts):
    _enroll()
    monkeypatch.setattr("warden.enterprise.workspace_scope.is_managed", lambda ws: False)
    agents.record_seen("bot", framework="langchain", workspace=tmp_path)
    assert posts == []


def test_once_per_process_and_disk_debounce(tmp_path, monkeypatch, posts):
    _enroll()
    monkeypatch.setattr("warden.enterprise.workspace_scope.is_managed", lambda ws: True)
    agents.record_seen("bot", framework="langchain", workspace=tmp_path)
    agents.record_seen("bot", framework="langchain", workspace=tmp_path)  # same process
    assert len(posts) == 1
    # New process (seen-set cleared) but within the disk debounce window.
    agents._SEEN_THIS_PROCESS.clear()
    agents.record_seen("bot", framework="langchain", workspace=tmp_path)
    assert len(posts) == 1
    debounce = json.loads(agents._register_debounce_path().read_text())
    assert "langchain|bot" in debounce
    # Expired debounce → registers again.
    debounce["langchain|bot"] = 0
    agents._register_debounce_path().write_text(json.dumps(debounce))
    agents._SEEN_THIS_PROCESS.clear()
    agents.record_seen("bot", framework="langchain", workspace=tmp_path)
    assert len(posts) == 2


def test_post_failure_never_raises(tmp_path, monkeypatch):
    """The real _post_registration against a dead endpoint stays silent."""
    _enroll()
    monkeypatch.setattr("warden.enterprise.workspace_scope.is_managed", lambda ws: True)
    # No _post_registration stub — the dead api_base (port 1) must be swallowed.
    agents.record_seen("bot", framework="crewai", workspace=tmp_path)  # must not raise
