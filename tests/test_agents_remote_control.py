"""Tests for org (remote) per-agent control merge (prismor/runtime/agents.py) and the
end-to-end kill-switch through evaluate_tool_call.

The org controls arrive in the verified signed policy's settings.agent_controls
(PolicyEngine.agent_controls) and merge tighten-only with the local agents.yaml.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from prismor.runtime import agents


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    agents._CONFIG_CACHE.clear()
    yield


def _local(workspace: Path, name: str, **fields):
    agents.upsert_agent(name, workspace, framework="openai-agents", **fields)


# ── merge precedence matrix ────────────────────────────────────────────────

def test_remote_disable_cannot_be_locally_reenabled(tmp_path):
    _local(tmp_path, "bot", enabled=True)
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": False}})
    assert ctl.enabled is False
    assert ctl.disabled_by == "org"


def test_local_disable_holds_even_if_remote_enabled(tmp_path):
    _local(tmp_path, "bot", enabled=False)
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True}})
    assert ctl.enabled is False
    assert ctl.disabled_by == "local"


def test_disabled_by_both(tmp_path):
    _local(tmp_path, "bot", enabled=False)
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": False}})
    assert ctl.enabled is False and ctl.disabled_by == "both"


def test_remote_mode_wins_over_local(tmp_path):
    _local(tmp_path, "bot", mode="observe")
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True, "mode": "enforce"}})
    assert ctl.mode == "enforce"


def test_remote_only_agent_not_in_local_registry(tmp_path):
    # An org can control an agent this machine has never registered locally.
    ctl = agents.resolve_agent_control("ghost", tmp_path, remote_controls={"ghost": {"enabled": False}})
    assert ctl.enabled is False and ctl.disabled_by == "org"


def test_iam_profile_remote_then_local_fallback(tmp_path):
    _local(tmp_path, "bot", iam_profile="local-ro")
    assert agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True, "iam_profile": "org-ro"}}).iam_profile == "org-ro"
    assert agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True}}).iam_profile == "local-ro"


def test_unregistered_agent_is_permissive(tmp_path):
    ctl = agents.resolve_agent_control("nobody", tmp_path, remote_controls={})
    assert ctl.enabled is True and ctl.mode is None and ctl.disabled_by is None


# ── end-to-end: a remote kill-switch blocks a benign call ──────────────────

def test_remote_killswitch_blocks_via_evaluate_tool_call(tmp_path, monkeypatch):
    """A managed workspace whose signed policy disables 'checkout-bot' → every
    tool call from that instance is blocked, even a benign one."""
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    # Force the engine to look managed and carry the org control, without a real
    # enrolled device / signed policy.
    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.workspace_managed = True
        self.agent_controls = {"checkout-bot": {"enabled": False}}

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)

    d = runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hello", "metadata": {"tool_name": "Bash"}},
        workspace=tmp_path, agent="openai-agents", agent_name="checkout-bot",
        mode="observe", session_id="s1", persist=False,
    )
    assert d.allow is False
    assert any(f.get("ruleId") == "agent-disabled" for f in d.findings)
    disabled = next(f for f in d.findings if f.get("ruleId") == "agent-disabled")
    assert "org" in disabled["evidence"] or "control plane" in disabled["evidence"]


def test_unmanaged_workspace_ignores_remote_controls(tmp_path, monkeypatch):
    """A personal (unmanaged) workspace never carries agent_controls, so a
    remote pause has no effect there."""
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.workspace_managed = False
        self.agent_controls = {}  # unmanaged → no remote overlay merged

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)

    d = runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hi", "metadata": {"tool_name": "Bash"}},
        workspace=tmp_path, agent="openai-agents", agent_name="checkout-bot",
        mode="observe", session_id="s2", persist=False,
    )
    assert not any(f.get("ruleId") == "agent-disabled" for f in d.findings)
