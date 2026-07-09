"""Org signed-policy tool denies (settings.tool_denies) — Phase 2b enforcement.

An org admin denies a tool tag from the Prismor web console; it ships in the
signed policy as settings.tool_denies and the device runtime blocks matching
tool calls by scope. Device-scoped entries are pre-filtered to the device
server-side, so org/device always apply here; agent/session match on the
event's agent name / session id.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime import agents
    agents._CONFIG_CACHE.clear()
    yield


def _eval(tmp_path, monkeypatch, tool_denies, *, agent_name="codex", session_id="s1", tool="Bash"):
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.tool_denies = tool_denies

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)
    return runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hi",
               "metadata": {"tool_name": tool}},
        workspace=tmp_path, agent="codex", agent_name=agent_name,
        mode="observe", session_id=session_id, persist=False,
    )


def test_org_scope_blocks_everyone(tmp_path, monkeypatch):
    d = _eval(tmp_path, monkeypatch, [{"id": "t1", "tool": "Bash", "action": "deny", "scope": "org"}])
    assert d.allow is False
    assert any(f.get("ruleId") == "org-tool-deny" for f in d.findings)


def test_agent_scope_matches_only_that_agent(tmp_path, monkeypatch):
    denies = [{"id": "t2", "tool": "Bash", "action": "deny", "scope": "agent", "scopeId": "codex"}]
    assert _eval(tmp_path, monkeypatch, denies, agent_name="codex").allow is False
    assert _eval(tmp_path, monkeypatch, denies, agent_name="claude").allow is True


def test_session_scope_matches_only_that_session(tmp_path, monkeypatch):
    denies = [{"id": "t3", "tool": "Bash", "action": "deny", "scope": "session", "scopeId": "s1"}]
    assert _eval(tmp_path, monkeypatch, denies, session_id="s1").allow is False
    assert _eval(tmp_path, monkeypatch, denies, session_id="s2").allow is True


def test_device_scope_applies_here_prefiltered(tmp_path, monkeypatch):
    # Device entries are pre-filtered to this device server-side, so scopeId is
    # not re-checked on the device — it always applies.
    d = _eval(tmp_path, monkeypatch, [{"id": "t4", "tool": "Bash", "action": "deny", "scope": "device", "scopeId": "whatever"}])
    assert d.allow is False


def test_different_tool_not_blocked(tmp_path, monkeypatch):
    denies = [{"id": "t5", "tool": "mcp__node_repl__js", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies, tool="Bash").allow is True


def test_mcp_tag_blocked_verbatim(tmp_path, monkeypatch):
    denies = [{"id": "t6", "tool": "mcp__node_repl__js", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__node_repl__js").allow is False


def test_non_deny_action_ignored(tmp_path, monkeypatch):
    denies = [{"id": "t7", "tool": "Bash", "action": "allow", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies).allow is True


def test_tool_denies_sig_matches_server_format():
    # Reproduces lib/tool-policy.ts toolDeniesSig: sorted
    # id:tool:action:scope:scopeId lines -> sha256 -> 16 hex.
    import hashlib
    from prismor.runtime.enterprise import remote_policy as rp
    denies = [
        {"id": "b", "tool": "Bash", "action": "deny", "scope": "org", "scopeId": None},
        {"id": "a", "tool": "WebSearch", "action": "deny", "scope": "agent", "scopeId": "codex"},
    ]
    rp.verify_and_load = lambda: {"settings": {"tool_denies": denies}}  # type: ignore
    lines = sorted([
        "b:Bash:deny:org:",
        "a:WebSearch:deny:agent:codex",
    ])
    expected = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    assert rp._current_tool_denies_sig() == expected
