"""Skill inventory + per-skill denies.

Every Claude Code skill invocation arrives under the single tool tag "Skill";
the name that says WHICH skill ran is only in the raw payload's tool_input.
The runtime lifts it into a qualified "Skill:<name>" tag so the console can
inventory skills individually and an admin can deny one skill without denying
the whole mechanism.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime import agents
    agents._CONFIG_CACHE.clear()
    yield


def _skill_event(skill_name, *, include_name=True):
    from prismor.runtime.hooks import _normalize_claude
    tool_input = {"skill": skill_name} if include_name else {}
    return _normalize_claude(
        {"hook_event_name": "PreToolUse", "cwd": "/tmp/ws",
         "tool_name": "Skill", "tool_input": tool_input},
        "s1", Path("/tmp/ws"),
    )


def _eval(tmp_path, monkeypatch, event, tool_denies, *, agent_name="claude", session_id="s1"):
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.tool_denies = tool_denies

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)
    return runtime.evaluate_tool_call(
        event=event, workspace=tmp_path, agent="claude", agent_name=agent_name,
        mode="observe", session_id=session_id, persist=False,
    )


# ── Tag resolution ─────────────────────────────────────────────────────────

def test_skill_name_lifts_into_qualified_tag():
    from prismor.runtime.scoped_agent import resolve_tool_tags
    assert resolve_tool_tags(_skill_event("wiki-query")) == ["Skill", "Skill:wiki-query"]


def test_nameless_skill_degrades_to_bare_tag():
    # An older/other agent shape with no skill in tool_input must still report
    # the bare tag rather than vanishing from the inventory.
    from prismor.runtime.scoped_agent import resolve_tool_tags
    assert resolve_tool_tags(_skill_event("", include_name=False)) == ["Skill"]


def test_non_skill_tools_are_untouched():
    from prismor.runtime.hooks import _normalize_claude
    from prismor.runtime.scoped_agent import resolve_tool_tags
    ev = _normalize_claude(
        {"hook_event_name": "PreToolUse", "cwd": "/tmp/ws",
         "tool_name": "Bash", "tool_input": {"command": "ls"}},
        "s1", Path("/tmp/ws"),
    )
    assert resolve_tool_tags(ev) == ["Bash"]


# ── Enforcement ────────────────────────────────────────────────────────────

def test_qualified_deny_blocks_only_that_skill(tmp_path, monkeypatch):
    denies = [{"id": "t1", "tool": "Skill:wiki-query", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, _skill_event("wiki-query"), denies).allow is False
    # A different skill rides the same bare tag — it must NOT be caught.
    assert _eval(tmp_path, monkeypatch, _skill_event("stop-slop"), denies).allow is True


def test_bare_deny_blocks_every_skill(tmp_path, monkeypatch):
    denies = [{"id": "t2", "tool": "Skill", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, _skill_event("wiki-query"), denies).allow is False
    assert _eval(tmp_path, monkeypatch, _skill_event("stop-slop"), denies).allow is False


def test_qualified_deny_respects_scope(tmp_path, monkeypatch):
    denies = [{"id": "t3", "tool": "Skill:wiki-query", "action": "deny",
               "scope": "agent", "scopeId": "claude"}]
    ev = _skill_event("wiki-query")
    assert _eval(tmp_path, monkeypatch, ev, denies, agent_name="claude").allow is False
    assert _eval(tmp_path, monkeypatch, ev, denies, agent_name="codex").allow is True


def test_capability_registration_reports_the_qualified_skill(tmp_path, monkeypatch):
    """The tags must actually reach record_seen — that call is what the agent
    page's Tool Access panel is built from."""
    from prismor.runtime import agents

    captured = {}
    monkeypatch.setattr(
        agents, "record_seen",
        lambda name, framework, workspace, tools, session_id: captured.update(tools=tools),
    )
    _eval(tmp_path, monkeypatch, _skill_event("wiki-query"), [])

    names = [t["name"] for t in captured.get("tools", [])]
    assert "Skill" in names
    assert "Skill:wiki-query" in names
    assert all(t["source"] == "observed" for t in captured["tools"])


def test_capability_registration_unaffected_for_plain_tools(tmp_path, monkeypatch):
    from prismor.runtime import agents
    from prismor.runtime.hooks import _normalize_claude

    captured = {}
    monkeypatch.setattr(
        agents, "record_seen",
        lambda name, framework, workspace, tools, session_id: captured.update(tools=tools),
    )
    ev = _normalize_claude(
        {"hook_event_name": "PreToolUse", "cwd": "/tmp/ws",
         "tool_name": "Bash", "tool_input": {"command": "ls"}},
        "s1", Path("/tmp/ws"),
    )
    _eval(tmp_path, monkeypatch, ev, [])
    assert [t["name"] for t in captured.get("tools", [])] == ["Bash"]


def test_org_allow_lifts_local_deny_for_one_skill(tmp_path, monkeypatch):
    from prismor.runtime import agents
    monkeypatch.setattr(
        agents, "resolve_agent_control",
        lambda name, ws, remote_controls=None: agents.AgentControl(
            name="claude", framework="claude", enabled=True, mode=None,
            deny_tools=("Skill:wiki-query",)),
    )
    ev = _skill_event("wiki-query")
    assert _eval(tmp_path, monkeypatch, ev, []).allow is False
    allow = [{"id": "a1", "tool": "Skill:wiki-query", "action": "allow", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, ev, allow).allow is True
