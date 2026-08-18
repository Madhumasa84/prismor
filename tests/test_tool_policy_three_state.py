"""Three-state per-tool policy: Allow / Ask (step_up) / Deny.

The console grid binds a tool to one of three handlings for an agent. Deny and
Ask must be mutually exclusive per tool (deny wins), and Ask must surface as a
step_up finding the gateway can route to approval — not a hard block.
"""
from pathlib import Path

import pytest

from prismor.runtime import agents
from prismor.runtime.runtime import evaluate_tool_call


def _verdict(ws, agent_name, tool, ev_type, **extra):
    ev = {"type": ev_type, "session_id": "s1", "agent": "mcp-gateway",
          "agent_event": "PreToolUse",
          "metadata": {"cwd": str(ws), "tool_name": tool}, **extra}
    d = evaluate_tool_call(event=ev, workspace=ws, agent="mcp-gateway",
                           mode="observe", session_id="s1", agent_name=agent_name)
    b = getattr(d, "blocking", None)
    if not b:
        return "allow"
    return str(b.get("action") or "block")


# ── set_tool_policy: the writer ──────────────────────────────────────────────

def test_three_actions_are_mutually_exclusive(tmp_path):
    r = agents.set_tool_policy(tmp_path, "agent", "Bash", "ask", agent="cc")
    assert r == {"deny_tools": [], "ask_tools": ["Bash"]}
    r = agents.set_tool_policy(tmp_path, "agent", "Bash", "deny", agent="cc")
    assert r == {"deny_tools": ["Bash"], "ask_tools": []}   # ask cleared
    r = agents.set_tool_policy(tmp_path, "agent", "Bash", "allow", agent="cc")
    assert r == {"deny_tools": [], "ask_tools": []}          # both cleared


def test_invalid_action_rejected(tmp_path):
    with pytest.raises(ValueError):
        agents.set_tool_policy(tmp_path, "agent", "Bash", "maybe", agent="cc")


def test_global_ask_scope(tmp_path):
    agents.set_tool_policy(tmp_path, "global", "Write", "ask")
    ctrl = agents.resolve_agent_control("anyone", tmp_path)
    assert "Write" in ctrl.ask_tools


# ── resolve_agent_control: deny wins over ask ────────────────────────────────

def test_deny_wins_when_a_tool_is_both(tmp_path):
    # Global ask + per-agent deny on the same tool → denied, not asked.
    agents.set_tool_policy(tmp_path, "global", "Bash", "ask")
    agents.set_tool_policy(tmp_path, "agent", "Bash", "deny", agent="cc")
    ctrl = agents.resolve_agent_control("cc", tmp_path)
    assert "Bash" in ctrl.deny_tools
    assert "Bash" not in ctrl.ask_tools


# ── enforcement: the three verdicts ──────────────────────────────────────────

def test_ask_produces_step_up_not_block(tmp_path):
    agents.set_tool_policy(tmp_path, "agent", "Bash", "ask", agent="cc")
    assert _verdict(tmp_path, "cc", "Bash", "shell", command="ls") == "step_up"


def test_deny_produces_block(tmp_path):
    agents.set_tool_policy(tmp_path, "agent", "Write", "deny", agent="cc")
    assert _verdict(tmp_path, "cc", "Write", "file_write",
                    path=str(tmp_path / "x"), content="y") == "block"


def test_allow_passes(tmp_path):
    agents.set_tool_policy(tmp_path, "agent", "Bash", "ask", agent="cc")
    # A different tool with no policy is untouched.
    assert _verdict(tmp_path, "cc", "Read", "file_read",
                    path=str(tmp_path / "x")) == "allow"


def test_denied_tool_never_also_asks(tmp_path):
    """A tool set to deny must block, never emit a redundant step_up, even if it
    somehow appears on both lists."""
    agents.set_tool_policy(tmp_path, "global", "Bash", "ask")
    agents.set_tool_policy(tmp_path, "agent", "Bash", "deny", agent="cc")
    assert _verdict(tmp_path, "cc", "Bash", "shell", command="ls") == "block"
