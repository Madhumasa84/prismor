"""Wildcard ("*") allow-all-except-denied semantics for session scoped rules.

The dashboard's Tool Call panel writes ``allowed_tools: ["*"]`` when an operator
denies a single tool for a session that had no prior allowlist, so the deny
does not silently become an allowlist that blocks every other tool.
"""
from __future__ import annotations

from prismor.runtime.scoped_agent import check_scoped_rules


def _ev(tag: str, etype: str = "shell"):
    return {"type": etype, "metadata": {"tool_name": tag}}


def test_wildcard_blocks_only_denied():
    rules = {"allowed_tools": ["*"], "deny_tools": ["Bash"], "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("Bash")) is not None          # denied → blocked
    assert check_scoped_rules(rules, _ev("Read", "file_read")) is None  # else allowed
    assert check_scoped_rules(rules, _ev("mcp__node_repl__js")) is None  # arbitrary MCP tag allowed


def test_wildcard_write_family_allowed_except_denied():
    rules = {"allowed_tools": ["*"], "deny_tools": ["Write"], "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("Write", "file_write")) is not None
    assert check_scoped_rules(rules, _ev("Edit", "file_write")) is None


def test_real_allowlist_still_restrictive():
    # Without the wildcard, an allowlist keeps its deny-by-default behavior.
    rules = {"allowed_tools": ["Read"], "deny_tools": [], "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("Bash")) is not None
    assert check_scoped_rules(rules, _ev("Read", "file_read")) is None
