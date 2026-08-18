"""Session scope must judge a mirrored built-in as the built-in it is.

When the built-ins are served through the MCP gateway, the same call reaches
the host's hook layer tagged ``mcp__<server>__Bash`` and the gateway tagged
``Bash``. Without aliasing, a scope that has never heard of that server denies
the first while the gateway allows the second: one call, two verdicts.
"""
import pytest

from prismor.runtime.scoped_agent import (
    BUILTIN_SCOPE_TOOLS,
    check_scoped_rules,
    native_alias,
    _static_fallback_rules,
)


def _ev(tool, type_="shell", **kw):
    return {"type": type_, "metadata": {"tool_name": tool}, **kw}


# ── alias resolution ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("tag,expected", [
    ("mcp__prismor__Bash", "Bash"),
    ("mcp__builtins__Read", "Read"),
    ("mcp__any_server__Grep", "Grep"),
    ("mcp__prismor__WebFetch", "WebFetch"),
])
def test_mirrored_tags_resolve_to_their_builtin(tag, expected):
    assert native_alias(tag) == expected


@pytest.mark.parametrize("tag", [
    "Bash",                       # already native
    "mcp__posthog__exec",         # ordinary MCP tool
    "mcp__github__create_issue",
])
def test_non_mirrored_tags_have_no_alias(tag):
    assert native_alias(tag) is None


# ── the regression this fixes ────────────────────────────────────────────────

def test_allowlist_naming_bash_covers_mirrored_bash():
    """The scope the synthesiser writes names built-ins, never
    mcp__<server>__Bash — so without aliasing every mirrored call is denied by
    omission the moment the scope has any MCP opinion at all."""
    rules = {"allowed_tools": ["Bash", "Read", "Edit", "Write", "mcp__other__*"],
             "deny_tools": [], "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__prismor__Bash")) is None
    assert check_scoped_rules(rules, _ev("mcp__prismor__Read", "file_read",
                                         path="/x/y.py")) is None


def test_denylist_naming_bash_still_blocks_mirrored_bash():
    """Aliasing must not become a bypass: moving Bash onto MCP cannot escape a
    deny written against Bash."""
    rules = {"allowed_tools": ["*"], "deny_tools": ["Bash"], "allowed_paths": ["**"]}
    finding = check_scoped_rules(rules, _ev("mcp__prismor__Bash"))
    assert finding is not None


def test_server_specific_deny_still_targets_one_copy():
    """An operator can still deny one server's mirrored tool without denying
    the native one."""
    rules = {"allowed_tools": ["Bash"], "deny_tools": ["mcp__prismor__Bash"],
             "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__prismor__Bash")) is not None
    assert check_scoped_rules(rules, _ev("Bash")) is None


def test_ordinary_mcp_tools_are_unaffected():
    rules = {"allowed_tools": ["Bash", "mcp__other__*"], "deny_tools": [],
             "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__posthog__exec")) is not None


# ── Glob/Grep are scopeable ──────────────────────────────────────────────────

def test_glob_and_grep_are_scope_tags():
    """Absent from this list they are denied by omission by every scope."""
    assert "Glob" in BUILTIN_SCOPE_TOOLS and "Grep" in BUILTIN_SCOPE_TOOLS


def test_static_fallback_allows_read_only_discovery():
    rules = _static_fallback_rules("summarize the readme", BUILTIN_SCOPE_TOOLS)
    for tool in ("Read", "Bash", "Glob", "Grep"):
        assert tool in rules["allowed_tools"], tool
    assert "Write" in rules["deny_tools"]
