"""Tests for the OpenAI Agents SDK adapter (adapters/openai-agents).

Exercises the adapter end to end against the real Warden policy pipeline with no
live LLM: allow / observe / enforce, and per-user IAM scoping. The adapter wraps
a plain callable, so we drive it by calling the wrapped function directly.
"""
import sys
from pathlib import Path

import pytest

# The adapter ships as a separate distribution under adapters/; make it
# importable for the in-repo test without an editable install.
_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "openai-agents"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from prismor_warden_openai import WardenBlocked, warden_guard  # noqa: E402


def _make_tool():
    """A tool that records whether it actually ran."""
    calls = {"ran": 0, "last": None}

    def run_shell(command: str) -> str:
        calls["ran"] += 1
        calls["last"] = command
        return f"ran: {command}"

    return run_shell, calls


def test_safe_call_runs(tmp_path):
    tool, calls = _make_tool()
    guarded = warden_guard(tool, workspace=tmp_path, mode="enforce")
    assert guarded(command="echo hello") == "ran: echo hello"
    assert calls["ran"] == 1


def test_enforce_blocks_destructive(tmp_path):
    tool, calls = _make_tool()
    guarded = warden_guard(tool, workspace=tmp_path, mode="enforce")
    with pytest.raises(WardenBlocked) as exc:
        guarded(command="rm -rf /")
    # Tool must NOT have executed.
    assert calls["ran"] == 0
    assert exc.value.decision is not None
    assert exc.value.decision.blocking is not None


def test_observe_never_blocks_but_records(tmp_path):
    tool, calls = _make_tool()
    guarded = warden_guard(tool, workspace=tmp_path, mode="observe")
    # Same dangerous input, but observe mode is log-only: the call proceeds.
    assert guarded(command="rm -rf /") == "ran: rm -rf /"
    assert calls["ran"] == 1


def test_no_raise_returns_decision(tmp_path):
    tool, calls = _make_tool()
    guarded = warden_guard(tool, workspace=tmp_path, mode="enforce", raise_on_block=False)
    decision = guarded(command="rm -rf /")
    assert decision.allow is False
    assert decision.blocking is not None
    assert calls["ran"] == 0


def test_subject_tagged_on_findings(tmp_path):
    tool, _ = _make_tool()
    guarded = warden_guard(
        tool, workspace=tmp_path, mode="enforce", subject="user:alice", raise_on_block=False
    )
    decision = guarded(command="rm -rf /")
    assert decision.subject is not None
    assert decision.subject.user_id == "alice"
    assert decision.blocking.get("subject", {}).get("user_id") == "alice"


def test_per_request_subject_context(tmp_path):
    # Guard with NO bound subject (the multi-tenant pattern): the per-request
    # context decides who the call is attributed to.
    from warden.principal import use_subject

    tool, _ = _make_tool()
    guarded = warden_guard(tool, workspace=tmp_path, mode="enforce", raise_on_block=False)

    with use_subject("user:dave"):
        decision = guarded(command="rm -rf /")
    assert decision.subject.user_id == "dave"
    assert decision.blocking.get("subject", {}).get("user_id") == "dave"

    with use_subject("user=erin;team=sre"):
        decision2 = guarded(command="rm -rf /")
    assert decision2.subject.user_id == "erin"
    assert decision2.subject.team_id == "sre"


def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor-warden"
    iam_dir.mkdir(parents=True, exist_ok=True)
    # bob is denied shell tools (Bash); other users have no profile → unrestricted.
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_per_user_iam_scoping(tmp_path, monkeypatch):
    # Ensure no ambient named-agent identity overrides subject-based selection.
    monkeypatch.delenv("WARDEN_AGENT_ID", raising=False)
    _write_iam(tmp_path)

    tool, calls = _make_tool()

    # bob: has a deny-Bash IAM profile → a safe shell call is still blocked.
    bob = warden_guard(tool, workspace=tmp_path, mode="enforce", subject="user:bob")
    with pytest.raises(WardenBlocked):
        bob(command="echo hi")
    assert calls["ran"] == 0

    # alice: no IAM profile → same safe call is allowed.
    alice = warden_guard(tool, workspace=tmp_path, mode="enforce", subject="user:alice")
    assert alice(command="echo hi") == "ran: echo hi"
    assert calls["ran"] == 1
