"""Unit tests for the LangChain and CrewAI adapters (no live LLM).

Drives the adapters with fake tool objects that mimic each framework's shape
(a structured tool with ``.func``; a CrewAI BaseTool-style object with ``._run``)
against the real Prismor policy pipeline.
"""
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _pkg in ("langchain", "crewai"):
    _src = _ROOT / "adapters" / _pkg
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

from prismor.langchain import (  # noqa: E402
    PrismorBlocked as LCBlocked,
    guard_tools as lc_guard,
    prismor_guard_tool as lc_guard_one,
)
from prismor.crewai import (  # noqa: E402
    guard_tools as crew_guard,
    prismor_guard_tool as crew_guard_one,
)


class FakeStructuredTool:
    """Mimics a LangChain @tool / CrewAI @tool structured tool (.name + .func)."""

    def __init__(self, fn):
        self.name = "run_shell"
        self.func = fn


class FakeBaseTool:
    """Mimics a CrewAI BaseTool subclass exposing ._run."""

    def __init__(self, ran):
        self.name = "run_shell"
        self._ran = ran

    def _run(self, command: str) -> str:
        self._ran.append(command)
        return f"ran: {command}"


# ── LangChain ───────────────────────────────────────────────────────────────

def test_langchain_safe_runs(tmp_path):
    ran = []
    tool = FakeStructuredTool(lambda command: ran.append(command) or "ok")
    lc_guard([tool], workspace=tmp_path, mode="enforce")
    assert tool.func(command="echo hi") == "ok"
    assert ran == ["echo hi"]


def test_langchain_enforce_blocks(tmp_path):
    ran = []
    tool = FakeStructuredTool(lambda command: ran.append(command) or "ok")
    lc_guard([tool], workspace=tmp_path, mode="enforce")
    out = tool.func(command="rm -rf /")
    assert "blocked" in out.lower()
    assert ran == []  # body never executed


def test_langchain_raise_on_block(tmp_path):
    tool = FakeStructuredTool(lambda command: "ok")
    lc_guard_one(tool, workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(LCBlocked):
        tool.func(command="rm -rf /")


def test_langchain_observe_never_blocks(tmp_path):
    ran = []
    tool = FakeStructuredTool(lambda command: ran.append(command) or "ok")
    lc_guard([tool], workspace=tmp_path, mode="observe")
    assert tool.func(command="rm -rf /") == "ok"
    assert ran == ["rm -rf /"]


# ── CrewAI ────────────────────────────────────────────────────────────────

def test_crewai_func_tool_blocks(tmp_path):
    ran = []
    tool = FakeStructuredTool(lambda command: ran.append(command) or "ok")
    crew_guard([tool], workspace=tmp_path, mode="enforce")
    assert tool.func(command="echo hi") == "ok"
    assert "blocked" in tool.func(command="rm -rf /").lower()
    assert ran == ["echo hi"]


def test_crewai_basetool_run_blocks(tmp_path):
    ran = []
    tool = FakeBaseTool(ran)
    crew_guard_one(tool, workspace=tmp_path, mode="enforce")
    assert tool._run(command="echo hi") == "ran: echo hi"
    assert "blocked" in tool._run(command="rm -rf /").lower()
    assert ran == ["echo hi"]


def test_crewai_per_user_iam(tmp_path):
    iam = tmp_path / ".prismor"
    iam.mkdir(parents=True, exist_ok=True)
    (iam / "iam.yaml").write_text(
        "agents:\n  user:bob:\n    allowed_tools: [Read]\n    deny_tools: [Bash]\n"
        "    deny_network: true\n    allowed_paths: ['**']\n",
        encoding="utf-8",
    )
    # bob is denied Bash → even a safe shell call is blocked.
    bob_tool = FakeStructuredTool(lambda command: "ok")
    crew_guard([bob_tool], workspace=tmp_path, mode="enforce", subject="user:bob")
    assert "blocked" in bob_tool.func(command="echo hi").lower()

    # alice has no profile → allowed.
    alice_tool = FakeStructuredTool(lambda command: "ok")
    crew_guard([alice_tool], workspace=tmp_path, mode="enforce", subject="user:alice")
    assert alice_tool.func(command="echo hi") == "ok"
