"""Tests for the CrewAI adapter (adapters/crewai).

Had zero test coverage at all before PrismorSec/prismor#138. Exercises real
crewai.tools.tool/BaseTool objects (both documented tool shapes) against the
real Prismor policy pipeline, no live LLM. Requires crewai (Python <3.14 at
the time of writing) — skipped when unavailable.
"""
import sys
from pathlib import Path

import pytest

pytest.importorskip("crewai")

_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "crewai"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from crewai.tools import BaseTool, tool  # noqa: E402

from prismor.crewai import PrismorBlocked, guard_tools, prismor_guard_tool  # noqa: E402


def _make_structured_tool():
    @tool("Shell runner")
    def run_shell(command: str) -> str:
        """Run a shell command."""
        return f"ran: {command}"

    return run_shell


class _ShellBaseTool(BaseTool):
    name: str = "Shell runner"
    description: str = "Runs a shell command"

    def _run(self, command: str) -> str:
        return f"ran: {command}"


def test_structured_tool_safe_call_runs(tmp_path):
    run_shell = _make_structured_tool()
    guarded = prismor_guard_tool(run_shell, workspace=tmp_path, raise_on_block=True)
    assert guarded.run(command="echo hi") == "ran: echo hi"


def test_structured_tool_blocks_destructive(tmp_path):
    run_shell = _make_structured_tool()
    guarded = prismor_guard_tool(run_shell, workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(PrismorBlocked):
        guarded.run(command="rm -rf /")


def test_base_tool_subclass_blocks_destructive(tmp_path):
    guarded = prismor_guard_tool(_ShellBaseTool(), workspace=tmp_path, mode="enforce", raise_on_block=True)
    assert guarded.run(command="echo hi") == "ran: echo hi"
    with pytest.raises(PrismorBlocked):
        guarded.run(command="rm -rf /")


def test_guard_tools_batch(tmp_path):
    run_shell = _make_structured_tool()
    guarded = guard_tools([run_shell], workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(PrismorBlocked):
        guarded[0].run(command="rm -rf /")


def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_use_subject_per_user_iam(tmp_path, monkeypatch):
    from prismor.crewai import use_subject

    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    run_shell = _make_structured_tool()
    guarded = guard_tools([run_shell], workspace=tmp_path, mode="enforce", raise_on_block=True)

    with use_subject("user:alice"):
        assert guarded[0].run(command="ls -la") == "ran: ls -la"

    with use_subject("user:bob"), pytest.raises(PrismorBlocked):
        guarded[0].run(command="ls -la")
