"""Regression: adapters must honor ``Decision.allow`` directly, not re-gate on the
app-passed ``mode``.

The runtime already folds mode + the org per-agent control (kill-switch /
forced-enforce) into ``Decision.allow`` (warden/runtime.py:106-107,152-155,214).
A deny that the control plane forces — e.g. an agent kill-switch — comes back as
``allow=False`` even when the app launched in ``observe`` mode. The adapters used
to re-check ``and mode == "enforce"``, which silently let the tool run and
defeated the org's emergency control. This test fails on that old behavior.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _pkg in ("langchain", "crewai"):
    _src = _ROOT / "adapters" / _pkg
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

import prismor.warden.langchain as lc   # noqa: E402
import prismor.warden.crewai as crew    # noqa: E402
from warden.runtime import Decision     # noqa: E402


class _Tool:
    """A structured tool with .name + .func (what both adapters wrap)."""

    def __init__(self, fn):
        self.name = "run_shell"
        self.func = fn


def _force_runtime_deny(monkeypatch, mod):
    # Simulate the org kill-switch: the runtime returns a hard deny regardless of
    # the app-passed mode.
    monkeypatch.setattr(
        mod, "evaluate_tool_call",
        lambda *a, **k: Decision(allow=False, reason="[CRITICAL] agent disabled by org"),
    )


def test_langchain_honors_forced_deny_even_in_observe(monkeypatch, tmp_path):
    _force_runtime_deny(monkeypatch, lc)
    ran = []
    tool = _Tool(lambda command: ran.append(command) or "ok")
    lc.guard_tools([tool], workspace=tmp_path, mode="observe")  # app runs OBSERVE
    out = tool.func(command="anything")
    assert "blocked" in str(out).lower()   # org kill-switch still blocks
    assert ran == []                        # body never executed


def test_crewai_honors_forced_deny_even_in_observe(monkeypatch, tmp_path):
    _force_runtime_deny(monkeypatch, crew)
    ran = []
    tool = _Tool(lambda command: ran.append(command) or "ok")
    crew.guard_tools([tool], workspace=tmp_path, mode="observe")
    out = tool.func(command="anything")
    assert "blocked" in str(out).lower()
    assert ran == []


def test_allow_still_runs(monkeypatch, tmp_path):
    # Sanity: when the runtime allows, the tool runs (we didn't break the allow path).
    monkeypatch.setattr(lc, "evaluate_tool_call", lambda *a, **k: Decision(allow=True))
    ran = []
    tool = _Tool(lambda command: ran.append(command) or "ok")
    lc.guard_tools([tool], workspace=tmp_path, mode="observe")
    assert tool.func(command="echo hi") == "ok"
    assert ran == ["echo hi"]
