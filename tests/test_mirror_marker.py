"""The active-mirror marker that stops mirrored calls being screened twice."""
import json
import os

import pytest

from prismor.runtime import mirror


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    yield


@pytest.fixture()
def ws(tmp_path):
    d = tmp_path / "ws"
    d.mkdir()
    return d


def test_no_marker_means_nothing_is_skipped(ws):
    assert mirror.active_tools(ws) == []
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False


def test_marker_makes_mirrored_tools_recognised(ws):
    mirror.mark_active(ws)
    assert set(mirror.active_tools(ws)) == set(mirror.mirror_tool_names())
    assert mirror.already_screened("mcp__prismor__Bash", ws) is True
    assert mirror.already_screened("mcp__anything__Read", ws) is True


def test_native_and_unrelated_mcp_tools_are_never_skipped(ws):
    mirror.mark_active(ws)
    assert mirror.already_screened("Bash", ws) is False          # native: hooks own it
    assert mirror.already_screened("mcp__posthog__exec", ws) is False
    assert mirror.already_screened("", ws) is False


def test_marker_is_per_workspace(ws, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    mirror.mark_active(ws)
    assert mirror.already_screened("mcp__prismor__Bash", other) is False


def test_clearing_restores_screening(ws):
    mirror.mark_active(ws)
    mirror.clear_active(ws)
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False


def test_stale_marker_from_a_dead_gateway_is_ignored_and_removed(ws):
    """A crashed gateway must not leave behind a rule that silently
    un-screens real tool calls."""
    mirror.mark_active(ws)
    path = mirror._marker_path(ws)
    data = json.loads(path.read_text())
    data["pid"] = 2 ** 22           # not a live pid
    path.write_text(json.dumps(data))
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False
    assert not path.exists(), "stale marker should be cleaned up"


def test_corrupt_marker_fails_towards_screening(ws):
    mirror.mark_active(ws)
    mirror._marker_path(ws).write_text("{not json")
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False


def test_marker_records_the_live_pid(ws):
    mirror.mark_active(ws)
    assert json.loads(mirror._marker_path(ws).read_text())["pid"] == os.getpid()
