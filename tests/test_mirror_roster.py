"""Mirror roster (per-tool on/off) and the override switch.

Two front-of-house controls, separate from allow/ask/deny: which built-ins the
mirror exposes, and whether it replaces the host's native toolkit at all.
"""
from pathlib import Path

import pytest

from prismor.runtime import mirror


def test_default_is_override_on_all_enabled(tmp_path):
    cfg = mirror.mirror_config(tmp_path)
    assert cfg["override"] is True and cfg["disabled_tools"] == []
    assert set(mirror.enabled_tool_names(tmp_path)) == set(mirror.mirror_tool_names())


def test_disabling_a_tool_hides_it_from_the_list(tmp_path):
    mirror.set_mirror_config(tmp_path, tool="Write", enabled=False)
    names = [t["name"] for t in mirror.mirror_tool_definitions(tmp_path)]
    assert "Write" not in names and "Bash" in names


def test_disabled_tool_refuses_to_execute(tmp_path):
    (tmp_path / "f.txt").write_text("hi")
    mirror.set_mirror_config(tmp_path, tool="Read", enabled=False)
    with pytest.raises(mirror.MirrorError, match="not enabled"):
        mirror.execute("Read", {"file_path": str(tmp_path / "f.txt")}, tmp_path)


def test_re_enabling_restores_the_tool(tmp_path):
    mirror.set_mirror_config(tmp_path, tool="Grep", enabled=False)
    assert "Grep" not in mirror.enabled_tool_names(tmp_path)
    mirror.set_mirror_config(tmp_path, tool="Grep", enabled=True)
    assert "Grep" in mirror.enabled_tool_names(tmp_path)


def test_override_off_still_serves_the_roster(tmp_path):
    """Override-off is pass-through, not silence. The host's natives were
    denied by `prismor mirror on`; a mirror that stopped advertising its tools
    would leave the agent with no Bash/Read at all mid-session."""
    mirror.set_mirror_config(tmp_path, override=False)
    assert set(mirror.enabled_tool_names(tmp_path)) == set(mirror.mirror_tool_names())
    assert len(mirror.mirror_tool_definitions(tmp_path)) == len(mirror.mirror_tool_names())


def test_override_off_still_executes(tmp_path):
    (tmp_path / "f.txt").write_text("hi")
    mirror.set_mirror_config(tmp_path, override=False)
    assert "hi" in mirror.execute("Read", {"file_path": str(tmp_path / "f.txt")}, tmp_path)


def test_override_off_reports_passthrough(tmp_path, monkeypatch):
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    assert mirror.passthrough_state(tmp_path) is None
    mirror.set_mirror_config(tmp_path, override=False)
    assert mirror.passthrough_state(tmp_path) == {"source": "override"}


def test_pause_outranks_override(tmp_path, monkeypatch):
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    st = mirror.passthrough_state(tmp_path)
    assert st and st["source"] == "pause"
    # ...and applies with no workspace at all (remote upstreams honour it too).
    assert mirror.passthrough_state(None)["source"] == "pause"


def test_set_config_preserves_install_record(tmp_path):
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "mirror.json").write_text(
        '{"override": true, "disabled_tools": [], "install": {"scope": "project"}}')
    mirror.set_mirror_config(tmp_path, tool="Write", enabled=False)
    import json
    data = json.loads((tmp_path / ".prismor" / "mirror.json").read_text())
    assert data["install"] == {"scope": "project"}
    assert data["disabled_tools"] == ["Write"]


def test_override_and_roster_are_independent(tmp_path):
    mirror.set_mirror_config(tmp_path, tool="Write", enabled=False)
    mirror.set_mirror_config(tmp_path, override=True)
    # Roster survives an override toggle.
    assert "Write" not in mirror.enabled_tool_names(tmp_path)
    assert "Bash" in mirror.enabled_tool_names(tmp_path)


def test_unknown_tool_rejected(tmp_path):
    with pytest.raises(mirror.MirrorError):
        mirror.set_mirror_config(tmp_path, tool="Nope", enabled=False)


def test_malformed_config_falls_back_to_default(tmp_path):
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "mirror.json").write_text("{ not json")
    cfg = mirror.mirror_config(tmp_path)
    assert cfg["override"] is True and cfg["disabled_tools"] == []


def test_no_workspace_returns_full_set():
    # Back-compat: callers without a workspace get every tool.
    assert len(mirror.mirror_tool_definitions()) == len(mirror.mirror_tool_names())
