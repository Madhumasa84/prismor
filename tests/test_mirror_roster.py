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


def test_override_off_serves_nothing(tmp_path):
    mirror.set_mirror_config(tmp_path, override=False)
    assert mirror.enabled_tool_names(tmp_path) == []
    assert mirror.mirror_tool_definitions(tmp_path) == []


def test_override_off_refuses_execution(tmp_path):
    (tmp_path / "f.txt").write_text("hi")
    mirror.set_mirror_config(tmp_path, override=False)
    with pytest.raises(mirror.MirrorError):
        mirror.execute("Read", {"file_path": str(tmp_path / "f.txt")}, tmp_path)


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
