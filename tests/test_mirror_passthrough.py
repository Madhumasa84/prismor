"""The two runtime exits from a governing mirror — `prismor pause` and the
override (pass-through) switch — and the config exit, `prismor mirror on/off`.

Background: the first live deployment blocked the human's own work and neither
`prismor pause` (gateway ignored it) nor the dashboard switch (turned the mirror
into "unknown tool" for every call) got them out. These pin the fixed behaviour.
"""
import json
from pathlib import Path

import pytest

from prismor.runtime import mirror
from prismor.runtime.mcp_gateway import Gateway, UpstreamSpec
from prismor.runtime.runtime import Decision


@pytest.fixture()
def ws(tmp_path):
    (tmp_path / "f.txt").write_text("hello\n")
    return tmp_path


def _gateway(ws, mode="enforce"):
    gw = Gateway([UpstreamSpec(name="builtins", local=True)], workspace=ws, mode=mode)
    sent = []
    gw._send = lambda msg: sent.append(msg)
    gw._handle_tools_list(1, {})
    return gw, sent


_BLOCK = Decision(allow=False, blocking={"severity": "critical", "title": "rm -rf",
                                          "ruleId": "destructive-command"})


def test_enforce_blocks_and_tells_the_human_how_out(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    res = sent[-1]["result"]
    assert res["isError"] is True
    text = res["content"][0]["text"]
    assert "Blocked by Prismor" in text and "destructive-command" in text
    # The gateway used to stop at the block; now it says how to lift it.
    assert "prismor pause" in text and "prismor mirror off" in text
    gw.close()


def test_pause_passes_the_call_through(ws, monkeypatch):
    """`prismor pause` must mean the same thing to the gateway as to the hooks:
    enforcement off, screening on."""
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None, "source": "local"})
    calls = []

    def _eval(**k):
        calls.append(k["event"]["agent_event"])
        return _BLOCK
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", _eval)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    res = sent[-1]["result"]
    assert not res.get("isError")
    assert "hello" in res["content"][0]["text"]
    # Still evaluated pre AND post — pass-through is observe, not blindness.
    assert calls == ["PreToolUse", "PostToolUse"]
    gw.close()


def test_pause_skips_redaction_too(ws, monkeypatch):
    """Paused = Prismor stops interfering. A redacted read is interference."""
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **k: Decision(allow=True))
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"X": "hello"})
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert "hello" in sent[-1]["result"]["content"][0]["text"]
    gw.close()


def test_override_off_passes_through_but_keeps_serving(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    mirror.set_mirror_config(ws, override=False)
    gw, sent = _gateway(ws)
    names = [t["name"] for t in sent[0]["result"]["tools"]]
    assert "Read" in names, "pass-through must not un-list the tools"
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert "hello" in sent[-1]["result"]["content"][0]["text"]
    gw.close()


def test_switching_back_to_governing_takes_effect_on_the_next_call(ws, monkeypatch):
    """No restart: the switch is read per call."""
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    mirror.set_mirror_config(ws, override=False)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert not sent[-1]["result"].get("isError")
    mirror.set_mirror_config(ws, override=True)
    gw._handle_tools_call_safe(3, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert sent[-1]["result"]["isError"] is True
    gw.close()


def test_pause_applies_to_remote_upstreams_as_well(tmp_path, monkeypatch):
    """A remote MCP tool call is a hooked call by another transport; a pause
    the hooks honour and the gateway ignores is a lie to the person who ran it."""
    from tests.test_mcp_gateway import stub, make_gateway, list_tools
    a = stub("github")
    gateway, sent = make_gateway(tmp_path, monkeypatch, [a])
    list_tools(gateway, sent)
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    gateway._handle_tools_call_safe("C2", {"name": "github__echo", "arguments": {}})
    assert not sent[-1]["result"].get("isError")
    assert any(m == "tools/call" for m, _ in a.requests)


# ── prismor mirror on / off ──────────────────────────────────────────────────

def test_mirror_on_then_off_round_trips_claude_config(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"prismor": {"type": "http", "url": "https://mcp.example/x"}}}))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": []}, "permissions": {"deny": ["WebSearch"], "allow": ["Bash(ls:*)"]}}))

    assert mirror_cli.mirror_on(tmp_path, mode="enforce", scope="project") == 0
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    entry = mcp["mcpServers"][mirror.MIRROR_SERVER_NAME]
    assert "--mirror" in entry["args"] and "--workspace" in entry["args"]
    assert "prismor" in mcp["mcpServers"], "the hosted connector must survive"
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    deny = settings["permissions"]["deny"]
    assert "WebSearch" in deny and all(t in deny for t in mirror.NATIVE_TOOLS_TO_DISABLE)
    assert "MultiEdit" in deny, "an ungoverned native writer would bypass the mirror"
    assert settings["permissions"]["allow"] == ["Bash(ls:*)"]
    assert settings["hooks"] == {"PreToolUse": []}
    assert (tmp_path / ".mcp.json.pre-mirror.bak").exists()
    assert mirror.mirror_config(tmp_path)["override"] is True

    # A second `on` is idempotent (no duplicate deny entries).
    assert mirror_cli.mirror_on(tmp_path, mode="enforce", scope="project") == 0
    deny = json.loads((tmp_path / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    assert len(deny) == len(set(deny))

    assert mirror_cli.mirror_off(tmp_path) == 0
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    assert mirror.MIRROR_SERVER_NAME not in mcp["mcpServers"] and "prismor" in mcp["mcpServers"]
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    # Only OUR entries went; the pre-existing deny and everything else stayed.
    assert settings["permissions"] == {"deny": ["WebSearch"], "allow": ["Bash(ls:*)"]}
    assert settings["hooks"] == {"PreToolUse": []}
    data = json.loads((tmp_path / ".prismor" / "mirror.json").read_text())
    assert "install" not in data


def test_mirror_on_creates_missing_files(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    assert mirror_cli.mirror_on(tmp_path, scope="project") == 0
    assert mirror.MIRROR_SERVER_NAME in json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"]
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert set(settings["permissions"]["deny"]) == set(mirror.NATIVE_TOOLS_TO_DISABLE)
    assert mirror_cli.mirror_off(tmp_path) == 0
    assert json.loads((tmp_path / ".claude" / "settings.json").read_text()) == {}


def test_mirror_off_when_never_on_is_a_noop(tmp_path, capsys):
    from prismor.runtime import mirror_cli
    assert mirror_cli.mirror_off(tmp_path, scope="project") == 0
    assert "nothing to undo" in capsys.readouterr().out
    assert not (tmp_path / ".prismor" / "mirror.json").exists()


def test_mirror_status_names_the_state(tmp_path, monkeypatch, capsys):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    mirror_cli.mirror_status(tmp_path)
    out = capsys.readouterr().out
    assert "not configured" in out and "governing" in out
    mirror.set_mirror_config(tmp_path, override=False)
    mirror_cli.mirror_status(tmp_path)
    assert "PASS-THROUGH" in capsys.readouterr().out
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    mirror_cli.mirror_status(tmp_path)
    assert "PAUSED" in capsys.readouterr().out
