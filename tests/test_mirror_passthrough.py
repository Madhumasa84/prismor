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

#: built at import time so this file never contains a literal placeholder,
#: which Prismor's own decloak hook would try to resolve and fail closed on.
PLACEHOLDER = "@@" + "SECRET:" + "DEMO_TOKEN" + "@@"


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


def test_pause_does_not_turn_off_secret_masking(ws, monkeypatch):
    """`prismor pause` suspends ENFORCEMENT, not Cloak.

    Corrects an earlier reading of pause as "stop interfering with everything".
    The hook-layer scrubber never consults the pause marker, so if the mirror
    did, the same command would leak a raw secret into the model's context over
    one transport and not the other — and pausing would quietly become a way to
    exfiltrate. Policy-driven data-boundary redaction does stop; cloak masking
    of registered values does not.
    """
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **k: Decision(allow=True))
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"X": "hello-secret-value"})
    (ws / "f.txt").write_text("token=hello-secret-value\n")
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    text = sent[-1]["result"]["content"][0]["text"]
    assert "hello-secret-value" not in text, "a paused mirror must still mask registered secrets"
    assert "SECRET" in text
    gw.close()


def test_mirrored_bash_decloaks_placeholders(ws, monkeypatch):
    """The cloak hook matches the exact tool name "Bash", so mirroring
    (mcp__prismor-tools__Bash) silently stopped substituting placeholders and
    the literal reached the shell."""
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"DEMO_TOKEN": "s3cr3t-value-1234"})
    out = mirror.execute("Bash", {"command": "echo " + PLACEHOLDER}, ws)
    assert "s3cr3t-value-1234" in out


def test_unregistered_placeholder_fails_closed(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map", lambda: {})
    with pytest.raises(mirror.MirrorError, match="unregistered secret placeholder"):
        mirror.execute("Bash", {"command": "echo " + PLACEHOLDER}, ws)


def test_decloaked_value_never_reaches_policy_or_the_model(ws, monkeypatch):
    """The placeholder form is what gets screened and logged; the real value
    exists only in the subprocess, and the output is masked back."""
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"DEMO_TOKEN": "s3cr3t-value-1234"})
    seen = []

    def _eval(**k):
        seen.append(json.dumps(k["event"]))
        return Decision(allow=True)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", _eval)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Bash",
                                   "arguments": {"command": "echo " + PLACEHOLDER}})
    assert not any("s3cr3t-value-1234" in ev for ev in seen), "policy saw the real secret"
    assert "s3cr3t-value-1234" not in json.dumps(sent[-1]), "the model saw the real secret"
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

    assert mirror_cli.mirror_on(tmp_path, mode="enforce") == 0
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
    assert mirror_cli.mirror_on(tmp_path, mode="enforce") == 0
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
    assert mirror_cli.mirror_on(tmp_path) == 0
    assert mirror.MIRROR_SERVER_NAME in json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"]
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert set(settings["permissions"]["deny"]) == set(mirror.NATIVE_TOOLS_TO_DISABLE)
    assert mirror_cli.mirror_off(tmp_path) == 0
    assert json.loads((tmp_path / ".claude" / "settings.json").read_text()) == {}


def test_mirror_off_when_never_on_is_a_noop(tmp_path, capsys):
    from prismor.runtime import mirror_cli
    assert mirror_cli.mirror_off(tmp_path) == 0
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


def test_relocated_prismor_home_is_pinned_into_the_server_entry(tmp_path, monkeypatch):
    """The host launches the gateway from its own environment. A $PRISMOR_HOME
    that only exists in the developer's shell would leave the gateway reading a
    different home than `prismor pause` writes to."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    assert mirror_cli.mirror_on(tmp_path) == 0
    entry = json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"][mirror.MIRROR_SERVER_NAME]
    assert entry["env"]["PRISMOR_HOME"] == str(tmp_path / "home")


def test_default_prismor_home_is_not_written_into_the_entry(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setenv("PRISMOR_HOME", str(Path.home() / ".prismor"))
    assert mirror_cli.mirror_on(tmp_path) == 0
    entry = json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"][mirror.MIRROR_SERVER_NAME]
    assert "PRISMOR_HOME" not in entry["env"]


def test_on_refuses_to_disable_natives_when_the_server_cannot_start(tmp_path, monkeypatch, capsys):
    """The worst outcome is a half-install: natives denied, mirror broken, agent
    with no tools and no explanation. Preflight has to fail closed."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (False, "boom"))
    assert mirror_cli.mirror_on(tmp_path) == 1
    out = capsys.readouterr().out
    assert "failed to start" in out and "Nothing was changed" in out
    assert not (tmp_path / ".mcp.json").exists()
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_preflight_really_starts_the_server_and_lists_tools(tmp_path, monkeypatch):
    """End-to-end through the actual entry the command writes: spawn it, speak
    MCP, get the roster back."""
    from prismor.runtime import mirror_cli
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    entry = mirror_cli._server_entry(tmp_path, "enforce")
    ok, detail = mirror_cli._preflight(entry, timeout=60.0)
    assert ok, detail
    assert "Bash" in detail and "Read" in detail


# ── host-side approval (the trap that made `on` a no-tools install) ──────────

def test_on_approves_only_this_server_in_local_settings(tmp_path, monkeypatch):
    """A project .mcp.json server does not load until a human approves it, and
    a project file cannot vouch for itself. Verified against Claude Code
    2.1.210: with this key the mirror connects; without it the agent gets no
    tools at all, because the natives are already denied."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash, Read"))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(
        json.dumps({"enabledMcpjsonServers": ["some-other"], "permissions": {"allow": ["WebFetch"]}}))

    assert mirror_cli.mirror_on(tmp_path) == 0
    local = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    assert local["enabledMcpjsonServers"] == ["some-other", "prismor-tools"]
    assert local["permissions"] == {"allow": ["WebFetch"]}, "unrelated local settings must survive"
    # Never the blanket grant: that would auto-trust every server any repo declares.
    assert "enableAllProjectMcpServers" not in local

    assert mirror_cli.mirror_off(tmp_path) == 0
    local = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    assert local["enabledMcpjsonServers"] == ["some-other"]


def test_off_removes_a_local_settings_file_it_created(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    assert mirror_cli.mirror_on(tmp_path) == 0
    assert (tmp_path / ".claude" / "settings.local.json").exists()
    assert mirror_cli.mirror_off(tmp_path) == 0
    assert not (tmp_path / ".claude" / "settings.local.json").exists()


def test_on_respects_an_explicit_human_no(tmp_path, monkeypatch, capsys):
    """If the human disabled this server, `on` must not flip it back — it warns
    instead, so they are not left silently toolless."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(
        json.dumps({"disabledMcpjsonServers": ["prismor-tools"]}))
    assert mirror_cli.mirror_on(tmp_path) == 0
    out = capsys.readouterr().out
    assert "could not auto-approve" in out and "disabledMcpjsonServers" in out
    local = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    assert "enabledMcpjsonServers" not in local


# ── tool permissions (the second reason `on` produced a toolless agent) ──────

def test_existing_allow_posture_is_carried_onto_the_mirrored_names(tmp_path, monkeypatch):
    """Claude Code gates MCP tools behind the same prompt as any other tool, and
    the mirror renames them, so every allow rule for Bash stops applying."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    # User had Bash/Read allowed outright, Glob only for one pattern.
    (home / ".claude" / "settings.json").write_text(json.dumps(
        {"permissions": {"allow": ["Bash", "Read", "Glob(src/**)", "WebFetch"]}}))
    ws = tmp_path / "proj"; ws.mkdir()

    assert mirror_cli.mirror_on(ws) == 0
    # The grant lands in the human's LOCAL settings: a project's shared
    # settings.json may restrict but may not widen its own authority, so an
    # allow rule written there is ignored by the host (verified live).
    local = json.loads((ws / ".claude" / "settings.local.json").read_text())
    allow = local["permissions"]["allow"]
    assert allow == ["mcp__prismor-tools__Bash", "mcp__prismor-tools__Read"]
    shared = json.loads((ws / ".claude" / "settings.json").read_text())
    assert "allow" not in shared.get("permissions", {})
    assert shared["permissions"]["deny"], "the restriction still belongs in the shared file"
    # A pattern-scoped rule has no meaning over MCP, so it is NOT widened.
    assert not any("Glob" in a for a in allow)
    # And nothing is invented for tools the human never allowed.
    assert not any("Write" in a for a in allow)

    assert mirror_cli.mirror_off(ws) == 0
    local = json.loads((ws / ".claude" / "settings.local.json").read_text()) \
        if (ws / ".claude" / "settings.local.json").exists() else {}
    assert "allow" not in local.get("permissions", {})


def test_allow_tools_flag_pre_allows_everything_for_headless(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    ws = tmp_path / "proj"; ws.mkdir()
    assert mirror_cli.mirror_on(ws, allow_tools=True) == 0
    allow = json.loads((ws / ".claude" / "settings.local.json").read_text())["permissions"]["allow"]
    assert sorted(allow) == sorted(f"mcp__prismor-tools__{t}" for t in mirror.mirror_tool_names())


def test_without_prior_allow_the_command_says_headless_will_stall(tmp_path, monkeypatch, capsys):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    ws = tmp_path / "proj"; ws.mkdir()
    assert mirror_cli.mirror_on(ws) == 0
    assert "--allow-tools" in capsys.readouterr().out


def test_no_split_brain_warning_for_one_install_spelled_two_ways(tmp_path, monkeypatch):
    """The hook installer and older builds disagree on whether PYTHONPATH names
    the package or its parent. Both spellings are the SAME install, and a
    warning that fires on every ordinary pipx setup is one nobody reads."""
    from prismor.runtime import mirror_cli
    site = tmp_path / "site-packages"
    (site / "prismor" / "runtime").mkdir(parents=True)
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command",
                    "command": f'PRISMOR_HOME="{home}/.prismor" PYTHONPATH="{site}/prismor" '
                               f'python3 -m prismor.runtime.immunity_cli hook-dispatch --agent claude'}]}]}}))
    # An installed tree can also carry a nested prismor/prismor/runtime; the
    # resolution must not mistake that for a second installation.
    (site / "prismor" / "prismor" / "runtime").mkdir(parents=True)
    entry = {"env": {"PYTHONPATH": str(site), "PRISMOR_HOME": str(home / ".prismor")}}
    assert mirror_cli._coherence_warnings(tmp_path, entry) == []

    # A genuinely different checkout still warns.
    other = tmp_path / "other"; (other / "prismor" / "runtime").mkdir(parents=True)
    entry["env"]["PYTHONPATH"] = str(other)
    warns = mirror_cli._coherence_warnings(tmp_path, entry)
    assert warns and "install-hooks" in warns[0]
