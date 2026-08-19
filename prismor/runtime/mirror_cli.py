"""`prismor mirror` — turn the mirrored built-ins on and off, and see what
state they are in.

Subcommands:
    on  [--mode enforce|observe] [--scope project|user]
        Register the mirror as an MCP server for Claude Code and disable the
        native tools it replaces (Bash/Read/Write/Edit/Glob/Grep, plus the other
        file-writers MultiEdit/NotebookEdit). Takes effect on the next session.
    off [--scope project|user]
        Undo exactly what `on` did: remove the server entry, remove the deny
        entries it added (nothing else in the file is touched), and hand the
        built-ins back to the agent. Takes effect on the next session.
    status
        Where the mirror is configured, whether it is governing, passing
        through or paused, its tool roster, and any live gateway processes.
    passthrough on|off
        Runtime switch (no restart): `on` makes the mirror execute its tools
        exactly as the natives would — no blocks, no redaction — while still
        logging. Same switch as the dashboard's mirror card. Prefer
        `prismor pause` for "stop interfering for a while": it covers hooks and
        the gateway together and auto-resumes.

Why a dedicated command
-----------------------
The first live deployment of the mirror was wired by hand: a deny-list added
to `.claude/settings.json`, a server added to `.mcp.json`, and the same again
in Claude Desktop. When the mirror then blocked something the human wanted, the
only ways out were `prismor pause` (which the gateway did not honour at the
time) or editing those files back — from inside a session whose own tool calls
were being screened by the very rules that forbid editing them. The escape
hatch has to be a command the human runs from their own terminal, and it has
to know precisely what to undo. That is this module.

Everything here rewrites config files the developer owns, so the rules are:
never touch a key we did not add, back up before the first write, refuse
rather than guess on an unrecognised shape.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime import mirror

# ── output helpers (match cli.py's ANSI style, no deps) ──────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[37m"
_RED = "\033[0;31m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{_RESET}"


# ── where things live ────────────────────────────────────────────────────────

def _claude_paths(workspace: Path, scope: str) -> Tuple[Path, Path, str]:
    """(mcp config path, settings path, top-level key holding the server block)
    for a Claude Code scope. Project scope is `.mcp.json` + `.claude/settings.json`
    in the workspace; user scope is `~/.claude.json` (where `claude mcp add
    --scope user` writes) + `~/.claude/settings.json`."""
    if scope == "user":
        home = Path.home()
        return home / ".claude.json", home / ".claude" / "settings.json", "mcpServers"
    return workspace / ".mcp.json", workspace / ".claude" / "settings.json", "mcpServers"


def _record_path(workspace: Path, scope: str) -> Path:
    """The install record: project scope shares `.prismor/mirror.json` with
    the roster/override config; user scope lives in the Prismor home."""
    if scope == "user":
        from prismor.runtime.pause import prismor_home
        return prismor_home() / "mirror-install.json"
    return workspace / ".prismor" / "mirror.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")
    return data


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _backup_once(path: Path) -> Optional[Path]:
    """Keep the pre-mirror original alongside, once. A second `on` must not
    overwrite the backup with an already-modified file."""
    if not path.exists():
        return None
    bak = Path(str(path) + ".pre-mirror.bak")
    if not bak.exists():
        bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return bak


def _read_record(workspace: Path, scope: str) -> Optional[Dict[str, Any]]:
    try:
        data = _load_json(_record_path(workspace, scope))
    except Exception:
        return None
    rec = data.get("install")
    return rec if isinstance(rec, dict) else None


def _write_record(workspace: Path, scope: str, rec: Optional[Dict[str, Any]]) -> None:
    path = _record_path(workspace, scope)
    try:
        data = _load_json(path)
    except Exception:
        data = {}
    if rec is None:
        if "install" not in data:
            return  # nothing to remove; do not create an empty file
        data.pop("install", None)
    else:
        data["install"] = rec
    _write_json(path, data)


# ── the server entry ─────────────────────────────────────────────────────────

def _server_entry(workspace: Path, mode: str, scope: str) -> Dict[str, Any]:
    """The MCP server block for the mirror.

    Same shape as the hook dispatcher (`hooks._dispatcher_command`): the current
    interpreter, `-m`, PYTHONPATH pinned to this install. The `prismor` console
    script is not assumed to be on PATH inside the agent's launch environment,
    and a pipx-installed `prismor` may not even be the one that owns this code.
    Project scope pins `--workspace` so policy resolves to this project no
    matter what cwd the host launches the server with; user scope leaves it to
    the gateway's cwd inference, since one entry serves every project.
    """
    repo_root = Path(mirror.__file__).resolve().parent.parent.parent
    args = ["-m", "prismor.runtime.immunity_cli", "mcp-gateway", "--mirror",
            "--mode", mode]
    if scope != "user":
        args += ["--workspace", str(workspace)]
    return {
        "command": sys.executable or "python3",
        "args": args,
        "env": {"PYTHONPATH": str(repo_root)},
    }


# ── on / off ─────────────────────────────────────────────────────────────────

def _announce_workspace(workspace: Path) -> None:
    """Say which project is about to be rewired, and why it was chosen.

    The CLI resolves the workspace from --workspace, then $PRISMOR_WORKSPACE,
    then cwd. Claude Code exports PRISMOR_WORKSPACE from a project's
    settings.json into every shell it spawns, so `cd /tmp/sandbox && prismor
    mirror on` run from inside such a session silently rewires the REAL project
    — which is how this command locked its own author's session the first time
    it was tried. Printing the source makes that visible before it matters."""
    src = "--workspace"
    try:
        env_ws = os.environ.get("PRISMOR_WORKSPACE")
        cwd = Path.cwd().resolve()
        if workspace.resolve() == cwd:
            src = "current directory"
        elif env_ws and Path(env_ws).resolve() == workspace.resolve():
            src = "$PRISMOR_WORKSPACE — not the current directory; pass --workspace to override"
    except Exception:
        pass
    print(f"  {_c('workspace', _DIM)} {workspace}  {_c('(' + src + ')', _DIM)}")


def mirror_on(workspace: Path, *, mode: str = "enforce", scope: str = "project",
              agent: str = "claude") -> int:
    if agent != "claude":
        print(_c(f"prismor mirror on: agent '{agent}' is not wired yet — Claude Code only for now.", _RED))
        print(_c("  Other hosts: run `prismor mcp-gateway --mirror` as an MCP server and disable "
                 "the host's own Bash/Read/Write tools (SDK: disallowed_tools).", _DIM))
        return 2
    _announce_workspace(workspace)
    mcp_path, settings_path, key = _claude_paths(workspace, scope)
    existing = _read_record(workspace, scope)

    # 1. MCP server entry.
    try:
        mcp = _load_json(mcp_path)
    except Exception as exc:
        print(_c(f"prismor mirror on: cannot read {mcp_path}: {exc}", _RED))
        return 1
    servers = mcp.get(key)
    if servers is None:
        servers = mcp[key] = {}
    if not isinstance(servers, dict):
        print(_c(f"prismor mirror on: {mcp_path} has an unrecognised '{key}' block — not touching it.", _RED))
        return 1
    _backup_once(mcp_path)
    servers[mirror.MIRROR_SERVER_NAME] = _server_entry(workspace, mode, scope)
    _write_json(mcp_path, mcp)

    # 2. Disable the natives. Only add what is missing, and remember exactly
    #    which entries were ours so `off` removes those and nothing else.
    try:
        settings = _load_json(settings_path)
    except Exception as exc:
        print(_c(f"prismor mirror on: cannot read {settings_path}: {exc}", _RED))
        return 1
    perms = settings.get("permissions")
    if perms is None:
        perms = settings["permissions"] = {}
    if not isinstance(perms, dict):
        print(_c(f"prismor mirror on: {settings_path} has an unrecognised 'permissions' block — not touching it.", _RED))
        return 1
    deny = perms.get("deny")
    if deny is None:
        deny = perms["deny"] = []
    if not isinstance(deny, list):
        print(_c(f"prismor mirror on: {settings_path} permissions.deny is not a list — not touching it.", _RED))
        return 1
    _backup_once(settings_path)
    already = set(str(x) for x in deny)
    added = [t for t in mirror.NATIVE_TOOLS_TO_DISABLE if t not in already]
    deny.extend(added)
    _write_json(settings_path, settings)

    # 3. Governing, and the record `off` will need.
    mirror.set_mirror_config(workspace, override=True)
    prior_added = list((existing or {}).get("deny_added") or [])
    _write_record(workspace, scope, {
        "agent": agent, "scope": scope, "mode": mode,
        "server": mirror.MIRROR_SERVER_NAME,
        "mcp_path": str(mcp_path), "settings_path": str(settings_path),
        # Union with a previous install's additions: a re-run must not forget
        # the entries the first run added just because they now pre-exist.
        "deny_added": sorted(set(prior_added) | set(added)),
        "at": time.time(),
    })

    print(f"  {_c('Prismor mirror is on', _GREEN)} ({scope} scope, {mode} mode)")
    print(f"  {_c('server', _DIM)}    {mcp_path}  →  {mirror.MIRROR_SERVER_NAME}")
    print(f"  {_c('natives', _DIM)}   {settings_path}  →  denied: "
          + ", ".join(mirror.NATIVE_TOOLS_TO_DISABLE))
    print()
    print(f"  {_c('Start a new Claude Code session for it to take effect.', _BOLD)}")
    print(f"  {_c('If it gets in your way:', _DIM)}  prismor pause          (lifts enforcement 24h, no restart)")
    print(f"  {_c('To go back to native tools:', _DIM)}  prismor mirror off     (next session)")
    return 0


def mirror_off(workspace: Path, *, scope: Optional[str] = None) -> int:
    _announce_workspace(workspace)
    scopes = [scope] if scope else ["project", "user"]
    done = 0
    for sc in scopes:
        rec = _read_record(workspace, sc)
        mcp_path, settings_path, key = _claude_paths(workspace, sc)
        # No record: nothing was installed by us at this scope. Still remove a
        # hand-added server entry that names our server, since that is the
        # obvious intent — but never guess at deny entries.
        server = (rec or {}).get("server") or mirror.MIRROR_SERVER_NAME
        removed_server = False
        try:
            mcp = _load_json(Path((rec or {}).get("mcp_path") or mcp_path))
            servers = mcp.get(key)
            if isinstance(servers, dict) and server in servers:
                del servers[server]
                _write_json(Path((rec or {}).get("mcp_path") or mcp_path), mcp)
                removed_server = True
        except Exception as exc:
            print(_c(f"prismor mirror off: could not update {mcp_path}: {exc}", _RED))
            return 1

        removed_deny: List[str] = []
        if rec:
            spath = Path(rec.get("settings_path") or settings_path)
            try:
                settings = _load_json(spath)
                perms = settings.get("permissions")
                deny = perms.get("deny") if isinstance(perms, dict) else None
                if isinstance(deny, list):
                    ours = set(rec.get("deny_added") or [])
                    kept = [x for x in deny if str(x) not in ours]
                    removed_deny = [str(x) for x in deny if str(x) in ours]
                    if removed_deny:
                        perms["deny"] = kept
                        if not kept:
                            del perms["deny"]
                        if not perms:
                            del settings["permissions"]
                        _write_json(spath, settings)
            except Exception as exc:
                print(_c(f"prismor mirror off: could not update {spath}: {exc}", _RED))
                return 1
            _write_record(workspace, sc, None)

        if removed_server or removed_deny or rec:
            done += 1
            print(f"  {_c('Prismor mirror is off', _GREEN)} ({sc} scope)")
            if removed_server:
                print(f"  {_c('server', _DIM)}    removed {server} from {mcp_path}")
            if removed_deny:
                print(f"  {_c('natives', _DIM)}   restored in {settings_path}: " + ", ".join(removed_deny))
    if not done:
        print("  Prismor mirror was not configured for Claude Code here — nothing to undo.")
        print(_c("  (If you wired it by hand, remove the server from .mcp.json and the deny "
                 "entries from .claude/settings.json yourself.)", _DIM))
        return 0
    print()
    print(f"  {_c('Start a new Claude Code session — the agent uses its native tools again.', _BOLD)}")
    print(_c("  Any session started before this keeps the mirror until it ends.", _DIM))
    return 0


# ── runtime switch ───────────────────────────────────────────────────────────

def mirror_passthrough(workspace: Path, on: bool) -> int:
    cfg = mirror.set_mirror_config(workspace, override=not on)
    if on:
        print(f"  {_c('Mirror is passing through', _YELLOW)} — built-ins run ungoverned "
              "(logged, not blocked or redacted). No restart needed.")
        print(_c("  Back to governing: prismor mirror passthrough off", _DIM))
    else:
        print(f"  {_c('Mirror is governing', _GREEN)} — policy screens every mirrored call again.")
    return 0 if cfg is not None else 1


# ── status ───────────────────────────────────────────────────────────────────

def _live_gateways(workspace: Path) -> List[Dict[str, Any]]:
    try:
        return [m for m in mirror._live_markers()  # noqa: SLF001 — same package
                if mirror._within(str(m.get("workspace") or ""), str(workspace))
                or mirror._within(str(workspace), str(m.get("workspace") or ""))]
    except Exception:
        return []


def mirror_status(workspace: Path) -> int:
    print(f"  {_c('Prismor mirror', _BOLD)} — {workspace}")

    configured = False
    for sc in ("project", "user"):
        rec = _read_record(workspace, sc)
        mcp_path, _settings_path, key = _claude_paths(workspace, sc)
        try:
            servers = _load_json(mcp_path).get(key) or {}
        except Exception:
            servers = {}
        names = [n for n, cfg in servers.items()
                 if isinstance(cfg, dict) and "--mirror" in [str(a) for a in (cfg.get("args") or [])]]
        if names or rec:
            configured = True
            how = "prismor mirror on" if rec else "by hand"
            mode = (rec or {}).get("mode") or "?"
            print(f"  {_c('Claude Code', _DIM)}   {sc} scope · server {', '.join(names) or (rec or {}).get('server')}"
                  f" · {mode} mode · {how}")
            if rec and rec.get("deny_added"):
                print(f"  {_c('natives off', _DIM)}   {', '.join(rec['deny_added'])}")
    if not configured:
        print(f"  {_c('Claude Code', _DIM)}   not configured — `prismor mirror on` to enable")

    state = mirror.passthrough_state(workspace)
    if state is None:
        gov = _c("governing", _GREEN) + " — policy screens every mirrored call"
    elif state["source"] == "pause":
        rec = state.get("pause") or {}
        until = rec.get("until")
        when = (" until " + datetime.fromtimestamp(float(until)).strftime("%H:%M")) if until else ""
        by = " (by your organization)" if rec.get("source") == "org" else ""
        gov = _c(f"PAUSED{when}{by}", _YELLOW) + " — passing through; `prismor resume` to govern again"
    else:
        gov = _c("PASS-THROUGH", _YELLOW) + " — override off; `prismor mirror passthrough off` to govern again"
    print(f"  {_c('governance', _DIM)}    {gov}")

    cfg = mirror.mirror_config(workspace)
    roster = []
    for t in mirror.mirror_tool_names():
        roster.append(t if t not in cfg["disabled_tools"] else _c(f"{t} (off)", _DIM))
    print(f"  {_c('roster', _DIM)}        {' '.join(roster)}")

    live = _live_gateways(workspace)
    if live:
        for m in live:
            print(f"  {_c('live gateway', _DIM)}  pid {m.get('pid')} · {m.get('workspace')}")
    else:
        print(f"  {_c('live gateway', _DIM)}  none — the gateway starts with the next agent session")

    print()
    print(_c("  prismor pause / resume        lift or restore enforcement (24h auto-resume)", _DIM))
    print(_c("  prismor mirror passthrough on|off   run built-ins ungoverned without a restart", _DIM))
    print(_c("  prismor mirror off            hand the built-ins back to the agent (next session)", _DIM))
    return 0


def run(args, workspace: Path) -> int:
    action = getattr(args, "mirror_command", None) or "status"
    if action == "on":
        return mirror_on(workspace, mode=args.mode, scope=args.scope, agent=args.agent)
    if action == "off":
        return mirror_off(workspace, scope=getattr(args, "scope", None))
    if action == "passthrough":
        return mirror_passthrough(workspace, on=(args.state == "on"))
    return mirror_status(workspace)
