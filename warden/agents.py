"""warden/agents.py — Named agent registry and per-agent runtime control.

An agent *name* is an instance label distinct from the framework id. Multiple
agents using the same framework ("vercel-ai") can have different names and
independent control settings.

Config resolution order (mirrors iam.py):
  1. ~/.prismor/agents.yaml          (global, user-level)
  2. .prismor-warden/agents.yaml     (per-project, takes precedence)

Config format:
  agents:
    support-bot:
      framework: vercel-ai       # auto-filled on first discovery
      enabled: true              # false = hard block ALL calls (kill switch)
      mode: enforce              # null/absent = inherit; else "observe"/"enforce"
      iam_profile: readonly-bot  # optional — enforce this IAM profile for this agent
      last_seen: 2026-06-28T...  # auto-updated on discovery

``enabled: false`` injects a CRITICAL blocking finding so the Decision flows
through the normal should_block → telemetry path unchanged.  The caller (runtime)
is responsible for using ``control.iam_profile`` when calling check_iam.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_GLOBAL_AGENTS_PATH = Path.home() / ".prismor" / "agents.yaml"
_PROJECT_AGENTS_FILE = "agents.yaml"

# Module-level seen-set: throttle record_seen() so we only update the YAML
# once per agent per process, not on every tool call.
_SEEN_THIS_PROCESS: set = set()

# (path+mtime) → parsed config
_CONFIG_CACHE: Dict[Any, Dict[str, Any]] = {}


# ── Config I/O ────────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        sys.stderr.write(f"[warden/agents] failed to load {path}: {exc}\n")
        return None


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return -1.0


def load_agents_config(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Load agents config, project overrides global. (path+mtime)-memoized."""
    project_path = (
        workspace / ".prismor-warden" / _PROJECT_AGENTS_FILE if workspace else None
    )
    cache_key = (
        str(_GLOBAL_AGENTS_PATH), _mtime(_GLOBAL_AGENTS_PATH),
        str(project_path) if project_path else "",
        _mtime(project_path) if project_path else -1.0,
    )
    cached = _CONFIG_CACHE.get(cache_key)
    if cached is not None:
        return cached

    config: Dict[str, Any] = {}
    global_cfg = _load_yaml(_GLOBAL_AGENTS_PATH)
    if global_cfg:
        config.update(global_cfg)
    if project_path is not None:
        project_cfg = _load_yaml(project_path)
        if project_cfg:
            project_agents = project_cfg.get("agents", {})
            if project_agents:
                config.setdefault("agents", {}).update(project_agents)

    _CONFIG_CACHE[cache_key] = config
    return config


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentControl:
    """Per-instance control settings for one named agent."""

    name: str
    framework: str = ""
    enabled: bool = True      # False = kill switch (hard block all calls)
    mode: Optional[str] = None   # None = inherit global mode; "observe"/"enforce"
    iam_profile: Optional[str] = None  # IAM profile name to enforce for this agent
    last_seen: Optional[str] = None


_DEFAULT = AgentControl(name="")  # sentinel — used for agents not in the registry


def resolve_agent_control(name: str, workspace: Optional[Path] = None) -> AgentControl:
    """Return the AgentControl for ``name``.

    Returns a permissive default (enabled=True, mode=None, iam_profile=None)
    when the agent is not in the registry, so unregistered agents are
    unaffected by the new control layer.
    """
    if not name:
        return AgentControl(name=name)
    config = load_agents_config(workspace)
    entry = config.get("agents", {}).get(name)
    if entry is None:
        return AgentControl(name=name)
    return AgentControl(
        name=name,
        framework=entry.get("framework", ""),
        enabled=bool(entry.get("enabled", True)),
        mode=entry.get("mode") or None,
        iam_profile=entry.get("iam_profile") or None,
        last_seen=entry.get("last_seen"),
    )


def list_agents(workspace: Optional[Path] = None) -> List[AgentControl]:
    """Return all agents defined in the active config."""
    config = load_agents_config(workspace)
    out = []
    for name, entry in config.get("agents", {}).items():
        out.append(AgentControl(
            name=name,
            framework=entry.get("framework", ""),
            enabled=bool(entry.get("enabled", True)),
            mode=entry.get("mode") or None,
            iam_profile=entry.get("iam_profile") or None,
            last_seen=entry.get("last_seen"),
        ))
    return out


# ── Writes ────────────────────────────────────────────────────────────────────

def _write_project_config(workspace: Path, config: Dict[str, Any]) -> None:
    """Write the project agents.yaml atomically."""
    try:
        import yaml
    except ImportError:
        sys.stderr.write("[warden/agents] PyYAML not available; cannot write agents.yaml\n")
        return
    path = workspace / ".prismor-warden" / _PROJECT_AGENTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=True), encoding="utf-8")
    # Bust cache so next read picks up the change
    _CONFIG_CACHE.clear()


def upsert_agent(name: str, workspace: Path, **fields: Any) -> AgentControl:
    """Write/merge control fields for ``name`` into the project agents.yaml.

    Accepted fields: ``enabled`` (bool), ``mode`` (str|None),
    ``iam_profile`` (str|None), ``framework`` (str), ``last_seen`` (str).
    Returns the updated AgentControl.
    """
    # Load current project config (not the merged global+project, so we only
    # persist project-level overrides).
    project_path = workspace / ".prismor-warden" / _PROJECT_AGENTS_FILE
    existing: Dict[str, Any] = {}
    if project_path.exists():
        loaded = _load_yaml(project_path)
        if loaded:
            existing = loaded

    agents = existing.setdefault("agents", {})
    entry: Dict[str, Any] = agents.get(name, {})

    ALLOWED_FIELDS = {"enabled", "mode", "iam_profile", "framework", "last_seen"}
    for k, v in fields.items():
        if k in ALLOWED_FIELDS:
            if v is None and k in entry:
                del entry[k]
            else:
                entry[k] = v
    agents[name] = entry
    existing["agents"] = agents

    _write_project_config(workspace, existing)
    return resolve_agent_control(name, workspace)


def record_seen(name: str, framework: str, workspace: Optional[Path]) -> None:
    """Auto-register a discovered agent; best-effort, once per process per agent."""
    if not name or not workspace:
        return
    seen_key = (name, str(workspace))
    if seen_key in _SEEN_THIS_PROCESS:
        return
    _SEEN_THIS_PROCESS.add(seen_key)
    try:
        upsert_agent(
            name, workspace,
            framework=framework,
            last_seen=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        sys.stderr.write(f"[warden/agents] record_seen error: {exc}\n")


# ── Kill-switch finding ────────────────────────────────────────────────────────

def make_disabled_finding(name: str, session_id: str = "") -> Dict[str, Any]:
    """Return a CRITICAL blocking finding for a disabled (paused) agent."""
    return {
        "id": f"{session_id}:agent-disabled:{name}",
        "ruleId": "agent-disabled",
        "severity": "critical",
        "category": "agent-control",
        "mode": "enforce",  # always blocks regardless of policy mode
        "title": f"[agent:{name}] Agent is paused — all tool calls blocked",
        "evidence": f"agent '{name}' is disabled in .prismor-warden/agents.yaml",
        "eventIndex": 0,
        "remediation": (
            f"Re-enable via dashboard or: immunity agents set {name} --enabled"
        ),
    }


# ── Display ────────────────────────────────────────────────────────────────────

def format_agent_table(agents: List[AgentControl]) -> str:
    if not agents:
        return "  (no named agents registered)"
    lines = [
        f"  {'NAME':<20} {'FRAMEWORK':<16} {'ENABLED':<8} {'MODE':<10} {'IAM PROFILE':<20}",
        "  " + "-" * 76,
    ]
    for a in agents:
        lines.append(
            f"  {a.name:<20} {a.framework:<16} {'yes' if a.enabled else 'NO':<8} "
            f"{(a.mode or '(global)'):<10} {(a.iam_profile or ''):<20}"
        )
    return "\n".join(lines)
