"""Shared tool-call evaluation pipeline.

Every adapter — coding-agent hooks (``cli.py hook-dispatch``), in-process
framework SDK adapters (``adapters/``), and the MCP proxy — funnels a single
normalized event through :func:`evaluate_tool_call`. It runs the policy engine,
session-scoped rules, IAM, cross-call learning correlation, persists the event,
forwards telemetry to sinks, records the enterprise heartbeat, and returns a
:class:`Decision` describing whether the call may proceed.

Keeping this in one place means a production framework agent gets the exact same
policy, observe/enforce semantics, and per-user attribution a local coding agent
already gets — the caller only differs in how it renders the decision (exit-2,
a JSON permission object, or a raised exception).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from warden.hooks import legacy_should_block, should_block
from warden.policy_engine import PolicyEngine
from warden.principal import Subject, resolve_subject
from warden.store import (
    append_session_event,
    read_session_events,
    save_session_snapshot,
)


@dataclass
class Decision:
    """Outcome of evaluating one tool call."""

    allow: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    blocking: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    subject: Optional[Subject] = None
    # Engine kept so callers that need post-decision config (e.g. the Claude
    # sandbox rewrite path) don't have to re-instantiate it.
    engine: Optional[PolicyEngine] = None


def _block_reason(finding: Dict[str, Any]) -> str:
    parts = [f"[{finding.get('severity', 'high')}] {finding.get('title', 'blocked')}"]
    if finding.get("evidence"):
        parts.append(str(finding["evidence"]))
    if finding.get("remediation"):
        parts.append(f"Recommended fix: {finding['remediation']}")
    return "\n".join(parts)


def evaluate_tool_call(
    *,
    event: Dict[str, Any],
    workspace: Path,
    agent: str,
    mode: str = "enforce",
    session_id: str = "",
    repo_root: Optional[Path] = None,
    subject: Optional[Subject] = None,
    persist: bool = True,
    agent_name: str = "",
) -> Decision:
    """Evaluate one normalized tool-call ``event`` against active policy.

    Args:
        event: canonical event (``type``, ``agent``, ``agent_event``, ...).
        workspace: workspace whose policy + session store apply.
        agent: agent/framework id (telemetry + heartbeat tagging).
        mode: ``enforce`` blocks on enforce-mode findings; ``observe`` is a local
            dry-run kill-switch (the control plane can still force enforce per rule).
        session_id: session to append to / read history from.
        repo_root: repo root for analysis (defaults to ``workspace``).
        subject: resolved end-user principal; if ``None`` it is resolved from
            ``WARDEN_SUBJECT`` / device identity so single-user installs are unchanged.
        persist: append the event + write a session snapshot (set ``False`` for
            pure pre-checks like ``immunity check``).

    Returns:
        A :class:`Decision`. ``allow`` is ``False`` only when a finding's effective
        mode is enforce; callers may further downgrade to observe (e.g. a local
        dry-run kill-switch).
    """
    repo_root = repo_root or workspace
    subject = subject or resolve_subject()
    # Normalise agent_name: default to the framework id for backward compat.
    _agent_name = agent_name or agent

    # Stamp principal and agent identity onto the event.
    meta = event.setdefault("metadata", {})
    if "subject" not in meta:
        meta["subject"] = subject.as_dict()
    meta.setdefault("agent_name", _agent_name)

    if persist:
        append_session_event(workspace, session_id, event)
        events = read_session_events(workspace, session_id)
        try:
            from warden.cli import analyze_events  # lazy: avoid import cycle
            analysis = analyze_events(
                events, repo_root=repo_root, workspace=workspace, session_id=session_id
            )
            save_session_snapshot(
                workspace=workspace,
                session_id=session_id,
                agent=agent,
                agent_name=_agent_name,
                source="hook",
                repo_url=None,
                events=events,
                analysis=analysis,
            )
        except Exception as exc:  # best-effort; never block on analysis failure
            sys.stderr.write(f"[warden] analysis error: {exc}\n")
    else:
        events = [event]

    engine = PolicyEngine(workspace=workspace)

    # Resolve per-agent control (kill-switch, mode override, IAM profile).
    # Runs AFTER engine construction so the org's remote controls — carried in
    # the verified signed policy's settings.agent_controls, managed workspaces
    # only — merge with the local agents.yaml (tighten-only: see agents.py).
    _control = None
    try:
        from warden.agents import resolve_agent_control, record_seen, make_disabled_finding
        _control = resolve_agent_control(
            _agent_name, workspace,
            remote_controls=getattr(engine, "agent_controls", None),
        )
        # Throttled auto-registration — once per agent per process.
        record_seen(_agent_name, framework=agent, workspace=workspace)
        # Per-agent mode override: takes precedence over the caller's mode.
        if _control.mode:
            mode = _control.mode
    except Exception as _exc:
        sys.stderr.write(f"[warden] agent control error: {_exc}\n")

    # Only the current event drives the real-time decision (stale prior findings
    # must not block an unrelated event — see cli.py hook-dispatch rationale).
    findings = engine.evaluate(event, len(events) - 1, session_id=session_id, subject=subject)

    # Session-scoped rules.
    try:
        from warden.scoped_agent import load_scoped_rules, check_scoped_rules
        scoped = load_scoped_rules(workspace, session_id)
        if scoped is not None:
            sr_finding = check_scoped_rules(scoped, event, session_id=session_id)
            if sr_finding:
                findings.append(sr_finding)
    except Exception as exc:
        sys.stderr.write(f"[warden] scoped enforcement error: {exc}\n")

    # Per-agent kill-switch: inject a CRITICAL finding when the agent is disabled.
    # This runs before IAM so the disabled state always wins.
    if _control is not None and not _control.enabled:
        try:
            from warden.agents import make_disabled_finding
            findings.insert(0, make_disabled_finding(
                _agent_name, session_id, disabled_by=_control.disabled_by))
        except Exception as exc:
            sys.stderr.write(f"[warden] kill-switch error: {exc}\n")

    # IAM named-identity enforcement (now subject-aware + per-agent profile).
    try:
        from warden.iam import check_iam
        iam_finding = check_iam(
            workspace=workspace,
            event=event,
            session_id=session_id,
            subject=subject,
            agent_profile=_control.iam_profile if _control else None,
        )
        if iam_finding:
            findings.append(iam_finding)
    except Exception as exc:
        sys.stderr.write(f"[warden] IAM enforcement error: {exc}\n")

    # Cross-call learning correlation on otherwise-clean shell events.
    if not findings and event.get("type") == "shell":
        for fn_name in ("detect_evasion", "detect_staged_execution"):
            try:
                from warden import learning
                detector = getattr(learning, fn_name)
                extra = detector(workspace, session_id, event, findings)
                if extra:
                    findings.extend(extra)
            except Exception as exc:
                sys.stderr.write(f"[warden] {fn_name} error: {exc}\n")

    _dispatch_telemetry(
        engine=engine,
        findings=findings,
        event=event,
        workspace=workspace,
        agent=agent,
        agent_name=_agent_name if _agent_name != agent else None,
        mode=mode,
        session_id=session_id,
        subject=subject,
    )

    # Per-call inspected-volume heartbeat (org observability), managed repos only.
    if getattr(engine, "workspace_managed", False):
        try:
            from warden.enterprise import heartbeat
            heartbeat.record_call(
                agent=agent,
                agent_name=_agent_name if _agent_name != agent else "",
                session_id=session_id,
            )
            heartbeat.maybe_flush()
        except Exception:
            pass

    blocking = should_block(findings, event)
    if blocking is None and mode == "enforce" and getattr(engine, "is_legacy_policy", False):
        blocking = legacy_should_block(findings, event, engine.block_categories)

    # Per-agent observe override: if the effective mode was downgraded to observe
    # (by the agent registry), suppress blocking even when policy findings say enforce.
    # Kill-switch (agent-control category) is exempt — it always blocks.
    if blocking is not None and mode == "observe":
        if blocking.get("category") != "agent-control":
            blocking = None

    return Decision(
        allow=blocking is None,
        findings=findings,
        blocking=blocking,
        reason=_block_reason(blocking) if blocking else None,
        subject=subject,
        engine=engine,
    )


def _dispatch_telemetry(
    *,
    engine: PolicyEngine,
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    workspace: Path,
    agent: str,
    agent_name: Optional[str] = None,
    mode: str,
    session_id: str,
    subject: Subject,
) -> None:
    """Forward findings to configured sinks before the blocking decision so a
    SIEM sees every event, including blocked ones. Best-effort."""
    if not (getattr(engine, "outputs", None) and findings):
        return
    try:
        from warden.sinks import dispatch as sink_dispatch
        exm = getattr(engine, "active_exemption", None)
        policy_scope = (
            f"repo_exemption:{exm.get('id')}"
            if isinstance(exm, dict) and exm.get("id")
            else "org"
        )
        repo = None
        if getattr(engine, "workspace_managed", False):
            try:
                from warden.enterprise import workspace_scope as ws
                repo = ws.detect_git_remote(workspace)
            except Exception:
                repo = None
        sink_dispatch(
            findings,
            engine.outputs,
            extra={
                "session_id": session_id,
                "agent": agent,
                # Instance label (adapter `name=`), distinct from the framework
                # id above — lets the org dashboard tell "checkout-bot" apart
                # from every other agent on the same framework.
                "agent_name": agent_name,
                "mode": mode,
                "workspace": str(workspace),
                "policy_scope": policy_scope,
                "repo": repo,
                "subject": subject.as_dict(),
            },
            raw_event=event,
        )
    except Exception as exc:
        sys.stderr.write(f"[warden] sink dispatch error: {exc}\n")
