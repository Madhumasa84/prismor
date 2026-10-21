"""Offline execution-boundary observations using native evaluation and forwarding.

Display all four observations:
    python3 -m pytest tests/test_harness_alignment_gateway.py -q -s
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import urllib.request

import pytest

from prismor.runtime import semantic_guard, semantic_guard_v2, sinks
from prismor.runtime.enterprise import approvals, heartbeat, identity, remote_policy
from prismor.runtime.policy_engine import validate_policy
from prismor.runtime.runtime import evaluate_tool_call
from test_mcp_gateway import FakeUpstream, list_tools, make_gateway, stub


POLICY = (Path(__file__).resolve().parents[1] / "research" /
          "harness_alignment" / "gateway_policy.yaml")


@pytest.fixture
def offline_boundary(tmp_path):
    # Own patch lifetime: third-party pytest plugins can initialize the shared
    # monkeypatch fixture before the repository's module-leak guard.
    with pytest.MonkeyPatch.context() as patches:
        yield from _offline_boundary(tmp_path, patches)


def _offline_boundary(tmp_path, monkeypatch):
    """Extend tests/conftest.py isolation; all service attempts fail the test.

    The approval module alone sees a synthetic identity. The runtime remains
    unenrolled, and native approval decoding/auditing still runs.
    """
    for name in list(os.environ):
        if name.startswith("PRISMOR_") or name.endswith("_API_KEY"):
            monkeypatch.delenv(name)
    state = tmp_path / "state"
    monkeypatch.setenv("PRISMOR_HOME", str(state))
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(state / "secrets"))
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:harness-fixture")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("PRISMOR_NO_UPDATE_CHECK", "1")
    # Isolate the verified-policy cache without changing its loader.
    monkeypatch.setattr(remote_policy, "_VERIFIED", {})
    monkeypatch.setattr(remote_policy, "check_and_refresh", lambda *a, **k: False)

    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append("unexpected network, telemetry, or judge invocation")
        raise AssertionError(attempts[-1])

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(sinks, "dispatch", forbidden)
    monkeypatch.setattr(heartbeat, "maybe_flush", forbidden)
    monkeypatch.setattr(heartbeat, "flush_at_exit", forbidden)
    monkeypatch.setattr(semantic_guard.SemanticGuard, "analyze", forbidden)
    monkeypatch.setattr(semantic_guard_v2.SemanticGuardV2, "analyze", forbidden)
    # An unexpected poll must never reach either a network or a long wait.
    monkeypatch.setattr(approvals, "_get_status_ex", forbidden)
    assert not identity.is_enrolled()
    assert approvals.enabled()

    workspace = tmp_path / "workspace"
    (workspace / ".prismor").mkdir(parents=True)
    policy = workspace / ".prismor" / "policy.yaml"
    policy.write_text(POLICY.read_text(encoding="utf-8"), encoding="utf-8")
    assert validate_policy(policy) == []
    yield workspace, attempts, monkeypatch
    # Runtime best-effort error handlers can swallow exceptions: check attempts
    # as well, so no external call can disappear behind such a handler.
    assert attempts == []


@pytest.mark.parametrize(
    "case,marker,source_status,verdict,rule,count",
    [
        ("A_permitted", "HA_ALLOW", None, "allow", None, 1),
        ("B_blocked", "HA_BLOCK", None, "block", "harness-marker-block", 0),
        ("C_approval_unavailable", "HA_APPROVAL", "unavailable", "step_up",
         "harness-marker-approval", 0),
        ("D_simulated_approval", "HA_APPROVAL", "approved", "step_up",
         "harness-marker-approval", 1),
    ],
)
def test_gateway_execution_boundary(offline_boundary, case, marker,
                                    source_status, verdict, rule, count):
    workspace, attempts, monkeypatch = offline_boundary
    upstream = stub("fixture")
    assert isinstance(upstream, FakeUpstream)
    gateway, sent = make_gateway(workspace, monkeypatch, [upstream], mode="enforce")
    source_requests = []

    def approval_source(ident, body, timeout):
        source_requests.append(deepcopy(body))
        assert ident == {"source": "offline-fixture"}
        if source_status == "unavailable":
            return None
        assert source_status == "approved", "unexpected approval request"
        return {"id": "simulated-approval", "status": "approved", "decision_mode": "full"}

    # Only approval-service dependencies are replaced. No enrolled device or
    # bearer credential exists, and await_step_up itself remains native.
    monkeypatch.setattr(approvals, "_identity", SimpleNamespace(
        load_identity=lambda: {"source": "offline-fixture"},
        revoked_backoff_active=lambda: False,
    ))
    monkeypatch.setattr(approvals, "_post_request", approval_source)

    pre, post, approval_outcomes = [], [], []

    def observe_return(frame, event, value):
        # Passive observation: do not wrap or replace either evaluator. Copy
        # on return so later post-action processing cannot overwrite evidence.
        if event != "return":
            return
        if frame.f_code is evaluate_tool_call.__code__ and value is not None:
            native_event = frame.f_locals["event"]
            observation = {"verdict": value.verdict, "allow": value.allow,
                           "rule_id": value.rule_id,
                           "matched_rules": [f["ruleId"] for f in value.findings]}
            assert not value.engine.semantic_guard_config.get("enabled")
            assert not value.engine.outputs
            if native_event["agent_event"] == "PreToolUse":
                pre.append(deepcopy(observation))
            else:
                post.append(deepcopy(observation))
        elif frame.f_code is approvals.await_step_up.__code__ and value is not None:
            approval_outcomes.append({"approved": value.approved,
                                      "status": value.status,
                                      "redacted": value.redacted})

    try:
        assert {t["name"] for t in list_tools(gateway, sent)} == {"fixture__echo"}
        assert gateway.mode == "enforce"
        assert gateway._passthrough(gateway._routes["fixture__echo"]) is None
        arguments = {"marker": marker, "message": "hello fixture"}
        previous_profile = sys.getprofile()
        try:
            sys.setprofile(observe_return)
            gateway._handle_tools_call_safe("experiment", {
                "name": "fixture__echo", "arguments": arguments,
            })
        finally:
            sys.setprofile(previous_profile)

        forwarded = deepcopy([params for method, params in upstream.requests
                              if method == "tools/call"])
        assert len(pre) == 1
        assert pre[0]["verdict"] == verdict
        assert pre[0]["rule_id"] == rule
        assert pre[0]["allow"] is (verdict == "allow")
        assert pre[0]["matched_rules"] == ([] if rule is None else [rule])
        assert len(source_requests) == (1 if source_status else 0)
        if source_status:
            expected_status = "request_failed" if source_status == "unavailable" else "approved"
            assert approval_outcomes == [{"approved": source_status == "approved",
                                          "status": expected_status, "redacted": False}]
            assert source_requests[0]["rule_id"] == rule
        else:
            assert approval_outcomes == []
        assert len(forwarded) == count
        assert forwarded == ([{"name": "echo", "arguments": arguments}] if count else [])
        assert len(post) == count
        assert all(p["verdict"] == "allow" for p in post)
        reply = sent[-1]
        assert reply["id"] == "experiment"
        assert "error" not in reply, reply
        assert bool(reply["result"].get("isError")) is (count == 0)
        assert attempts == []
        print(json.dumps({
            "case": case, "model_status": "not_run", "pre_action": pre[0],
            "approval_source": source_status or "not_requested",
            "approval_outcome": approval_outcomes[0] if approval_outcomes else None,
            "tools_call_count": len(forwarded), "forwarded": forwarded,
            "response_status": "tool_error" if reply["result"].get("isError") else "ok",
            "post_action": post,
        }, sort_keys=True))
    finally:
        gateway.close()
