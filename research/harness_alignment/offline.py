"""Disposable native gateway/evaluator fixture, following the Prompt 2 boundary.

Only upstream transport and external-service dependencies are substituted.
Neither Gateway._evaluate nor runtime.evaluate_tool_call is replaced.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import urllib.request

from prismor.runtime import mcp_gateway, policy_engine, semantic_guard, semantic_guard_v2, sinks
from prismor.runtime.enterprise import approvals, heartbeat, identity, remote_policy
from prismor.runtime.principal import Subject
from prismor.runtime.runtime import evaluate_tool_call

from .casebook import policy_path


class RecordingUpstream(mcp_gateway.Upstream):
    """The FakeUpstream recording pattern from tests/test_mcp_gateway.py."""
    def __init__(self, spec):
        super().__init__(spec)
        self.requests = []

    def request(self, method, params, timeout=30):
        self.requests.append((method, deepcopy(params)))
        if method == "tools/list":
            return {"tools": [{"name": "echo", "description": "Synthetic echo fixture",
                               "inputSchema": {"type": "object"}}]}
        if method == "tools/call":
            return {"content": [{"type": "text", "text": "fixture:echo"}]}
        raise AssertionError(f"unexpected upstream method: {method}")

    def notify(self, method, params):
        self.requests.append((method, deepcopy(params)))


@contextmanager
def isolated(policy_reference, approval_source):
    with TemporaryDirectory(prefix="prismor-casebook-") as temp, ExitStack() as stack:
        root = Path(temp)
        workspace = root / "workspace"
        (workspace / ".prismor").mkdir(parents=True)
        (workspace / ".prismor" / "policy.yaml").write_bytes(policy_path(policy_reference).read_bytes())
        # No HOME reassignment: every Prismor and XDG state path is explicit.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("PRISMOR_") and not k.endswith("_API_KEY")}
        env.update(PRISMOR_HOME=str(root / "state"), PRISMOR_SECRETS_DIR=str(root / "secrets"),
                   PRISMOR_SUBJECT="user:harness-fixture", PRISMOR_NO_UPDATE_CHECK="1",
                   XDG_CONFIG_HOME=str(root / "config"), XDG_CACHE_HOME=str(root / "cache"))
        stack.enter_context(patch.dict(os.environ, env, clear=True))
        attempts, source_requests = [], []

        def forbid(*a, **k):
            attempts.append("unexpected external service or judge invocation")
            raise RuntimeError(attempts[-1])

        for module, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"),
                             (urllib.request, "urlopen"), (sinks, "dispatch"),
                             (heartbeat, "maybe_flush"), (heartbeat, "flush_at_exit"),
                             (semantic_guard.SemanticGuard, "analyze"),
                             (semantic_guard_v2.SemanticGuardV2, "analyze")):
            stack.enter_context(patch.object(module, name, forbid))
        stack.enter_context(patch.object(remote_policy, "_VERIFIED", {}))
        stack.enter_context(patch.object(policy_engine, "_YAML_CACHE", {}))
        stack.enter_context(patch.object(remote_policy, "check_and_refresh", lambda *a, **k: False))
        if identity.is_enrolled():
            raise RuntimeError("fixture runtime must remain unenrolled")
        stack.enter_context(patch.object(approvals, "_identity", SimpleNamespace(
            load_identity=lambda: {"source": "offline-fixture"},
            revoked_backoff_active=lambda: False)))

        def post_request(ident, body, timeout):
            source_requests.append(deepcopy(body))
            if approval_source == "unavailable":
                return None
            if approval_source in ("approved", "denied"):
                return {"id": "simulated-approval", "status":
                        "approved" if approval_source == "approved" else "pending"}
            return forbid()

        def poll(*a, **k):
            if approval_source == "denied":
                return "denied", "full"
            return forbid()

        stack.enter_context(patch.object(approvals, "_post_request", post_request))
        stack.enter_context(patch.object(approvals, "_get_status_ex", poll))
        # A single denied poll uses the native scheduler (no mock clock).
        yield workspace, attempts, source_requests, stack
        if attempts:
            raise RuntimeError("; ".join(attempts))


def snapshot(decision):
    return {"verdict": decision.verdict, "allow": decision.allow,
            "rule_id": decision.rule_id,
            "matched_rules": [f["ruleId"] for f in decision.findings],
            "reason": decision.reason}


def evaluate_native(case, mode):
    setup = case["evaluator"]["native_setup"]
    with isolated(setup["policy"], setup["approval_source"]) as (workspace, attempts, requests, stack):
        spec = mcp_gateway.UpstreamSpec(name="fixture", command=["true"], transport="stdio")
        upstream = RecordingUpstream(spec)
        stack.enter_context(patch.object(mcp_gateway, "make_upstream", lambda *a, **k: upstream))
        gateway = mcp_gateway.Gateway([spec], workspace=workspace, mode="enforce",
                                      session_id="offline-case")
        sent = []
        stack.enter_context(patch.object(gateway, "_send", sent.append))
        try:
            gateway._handle_tools_list("discovery", {})
            names = {t["name"] for t in sent[-1]["result"]["tools"]}
            if names != {"fixture__echo"}:
                raise RuntimeError("call-time fixture tool disappeared during discovery")
            route = gateway._routes["fixture__echo"]
            if gateway._passthrough(route) is not None:
                raise RuntimeError("fixture passthrough must be inactive")
            arguments = deepcopy(case["input"]["proposed_action"]["arguments"])
            if mode == "decision_only":
                decision = evaluate_tool_call(
                    event=gateway._build_call_event(route, arguments), workspace=workspace,
                    agent="mcp-gateway", mode="enforce", session_id="offline-case",
                    subject=Subject(user_id="harness-fixture", source="research-fixture"),
                    persist=False, record=False, register_agent=False, flush_at_exit=False)
                if upstream.requests != [("tools/list", {})] or requests:
                    raise RuntimeError("decision-only evaluation performed an action")
                return {"native_decision": snapshot(decision),
                        "final_pre_action_decision": snapshot(decision),
                        "actual_forwarding": None, "approval_outcome": None,
                        "post_action": [], "response_status": None}

            pre, post, outcomes = [], [], []

            def observe(frame, event, value):
                if event != "return" or value is None:
                    return
                if frame.f_code is evaluate_tool_call.__code__:
                    target = pre if frame.f_locals["event"]["agent_event"] == "PreToolUse" else post
                    target.append(snapshot(value))
                elif frame.f_code is approvals.await_step_up.__code__:
                    outcomes.append({"approved": value.approved, "status": value.status,
                                     "redacted": value.redacted, "simulated": True})

            previous = sys.getprofile()
            try:
                sys.setprofile(observe)
                gateway._handle_tools_call_safe("action", {"name": "fixture__echo", "arguments": arguments})
            finally:
                sys.setprofile(previous)
            if len(pre) != 1:
                raise RuntimeError(f"expected one pre-action decision, observed {len(pre)}")
            reply = sent[-1]
            if reply.get("id") != "action" or "error" in reply:
                raise RuntimeError(f"gateway protocol error: {reply}")
            forwarded = [p for method, p in upstream.requests if method == "tools/call"]
            if attempts:
                raise RuntimeError("; ".join(attempts))
            final = deepcopy(pre[0])
            if pre[0]["verdict"] == "step_up" and outcomes:
                # Research description of the observed native approval branch,
                # not a new native Decision or a replacement authorization rule.
                final = {"verdict": "allow" if outcomes[0]["approved"] else "block",
                         "source": "observed_native_gateway_approval_branch",
                         "native_requirement": "step_up", "rule_id": pre[0]["rule_id"],
                         "reason": "Simulated approval source: " + outcomes[0]["status"]}
            return {"native_decision": pre[0], "final_pre_action_decision": final,
                    "actual_forwarding": {"tools_call_count": len(forwarded),
                                          "requests": deepcopy(forwarded)},
                    "approval_outcome": outcomes[0] if outcomes else None,
                    "post_action": post,
                    "response_status": "tool_error" if reply["result"].get("isError") else "ok"}
        finally:
            gateway.close()
