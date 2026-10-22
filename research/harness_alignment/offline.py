"""Disposable native gateway/evaluator fixture, following the Prompt 2 boundary.

Only upstream transport and external-service dependencies are substituted.
Neither Gateway._evaluate nor runtime.evaluate_tool_call is replaced.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack, nullcontext
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
from .judge import ScriptedJudge, action_hash
from .judged_gateway import ResearchGateway


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
            if approval_source in ("approved", "approved_redacted", "denied"):
                return {"id": "simulated-approval", "status":
                        "pending" if approval_source == "denied" else "approved",
                        "decision_mode": "redacted" if approval_source == "approved_redacted" else "full"}
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
    record = deepcopy(decision.as_dict())
    record["matched_rules"] = [f["ruleId"] for f in decision.findings]
    return record


class ObservationFailure(RuntimeError):
    """A failed fixture execution with observations captured before cleanup."""
    def __init__(self, cause, evidence):
        super().__init__(str(cause))
        self.evidence = deepcopy(evidence)


def evaluate_native(case, mode, judge_configuration=None):
    evidence = {}
    try:
        return _evaluate_native(case, mode, judge_configuration, evidence)
    except Exception as exc:
        raise ObservationFailure(exc, evidence) from exc


def _evaluate_native(case, mode, judge_configuration, evidence):
    setup = case["evaluator"]["native_setup"]
    if judge_configuration and mode != "gateway":
        raise ValueError("scripted composition is supported at the gateway seam only")
    with isolated(setup["policy"], setup["approval_source"]) as (workspace, attempts, requests, stack):
        spec = mcp_gateway.UpstreamSpec(name="fixture", command=["true"], transport="stdio")
        upstream = RecordingUpstream(spec)
        stack.enter_context(patch.object(mcp_gateway, "make_upstream", lambda *a, **k: upstream))
        gateway_kwargs = {"workspace": workspace, "mode": "enforce", "session_id": "offline-case"}
        if judge_configuration:
            gateway = ResearchGateway(
                [spec], **gateway_kwargs, visible_input=case["input"],
                experiment=judge_configuration["experiment"],
                fast=ScriptedJudge("scripted-fast", judge_configuration["fast"]),
                stronger=ScriptedJudge("scripted-stronger", judge_configuration["stronger"]),
                native_short_circuit=judge_configuration.get("native_short_circuit", False),
                unchanged_approval_fixture=setup["approval_source"] in
                ("not_requested", "unavailable", "approved", "denied"))
        else:
            gateway = mcp_gateway.Gateway([spec], **gateway_kwargs)
        pre, post, outcomes = [], [], []
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
                with gateway.judging_action() if judge_configuration else nullcontext():
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
            research = gateway.research_records[0] if judge_configuration else None
            if research:
                native_record = research["native_decision"]
                final = deepcopy(research["composed_decision"])
            else:
                native_record = pre[0]
                final = deepcopy(pre[0])
            composed_requirement = final["verdict"]
            if composed_requirement == "step_up" and outcomes:
                # Research description of the observed native approval branch,
                # not a new native Decision or a replacement authorization rule.
                final = {"verdict": "allow" if outcomes[0]["approved"] else "block",
                         "source": "observed_native_gateway_approval_branch",
                         "native_requirement": "step_up", "rule_id": native_record["rule_id"],
                         "reason": "Simulated approval source: " + outcomes[0]["status"]}
            original = deepcopy(case["input"]["proposed_action"])
            effective = {"tool": forwarded[0]["name"], "arguments": deepcopy(forwarded[0]["arguments"])} if forwarded else None
            # Known unchanged-argument approval fixtures and unsupported modify
            # refusal bind all supported forwarding. An unexpected mismatch is
            # surfaced as a failed integration, never counted as agreement.
            if research and any(action_hash({"tool": p["name"], "arguments": p["arguments"]})
                                != action_hash(original) for p in forwarded):
                raise RuntimeError("forwarded action differs from the judged action; composition unsupported")
            extra = {"original_action": original, "effective_transformed_action": effective,
                     "judge_visible_action": original if research and research["judge_results"] else None,
                     "forwarded_arguments": [deepcopy(p["arguments"]) for p in forwarded],
                     "binding_status": "matched" if research and forwarded else "not_forwarded"
                     if research else "not_applicable",
                     "judge_results": [], "judge_call_count": 0, "scripted_call_count": 0,
                     "judge_errors": [],
                     "model_call_count": 0, "composition_status": "supported",
                     "routing_reason": "native_rules", "judgment_provenance": None,
                     "human_approval_route": {"native_required": native_record["verdict"] == "step_up",
                                              "route": "native_gateway_approval" if outcomes else "not_requested"}}
            if research:
                extra.update({k: deepcopy(research[k]) for k in (
                    "judge_results", "judge_call_count", "scripted_call_count", "model_call_count",
                    "composition_status", "routing_reason", "judgment_provenance", "human_approval_route")})
                extra["judge_errors"] = [deepcopy(call["result"]) for call in research["judge_results"]
                                         if call["result"]["status"] == "error"]
                if research["composition_status"] == "unsupported":
                    extra["binding_status"] = "unsupported"
            extra["native_defer_resolution"] = "unsupported_at_production_gateway" if native_record["verdict"] == "defer" else "not_required"
            extra["human_approval_route"]["outcome"] = deepcopy(outcomes[0]) if outcomes else None
            return {"native_decision": native_record, "final_pre_action_decision": final,
                    "composed_pre_action_decision": deepcopy(research["composed_decision"]) if research else deepcopy(pre[0]),
                    "judge_decision": deepcopy(research["judge_decision"]) if research else None,
                    "actual_forwarding": {"tools_call_count": len(forwarded),
                                          "requests": deepcopy(forwarded)},
                    "approval_outcome": outcomes[0] if outcomes else None,
                    "post_action": post,
                    "response_status": "tool_error" if reply["result"].get("isError") else "ok", **extra}
        finally:
            # Observe before cleanup, including exceptions raised after forwarding.
            # Detection after a call is evidence of execution, not prevention.
            forwarded = [deepcopy(p) for method, p in upstream.requests if method == "tools/call"]
            records = getattr(gateway, "research_records", [])
            research = records[0] if records else None
            original = deepcopy(case["input"]["proposed_action"])
            mismatch = any(action_hash({"tool": p["name"], "arguments": p["arguments"]})
                           != action_hash(original) for p in forwarded)
            evidence.update(
                upstream_requests=deepcopy(upstream.requests),
                actual_forwarding={"tools_call_count": len(forwarded), "requests": forwarded}
                if mode == "gateway" else None,
                forwarded_arguments=[deepcopy(p["arguments"]) for p in forwarded],
                native_decision=deepcopy(research["native_decision"]) if research else deepcopy(pre[0]) if pre else None,
                decision_snapshots=deepcopy(pre), post_action=deepcopy(post),
                approval_outcome=deepcopy(outcomes[0]) if outcomes else None,
                approval_requests=deepcopy(requests), original_action=original,
                effective_transformed_action={"tool": forwarded[0]["name"], "arguments": deepcopy(forwarded[0]["arguments"])} if forwarded else None,
                binding_status="mismatch_observed_after_forward" if mismatch else "matched" if forwarded else "not_forwarded",
                model_call_count=research["model_call_count"] if research else 0,
                judge_call_count=research["judge_call_count"] if research else 0,
                scripted_call_count=research["scripted_call_count"] if research else 0,
                judge_results=deepcopy(research["judge_results"]) if research else [],
                composed_pre_action_decision=deepcopy(research["composed_decision"]) if research else deepcopy(pre[0]) if pre else None)
            gateway.close()
