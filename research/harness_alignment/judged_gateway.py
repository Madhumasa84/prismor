"""Research composition at the real gateway evaluator seam; no forwarding fork."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json

from prismor.runtime.contract import Decision, strongest
from prismor.runtime.mcp_gateway import Gateway

from .judge import EXPERIMENTS, JudgeError, JudgeRequest, Judgment, action_hash, reply_record


def compose(native, research_finding):
    """Construct via the native contract; never assign derived verdict fields."""
    findings = deepcopy(native.findings) + [deepcopy(research_finding)]
    candidates = [deepcopy(native.blocking)] if native.blocking else []
    if research_finding["action"] == "block":
        candidates.append(deepcopy(research_finding))
    blocking = strongest(candidates)
    return Decision(allow=blocking is None, findings=findings, blocking=blocking,
                    reason=(native.reason if blocking == native.blocking else blocking["title"])
                    if blocking else None,
                    subject=native.subject, engine=native.engine, explain=deepcopy(native.explain))


class ResearchGateway(Gateway):
    """Only _evaluate is extended. All tool forwarding/approval stays inherited.

    General input transformations are unsupported. STEP_UP is supported only
    with this runner's known unchanged-argument approval fixtures; callers that
    cannot establish that property get a refusal before any forwarding.
    """
    def __init__(self, *args, visible_input, experiment, fast=None, stronger=None,
                 unchanged_approval_fixture=False, **kwargs):
        if experiment not in EXPERIMENTS[1:] or kwargs.get("mode", "enforce") != "enforce":
            raise ValueError("research gateway requires an explicit scripted mode and enforcement")
        super().__init__(*args, **kwargs)
        self._request = JudgeRequest.from_input(visible_input)
        self.experiment = experiment
        self.fast, self.stronger = fast, stronger
        self.unchanged_approval_fixture = unchanged_approval_fixture
        self._research_active = False
        self.research_records = []

    @contextmanager
    def judging_action(self):
        self._research_active = True
        try:
            yield
        finally:
            self._research_active = False

    def _invoke(self, judge, route, record):
        # Record the attempt even when a provider raises or returns a bad type.
        call = {"route": route, "provenance": deepcopy(judge.provenance) if judge else
                {"kind": "scripted", "judge": "unavailable"},
                "judge_visible_input": json.loads(self._request.serialized_input),
                "action_sha256": self._request.action_sha256}
        record["judge_results"].append(call)
        try:
            result = judge.judge(self._request) if judge else JudgeError("unavailable", "judge not configured")
            if not isinstance(result, (Judgment, JudgeError)):
                result = JudgeError("invalid_output", "provider returned an invalid reply type")
        except TimeoutError:
            result = JudgeError("timeout", "judge invocation timed out")
        except Exception as exc:
            result = JudgeError("unavailable", f"judge invocation failed: {type(exc).__name__}")
        call["result"] = reply_record(result)
        return result

    def _evaluate(self, event):
        native = super()._evaluate(event)
        if (not self._research_active or event.get("agent_event") != "PreToolUse"
                or event.get("mcp_server") != "fixture" or event.get("mcp_tool") != "echo"):
            return native
        if native is None:
            raise RuntimeError("research composition requires a native enforce-mode Decision")
        actual = {"tool": event["mcp_tool"], "arguments": deepcopy(event["metadata"].get("kwargs"))}
        # as_dict exposes references to findings: copy BEFORE composition.
        record = {"native_decision": deepcopy(native.as_dict()), "judge_results": [],
                  "routing_reason": None, "composition_status": "supported",
                  "judge_decision": None, "judgment_provenance": "scripted",
                  "original_action": actual,
                  "model_call_count": 0}
        self.research_records.append(record)
        unsupported = None
        if action_hash(actual) != self._request.action_sha256:
            unsupported = "Action differs from the judge-visible proposal."
        elif native.verdict == "modify":
            unsupported = "Native input transformation cannot be safely judged at this pre-transform seam."
        elif native.verdict == "defer":
            unsupported = "Production gateway does not resolve native defer; research does not clear it."
        elif native.verdict == "step_up" and not self.unchanged_approval_fixture:
            unsupported = "Approval may transform arguments; only verified full-approval fixtures are supported."

        result = None
        if unsupported and action_hash(actual) != self._request.action_sha256:
            record["routing_reason"] = "unsupported_action_binding"
        else:
            if self.experiment == "scripted-stronger":
                result = self._invoke(self.stronger, "stronger", record)
                record["routing_reason"] = "direct_scripted_stronger"
            else:
                result = self._invoke(self.fast, "fast", record)
                record["routing_reason"] = "direct_scripted_fast"
                if (self.experiment == "scripted-selective" and isinstance(result, Judgment)
                        and result.decision == "unresolved_semantics" and not unsupported):
                    result = self._invoke(self.stronger, "stronger", record)
                    record["routing_reason"] = "research_semantic_escalation"
            if isinstance(result, Judgment):
                record["judge_decision"] = reply_record(result)

        refusal = unsupported
        if unsupported:
            record["composition_status"] = "unsupported"
            record["routing_reason"] = (record["routing_reason"] or "unsupported") + ": " + unsupported
        if isinstance(result, JudgeError):
            refusal = f"Research judge error: {result.kind}: {result.message}"
            record["routing_reason"] += ": error_" + result.kind
        elif isinstance(result, Judgment) and result.decision != "allow":
            refusal = f"Research judgment {result.decision}: {result.reason}"
            record["routing_reason"] += ": " + result.decision + "_hold"
        elif isinstance(result, Judgment):
            record["routing_reason"] += ": allow_preserves_native"
        if refusal is None and result is None:
            refusal = "No research judgment is available."
        finding = {"ruleId": "research-judge-refusal" if refusal else "research-judge-allow",
                   "category": "research_judgment", "severity": "HIGH" if refusal else "INFO",
                   "title": refusal or "Scripted research allow; native requirements remain authoritative.",
                   "mode": "enforce" if refusal else "observe", "action": "block" if refusal else "log",
                   "provenance": "research_extension_scripted"}
        final = compose(native, finding)
        record["composed_decision"] = deepcopy(final.as_dict())
        record["judge_call_count"] = len(record["judge_results"])
        record["scripted_call_count"] = record["judge_call_count"]
        record["human_approval_route"] = {
            "native_required": native.verdict == "step_up",
            "research_authorization_required": isinstance(result, Judgment) and result.decision == "missing_authorization",
            "route": "native_gateway_approval" if final.verdict == "step_up" else
                     "not_reached_due_to_refusal" if native.verdict == "step_up" else
                     "research_authorization_hold_no_verified_approval_route"
                     if isinstance(result, Judgment) and result.decision == "missing_authorization" else "not_required"}
        return final
