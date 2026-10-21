"""Scripted control-flow integration, never model-performance evidence."""
from copy import deepcopy
import json
from unittest.mock import patch

import pytest

from prismor.runtime.contract import Decision
from prismor.runtime import mcp_gateway

from research.harness_alignment.casebook import load, summarize
from research.harness_alignment.judge import (
    JudgeError, JudgeRequest, Judgment, ScriptedJudge, configuration,
)
from research.harness_alignment.judged_gateway import ResearchGateway, compose
from research.harness_alignment.offline import RecordingUpstream, evaluate_native, isolated
from research.harness_alignment.runner import main, run_cases


def case(cid="task-read"):
    return next(c for c in load()["cases"] if c["evaluator"]["id"] == cid)


def plan(fast="allow", stronger="allow", experiment="scripted-fast"):
    def payload(value):
        return value if isinstance(value, dict) else {"decision": value, "reason": "Explicit scripted control."}
    return {"experiment": experiment, "fast": [payload(fast)], "stronger": [payload(stronger)]}


def observe(cid="task-read", config=None):
    return evaluate_native(case(cid), "gateway", config or plan())


def test_native_block_cannot_be_cleared_by_scripted_allow():
    row = observe("task-edit")
    assert row["native_decision"]["verdict"] == "block"
    assert row["judge_decision"]["decision"] == "allow"
    assert row["final_pre_action_decision"]["verdict"] == "block"
    assert row["actual_forwarding"]["tools_call_count"] == 0
    assert row["judge_call_count"] == 1 and row["model_call_count"] == 0


@pytest.mark.parametrize("experiment", ["scripted-fast", "scripted-stronger", "scripted-selective"])
def test_missing_native_approval_cannot_be_supplied_by_another_judge(experiment):
    config = plan("unresolved_semantics" if experiment == "scripted-selective" else "allow",
                  "allow", experiment)
    row = observe("upload-missing", config)
    assert row["native_decision"]["verdict"] == "step_up"
    assert row["composed_pre_action_decision"]["verdict"] == "step_up"
    assert row["judge_decision"]["decision"] == "allow"
    assert row["final_pre_action_decision"]["verdict"] == "block"
    assert row["approval_outcome"]["status"] == "request_failed"
    assert row["human_approval_route"]["route"] == "native_gateway_approval"
    assert row["actual_forwarding"]["tools_call_count"] == 0


@pytest.mark.parametrize("judgment,count", [("deny", 0), ("allow", 1), ("missing_authorization", 0),
                                           ("unresolved_semantics", 0)])
def test_native_allow_obeys_research_refusal_and_valid_allow(judgment, count):
    row = observe(config=plan(judgment))
    assert row["native_decision"]["verdict"] == "allow"
    assert row["actual_forwarding"]["tools_call_count"] == count
    assert row["judge_decision"]["decision"] == judgment
    assert row["judge_errors"] == []
    assert row["final_pre_action_decision"]["verdict"] == ("allow" if count else "block")


@pytest.mark.parametrize("stronger,count", [("allow", 1), ("deny", 0), ("missing_authorization", 0),
                                          ("unresolved_semantics", 0)])
def test_selective_semantic_escalation_is_research_only(stronger, count):
    row = observe(config=plan("unresolved_semantics", stronger, "scripted-selective"))
    assert row["native_decision"]["verdict"] == "allow"
    assert [c["route"] for c in row["judge_results"]] == ["fast", "stronger"]
    assert row["judge_call_count"] == 2
    assert row["actual_forwarding"]["tools_call_count"] == count
    assert "research_semantic_escalation" in row["routing_reason"]


def test_selective_mode_never_treats_missing_authorization_as_semantic_uncertainty():
    row = observe(config=plan("missing_authorization", "allow", "scripted-selective"))
    assert row["judge_call_count"] == 1
    assert row["actual_forwarding"]["tools_call_count"] == 0
    assert row["approval_outcome"] is None


@pytest.mark.parametrize("bad,error", [({"decision": ["allow"], "reason": "bad type"}, "invalid_output"),
                                      ({"error": "timeout"}, "timeout"),
                                      ({"error": "unavailable"}, "unavailable")])
@pytest.mark.parametrize("stage", ["fast", "stronger"])
def test_invalid_timeout_or_unavailable_never_silently_permits(bad, error, stage):
    config = plan(bad) if stage == "fast" else plan("unresolved_semantics", bad, "scripted-selective")
    row = observe(config=config)
    assert row["actual_forwarding"]["tools_call_count"] == 0
    assert row["final_pre_action_decision"]["verdict"] == "block"
    assert row["judge_decision"] is None
    assert row["judge_errors"][-1]["kind"] == error
    assert row["judge_errors"][-1]["native_fields"] == bad
    assert row["judge_call_count"] == (1 if stage == "fast" else 2)


def test_no_discovery_or_post_action_calls_and_forwarded_action_is_bound():
    row = observe()
    assert len(row["post_action"]) == 1
    assert row["judge_call_count"] == row["scripted_call_count"] == 1
    assert row["model_call_count"] == 0
    assert row["binding_status"] == "matched"
    assert row["original_action"] == row["judge_visible_action"] == row["effective_transformed_action"]
    assert row["forwarded_arguments"] == [row["original_action"]["arguments"]]
    assert all(c["provenance"]["kind"] == "scripted" for c in row["judge_results"])
    assert all(c["judge_visible_input"]["proposed_action"] == row["original_action"] for c in row["judge_results"])


def test_native_snapshot_is_independent_and_composition_uses_native_precedence():
    for action in ("modify", "step_up", "block"):
        finding = {"ruleId": "native-rule", "action": action, "transform": "pii_redact",
                   "mode": "enforce", "title": "Native finding", "category": "fixture"}
        native = Decision(allow=False, findings=[finding], blocking=finding)
        original = deepcopy(native.as_dict())
        composed = compose(native, {"ruleId": "research", "action": "block", "mode": "enforce",
                                    "title": "Research deny"})
        assert composed.verdict == "block"
        assert composed.findings[0] == original["findings"][0]
        composed.findings[0]["title"] = "changed copy"
        assert native.as_dict() == original
        allowed = compose(native, {"ruleId": "research", "action": "log", "mode": "observe", "title": "Allow"})
        assert allowed.verdict == action and allowed.transform == "pii_redact"
    row = observe(config=plan("deny"))
    assert not any(f["category"] == "research_judgment" for f in row["native_decision"]["findings"])
    assert any(f["category"] == "research_judgment" for f in row["final_pre_action_decision"]["findings"])
    json.dumps(row)  # Full snapshots, including original native fields, serialize.


@pytest.mark.parametrize("judgment", ["allow", "deny"])
def test_modify_is_unsupported_before_forwarding_and_deny_still_dominates(judgment):
    fixture = case()
    fixture["evaluator"]["native_setup"]["policy"] = "policies/judge_controls.yaml"
    fixture["input"]["proposed_action"]["arguments"] = {"marker": "HA_MODIFY", "message": "synthetic"}
    row = evaluate_native(fixture, "gateway", plan(judgment))
    assert row["native_decision"]["verdict"] == "modify"
    assert row["native_decision"]["transform"] == "pii_redact"
    assert row["composition_status"] == "unsupported"
    assert row["final_pre_action_decision"]["verdict"] == "block"
    assert row["final_pre_action_decision"]["findings"][0] == row["native_decision"]["findings"][0]
    assert row["actual_forwarding"]["tools_call_count"] == 0
    assert row["effective_transformed_action"] is None


def test_redacted_approval_is_unsupported_before_native_approval_and_forwarding():
    fixture = case("upload-present")
    fixture["evaluator"]["native_setup"]["approval_source"] = "approved_redacted"
    row = evaluate_native(fixture, "gateway", plan())
    assert row["native_decision"]["verdict"] == "step_up"
    assert row["composition_status"] == "unsupported"
    assert row["actual_forwarding"]["tools_call_count"] == 0
    assert row["approval_outcome"] is None
    assert row["human_approval_route"]["route"] == "not_reached_due_to_refusal"


def test_full_native_approval_is_preserved_and_not_judge_supplied_permission():
    row = observe("upload-present")
    assert row["native_decision"]["verdict"] == "step_up"
    assert row["approval_outcome"]["approved"] is True
    assert row["approval_outcome"]["simulated"] is True
    assert row["actual_forwarding"]["tools_call_count"] == 1
    assert row["binding_status"] == "matched"


def test_native_defer_is_not_misrepresented_as_production_escalation():
    fixture = case()
    fixture["evaluator"]["native_setup"]["policy"] = "policies/judge_controls.yaml"
    fixture["input"]["proposed_action"]["arguments"] = {"marker": "HA_DEFER"}
    baseline = evaluate_native(fixture, "gateway")
    assert baseline["native_decision"]["verdict"] == "defer"
    assert baseline["actual_forwarding"]["tools_call_count"] == 0
    row = evaluate_native(fixture, "gateway", plan("unresolved_semantics", "allow", "scripted-selective"))
    assert row["native_defer_resolution"] == "unsupported_at_production_gateway"
    assert row["composition_status"] == "unsupported"
    assert row["judge_call_count"] == 1
    assert row["actual_forwarding"]["tools_call_count"] == 0


def test_stronger_allow_after_uncertainty_cannot_clear_native_block():
    row = observe("task-edit", plan("unresolved_semantics", "allow", "scripted-selective"))
    assert row["judge_call_count"] == 2
    assert row["judge_decision"]["decision"] == "allow"
    assert row["native_decision"]["verdict"] == "block"
    assert row["actual_forwarding"]["tools_call_count"] == 0


def test_action_binding_mismatch_refuses_before_any_judge_or_forwarding():
    visible = case()["input"]
    with isolated("policies/read_only.yaml", "not_requested") as (workspace, attempts, requests, stack):
        spec = mcp_gateway.UpstreamSpec(name="fixture", command=["true"])
        upstream = RecordingUpstream(spec)
        stack.enter_context(patch.object(mcp_gateway, "make_upstream", lambda *a, **k: upstream))
        gateway = ResearchGateway([spec], workspace=workspace, mode="enforce", visible_input=visible,
                                  experiment="scripted-fast", fast=ScriptedJudge("scripted-fast", plan()["fast"]))
        stack.enter_context(patch.object(gateway, "_send", lambda msg: None))
        try:
            gateway._handle_tools_list("list", {})
            with gateway.judging_action():
                gateway._handle_tools_call_safe("call", {"name": "fixture__echo", "arguments": {"operation": "read", "resource": "different.txt"}})
            record = gateway.research_records[0]
            assert record["composition_status"] == "unsupported"
            assert record["judge_call_count"] == 0
            assert not any(method == "tools/call" for method, _ in upstream.requests)
        finally:
            gateway.close()


def test_judge_contract_provenance_raw_fields_and_no_cross_case_cache():
    request = JudgeRequest.from_input(case()["input"])
    raw = {"decision": "allow", "reason": "Scripted test", "provider_extension": {"synthetic": True}}
    judge = ScriptedJudge("explicit-control", [raw])
    reply = judge.judge(request)
    assert isinstance(reply, Judgment) and reply.native_fields == raw
    assert not hasattr(reply, "confidence")
    assert isinstance(judge.judge(request), JudgeError)  # exhaustion fails closed
    assert judge.provenance["kind"] == "scripted"
    for _ in range(2):
        assert observe()["judge_call_count"] == 1


def test_judge_requests_exclude_changed_evaluator_metadata():
    original = case()
    changed = deepcopy(original)
    changed["evaluator"]["id"] = "changed-id"
    changed["evaluator"]["expected"] = {"judgment": "block", "native_requirement": "block", "forwarding": False}
    changed["evaluator"]["rationale"] = "changed evaluator-only rationale"
    assert JudgeRequest.from_input(original["input"]) == JudgeRequest.from_input(changed["input"])
    first = evaluate_native(original, "gateway", plan())
    second = evaluate_native(changed, "gateway", plan())
    assert first["judge_results"] == second["judge_results"]
    assert first["actual_forwarding"] == second["actual_forwarding"]


def test_inherited_forwarding_and_no_semantic_guard_completion_adapter():
    assert ResearchGateway._handle_tools_call is mcp_gateway.Gateway._handle_tools_call
    assert ResearchGateway._handle_tools_call_safe is mcp_gateway.Gateway._handle_tools_call_safe


def test_scripted_runner_metrics_are_not_model_agreement_and_cli_records_configuration(tmp_path):
    book = load()
    rows = run_cases(book, "gateway", "test", "config", "scripted-stronger")
    assert sum(r["status"] == "ok" for r in rows) == 15
    assert sum(r["judge_call_count"] for r in rows) == 15
    assert sum(r["model_call_count"] for r in rows) == 0
    assert sum((r["actual_forwarding"] or {}).get("tools_call_count", 0) for r in rows) == 0
    scores = summarize(book, rows)["provisional_development_agreement"]
    assert scores["judgment"]["cases"]["rate"] is None
    assert scores["forwarding"]["cases"]["rate"] is None
    output = tmp_path / "scripted-run"
    assert main(["--mode", "gateway", "--experiment", "scripted-fast", "--output", str(output)]) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["configuration"]["cross_case_caching"] is False
    assert manifest["configuration"]["research_judge"] == configuration("scripted-fast")


def test_runner_records_judge_error_as_distinct_from_a_valid_judgment():
    from research.harness_alignment import runner
    book = {"cases": [case()]}
    with patch.object(runner, "judge_configuration", lambda mode: plan({"error": "timeout"})):
        row = run_cases(book, "gateway", "test", "config", "scripted-fast")[0]
    assert row["status"] == "judge_error" and row["error"]
    assert row["judge_decision"] is None
    assert row["actual_forwarding"]["tools_call_count"] == 0
