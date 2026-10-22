"""Offline integration infrastructure. No provider protocol or real inference."""
from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from research.harness_alignment.casebook import ROOT, load
from research.harness_alignment.comparison import (
    judge_agreement, main, plans, select_pair,
)
from research.harness_alignment.judge import JudgeRequest, Judgment
from research.harness_alignment.model_io import (
    Budget, dispatch, missing_prerequisites, replay, request_identity,
)
from research.harness_alignment.evidence import RecordingBoundary
from research.harness_alignment.offline import evaluate_native
from research.harness_alignment.runner import run_cases


def request():
    return JudgeRequest.from_input(load()["cases"][0]["input"])


def identity():
    return request_identity(request(), model_version="synthetic-test-version",
                            inference_configuration={"output_limit": 50, "timeout_seconds": 1},
                            conditioning={"prompt": "explicit synthetic test"},
                            adapter="offline-test", parser_version="fixture-v1", aggregation_version="single-v1")


def envelope(**kwargs):
    return {"raw_response": {"answer": "allow", "confidence_text": "perhaps"},
            "actual_model_version": "synthetic-test-version", **kwargs}


def parse_fixture(raw):
    return Judgment(raw["answer"], "test", raw)


TEST_BOUNDARY = RecordingBoundary(kind="test_fixture", parsers={("offline-test", "fixture-v1"): parse_fixture})


def attempt(send, **kwargs):
    return dispatch(Budget({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": 1}, 1),
                    identity(), send, parse_fixture, boundary=TEST_BOUNDARY,
                    timeout_seconds=1, output_limit=50, **kwargs)


def test_disabled_gate_precedes_every_callback():
    send, parse = Mock(), Mock()
    budget = Budget({"LIVE_MODEL_RUN": False, "MAX_REAL_REQUESTS": 100}, 2)
    with pytest.raises(PermissionError):
        dispatch(budget, identity(), send, parse, timeout_seconds=1, output_limit=50)
    send.assert_not_called()
    parse.assert_not_called()
    assert budget.requests == 0


def test_budget_counts_questions_and_failed_retry_not_just_decisions():
    budget = Budget({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": 10}, 2)
    send = Mock(side_effect=TimeoutError)
    for _ in range(2):
        row = dispatch(budget, identity(), send, Mock(), timeout_seconds=1, output_limit=50)
        assert row["status"] == "timeout"
    with pytest.raises(PermissionError):
        dispatch(budget, identity(), send, Mock(), timeout_seconds=1, output_limit=50)
    assert budget.requests == send.call_count == 2


@pytest.mark.parametrize("settings,cap", [({"LIVE_MODEL_RUN": "false", "MAX_REAL_REQUESTS": 0}, 1),
    ({"LIVE_MODEL_RUN": False, "MAX_REAL_REQUESTS": True}, 1),
    ({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": -1}, 1),
    ({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": 1}, -1)])
def test_invalid_budget(settings, cap):
    with pytest.raises(ValueError):
        Budget(settings, cap)


@pytest.mark.parametrize("failure,status", [(TimeoutError, "timeout"), (ConnectionError, "unavailable"),
                                            (ValueError, "invalid_output")])
def test_distinct_failures(failure, status):
    row = attempt(Mock(side_effect=failure("synthetic credential must not be echoed")))
    assert row["status"] == status
    assert "credential" not in json.dumps(row)
    assert row["live_latency_ms"] is None


def test_raw_native_fields_preserved_without_fake_probabilities_usage_or_cost():
    row = attempt(Mock(return_value=envelope()))
    assert row["status"] == row["parsing_status"] == "valid"
    assert row["raw_response"]["confidence_text"] == "perhaps"
    assert row["normalized"]["native_fields"] == row["raw_response"]
    assert row["usage"] is row["monetary_cost"] is None
    assert row["measured_attempt_ms"] >= 0 and row["live_latency_ms"] is None
    assert "probabilities" not in row


def test_provider_usage_and_cost_retained_only_when_present():
    row = attempt(Mock(return_value=envelope(usage={"tokens": 2}, monetary_cost={"usd": 0.001})))
    assert row["usage"] == {"tokens": 2}
    assert row["monetary_cost"] == {"usd": 0.001}


def test_missing_actual_version_is_invalid():
    assert attempt(Mock(return_value=envelope(actual_model_version=None)))["status"] == "invalid_output"


def test_mismatched_limits_are_rejected_before_budget_or_send():
    budget, send = Budget({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": 1}, 1), Mock()
    with pytest.raises(ValueError, match="hashed inference configuration"):
        dispatch(budget, identity(), send, Mock(), timeout_seconds=1, output_limit=99)
    assert budget.requests == 0
    send.assert_not_called()


def test_credentials_redacted_from_raw_and_normalized_records():
    row = attempt(Mock(return_value=envelope(raw_response={"answer": "allow", "text": "synthetic-credential"})),
                  credential_values=("synthetic-credential",))
    assert "synthetic-credential" not in json.dumps(row)
    assert row["raw_response"]["text"] == "[credential redacted]"


def genuine_replay_fixture():
    # Explicit fabricated test provenance to exercise replay verification, NOT
    # written to pilot records and never evidence of an actual model response.
    return attempt(Mock(return_value=envelope()))


@pytest.mark.parametrize("field", ["judge_input", "model_version", "inference_configuration", "conditioning"])
def test_replay_requires_complete_identity(field):
    row = genuine_replay_fixture()
    changed = deepcopy(identity())
    changed[field] = {"different": True} if field != "model_version" else "other-version"
    with pytest.raises(ValueError):
        replay(row, changed, boundary=TEST_BOUNDARY)


def test_replay_matches_policy_context_and_never_claims_live_latency():
    row = genuine_replay_fixture()
    result = replay(row, identity(), boundary=TEST_BOUNDARY)
    assert result["provenance"] == "offline_replay" and result["live_latency_ms"] is None
    assert result["replay_processing_ms"] >= 0
    changed = identity()
    changed["judge_input"]["policy"]["text"] += " changed"
    with pytest.raises(ValueError):
        replay(row, changed, boundary=TEST_BOUNDARY)
    row["actual_model_version"] = "different-version"
    with pytest.raises(ValueError):
        replay(row, identity(), boundary=TEST_BOUNDARY)


def test_scripted_or_test_records_cannot_be_replayed_as_models():
    with pytest.raises(ValueError):
        replay(attempt(Mock(return_value=envelope())), identity())


def test_evaluator_labels_ids_review_and_group_do_not_change_full_request_identity():
    case = deepcopy(load()["cases"][0])
    before = JudgeRequest.from_input(case["input"])
    case["evaluator"] = {"id": "different", "expected": "deny", "label_status": "reviewed"}
    assert before == JudgeRequest.from_input(case["input"])


def test_comparison_gateway_short_circuits_native_block_but_keeps_forwarding_implementation():
    case = next(c for c in load()["cases"] if c["evaluator"]["id"] == "task-edit")
    row = evaluate_native(case, "gateway", {"experiment": "scripted-fast", "native_short_circuit": True,
                         "fast": [{"decision": "allow", "reason": "test"}], "stronger": []})
    assert row["native_decision"]["verdict"] == "block"
    assert row["actual_forwarding"]["tools_call_count"] == 0
    assert row["judge_results"] == [] and row["judge_call_count"] == 0
    assert row["routing_reason"] == "native_block_short_circuit"


def test_pair_planning_does_not_short_circuit_judge_only_or_fabricate_execution():
    book = load()
    native = run_cases(book, "validate", "test", "test")
    # Supply only baseline reference for routing, not fake execution records.
    row = next(r for r in native if r["case_id"] == "task-edit")
    row.update(status="ok", native_decision={"verdict": "block"})
    models = json.loads((ROOT / "models.json").read_text())
    rows = plans(book, models, select_pair(book, "task:0"), native)
    pair = [r for r in rows if r["evaluation"] == "judge-only" and r["configuration_id"] == "native-plus-niti"]
    assert {r["case_id"] for r in pair} == {"task-read", "task-edit"}
    assert all(r["actual_forwarding"] is None and r["judges_actually_run"] == [] for r in pair)
    assert all(r["planned_route"] == "both_pair_members_independently" for r in pair)
    assert next(r for r in rows if r["evaluation"] == "gateway" and r["case_id"] == "task-edit")["planned_route"] == "native_block_short_circuit"
    assert all(missing_prerequisites(c) for c in models.values())


SCORE_BOUNDARY = None


def score_rows():
    global SCORE_BOUNDARY
    SCORE_BOUNDARY = RecordingBoundary(kind="test_fixture", parsers={("offline-test", "fixture-v1"): parse_fixture})
    rows = []
    for cid, decision in (("task-read", "allow"), ("task-edit", "deny")):
        case = next(c for c in load()["cases"] if c["evaluator"]["id"] == cid)
        ident = identity()
        ident["judge_input"] = json.loads(JudgeRequest.from_input(case["input"]).serialized_input)
        SCORE_BOUNDARY.declare(cid, "test", "judge-only", [ident])
        record = dispatch(Budget({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": 1}, 1),
                          ident, Mock(return_value=envelope(raw_response={"answer": decision})),
                          parse_fixture, timeout_seconds=1, output_limit=50, boundary=SCORE_BOUNDARY)
        rows.append({"case_id": cid, "configuration_id": "test", "evaluation": "judge-only", "status": "ok",
                     "response_provenance": "test_fixture", "judge_decision": {"decision": decision},
                     "aggregation_version": "single-v1", "model_attempts": [record],
                     "model_call_count": 1, "judges_actually_run": ["offline-test"]})
    return rows


def test_paired_judge_scoring_needs_both_valid_genuine_responses_and_suitable_labels():
    book, rows = load(), score_rows()
    def scores(rs, label="provisional"):
        return judge_agreement(book, rs, configuration_id="test", evaluation="judge-only", label_status=label, boundary=SCORE_BOUNDARY, evidence_kind="test_fixture")
    assert scores(rows)["pairs"] == {"matches": 1, "denominator": 1, "rate": 1}
    assert scores(rows[:1])["pairs"]["rate"] is None
    assert scores(rows, "human_reviewed")["cases"]["rate"] is None
    for provenance in ("scripted", "offline_replay", None):
        changed = deepcopy(rows)
        changed[1]["response_provenance"] = provenance
        assert scores(changed)["pairs"]["denominator"] == 0
    changed = deepcopy(rows)
    changed[1]["judge_decision"]["decision"] = "allow"
    assert scores(changed)["pairs"]["matches"] == 0
    assert scores(rows + rows)["cases"]["denominator"] == 0
    for field, value in (("model_attempts", []), ("model_call_count", 0), ("judges_actually_run", [])):
        changed = deepcopy(rows)
        changed[1][field] = value
        assert scores(changed)["pairs"]["denominator"] == 0


def test_real_smoke_false_is_refused_before_inference(tmp_path, capsys):
    assert main(["--mode", "real-smoke", "--max-real-requests", "2", "--output", str(tmp_path / "run")]) == 2
    assert "disabled" in capsys.readouterr().out
    assert not (tmp_path / "run").exists()


def test_enabled_without_verified_interface_still_refuses(tmp_path, capsys):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"LIVE_MODEL_RUN": True, "MAX_REAL_REQUESTS": 2}))
    assert main(["--mode", "real-smoke", "--settings", str(settings), "--max-real-requests", "2"]) == 2
    assert "no verified concrete adapters" in capsys.readouterr().out


def test_dry_run_records_actual_native_observations_and_unavailable_models(tmp_path, capsys):
    output = tmp_path / "run"
    assert main(["--mode", "dry-run", "--output", str(output)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["real_requests"] == 0 and printed["observed_tools_call_count"] == 10
    report = json.loads((output / "pilot.json").read_text())
    assert report["native_provisional_forwarding_errors"] == {"incorrect_permits": 0, "unnecessary_blocks": 0, "denominator": 15}
    assert report["model_outcomes"]["live_latency_ms"] is None
    for result in report["judge_evaluations"].values():
        assert result["reviewed_correctness"]["pairs"]["rate"] is None
        assert result["provisional_development_agreement"]["pairs"]["denominator"] == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["effective_max_real_requests"] == 0
    assert manifest["native_shipped_semantic_configuration"]["enabled"] is True
    assert "--max-real-requests 2" in printed["future_smoke_command"]
    assert main(["--mode", "dry-run", "--output", str(output)]) == 2
