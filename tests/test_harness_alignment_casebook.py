"""Development casebook checks; preserve the four-case Prompt 2 test separately."""
from copy import deepcopy
import hashlib
import json

import pytest

from research.harness_alignment.casebook import load, serialize_judge_request, summarize, validate
from research.harness_alignment.offline import evaluate_native, isolated
from research.harness_alignment.runner import main, run_cases


def test_casebook_coverage_and_provisional_labels():
    book = load()
    assert len(book["cases"]) == 24
    assert len(book["families"]) == 8
    assert sum(len(f["scored_pairs"]) for f in book["families"]) == 16
    assert sum(c["evaluator"]["label_status"] == "unresolved" for c in book["cases"]) == 2
    assert all(c["evaluator"]["label_status"] in ("provisional", "unresolved") for c in book["cases"])


@pytest.mark.parametrize("mutation", ["duplicate_id", "membership", "pair", "provenance",
                                    "unknown_field", "reviewed", "policy", "approval_evidence"])
def test_validation_rejects_invalid_casebooks(mutation):
    book = load()
    if mutation == "duplicate_id":
        book["cases"][1]["evaluator"]["id"] = book["cases"][0]["evaluator"]["id"]
    elif mutation == "membership":
        book["cases"][0]["evaluator"]["family"] = "wrong"
    elif mutation == "pair":
        book["families"][0]["scored_pairs"][0] = ["not-a-member", "task-read"]
    elif mutation == "provenance":
        del book["cases"][0]["input"]["policy"]["provenance"]
    elif mutation == "unknown_field":
        book["cases"][0]["input"]["expected"] = "allow"
    elif mutation == "reviewed":
        book["cases"][0]["evaluator"]["label_status"] = "human-reviewed"
    elif mutation == "policy":
        book["cases"][0]["evaluator"]["native_setup"]["policy"] = "../../.prismor/policy.yaml"
    else:
        next(c for c in book["cases"] if c["evaluator"]["id"] == "upload-present")["input"]["authorization_evidence"] = []
    with pytest.raises(ValueError):
        validate(book)


def test_evaluator_only_metadata_cannot_change_judge_request():
    # Exercise every case, not merely one empty request. Labels, IDs, membership,
    # rationale, review status and integration config all remain outside input.
    for case in load()["cases"]:
        changed = deepcopy(case)
        changed["evaluator"] = {"id": "different-id", "family": "different-family",
                                "expected": {"judgment": "opposite"},
                                "label_status": "arbitrary-review-metadata",
                                "rationale": "different rationale", "native_setup": {}}
        original_request = serialize_judge_request(case)
        assert serialize_judge_request(changed) == original_request
        assert json.loads(original_request) == case["input"]
        changed["input"]["policy"]["text"] += " A trusted policy update."
        assert serialize_judge_request(changed) != original_request


def test_decision_only_never_reports_execution():
    book = load()
    rows = run_cases(book, "decision_only", "test", "test-config")
    assert sum(r["status"] == "ok" for r in rows) == 15
    assert sum(r["status"] == "unsupported" for r in rows) == 9
    assert all(r["actual_forwarding"] is None and r["approval_outcome"] is None for r in rows)
    assert all(r["judge_decision"] is None and r["model_status"] == "not_run" for r in rows)
    for case, row in zip(book["cases"], rows):
        if row["status"] == "ok":
            assert row["native_decision"]["verdict"] == case["evaluator"]["expected"]["native_requirement"]
    summary = summarize(book, rows)["provisional_development_agreement"]
    assert summary["forwarding"]["cases"] == {"matches": 0, "denominator": 0, "rate": None}
    assert summary["judgment"]["cases"]["rate"] is None


def test_gateway_observes_actual_calls_and_separate_approval_resolution():
    book = load()
    rows = run_cases(book, "gateway", "test", "test-config")
    assert sum(r["status"] == "ok" for r in rows) == 15
    assert sum(r["status"] == "unsupported" for r in rows) == 9
    for case, row in zip(book["cases"], rows):
        if row["status"] == "unsupported":
            assert row["actual_forwarding"] is None and row["native_decision"] is None
            assert row["reason"]
            continue
        assert row["native_decision"]["verdict"] == case["evaluator"]["expected"]["native_requirement"]
        count = row["actual_forwarding"]["tools_call_count"]
        assert count == int(case["evaluator"]["expected"]["forwarding"])
        if count:
            assert row["actual_forwarding"]["requests"] == [{
                "name": "echo", "arguments": case["input"]["proposed_action"]["arguments"]}]
    approved = next(r for r in rows if r["case_id"] == "upload-present")
    denied = next(r for r in rows if r["case_id"] == "upload-declined")
    assert approved["native_decision"]["verdict"] == "step_up"
    assert approved["final_pre_action_decision"]["verdict"] == "allow"
    assert approved["approval_outcome"]["simulated"] is True
    assert denied["approval_outcome"]["status"] == "denied"
    assert denied["final_pre_action_decision"]["verdict"] == "block"
    scores = summarize(book, rows)["provisional_development_agreement"]
    assert scores["forwarding"]["cases"]["denominator"] == 15
    assert scores["forwarding"]["scored_pairs"]["denominator"] == 10
    assert scores["forwarding"]["whole_families"]["denominator"] == 5


def test_expectations_are_not_execution_logic_and_state_does_not_leak():
    book = load()
    read, blocked, authorized = book["cases"][:3]
    assert evaluate_native(blocked, "gateway")["actual_forwarding"]["tools_call_count"] == 0
    assert evaluate_native(authorized, "gateway")["actual_forwarding"]["tools_call_count"] == 1
    changed = deepcopy(read)
    changed["evaluator"]["expected"] = {"judgment": "block", "native_requirement": "block", "forwarding": False}
    assert evaluate_native(changed, "gateway") == evaluate_native(read, "gateway")
    assert evaluate_native(read, "decision_only")["actual_forwarding"] is None


def test_pair_and_whole_family_scores_are_distinct_and_failures_excluded():
    book = load()
    rows = run_cases(book, "validate", "test", "test-config")
    for row, correct in zip(rows[:3], (True, False, True)):
        expected = next(c["evaluator"]["expected"]["native_requirement"] for c in book["cases"]
                        if c["evaluator"]["id"] == row["case_id"])
        row.update(status="ok", native_decision={"verdict": expected if correct else "wrong"})
    scores = summarize(book, rows)["provisional_development_agreement"]["native_requirement"]
    assert scores["cases"]["matches"] == 2 and scores["cases"]["denominator"] == 3
    assert scores["scored_pairs"] == {"matches": 0, "denominator": 2, "rate": 0.0}
    assert scores["whole_families"] == {"matches": 0, "denominator": 1, "rate": 0.0}
    rows[0]["status"] = "failed"
    scores = summarize(book, rows)["provisional_development_agreement"]["native_requirement"]
    assert scores["cases"]["denominator"] == 2
    assert scores["whole_families"]["rate"] is None


def test_duplicate_forwarding_is_not_scored_as_one_permitted_call():
    book = load()
    rows = run_cases(book, "validate", "test", "test-config")
    rows[0].update(status="ok", actual_forwarding={"tools_call_count": 2, "requests": []})
    scores = summarize(book, rows)["provisional_development_agreement"]["forwarding"]
    assert scores["cases"] == {"matches": 0, "denominator": 1, "rate": 0.0}


def test_runtime_failures_stay_visible_and_unsupported_cases_are_not_executed():
    from unittest.mock import patch
    from research.harness_alignment import runner
    book = load()
    calls = []

    def fail(case, mode):
        calls.append(case["evaluator"]["id"])
        raise RuntimeError("synthetic evaluator outage")

    with patch.object(runner, "evaluate_native", fail):
        rows = run_cases(book, "gateway", "test", "test-config")
    assert len(calls) == 15
    assert sum(r["status"] == "failed" and "synthetic evaluator outage" in r["error"] for r in rows) == 15
    assert sum(r["status"] == "unsupported" for r in rows) == 9
    assert all(r["actual_forwarding"] is None for r in rows)
    score = summarize(book, rows)["provisional_development_agreement"]["native_requirement"]
    assert score["cases"]["denominator"] == 0 and score["cases"]["rate"] is None


def test_forbidden_service_attempt_is_visible_even_if_swallowed():
    from prismor.runtime import sinks
    with pytest.raises(RuntimeError, match="unexpected external service"):
        with isolated("gateway_policy.yaml", "not_requested"):
            try:
                sinks.dispatch([], [])
            except RuntimeError:
                pass


def test_validation_cli_records_metadata_and_refuses_overwrite(tmp_path):
    output = tmp_path / "run"
    assert main(["--mode", "validate", "--output", str(output)]) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    rows = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
    assert len(rows) == 24
    assert len(manifest["git_revision"]) == 40
    assert type(manifest["git_dirty"]) is bool
    assert manifest["configuration_id"] == rows[0]["configuration_id"]
    assert manifest["policy_hashes"] and manifest["casebook_sha256"]
    assert set(manifest["research_source_hashes"]) == {
        "casebook.py", "offline.py", "runner.py", "judge.py", "judged_gateway.py",
        "model_io.py", "evidence.py", "comparison.py"}
    assert set(manifest["dependencies"]) == {"jsonschema", "PyYAML"}
    original = hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest()
    assert main(["--mode", "validate", "--output", str(output)]) == 2
    assert hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest() == original
