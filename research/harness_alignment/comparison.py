"""Zero-inference comparison planning and native-fixture pilot reporting."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import time
import uuid

import yaml

from .casebook import ROOT, load, summarize
from .judge import JudgeRequest
from .model_io import Budget, INTERFACE_FIELDS, missing_prerequisites, sha
from .runner import REPO, digest, metadata, run_cases

CONFIGURATIONS = {
    "native-rules": (), "native-plus-niti": ("niti",),
    "native-plus-stronger": ("stronger",),
    "native-plus-niti-selective": ("niti", "stronger"),
}
SMOKE_COMMAND = (
    "python3 -m research.harness_alignment.comparison --mode real-smoke "
    "--evaluation judge-only --configuration native-plus-niti --pair task:0 "
    "--settings research/harness_alignment/live_settings.json "
    "--models research/harness_alignment/models.json "
    "--max-real-requests 2 --timeout-seconds 30 --max-output-tokens 256"
)


def select_pair(book, selector):
    try:
        fid, index = selector.rsplit(":", 1)
        family = next(f for f in book["families"] if f["id"] == fid)
        number = int(index)
        if number < 0:
            raise ValueError("negative pair")
        return list(family["scored_pairs"][number])
    except (StopIteration, ValueError, IndexError):
        raise ValueError("pair must identify a declared family and zero-based pair, e.g. task:0") from None


def plans(book, models, pair, native_rows):
    """Plans are NOT execution observations or fabricated model responses."""
    by_id = {r["case_id"]: r for r in native_rows}
    rows = []
    for case in book["cases"]:
        cid = case["evaluator"]["id"]
        for configuration, roles in CONFIGURATIONS.items():
            for evaluation in ("judge-only", "gateway"):
                if evaluation == "judge-only" and (cid not in pair or not roles):
                    continue
                missing = {role: missing_prerequisites(models[role]) for role in roles}
                native = by_id[cid]
                supported = native["status"] == "ok"
                blocked = supported and native["native_decision"]["verdict"] == "block"
                if evaluation == "gateway" and not roles:
                    status, reason = native["status"], native["reason"]
                    observed = deepcopy(native["actual_forwarding"])
                else:
                    observed = None
                    status = "unavailable" if roles else "unsupported"
                    reason = "Required verified model configuration/adapter is unavailable."
                    if evaluation == "gateway" and not supported:
                        status, reason = "unsupported", native["reason"]
                rows.append({"case_id": cid, "family_id": case["evaluator"]["family"],
                             "configuration_id": configuration, "evaluation": evaluation,
                             "status": status, "reason": reason, "missing_prerequisites": missing,
                             "model_status": "not_run", "judges_actually_run": [],
                             "judge_results": [], "raw_response": None, "judge_decision": None,
                             "final_pre_action_decision": native["final_pre_action_decision"]
                             if evaluation == "gateway" and not roles else None,
                             "native_baseline_reference": deepcopy(native["native_decision"]),
                             "actual_forwarding": observed, "model_call_count": 0,
                             "judge_input_sha256": sha(json.loads(JudgeRequest.from_input(case["input"]).serialized_input)),
                             "planned_route": "native_block_short_circuit" if evaluation == "gateway" and blocked
                             else "both_pair_members_independently" if evaluation == "judge-only"
                             else "niti_then_stronger_only_on_valid_unresolved_semantics"
                             if len(roles) == 2 else "direct_judge" if roles else "native_only",
                             "execution_kind": "offline_native_gateway_fixture" if not roles else "plan_only"})
    return rows


def score(values):
    return {"matches": sum(values), "denominator": len(values),
            "rate": sum(values) / len(values) if values else None}


def judge_agreement(book, rows, *, configuration_id, evaluation, label_status):
    """No credit for native short-circuits, scripts, replay, errors or absent pairs.

    Only complete, genuine responses from a verified adapter are eligible. Labels
    are consulted here, after observations; never to route or normalize requests.
    The development schema currently admits no reviewed labels.
    """
    outcomes = {}
    mapping = {"allow": "allow", "deny": "block", "missing_authorization": "step_up"}
    counts = Counter(r["case_id"] for r in rows if r.get("configuration_id") == configuration_id
                     and r.get("evaluation") == evaluation)
    for row in rows:
        if (row.get("configuration_id") != configuration_id or row.get("evaluation") != evaluation
                or row.get("status") != "ok" or counts[row["case_id"]] != 1
                or row.get("response_provenance") != "genuine_live"
                or row.get("verified_adapter") is not True or row.get("complete_decision") is not True):
            continue
        case = next((c for c in book["cases"] if c["evaluator"]["id"] == row["case_id"]), None)
        if not case or case["evaluator"]["label_status"] != label_status:
            continue
        attempts = row.get("model_attempts") or []
        expected_input = json.loads(JudgeRequest.from_input(case["input"]).serialized_input)
        if (not attempts or not row.get("judges_actually_run")
                or row.get("model_call_count") != len(attempts)
                or attempts[-1].get("status") != "valid"
                or not attempts[-1].get("actual_model_version")):
            continue
        if any(a.get("provenance") != "genuine_live"
               or a.get("request_identity", {}).get("judge_input") != expected_input
               or a.get("request_input_sha256") != sha(expected_input)
               or a.get("request_identity_sha256") != sha(a.get("request_identity"))
               for a in attempts):
            continue
        expected = case["evaluator"]["expected"]["judgment"]
        actual = (row.get("judge_decision") or {}).get("decision")
        if expected is not None and actual in mapping:
            outcomes[row["case_id"]] = mapping[actual] == expected
    pairs, families = [], []
    for family in book["families"]:
        for pair in family["scored_pairs"]:
            if all(cid in outcomes for cid in pair):
                pairs.append(all(outcomes[cid] for cid in pair))
        if all(cid in outcomes for cid in family["members"]):
            families.append(all(outcomes[cid] for cid in family["members"]))
    return {"cases": score(list(outcomes.values())), "pairs": score(pairs), "whole_families": score(families)}


def pilot(book, native_rows, comparison_rows):
    compatible = []
    by_id = {c["evaluator"]["id"]: c for c in book["cases"]}
    for row in native_rows:
        meta = by_id[row["case_id"]]["evaluator"]
        if row["status"] == "ok" and meta["label_status"] == "provisional" and meta["expected"]["forwarding"] is not None:
            compatible.append((row, meta))
    native_scores = summarize(book, native_rows)
    return {
        "scope": "development integration pilot; no live model run",
        "actual_real_requests": 0, "model_status": "not_run",
        "label_counts": dict(Counter(c["evaluator"]["label_status"] for c in book["cases"])),
        "native_fixture": native_scores,
        "judge_evaluations": {f"{configuration}/{evaluation}": {
            "reviewed_correctness": judge_agreement(book, comparison_rows, configuration_id=configuration,
                                                    evaluation=evaluation, label_status="human_reviewed"),
            "provisional_development_agreement": judge_agreement(book, comparison_rows, configuration_id=configuration,
                                                                  evaluation=evaluation, label_status="provisional")}
            for configuration in CONFIGURATIONS if configuration != "native-rules"
            for evaluation in ("judge-only", "gateway")},
        "native_provisional_forwarding_errors": {
            "incorrect_permits": sum(r["actual_forwarding"]["tools_call_count"] > 0 and not m["expected"]["forwarding"] for r, m in compatible),
            "unnecessary_blocks": sum(r["actual_forwarding"]["tools_call_count"] == 0 and m["expected"]["forwarding"] for r, m in compatible),
            "denominator": len(compatible)},
        "native_approval_requests": {"count": sum(r.get("approval_outcome") is not None for r in native_rows),
                                     "denominator": sum(r["status"] == "ok" for r in native_rows), "simulated": True},
        "observed_tools_call_count": sum((r["actual_forwarding"] or {}).get("tools_call_count", 0) for r in native_rows),
        "model_outcomes": {"genuine_response_count": 0, "stronger_requests": 0,
                           "invalid_outputs": {"count": 0, "request_denominator": 0, "rate": None},
                           "timeout_count": 0, "unavailable_configurations": 3,
                           "live_latency_ms": None, "usage": None, "monetary_cost": None,
                           "replay_latency_ms": None},
        "comparison_status_counts": dict(Counter(r["status"] for r in comparison_rows)),
        "unsupported_native_cases": [{"id": r["case_id"], "reason": r["reason"]}
                                     for r in native_rows if r["status"] == "unsupported"],
        "stronger_routing": "Only a valid explicit unresolved_semantics outcome; no confidence-band claim.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("dry-run", "real-smoke"), required=True)
    parser.add_argument("--evaluation", choices=("all", "judge-only", "gateway"), default="all")
    parser.add_argument("--configuration", choices=tuple(CONFIGURATIONS), default="native-plus-niti")
    parser.add_argument("--pair", default="task:0")
    parser.add_argument("--settings", type=Path, default=ROOT / "live_settings.json")
    parser.add_argument("--models", type=Path, default=ROOT / "models.json")
    parser.add_argument("--max-real-requests", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=float, default=30)
    parser.add_argument("--max-output-tokens", type=int, default=256)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        settings = json.loads(args.settings.read_text())
        models = json.loads(args.models.read_text())
        if set(settings) != {"LIVE_MODEL_RUN", "MAX_REAL_REQUESTS"}:
            raise ValueError("unknown live settings fields")
        if (not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0
                or args.max_output_tokens <= 0):
            raise ValueError("positive finite timeout and output limit required")
        if set(models) != {"niti", "stronger"}:
            raise ValueError("model roles must be niti and stronger")
        # No arbitrary model configuration or authentication material is logged.
        for config in models.values():
            if set(config) != {"available", *INTERFACE_FIELDS}:
                raise ValueError("unknown model configuration fields")
        budget = Budget(settings, args.max_real_requests)
        book = load()
        pair = select_pair(book, args.pair)
        if args.mode == "real-smoke":
            if not budget.enabled or budget.limit == 0:
                raise ValueError("real inference disabled or zero budget; no requests made")
            missing = {role: missing_prerequisites(models[role]) for role in CONFIGURATIONS[args.configuration]}
            raise ValueError(f"real execution unavailable: no verified concrete adapters; prerequisites: {missing}")
        # Dry run is explicitly offline regardless of supplied live settings.
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        manifest = metadata(ROOT / "casebook.json", book, "gateway", run_id)
        manifest.update(mode="dry-run", requested_settings=settings, effective_live_model_run=False,
                        effective_max_real_requests=0, selected_pair=pair,
                        model_configuration_sha256=sha(models), settings_sha256=sha(settings),
                        comparison_request_bounds={"timeout_seconds": args.timeout_seconds,
                                                   "output_limit": args.max_output_tokens,
                                                   "requested_cli_cap": args.max_real_requests,
                                                   "effective_real_request_cap": 0},
                        selected_evaluation=args.evaluation,
                        model_prerequisites={role: missing_prerequisites(c) for role, c in models.items()},
                        native_shipped_semantic_configuration=yaml.safe_load(
                            (REPO / "prismor/runtime/default_policy.yaml").read_text())["settings"]["semantic_guard"],
                        active_live_configuration="not queried; may differ from shipped defaults",
                        experimental_semantic_screening="disabled by all temporary policies; same across modes",
                        future_smoke_command=SMOKE_COMMAND)
        manifest["comparison_source_hashes"] = {name: digest((ROOT / name).read_bytes()) for name in
                                               ("comparison.py", "model_io.py")}
        destination = args.output or ROOT / "runs" / run_id
        destination.mkdir(parents=True, exist_ok=False)
        started = time.perf_counter()
        native_rows = run_cases(book, "gateway", run_id, manifest["configuration_id"])
        manifest["offline_native_fixture_elapsed_ms"] = (time.perf_counter() - started) * 1000
        rows = plans(book, models, pair, native_rows)
        if args.evaluation != "all":
            rows = [r for r in rows if r["evaluation"] == args.evaluation]
        for row in rows:
            row.update(run_id=run_id, casebook_sha256=manifest["casebook_sha256"],
                       policy_hashes=manifest["policy_hashes"],
                       native_fixture_configuration_id=manifest["configuration_id"],
                       comparison_configuration_sha256=sha({
                           "configuration_id": row["configuration_id"], "evaluation": row["evaluation"],
                           "models_sha256": manifest["model_configuration_sha256"],
                           "native_fixture": manifest["configuration"],
                           "timeout_seconds": args.timeout_seconds, "output_limit": args.max_output_tokens,
                           "routing": "valid_explicit_unresolved_semantics_only", "caching": False}))
        report = pilot(book, native_rows, rows)
        for name, value in (("manifest.json", manifest), ("pilot.json", report)):
            (destination / name).write_text(json.dumps(value, indent=2) + "\n")
        for name, values in (("native_observations.jsonl", native_rows), ("comparison_plan.jsonl", rows)):
            (destination / name).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in values))
        print(json.dumps({"output": str(destination), "real_requests": budget.requests,
                          "native_status_counts": report["native_fixture"]["status_counts"],
                          "observed_tools_call_count": report["observed_tools_call_count"],
                          "comparison_status_counts": report["comparison_status_counts"],
                          "future_smoke_command": SMOKE_COMMAND}, indent=2))
        return 1 if any(r["status"] == "failed" for r in native_rows) else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Do not echo supplied config values (they may include credentials).
        message = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__
        print(f"comparison: {message}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
