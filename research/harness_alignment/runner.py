"""Small offline development runner. Run with python3 -m ...runner --help."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import sys
import uuid

from .casebook import ROOT, load, policy_path, serialize_judge_request, summarize
from .offline import evaluate_native
from .judge import EXPERIMENTS, configuration as judge_configuration

REPO = ROOT.parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_cases(book, mode, run_id, configuration_id, experiment="native-rules"):
    rows = []
    for case in book["cases"]:
        meta = case["evaluator"]
        row = {"run_id": run_id, "configuration_id": configuration_id,
               "experiment": experiment,
               "case_id": meta["id"], "family_id": meta["family"],
               "label_status": meta["label_status"], "model_status": "not_run",
               "integration_support": meta["integration_support"],
               "fixture_configuration": meta["native_setup"],
               "judge_request_sha256": digest(serialize_judge_request(case).encode()),
               "native_decision": None, "judge_decision": None,
               "final_pre_action_decision": None, "actual_forwarding": None,
               "composed_pre_action_decision": None,
               "approval_outcome": None, "post_action": [], "response_status": None,
               "status": "validated", "error": None, "reason": "Schema and group checks passed."}
        row.update(judge_results=[], judge_call_count=0, scripted_call_count=0, model_call_count=0,
                   judge_errors=[], routing_reason="not_evaluated", human_approval_route=None,
                   original_action=case["input"]["proposed_action"], effective_transformed_action=None,
                   judge_visible_action=None, forwarded_arguments=None, judgment_provenance=None)
        if mode != "validate":
            support = meta["integration_support"][mode]
            if not support["supported"]:
                row.update(status="unsupported", reason=support["reason"])
            elif mode != "gateway" and experiment != "native-rules":
                row.update(status="unsupported", reason="Research judge composition is supported at the gateway seam only.")
            else:
                try:
                    observed = evaluate_native(case, mode) if experiment == "native-rules" else evaluate_native(
                        case, mode, judge_configuration(experiment))
                    row.update(observed)
                    row.update(status="ok", reason=row["final_pre_action_decision"]["reason"] or
                               "No blocking composed finding; fixture action is permitted.")
                    if row.get("composition_status") == "unsupported":
                        row.update(status="unsupported", reason=row["routing_reason"])
                    elif row.get("judge_errors"):
                        row.update(status="judge_error", error=json.dumps(row["judge_errors"]),
                                   reason="Research judge failed; native gateway refused the action.")
                except Exception as exc:
                    row.update(status="failed", error=f"{type(exc).__name__}: {exc}",
                               reason="Offline integration failed; excluded from agreement.")
        rows.append(row)
    return rows


def metadata(book_path, book, mode, run_id, experiment="native-rules"):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(REPO), *args], text=True).strip()

    policies = sorted({c["evaluator"]["native_setup"]["policy"] for c in book["cases"]
                       if c["evaluator"]["native_setup"]["policy"] is not None})
    hashes = {name: digest(policy_path(name).read_bytes()) for name in policies}
    hashes["prismor/runtime/default_policy.yaml"] = digest(
        (REPO / "prismor/runtime/default_policy.yaml").read_bytes())
    configuration = {"mode": mode, "device_mode": "enforce", "model_status": "not_run",
                     "research_judge": judge_configuration(experiment), "cross_case_caching": False,
                     "upstream": "recording_fixture", "approvals": "simulated_service_only",
                     "remote_refresh": False, "network": False, "telemetry": False,
                     "policy_hashes": hashes,
                     "decision_only_options": {"persist": False, "record": False,
                                               "register_agent": False, "flush_at_exit": False}}
    status = git("status", "--porcelain=v1")
    return {"run_id": run_id, "git_revision": git("rev-parse", "HEAD"),
            "git_dirty": bool(status), "git_status": status.splitlines(),
            "casebook_sha256": digest(Path(book_path).read_bytes()),
            "schema_sha256": digest((ROOT / "casebook.schema.json").read_bytes()),
            "policy_hashes": hashes, "configuration": configuration,
            "configuration_id": digest(json.dumps(configuration, sort_keys=True).encode())[:16],
            "python": sys.version,
            "dependencies": {name: version(name) for name in ("jsonschema", "PyYAML")},
            "research_source_hashes": {name: digest((ROOT / name).read_bytes())
                                       for name in ("casebook.py", "offline.py", "runner.py", "judge.py", "judged_gateway.py")},
            "scripted_controls_sha256": digest((ROOT / "scripted_controls.json").read_bytes()),
            "created_at": datetime.now(timezone.utc).isoformat()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("validate", "decision-only", "gateway"), required=True)
    parser.add_argument("--casebook", type=Path, default=ROOT / "casebook.json")
    parser.add_argument("--experiment", choices=EXPERIMENTS, default="native-rules")
    parser.add_argument("--output", type=Path, help="New output directory; existing directories are refused")
    args = parser.parse_args(argv)
    try:
        book = load(args.casebook)
        mode = args.mode.replace("-", "_")
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        manifest = metadata(args.casebook, book, mode, run_id, args.experiment)
        destination = args.output or ROOT / "runs" / run_id
        # Refuse overwrite and fail before executing if output cannot be created.
        destination.mkdir(parents=True, exist_ok=False)
        rows = run_cases(book, mode, run_id, manifest["configuration_id"], args.experiment)
        summary = summarize(book, rows)
        summary.update(run_id=run_id, configuration_id=manifest["configuration_id"], mode=mode,
                       label_status_counts=dict(Counter(r["label_status"] for r in rows)))
        summary.update(experiment=args.experiment,
                       judge_call_count=sum(r["judge_call_count"] for r in rows),
                       scripted_call_count=sum(r["scripted_call_count"] for r in rows),
                       model_call_count=sum(r["model_call_count"] for r in rows),
                       observed_tools_call_count=sum((r["actual_forwarding"] or {}).get("tools_call_count", 0) for r in rows))
        summary["scripted_seam_cases"] = sum(r.get("judgment_provenance") == "scripted" for r in rows)
        (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (destination / "observations.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
        (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps({"output": str(destination), "run_id": run_id, "mode": mode,
                          "cases": summary["case_count"], "status_counts": summary["status_counts"],
                          "experiment": args.experiment, "judge_call_count": summary["judge_call_count"],
                          "model_call_count": summary["model_call_count"],
                          "observed_tools_call_count": summary["observed_tools_call_count"],
                          "label_status_counts": summary["label_status_counts"],
                          "coverage": summary["integration_coverage"],
                          "provisional_development_agreement": {
                              target: values["cases"] for target, values in
                              summary["provisional_development_agreement"].items()}}, sort_keys=True))
        return 1 if any(r["status"] in ("failed", "judge_error") for r in rows) else 0
    except (ValueError, OSError) as exc:
        print(f"casebook runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
