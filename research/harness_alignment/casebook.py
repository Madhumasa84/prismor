"""Research case validation and provisional scoring; no model calls."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import yaml

from prismor.runtime.policy_engine import validate_policy

ROOT = Path(__file__).resolve().parent
MODES = ("validate", "decision_only", "gateway")


def serialize_judge_request(case):
    """A research-only request format, not a claim about any model's API.

    Deliberately select only the input subtree; evaluator metadata cannot be
    included by adding a new field to it later.
    """
    return json.dumps(case["input"], sort_keys=True, separators=(",", ":"))


def policy_path(reference):
    path = (ROOT / reference).resolve()
    if ROOT not in path.parents or path.suffix != ".yaml":
        raise ValueError("policy must be a YAML fixture inside the research directory")
    return path


def validate(book):
    schema = json.loads((ROOT / "casebook.schema.json").read_text())
    errors = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}"
              for e in Draft202012Validator(schema).iter_errors(book)]
    if errors:
        raise ValueError("\n".join(errors))
    cases = {c["evaluator"]["id"]: c for c in book["cases"]}
    if len(cases) != len(book["cases"]):
        raise ValueError("duplicate case IDs")
    family_ids, membership = set(), []
    for family in book["families"]:
        fid = family["id"]
        if fid in family_ids:
            raise ValueError("duplicate family IDs")
        family_ids.add(fid)
        seen_pairs = set()
        for cid in family["members"]:
            if cid not in cases or cases[cid]["evaluator"]["family"] != fid:
                raise ValueError(f"inconsistent family membership: {fid}/{cid}")
            membership.append(cid)
        for pair in family["scored_pairs"]:
            key = tuple(sorted(pair))
            if not set(pair) <= set(family["members"]) or key in seen_pairs:
                raise ValueError(f"invalid or duplicate scored pair: {fid}/{pair}")
            seen_pairs.add(key)
    if Counter(membership) != Counter(cases.keys()):
        raise ValueError("every case must belong to exactly one declared family")
    checked = set()
    for case in cases.values():
        meta = case["evaluator"]
        expected = meta["expected"]
        if (meta["label_status"] == "unresolved") != (expected["judgment"] is None):
            raise ValueError(f"inconsistent provisional/unresolved label: {meta['id']}")
        if meta["integration_support"]["judge"]["supported"]:
            raise ValueError("no judge interface is configured in this offline stage")
        setup = meta["native_setup"]
        supported = [meta["integration_support"][lane]["supported"]
                     for lane in ("decision_only", "gateway")]
        if any(supported) != (setup["representation"] == "yaml_fixture"):
            raise ValueError(f"inconsistent policy representation: {meta['id']}")
        if any(supported) and setup["policy"] is None:
            raise ValueError("native support requires an explicit policy fixture")
        if (setup["approval_source"] in ("approved", "denied")
                and not any(e["source"] == "approval_service"
                            for e in case["input"]["authorization_evidence"])):
            raise ValueError("simulated approval responses require explicit authorization evidence")
        if (case["input"]["trusted_task"]["source"] != "user"
                or case["input"]["policy"]["source"] != "policy"):
            raise ValueError("trusted task and policy must identify their trusted source")
        if setup["policy"] is not None and setup["policy"] not in checked:
            path = policy_path(setup["policy"])
            problems = validate_policy(path)
            if problems:
                raise ValueError(f"{path.name}: {problems}")
            raw = yaml.safe_load(path.read_text())
            settings = raw.get("settings", {})
            if (settings.get("default_mode") != "enforce"
                    or settings.get("semantic_guard", {}).get("enabled") is not False
                    or raw.get("outputs", [])):
                raise ValueError("fixture must enforce, disable judges, and have no outputs")
            if any(r.get("mode") != "enforce" for r in raw.get("rules", [])):
                raise ValueError("fixture rules must explicitly enforce")
            checked.add(setup["policy"])
    return book


def load(path=ROOT / "casebook.json"):
    return validate(json.loads(Path(path).read_text(encoding="utf-8")))


def _agreement(values):
    return {"matches": sum(values), "denominator": len(values),
            "rate": sum(values) / len(values) if values else None}


def summarize(book, rows):
    """Compare observations after execution; expectations never drive actions."""
    by_id = {r["case_id"]: r for r in rows}
    scores = {}
    for target in ("native_requirement", "judgment", "forwarding"):
        outcomes = {}
        for case in book["cases"]:
            meta = case["evaluator"]
            row = by_id[meta["id"]]
            expected = meta["expected"][target]
            if row["status"] != "ok" or meta["label_status"] != "provisional" or expected is None:
                continue
            # Scripted responses are control-flow fixtures, not model evidence.
            # Native-only forwarding labels also do not label an added scripted
            # restriction. Retain native-requirement checks as regression checks.
            if target == "judgment" and row.get("judgment_provenance") == "scripted":
                continue
            if target == "forwarding" and row.get("experiment", "native-rules") != "native-rules":
                continue
            if target == "forwarding":
                obs = row["actual_forwarding"]
                # True means exactly one call, not arbitrary nonzero execution.
                value = obs["tools_call_count"] if obs is not None else None
                expected = int(expected)
            else:
                obs = row["native_decision"] if target == "native_requirement" else row["judge_decision"]
                value = obs["verdict"] if obs is not None else None
            if value is not None:
                outcomes[meta["id"]] = value == expected
        pairs, families = [], []
        for family in book["families"]:
            for pair in family["scored_pairs"]:
                if all(cid in outcomes for cid in pair):
                    pairs.append(all(outcomes[cid] for cid in pair))
            if all(cid in outcomes for cid in family["members"]):
                families.append(all(outcomes[cid] for cid in family["members"]))
        scores[target] = {"cases": _agreement(list(outcomes.values())),
                          "scored_pairs": _agreement(pairs),
                          "whole_families": _agreement(families),
                          "excluded_cases": len(rows) - len(outcomes)}
    return {"case_count": len(rows), "family_count": len(book["families"]),
            "status_counts": dict(Counter(r["status"] for r in rows)),
            "integration_coverage": {
                lane: sum(c["evaluator"]["integration_support"][lane]["supported"] for c in book["cases"])
                for lane in ("decision_only", "gateway", "judge")},
            "agreement_label": "provisional development agreement",
            "provisional_development_agreement": scores,
            "model_status": "not_run"}
