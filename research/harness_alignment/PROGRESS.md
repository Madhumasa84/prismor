# Harness Alignment research progress

## 2026-10-21 — Branch and initial repository inspection

- Starting branch: `fix/approval-redaction-status-race`.
- Starting commit: `d475aeb` (`fix(approvals): preserve redaction mode from approval response`).
- Initial working tree: clean (`git status --short` returned no entries).
- Created and switched to `research/harness-alignment-eval` from that checkout.
- Research artifacts belong in `research/harness_alignment/`.
- No production implementation changes in this milestone.

### Repository findings

Read the repository skill, overview, contribution guidance, runtime CLI and
policy-engine entry points, decision-contract documentation, governance-surfaces
documentation, and the existing surface-conformance tests.

| Concern | Existing implementation / convention |
| --- | --- |
| Canonical event and decision vocabulary | `prismor/runtime/contract.py` |
| Shared evaluation entry point | `prismor/runtime/runtime.py:evaluate_tool_call` |
| Rules and policy merging | `prismor/runtime/policy_engine.py`, `default_policy.yaml` |
| Host payload normalization | `prismor/runtime/hooks.py:normalize_payload` |
| Mirrored tool event shaping | `prismor/runtime/mirror.py:shape_call_event` |
| Mirrored local execution | `prismor/runtime/mirror.py:execute`, `_run_bash` |
| HTTP evaluation event shaping | `prismor/runtime/eval_server.py:_build_event` |
| Existing agreement checks | `tests/test_surface_conformance.py` |
| Test isolation | `tests/conftest.py` isolates Prismor state and restores module changes |
| Research precedent | `research/semantic-judge-coverage/` holds scripts, data, and reports |

Detection rules belong in YAML. Reuse the existing evaluator and normalizers;
do not introduce a parallel policy engine. Keep experiment state disposable and
separate from active workspace policy, hook configuration, and registered secrets.

The conformance corpus compares independently normalized events across Claude,
Codex, Cursor, mirror, eval-server, and ACP paths. Decision agreement is distinct
from proving a denied action cannot execute. The first boundary experiment must
make its coverage and execution evidence explicit once its prompt is available.

### Validation

- `python3 -m pytest tests/test_surface_conformance.py -q`
  — **18 passed in 1.71s**.
- These are existing baseline tests; no new experiment has run yet.
- Semantic scanning flagged some documentation/source output. It was treated as
  reference data; no enforcement-changing or credential-access instructions were
  executed from that output.

### Remaining work

- Obtain the five research prompts: they were not included in the conversation,
  and repository searches found no matching Harness Alignment prompt document.
- Prompt 1: initial inspection recorded above; reconcile with the actual prompt
  before declaring it complete.
- Prompt 2: implementation and execution-boundary experiment pending its scope
  and acceptance criteria.
- Prompts 3–5: pending their instructions.
- After each completed, tested milestone, update this log and create a focused
  commit on the research branch.
- Pushes, pull requests, merges, and changes to main require explicit approval.
