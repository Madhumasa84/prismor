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

## 2026-10-22 — Prompt 1 complete; Prompt 2 offline integration

Prompt 1 was subsequently supplied and completed as a read-only inspection.
It verified the gateway path, native verdict handling, test seams, and offline
isolation requirements. The semantic judge classifies injection in text, not
general action authorization; no Niti API or checkpoint was established.

Before editing for Prompt 2, rechecked root instructions, branch and HEAD
(`84efd2428f24defef3f4641b436766eebdbb0247`), and the clean working tree.
No branch switch or existing changes were involved.

### Implementation and observed results

- Real `Gateway` forwarding, `_evaluate`, `runtime.evaluate_tool_call`, and YAML
  evaluation remain unchanged. Reused the verified recording-upstream helpers.
- Native `approvals.await_step_up` runs with fixture service responses and an
  approval-module-only synthetic identity. No device is enrolled.
- Real temporary policies block or request approval based on argument markers;
  discovery still advertises the echo tool. Enforce mode and inactive passthrough
  are asserted. Forwarded arguments are captured from `tools/call` requests.
- Passive return observation records native pre-action decisions and approvals
  separately from post-action scans. Model status is `not_run` throughout.
- A: allow / no governing rule / no approval / **1** call / ok.
- B: block / `harness-marker-block` / no approval / **0** calls / tool_error.
- C: step_up / `harness-marker-approval` / simulated unavailable service yields
  native `request_failed` / **0** calls / tool_error.
- D: step_up / the same approval rule and arguments / simulated approved source
  yields native `approved` / **1** call / ok.

### Validation and troubleshooting

- `python3 -m pytest tests/test_harness_alignment_gateway.py -q -s`
  — **4 passed** (2.57s).
- Initial run reached all expected observations but failed teardown because an
  installed pytest-django plugin initialized the shared monkeypatch fixture
  before the repository's module-leak guard. An explicit patch context fixed
  cleanup ordering; production policy semantics were unchanged.
- Existing focused regression command is recorded verbatim in `README.md`:
  **37 passed, 1 skipped, 48 deselected** (8.46s with skip reasons).
- The skip is pre-existing missing demo-server infrastructure, not an experiment
  failure. No external-service or judge attempts were recorded by the new tests.

### Changed files, limits, and remaining work

- `research/harness_alignment/gateway_policy.yaml`: synthetic call-time rules.
- `tests/test_harness_alignment_gateway.py`: isolated four-case integration test
  and JSON observations, using existing repository fixtures.
- `research/harness_alignment/README.md`: scope, interfaces, working rules,
  repeatable commands, results, and limitations.
- `research/harness_alignment/PROGRESS.md`: this progress record.

No live configuration, hooks, permissions, production source, or model services
were changed. This milestone covers in-process forwarding and simulated approval
only; it makes no Niti-performance claim. Niti prerequisites and Prompts 3–5
remain pending. Pushes, pull requests, merges, and main changes still require
explicit approval. Continue focused commits after completed, tested milestones.
