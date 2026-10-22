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

## 2026-10-22 — Prompt 3 development casebook and runner

Started from clean `b6a2a189bd417f9f2af84549ce8dea181d19896d`; read the research
README/progress and checked the current diff and applicable root guidance.
Preserved the original four-case test and its policy unchanged. All additions
remain under the research directory plus one focused test file.

### Scope and implementation

- Added a one-page `SPEC.md`, `CASE_FORMAT.md`, closed JSON Schema, and 24
  synthetic development cases in eight triples with 16 explicit scored pairs.
  Families cover task scope, resources, uploads, provenance, argument-bound
  grants, dummy sensitivity, context, and paraphrases/benign lookalikes.
- Split every case into judge-visible `input` and evaluator-only metadata.
  Expectations distinguish research judgment, native requirement and exact
  forwarding. All 22 resolved labels are provisional; two remain unresolved.
- Added native YAML fixtures and `casebook.py` validation/scoring, `offline.py`
  isolated real-gateway fixture, and the `runner.py` CLI entry point. Native
  evaluation/forwarding/approval handling remain real. External upstream and
  approval service responses are explicit fixtures, following Prompt 2's pattern.
- Validation checks schema, unique IDs, complete family membership and pairs,
  source/provenance, authorization evidence and native policy representation.
- Decision-only uses verified side-effect flags (`persist=False`, `record=False`,
  `register_agent=False`, `flush_at_exit=False`) and leaves execution null.
  Gateway execution is measured only from recorded `tools/call` requests.
- Pre-action native decisions remain separate from post-action scans. Final
  gateway approval-resolution reporting is explicitly a research description of
  the observed native branch, not a new native Decision or judge arbiter.
- Outputs are JSONL observations, compact summary and manifest in ignored
  `runs/<run-id>/`; metadata records revision/dirty state, configuration/run IDs,
  source/casebook/schema/default-policy/fixture hashes and dependency versions.
  No run output is staged. Each case uses fresh disposable state and guarded
  services. No dependencies were installed or model/service calls performed.

### Commands and results

```bash
python3 -m research.harness_alignment.runner --mode validate
python3 -m research.harness_alignment.runner --mode decision-only
python3 -m research.harness_alignment.runner --mode gateway
python3 -m pytest tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/test_mcp_gateway.py tests/test_tool_policy_three_state.py tests/test_surface_conformance.py -q -rs -k 'call_forwarded_on_allow or call_blocked_pre_forward or engine_error_fails_closed or call_step_up or call_modify or gateway_end_to_end_real_engine or three_state or surface_conformance'
ruff check --select E9,F63,F7,F82 research/harness_alignment/casebook.py research/harness_alignment/offline.py research/harness_alignment/runner.py tests/test_harness_alignment_casebook.py
```

- Validation: 24 valid cases, eight families, 16 scored pairs.
- Both native modes: 15 successful, nine unsupported, zero failed. Two of the
  unsupported cases also have unresolved labels. Every judge result is null;
  every `model_status` is `not_run`.
- Provisional development agreement: native requirements 15/15 cases, 10/10
  compatible pairs, 5/5 whole families; gateway forwarding matches the same
  denominators. These are wiring observations against provisional expectations,
  not independently validated accuracy. Judge and decision-only forwarding
  rates are null with zero denominators.
- Focused tests: 22 passed (21.42s). Checks include label/ID serialization
  separation across all cases, execution independence from expected answers,
  real integration, state isolation, duplicate forwarding, failure visibility,
  unsupported exclusions, null rates, and distinct pair/whole-family scoring.
- Existing checks: 33 passed, one pre-existing missing-demo skip, 48 deselected
  (3.06s). Selected lint checks passed. No unrelated failures were observed.
- The three CLI runs were recorded against the starting revision with dirty
  state explicitly reported; generated manifests identify the tested sources.

### Changed files and remaining prerequisites

Added `casebook.json`, `casebook.schema.json`, `casebook.py`, `offline.py`,
`runner.py`, `SPEC.md`, `CASE_FORMAT.md`, four YAML files in `policies/`,
`requirements.txt`, and local `.gitignore`; added
`tests/test_harness_alignment_casebook.py`; updated README and this progress log.

Review all 22 provisional labels with the operator/mentor. In particular,
`provenance-unknown` and `context-missing` need a resolved rubric. All nine cases
in provenance, grant and context families are retained with precise unsupported
mapping reasons. Supported task constraints are projections into explicit YAML,
not evidence that native Prismor understands the natural-language task. Simulated
approval does not establish an argument-bound grant API. General judge support
remains zero until Niti's actual interface/checkpoint and inference settings are
established. No held-out benchmark or model-performance claim was created.
Prompts 4–5 remain pending; existing project restrictions continue to apply.

## 2026-10-22 — Prompt 4 research judge composition and scripted routing

Started from clean `f78964f4ecc42a8fb5c3acb575ddebe45895db55`. Read the research
specification, format, progress, applicable root instructions and current
gateway/Decision implementation. The production API verified here is
`Decision.as_dict`, the `Decision` constructor and `contract.strongest`; verdict
and transform are derived from blocking. No production implementation changed.

### Implemented behavior

- Added a research `Judge` protocol and explicit `ScriptedJudge`, with a typed
  valid `Judgment` separate from `JudgeError`. Values distinguish allow, deny,
  missing authorization and semantic uncertainty; errors distinguish invalid
  output, timeout and unavailable. Raw native fields are preserved without
  inventing confidence. This is not Niti's API/checkpoint or an inference adapter.
- Added `ResearchGateway`, extending only `_evaluate`: call the native parent,
  deep-copy native evidence, invoke scripts only for the explicitly active
  pre-action echo call, construct a separate native-contract Decision, and return
  to inherited forwarding/approval handling. No independent execution path or
  semantic_guard completion adapter is used.
- Native blocks remain blocks; allow cannot clear native step_up/modify, and
  research deny wins over weaker native verdicts. Findings, native transforms,
  subject, engine and explanation are preserved. Native evidence is never edited
  to present composition as a native finding.
- Research selective escalation happens only for valid semantic uncertainty.
  Missing authorization, errors and unresolved final judgments refuse. Native
  defer remains unsupported at this gateway and is not cleared by a script.
- Native modify and possibly redacted approval composition are unsupported and
  refused before forwarding. Step_up composition is supported only with verified
  unchanged-argument approval fixtures, never arbitrary/live services. Original,
  judge-visible, effective observed actions and forwarded arguments/hashes are
  separate; mismatched proposals refuse before judging/forwarding.
- Native, fast-script, stronger-script and selectively escalated modes share
  policies, cases, enforcement and fresh state. Scripts never receive expected
  labels. Every script result has provenance. Caching remains off; true model
  calls are zero and are counted separately from script invocations.
- Added composed pre-action evidence, native approval routing/outcome, each
  judgment/error, routing reason and binding records to JSONL. Scripted results
  are excluded from model agreement; native-only forwarding expectations do not
  score added scripted restrictions. Reproducibility metadata includes control
  configuration and hash plus the new research source hashes.

### Commands and observations

```bash
python3 -m research.harness_alignment.runner --mode gateway --experiment native-rules
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-fast
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-stronger
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-selective
python3 -m pytest tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/test_mcp_gateway.py tests/test_tool_policy_three_state.py tests/test_surface_conformance.py -q -rs -k 'call_forwarded_on_allow or call_blocked_pre_forward or engine_error_fails_closed or call_step_up or call_modify or gateway_end_to_end_real_engine or three_state or surface_conformance'
ruff check --select E9,F63,F7,F82 research/harness_alignment/*.py tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py
```

All four modes: 15 native-supported cases, nine unmapped cases retained, no
inference. Observed script-call / upstream-call totals were respectively:
native **0 / 10**, fast **15 / 10**, stronger **15 / 0**, selective **30 / 10**.
The stronger default deliberately denies; selective defaults to explicit
uncertainty then explicit allow. These are scripted control-flow observations,
not accuracy, calibration, attack-success reduction or real inference cost.

Focused integration: **55 passed** (33 new judge tests plus 22 prior checks).
Tests cover all requested branches, separate valid replies/errors, timeout and
unavailable stronger behavior, native decision independence and precedence,
unsupported transform/defer paths, action binding, preserved native approval,
script provenance/call counts, no discovery/post calls, no caching and unchanged
judge input after evaluator-only metadata changes. Existing checks: **33 passed,
one pre-existing missing-demo skip, 48 deselected**. Selected lint checks passed.
No unrelated failures were observed. Generated artifacts remain ignored; their
manifests report the starting revision and dirty tested-source state.

### Files and limits

Added `judge.py`, `judged_gateway.py`, `scripted_controls.json`,
`policies/judge_controls.yaml`, `JUDGE_INTERFACE.md`, and
`tests/test_harness_alignment_judge.py`. Extended `offline.py`, `runner.py`,
`casebook.py` reporting, the casebook metadata test, README/spec/format and this
log. The original four-case test, original policy, 24-case data and production
source remain unchanged. No hooks, live policy, permissions or real services
were touched. Previously flagged source examples were treated as reference data.

Remaining: mentor review of provisional/unresolved labels; establish Niti's
actual API/checkpoint/configuration before inference; design verified transform
rebinding and typed grant/provenance/context adapters if needed. The subclass is
for synchronous disposable research fixtures, not a production deployment.
Prompt 5 remains pending; all existing working rules remain in force.

## Prompt 5 — zero-request comparison infrastructure

Rechecked the clean research branch, applicable root instructions and the
previous specification/format/progress/code/diff before editing. Starting HEAD:
`583dbfaf5921d2de70babb8884ecfd1c987b29a9`. No branch switch or production change.
All established scope/input boundaries/fixture working rules remain in force.

Repository searches found no supplied Niti interface or selected comparison
judge configuration. Older semantic-judge-coverage examples are injection
screening, not evidence of either requested authorization API. Both roles are
explicitly unavailable in `models.json`; `live_settings.json` is false/zero.
Exact missing evidence: endpoint/checkpoint, request/response schemas,
policy/task/authorization/context conditioning, model/version, supported
parameters, authentication/credential reference, then a verified concrete adapter.
No model call, model download, approval-network call or external lookup ran.

Added `model_io.py` internal budget/attempt/replay utilities and `comparison.py`
zero-request planning/native pilot entry point. Every eventual inference
attempt/question/retry must consume a shared budget; no hidden retries/fallback
are supplied. Raw synthetic response/native fields and normalized parsing/error
records are separate. Unknown usage/cost stay null; confidence text is not a
probability. Exact replay identity includes full visible input, conditioning,
version and inference configuration; replay never establishes live latency.
Only explicit offline unit fixtures exercise the generic dispatch recorder.
Concrete provider normalization and multi-question aggregation are blocked by
missing interface evidence, rather than approximated with an invented schema.

Judge-only plans retain both selected pair members regardless of native blocks.
Gateway plans record actual judges-run lists separately and retain native
short-circuiting. Added an optional short-circuit flag at the existing subclass
seam (default false for the prior scripted controls) and tested that a native
block invokes zero judges and forwards zero calls through inherited methods.
No alternate forwarding path was introduced. All model plans remain unexecuted
with null forwarding/judgment fields. No model gets credit for native blocks.
The dry run separately executes only the established disposable native gateway.

Run command:

```bash
python3 -m research.harness_alignment.comparison --mode dry-run
python3 -m pytest tests/test_harness_alignment_models.py tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
ruff check --select E9,F63,F7,F82 research/harness_alignment/*.py tests/test_harness_alignment_models.py
```

Actual dry run `20261021T192852Z-f1f7edf1`: zero inference; 15 supported native
cases, nine unsupported; 10 recorded upstream calls; three simulated native
approval requests. Provisional native requirement/forwarding agreement each
15/15 cases, 10/10 pairs, 5/5 whole families. Incorrect permits and unnecessary
blocks each 0/15 against provisional forwarding expectations. No reviewed labels
or genuine judge responses; all judge paired rates and live latency/usage/cost
unavailable. Comparison-plan rows: 15 observed native, 51 unavailable and 36
unsupported (not model-request counts). Generated outputs remain ignored and
include hashes, Git dirty state/configuration, source versions and run ID.
The manifest separately records shipped native semantic enabled/auto settings;
all fixture modes disable screening to avoid hidden model inference. Active live
workspace/org effective settings were not resolved/refreshed and remain unknown.

Final focused suite: **82 passed in 73.21s** (55 preceding checks and 27 new
infrastructure checks); selected lint passed. No unrelated failures.
Added tests for zero-call gates, failed retry budget, raw/text/usage retention,
credential redaction, missing actual version, distinct errors, exact replay,
input metadata boundary, genuine pair scoring and no credit for scripted/replay/
short-circuit records. False/zero and enabled-but-unconfigured smoke refusal were
exercised only in offline tests. The bounded future smoke command is documented
and printed by dry run; it was not executed against any model.

Changed files: new `comparison.py`, `model_io.py`, `live_settings.json`,
`models.json`, `MODEL_INTEGRATION.md`, `PILOT_REPORT.md`,
`INDEPENDENT_EVALUATION_PLAN.md`, `tests/test_harness_alignment_models.py`;
small optional seam changes in `judged_gateway.py`/`offline.py`; README and this
log. The separate mentor report states contribution, results, failure controls,
limitations and next experiment. No final holdout was generated. Existing
casebook, expectations, policy semantics, original gateway proof and production
code are unchanged. Source examples flagged by Prismor were treated as data;
no suggested live screening changes or external judge invocation was followed.

Final scoped review also bound attempt limits to the hashed inference
configuration and required genuine attempt records plus actual judges-run lists
before judge scoring. This prevents native-only or synthetic metadata from
earning judge credit. Repeated dry run retained zero real requests and the same
native counts; generated run artifacts are confirmed ignored.

## 2026-10-22 — Measurement/evidence hardening (offline only)

Inspected actual branch `research/harness-alignment-eval`, HEAD
`54f99441e038a3501e67a234561bbe133f438d2b`. Initial tracked diff was empty;
`reports/20261021T193914Z` was already untracked and is preserved. Read applicable
root/parent instructions, prior progress, actual definitions/tests and latest
audit/probe script. The parent JEV helper uses an external TypeSafe client, so
it was not invoked under the explicit no-remote-services restriction.

Before editing, ran the existing A1–A3 audit script and full-checkout source
helper probes for R1–R3. Also reproduced all six with six pytest probes in a
full local archive of the inspected starting revision, including valid raw
uncertainty and a real native-gateway post-forward fault. No extracted-definition
helper substituted for integration. See the new, separate
`hardening/20261022-offline/` output directory; historical artifacts remain intact.

Implemented a separately retained recording boundary, predeclared full request
identities and required stages, registered parser versions, explicit versioned
single/all-required/selective aggregation, exact requested/actual model-version
checks, and authoritative-record validation/re-parsing for replay and scoring.
Offline fixture parsers remain outside the empty live adapter registry. The
trust boundary excludes whole-process or manifest-owner compromise; checksums
are consistency checks, not cryptographic provider provenance. Old unbound rows
fail closed. Replay always has replay provenance and null live latency.

Reporting now exposes population/attempt/completion/decisive/abstention/
authorization/error counts, coverage, conditional and unconditional correctness,
predeclared/attempted/completed/answered pairs, unresolved references and duplicate
rows. Valid allow/uncertainty gives 1/1 decisive accuracy, 1/2 coverage, 1/2
correct over attempts, 0/1 correct attempted pairs and null conditional pair rate.
Native failures carry partial requests/arguments/snapshots/counts/binding evidence
through `ObservationFailure`; post-forward detection is not prevention. Unknown
forwarding remains separately counted. No native execution semantics changed.

Budget deadlines refuse new calls and reject late callback/normalization results;
retained canonical UTF-8 response bytes have a separate cap. These are callback
contracts, not provider transport experiments or cancellation guarantees. No
Niti transport was invented. Actual token-cap/streaming/hard-deadline/SDK-retry
verification remains a concrete adapter prerequisite.

Added 24 blank blind review forms, evaluator-only hash/family map and a proposed
version-1 annotation sidecar schema. No original labels/schema or fixture policies
changed. No human reviewer, decision or approval was invented. The later human
import procedure is documented; automatic import/approval is not implemented.

Actual verification (commands/logs in `hardening/20261022-offline/REPRODUCE.md`):

- Full focused suite: **107 passed in 106.16s**, including **25** new hardening
  regressions. JUnit and log: `passing_focused_tests.*`.
- Existing gateway/tool-policy/surface selection: **33 passed, one pre-existing
  missing-demo skip, 48 deselected**, 10.70s.
- Six pre-hardening full-checkout witness tests: **6 passed**, 8.32s.
- Native four-case forwarding: **1,0,0,1**. Final native dry run: **15 supported,
  nine unsupported, ten upstream calls**, three simulated approval requests;
  provisional native requirements/forwarding each **15/15 cases, 10/10 pairs,
  5/5 whole families**. These remain engineering observations, not model accuracy.
- Selected lint and `git diff --check` pass. Interim logs retain a stale source-
  hash-list expectation and a deadline-test setup failure, both corrected; neither
  was an actual model failure.

Changed only research implementation/docs, focused tests and the new hardening
output. No production source, live hooks/policies/settings, model download,
external service, branch switch/reset/stash/pull, Git commit/push/merge occurred.
`LIVE_MODEL_RUN=false`, `MAX_REAL_REQUESTS=0`; real external inference requests:
**zero**. Explicit offline budgets were fixture-only and never genuine results.

Single next experiment: the same independently reviewed two-case judge-only
bounded development smoke, after the actual Niti/stronger schemas, immutable
identities, conditioning, concrete verified transports/parameters/auth references,
deadline/token/byte/retry accounting and separate human live authorization exist.
Exact prerequisites and limits: `MODEL_INTEGRATION.md` and the new hardening review.

## 2026-10-22 — Checkpoint and conservative documentation cleanup

Created the explicitly approved 19-file local checkpoint:
`9e2ca79dcf842cdd13d4b1c45c7c2e724d6b7e60` —
`Checkpoint offline harness alignment hardening`. Before committing, checked the
exact staged list, credentials patterns and `git diff --cached --check`; no
unrelated or production files were staged. No push, merge or PR was created.

Backed up both complete evidence directories, including ignored/untracked files,
to `/tmp/prismor-harness-evidence-checkpoint-20261022T144104421425Z/evidence.tar.gz`.
The adjacent `manifest.json` records every file hash and archive verification.
All 163 archived files matched the originals; existing hardening checksums were
49/49 and historical-audit checksums 111/111. Archive SHA-256:
`8b560a1b900bfbe0cd5a48b84357e34a6769cb0a0b2427d957f798ec6110707a`.
This is a local `/tmp` backup; retain a durable copy before temporary storage is
cleared. The original directories remain in place, with their evidence untracked
or ignored except for the three checkpointed hardening instructions.

Cleanup is limited to `README.md` and this appended progress note. Consolidated
the README from 234 to 146 lines into current scope, decision-to-forwarding path,
existing-environment setup, exact reproduction commands, measured observations,
unsupported behavior and model/annotation prerequisites. Removed repeated
explanations, conversational exclusions and superseded test summaries from that
guide. No files were deleted: the other documents define contracts, preserve
results or have citations. The unused-import check found none. Existing cache
and `/runs/` ignore rules suffice; no new rules hide historical evidence.
Implementation, tests, prompts/controls, casebooks, labels, policies,
configurations, forms and historical reports/results remain unchanged.

New verification is separate from historical evidence at
`runs/20261022T144413Z-cleanup-verification/`; exact invocations are in
`commands.json`, with per-command logs, JUnit and `native-dry-run/` observations.
The tested revision is the checkpoint with the README cleanup dirty.

- Full focused harness suite, including 25 hardening regressions: **107 passed**,
  100.85s. No failures.
- Same selected native gateway/tool-policy/surface checks: **33 passed,
  one pre-existing missing-demo skip, 48 deselected**, 10.33s.
- Separate original forwarding experiment: **4 passed**, 6.33s;
  before/after counts remain **1,0,0,1**.
- Supported-subset dry run: before/after **15 supported, nine unsupported,
  ten upstream calls**; real model requests remain **zero**.
- Selected lint plus unused imports passed; README links and `git diff --check`
  passed. Historical checksums and all original evidence bytes still match.

Live inference stays false/zero; no remote service or real approval system was
used, and no labels were marked reviewed. The parent JEV helper remains uncalled
because it invokes a remote service. Cleanup changes are left uncommitted for
review, with the Git index empty.
