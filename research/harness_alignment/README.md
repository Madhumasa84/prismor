# Prismor Harness Alignment

This research harness asks how a future decision judge responds to trusted task,
policy, authorization and context changes, and how Prismor governs the resulting
tool execution. Current scope is **offline integration and evidence handling**.
Passing these tests is not evidence of Niti effectiveness. No genuine model
results exist; real external inference requests remain **zero**.

The development casebook has 24 synthetic cases in eight families and 16 declared
pairs: 22 provisional expectations, two unresolved references and no reviewed
labels. Only the `input` subtree is judge-visible; labels, family IDs, review
annotations and native fixture configuration remain evaluator-only. Inputs,
expectations, policies, configurations and scripted controls are preserved.

## Decision-to-forwarding path

1. `runner.py` validates the casebook and creates fresh disposable state for each
   supported case. Unsupported mappings retain their reasons and null observations.
2. `offline.py` drives Prismor's real MCP gateway and `evaluate_tool_call` with
   explicit fixture YAML. Native policy reads tool arguments, not the casebook's
   natural-language task or authorization evidence.
3. In scripted modes, `ResearchGateway._evaluate` snapshots the native decision
   and composes an additional restriction through the native `Decision` contract.
   A scripted allow cannot clear a native block or approval requirement.
   Only valid semantic uncertainty triggers selective stronger-script routing;
   missing authorization and errors remain distinct and refuse.
4. Inherited gateway code performs forwarding and approval processing. The
   upstream is an in-process recording echo fixture; approval-service responses
   are simulated. Discovery and post-action scans never invoke a research judge.
5. Records separate native/composed decisions, approval resolution, arguments,
   forwarding and script/model counts. Failures retain partial evidence; a
   post-forward mismatch detects execution that already happened. Unknown is
   not zero. Model scoring/replay require a trusted recording boundary,
   registered parser/version and explicit required-attempt aggregation.

Network, telemetry, remote refresh and native semantic inference are guarded or
explicitly disabled in disposable fixtures. Live policies and hooks are untouched.
`decision-only` evaluates without forwarding or resolving approval. Scripted,
fixture, replay and genuine-live provenance remain separate; scripts are never
credited as model observations. Replay provides no new live-latency evidence.

## Existing environment and reproduction

Run from the repository root using the existing Python environment with runtime
dependencies from `pyproject.toml`, pytest and jsonschema (research constraint in
[requirements.txt](requirements.txt)). No install or model download is needed in
this checkout. Check the environment, then run the full focused suite:

```bash
python3 -c 'import prismor, pytest, yaml, jsonschema'
python3 -m pytest tests/test_harness_alignment_models.py tests/test_harness_alignment_hardening.py tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q -s
```

Run the same selected native regressions and the original four-case experiment:

```bash
env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/test_mcp_gateway.py tests/test_tool_policy_three_state.py tests/test_surface_conformance.py -q -rs -k 'call_forwarded_on_allow or call_blocked_pre_forward or engine_error_fails_closed or call_step_up or call_modify or gateway_end_to_end_real_engine or three_state or surface_conformance'
python3 -m pytest tests/test_harness_alignment_gateway.py -q -s
```

Run the supported-subset dry run or inspect the other offline modes:

```bash
python3 -m research.harness_alignment.comparison --mode dry-run
python3 -m research.harness_alignment.runner --mode validate
python3 -m research.harness_alignment.runner --mode decision-only
python3 -m research.harness_alignment.runner --mode gateway --experiment native-rules
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-fast
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-stronger
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-selective
ruff check --select E9,F63,F7,F82 research/harness_alignment/*.py tests/test_harness_alignment*.py
git diff --check
```

Each CLI invocation creates a new ignored `runs/<run-id>/` with observations,
summary/pilot and a provenance manifest. `--output <new-directory>` selects a
location; existing destinations are refused. Preserve old runs. Manifest hashes,
Git revision/dirty state and configurations identify the tested snapshot.
Default CLI outputs and Python caches are already ignored; historical evidence
under `reports/` and `hardening/` must remain intact, including ignored logs.

## What has been measured

The hardening snapshot recorded 107 focused passes (25 hardening regressions)
and 33 selected native passes, with one missing-stdio-demo skip. New verification
belongs in a new run and the [progress log](PROGRESS.md), not historical reports.

| Offline observation | Recorded result |
| --- | --- |
| Original permitted / blocked / approval unavailable / approval simulated | **1,0,0,1** forwarded calls |
| Supported native subset | **15 supported, nine unsupported, ten upstream calls** |
| Native simulated approval requests | 3 |
| Provisional native requirement and forwarding agreement | 15/15 cases, 10/10 compatible pairs, 5/5 whole families |
| Real inference requests, genuine responses, reviewed labels | **0** |
| Model accuracy, live latency, usage and monetary cost | unavailable |

These are wiring observations against provisional expectations, not independently
validated accuracy. Metrics separate the preselected population, attempts,
completed responses, decisive answers, semantic abstentions, authorization
requests and errors. Conditional correctness is accompanied by answer coverage
and unconditional case/pair counts; duplicates add no samples. Unresolved
reference labels are not forced correctness targets.

The preserved scripted controls recorded script/forwarded-call totals of
0/10 (native), 15/10 (fast), 15/0 (stronger) and 30/10 (selective), all with zero
model calls. The stronger script deliberately denies: it is a control, not a
stronger-model effectiveness result.

## Unsupported behavior and prerequisites

Nine cases lack native mappings for provenance, argument-bound grants or context.
General transforms, redacted approval binding and native defer resolution remain
unsupported for research composition. The fixture does not test a live approval
system, stdio wire transport or production concurrency.

`live_settings.json` remains `LIVE_MODEL_RUN=false`, `MAX_REAL_REQUESTS=0`;
`models.json` leaves both model roles unavailable and `VERIFIED_ADAPTERS` is empty.
Niti and the selected comparison model still need verified endpoint/checkpoint,
request/response schemas, all questions/stages and aggregation, policy/task/
authorization/context conditioning, immutable model identities, generation
parameters and authentication references. A concrete verified transport must
also establish deadlines/cancellation, provider token caps, streaming byte caps
and complete retry/underlying-attempt accounting. Local callback deadline tests
are not transport experiments and do not establish cancellation of inference.

All 24 blank independent-review forms and their proposed versioned sidecar are
preserved in [the label handoff](hardening/20261022-offline/LABEL_REVIEW.md).
Reviewers must label independently; exported forms approve nothing. Hash binding,
human provenance and adjudication must be checked at the documented subsequent
import step. No importer or automatic label approval is enabled.

## Contracts and preserved evidence

- [Specification](SPEC.md), [case format](CASE_FORMAT.md) and
  [scripted judge contract](JUDGE_INTERFACE.md): input boundaries, composition and
  supported behavior; controls remain in `scripted_controls.json`.
- [Model integration contract](MODEL_INTEGRATION.md): exact recording/replay/
  aggregation rules, trust boundary and transport prerequisites. Checksums prove
  consistency, not remote inference; whole-process or joint row/manifest rewrite
  is outside the trust boundary.
- [Hardening review](hardening/20261022-offline/HARDENING_REVIEW.md) and
  [reproduction record](hardening/20261022-offline/REPRODUCE.md): original witnesses,
  manifests, logs and documented intermediate failures.
- [Historical pilot](PILOT_REPORT.md) and
  [independent evaluation plan](INDEPENDENT_EVALUATION_PLAN.md): retained for their
  recorded results and future evaluation constraints, not current model evidence.
