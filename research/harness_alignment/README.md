# Prismor Harness Alignment: offline gateway boundary

Scope: establish how trusted fixture policy and simulated authorization govern
execution through Prismor's actual MCP gateway. This is an integration milestone;
`model_status` is `not_run`. Niti's API/checkpoint remain unverified. VLM monitoring
and the Gemma competition project are separate.

## Model comparison infrastructure (live execution disabled)

**No live model was run.** Both real configurations remain unavailable because
no supplied Niti/comparison protocol or selected model configuration was found.
The [integration status](MODEL_INTEGRATION.md) lists exact prerequisites and the
bounded future smoke command. The [mentor pilot report](PILOT_REPORT.md) separates
actual native observations from unavailable model plans. A
[fresh reviewed evaluation plan](INDEPENDENT_EVALUATION_PLAN.md) is separate from
the current development casebook.

```bash
python3 -m research.harness_alignment.comparison --mode dry-run
python3 -m pytest tests/test_harness_alignment_models.py tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
```

Dry run makes zero real requests, records the native fixture baseline (15
supported, nine unsupported, ten recorded tool calls), and plans both members
of a selected judge-only pair separately from native-short-circuiting deployment.
Null model results stay null. Reviewed and genuine judge-pair denominators are
zero/unavailable. The focused suite passed **82 tests**. Live configuration,
permissions and production behavior remain unchanged.

## Scripted research judge

[Judge interface and composition](JUDGE_INTERFACE.md) describes the research
protocol and safety limits. This is our contract, not Niti's API. The native
evaluator and forwarding branch remain real. A research-only Gateway subclass
snapshots native evidence and adds restrictions through the native `Decision`
constructor and precedence API. It cannot clear native blocks or approvals.

Run the comparable controls (same casebook, fixture policy and enforcement):

```bash
python3 -m research.harness_alignment.runner --mode gateway --experiment native-rules
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-fast
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-stronger
python3 -m research.harness_alignment.runner --mode gateway --experiment scripted-selective
python3 -m pytest tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
```

`ScriptedJudge` receives only judge-visible input, never expected labels. It
distinguishes valid allow/deny/missing-authorization/semantic-uncertainty results
from invalid-output/timeout/unavailable errors. All replies have scripted
provenance. The default stronger control deliberately denies; selective mode
escalates an explicit uncertainty to an explicit allow. These are control-flow
fixtures, not model decisions. Script calls are counted separately from actual
model calls (zero); no cross-case cache is used. No accuracy, calibration,
attack-success or inference-cost claim follows from the controls.

Native snapshots, composed decisions, approval routing/outcomes, original and
judge-visible actions, effective action when available, and forwarded arguments
remain separate in JSONL. General transforms/redacted approvals and native
defer composition are explicitly unsupported and refuse before forwarding.
Selective semantic escalation is a research extension; production gateway defer
handling has not been changed. Full simulated native approval remains required
for uploads even when a research judge allows. Errors and unresolved replies
also refuse. General Niti/model-interface coverage remains zero.

The comparable development runs each retained 15 native-supported cases and
nine unsupported mappings. Their observed control-flow totals were:

| Mode | Script calls | Model calls | Upstream tools/call |
| --- | --- | --- | --- |
| native-rules | 0 | 0 | 10 |
| scripted-fast | 15 | 0 | 10 |
| scripted-stronger | 15 | 0 | 0 |
| scripted-selective | 30 | 0 | 10 |

Focused integration tests: **55 passed** across the judge, casebook and original
gateway suites. Relevant existing checks: **33 passed, one pre-existing skip**
for the missing stdio demo. Selected lint checks passed. The nine unmapped
casebook cases and original provisional/unresolved labels remain unchanged.

## Development casebook and runner

The [one-page specification](SPEC.md) defines this stage. The
[case format](CASE_FORMAT.md) and `casebook.schema.json` separate judge-visible
input from evaluator-only metadata. The casebook has **24 development cases in
eight triples**, with 16 explicit scored pairs. Labels are 22 provisional and two
unresolved; none are human-reviewed. There is no held-out benchmark.

Run from the repository root using the existing development environment
(runtime dependencies, pytest for tests, and jsonschema from this directory's
`requirements.txt`; no dependencies were installed during this milestone):

```bash
python3 -m research.harness_alignment.runner --mode validate
python3 -m research.harness_alignment.runner --mode decision-only
python3 -m research.harness_alignment.runner --mode gateway
python3 -m pytest tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
```

Each runner command prints a compact summary and its output directory. The
default is ignored `runs/<run-id>/`, containing `observations.jsonl`,
`summary.json`, and `manifest.json`. `--output <new-directory>` selects another
location; existing directories are refused. The manifest records Git revision
and dirty state, casebook/schema/policy hashes, Python version, configuration and
run IDs. Generated runs stay out of commits.

Validation covers all 24 cases. Native decision/gateway modes support 15 cases
in task-scope, resource, upload, dummy-sensitivity and paraphrase families. Nine
cases in provenance, argument-bound grants and contextual sufficiency remain
unsupported, with precise per-case reasons. Two of those nine are unresolved
(`provenance-unknown`, `context-missing`). Review all 22 provisional labels with
the mentor; resolve these two before stronger evaluation.

Supported native restrictions are explicitly encoded in fixture YAML. Native
Prismor does not read the casebook's natural-language task, policy explanation
or authorization evidence. Authorization is an explicit simulated service
configuration; no grant validation or provenance understanding is implied.
All general judge evaluations remain unsupported and `model_status: not_run`.

Decision-only uses real event construction and `evaluate_tool_call` with
`persist=False`, `record=False`, `register_agent=False`, `flush_at_exit=False`;
it never calls a tool or resolves approval, and execution fields remain null.
Gateway mode uses the real native branch with a recording upstream. The original
four-case test below remains unchanged. New `offline.py` follows its fixture
pattern, isolates each case, and guards external services without importing
pytest into the runner. A denied simulated service response also exercises
native approval polling. Service attempt counters fail even when errors are
swallowed by native best-effort handling.

Metrics are **provisional development agreement**, separately for native
requirements, optional judge judgments and actual forwarding. On the development
run, native requirements matched 15/15 compatible cases, 10/10 pairs and 5/5 whole
families; gateway forwarding matched the same denominators. This is an integration
observation against provisional labels, not independently validated accuracy.
Decision-only forwarding and every judge denominator are zero, with null rates.
Unsupported/unresolved/failed/unobserved cases are excluded from incompatible
denominators and remain visible. A blocked tool response is a successful
integration observation (`status: ok`, `response_status: tool_error`), not a
runner failure.

Validation: **22 passed** in the casebook/original-boundary focused command;
the existing gateway/tool-policy/surface selection passed **33 tests**, with one
pre-existing skip for the missing stdio demo fixture. The exact existing-check
command is recorded in [the progress log](PROGRESS.md). Selected repository lint checks also
passed. No production files or the original four-case test were changed.

## Original four-case boundary

From the repository root, display and check all four JSON observations:

```bash
python3 -m pytest tests/test_harness_alignment_gateway.py -q -s
```

| Case | Native pre-action verdict | Governing rule | Native approval outcome | Upstream tools/call | Response |
| --- | --- | --- | --- | --- | --- |
| A | allow | none | not requested | 1 | ok |
| B | block | harness-marker-block | not requested | 0 | tool_error |
| C | step_up | harness-marker-approval | request_failed (simulated unavailable service) | 0 | tool_error |
| D | step_up | harness-marker-approval | approved (simulated service response) | 1 | ok |

The JSON includes the actual forwarded tool name and arguments. C and D send the
same `HA_APPROVAL` argument and use the same policy. D is **simulated approval**,
not a human approval workflow. Discovery requests never contribute to the count.

## Interfaces and isolation

The focused test reuses `FakeUpstream`, `stub`, `make_gateway`, and `list_tools`
from `tests/test_mcp_gateway.py`. It never uses `allow_all`. The upstream is an
in-process recording fixture exposing one harmless `echo` tool with a fixed
benign response. `Gateway._handle_tools_call_safe`, `_handle_tools_call`,
`_build_call_event`, `_evaluate`, `runtime.evaluate_tool_call`, and
`PolicyEngine.evaluate` remain native.

`gateway_policy.yaml` is validated and copied into each disposable workspace's
`.prismor/policy.yaml`. Its MCP rules match markers in `response`, the real
gateway's serialized argument field for an ordinary stdio tool. Empty discovery
arguments do not match: the tool remains advertised in every case. Both rules
explicitly enforce; the test verifies native passthrough is inactive.

`approvals.await_step_up` remains native. Only its `_post_request` service source
and module-local identity dependency are simulated. The runtime itself remains
unenrolled. C returns no service response; D returns an immediate approved
response. Any poll is forbidden. Native approval outcome decoding and local
audit recording remain active.

`sys.setprofile` observes evaluator and approval-handler returns without
replacing them. Pre-action snapshots and post-action scans are recorded
separately; D's later allow result cannot replace its pre-action `step_up`.
This instrumentation measures behavior, not performance.

Tests inherit disposable HOME/state isolation from `tests/conftest.py`, add
fresh Prismor/config/cache/secret directories, remove inherited Prismor/API-key
settings, and use a synthetic principal. Remote refresh is stubbed, its verified
cache is isolated, semantic analysis is disabled by fixture policy, and network,
telemetry, judge, and approval-poll entry points are guarded. Attempt counters
also catch exceptions swallowed by runtime best-effort handlers. Patches have
an explicit cleanup scope to avoid third-party pytest plugin teardown ordering.

Working rules: preserve production behavior and live configuration; no hook
installation, enrollment, permission changes, real approval calls, model calls,
downloads, pushes, publication, or merging. All runtime writes are disposable.

## Checks and limitations

The focused command passed all four cases. Relevant existing checks plus the
new cases:

```bash
env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/test_mcp_gateway.py tests/test_tool_policy_three_state.py tests/test_surface_conformance.py tests/test_harness_alignment_gateway.py -q -rs -k 'gateway_execution_boundary or call_forwarded_on_allow or call_blocked_pre_forward or engine_error_fails_closed or call_step_up or call_modify or gateway_end_to_end_real_engine or three_state or surface_conformance'
```

Result: **37 passed, 1 skipped, 48 deselected**. The existing real-stdio demo
test skipped because `examples/mcp-block-demo/mcp_server.py` is absent.
Plugin autoload is disabled for that regression command to exclude unrelated
installed plugins; the focused command also passes with normal plugin loading.

This proves the in-process gateway forwarding boundary with real policy. It
does not test stdio wire transport, a live approval server, model decisions,
Niti performance, latency, redacted approvals, or defer/modify behavior. Native
gateway defer resolution remains a separate gap identified in Prompt 1.

## Measurement hardening milestone

The [offline hardening review](hardening/20261022-offline/HARDENING_REVIEW.md)
contains reproduced A1–A3/R1–R3 witnesses, patched regressions, exact test logs and
native observations. Conditional agreement is now accompanied by attempted-case
coverage and unconditional counts; native failed executions preserve partial
forwarding evidence. Scoring/replay require a separately retained recording
boundary and versioned registered normalization/aggregation. Historical counts
above remain historical; the updated contract and transport limitations are in
[MODEL_INTEGRATION.md](MODEL_INTEGRATION.md#offline-hardening-contract-2026-10-22).
The [label handoff](hardening/20261022-offline/LABEL_REVIEW.md) provides 24 blank
blind forms and a proposed annotation sidecar, without approving any label.
