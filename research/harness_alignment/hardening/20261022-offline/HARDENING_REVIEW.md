# Harness Alignment offline hardening

Starting and finishing branch: `research/harness-alignment-eval`, HEAD
`54f99441e038a3501e67a234561bbe133f438d2b`. HEAD was inspected, not assumed.
The initial tracked diff was empty; the pre-existing timestamped audit directory
was untracked and has been preserved. All changes are uncommitted research code,
focused tests, documentation and this separate output directory. No production
Prismor source, casebook labels/policies, historical report or live settings changed.

| Issue | Reproduced before | Hardened behavior / exact evidence |
| --- | --- | --- |
| A1 | Two normalized allows with allow/deny summaries earned 1/1 pairs | `RecordingBoundary` predeclares identities/required stages, captures records, re-parses and aggregates; inconsistent summary gets no completion/credit. `after_checks.json:A1` and summary/multi-stage/selective regressions. Caller booleans are ignored. |
| A3 | Changed raw response replayed successfully | Independent raw, normalized, model, parser and context mutations are rejected against the retained recording manifest; summary/aggregation mutations fail scoring. Replay re-parses with registered version and remains `offline_replay`, with null live latency. |
| R2 | Requested LOCAL-FIXTURE-v1 / actual v2 returned valid | Exact pinned version equality at dispatch, boundary validation/scoring and replay. Diagnostic actual version retained; mismatch is invalid output and cannot earn credit. No alias or fallback model. |
| R1 | Valid allow/uncertainty yielded cases 1/1, pairs unavailable, no coverage | Two-case fixture now reports attempted/completed 2, decisive 1, abstentions 1, accuracy 1/1, coverage 1/2, correct over attempts 1/2, fully correct attempted pairs 0/1, conditional pair rate null. Unresolved references, authorization requests and errors are separate. Duplicate rows earn no extra samples. |
| R3 | Native post-forward mismatch failed with forwarding null after one recorded call | `ObservationFailure` carries observations into failed runner rows: pre-call fault retains known zero, post-forward fault retains one call, arguments, native/composed snapshots, approvals, binding mismatch and call counts. Detection after forwarding is not prevention. Unknown forwarding is separately counted. |
| A2 | 1 ms callback slept ~20 ms and retained 2,000 characters under intended token cap 1 | Late returned envelopes rejected; decision deadline also checked after normalization; expired budget prevents another callback; retained canonical UTF-8 byte cap enforced after callback. Provider token caps, streaming allocation bounds, hard cancellation and hidden SDK retries remain transport prerequisites. Callback tests are not transport experiments. |

All six old failures were reproduced before repair; six additional pytest probes
against a full archived checkout passed. The archive retains the real native
gateway and runtime, and the R3 witness performs a controlled post-forward fault.
See `before_audit.json`, `before_helpers.json`, `before_full_checkout_tests.log`
and the repeatable instructions in [REPRODUCE.md](REPRODUCE.md).

## Trust boundary and limits

The trusted evaluator owns parser registration, predeclared plans and the
recording manifest independently of editable result rows. The current offline
implementation keeps separate in-process digest/plan copies; importing a saved
manifest explicitly requires the caller to supply a trusted manifest. A future
live recorder needs independently protected storage or an authenticated archive
whose signing key is outside the result writer. None is deployed here. Digests
establish consistency, not proof that a remote provider ran inference. Ownership
of the whole Python process/parser code, or simultaneous rewriting of rows and
the authoritative manifest, is outside this boundary.

The live adapter registry remains empty. Offline parsers are registered only on
explicit `test_fixture` boundaries; genuine execution with those adapters is
refused. No synthetic trace is stored as a genuine model result. Expected labels
are consulted only after observation validation. Versioned aggregation retains
all required attempts; it does not blindly treat the final attempt as the final
decision. Old unbound records fail closed. Native forwarding/approval semantics
are inherited unchanged; the only production-adjacent changes are observation
handling in the research fixture. No production change was necessary.

## Validation and handoff

Final focused suite: **107 passed in 106.16s**, including **25 hardening
regressions**. Existing selection: **33 passed, one pre-existing skip,
48 deselected**. Six archived pre-patch witnesses passed. Selected lint and
`git diff --check` passed. Exact commands/results are in `hardening_results.json`
and the linked logs; intermediate failures are preserved with their corrections.
All **111/111** published checksums of the historical report still match. Native baseline
counts remain **1,0,0,1**, and the supported-subset dry run remains **15 supported,
nine unsupported, ten upstream calls**, with provisional engineering agreement
15/15 cases, 10/10 compatible pairs and 5/5 families. These are integration
observations, not model-effectiveness results. Real external inference requests:
**zero**. Live settings remain false/zero; model latency, usage and cost are null.

[LABEL_REVIEW.md](LABEL_REVIEW.md) hands off all 24 blank blind forms and a
proposed version-1 annotation sidecar. No reviewer, approval or reviewed label
was invented; no automatic importer was enabled. All annotations/family metadata
stay evaluator-only. The existing casebook schema is unchanged.

Niti and the selected stronger judge still require: actual endpoint/checkpoint
and invocation; complete request/response schemas; all questions/stages and
aggregation; policy/task/authorization/context/provenance conditioning; immutable
model identity and returned-version semantics; supported generation parameters;
authentication mechanism with a credential reference (not a value); verified
parser and concrete transport; connect/read/overall deadlines and cancellation
semantics; provider generation-token and streaming byte caps; disabled or fully
reserved SDK retries and complete underlying attempt accounting. See the limit
ownership table in `MODEL_INTEGRATION.md`. No Niti interface was invented.

The single next experiment is a bounded **judge-only development smoke on the
same independently reviewed two-case pair**, once that actual transport contract
is supplied and verified and a human separately authorizes a nonzero budget.
These repairs enable trustworthy evidence/coverage reporting for that smoke;
they do not authorize it or establish model effectiveness.

The parent JEV helper was inspected but not called because it invokes a remote
TypeSafe service, conflicting with the explicit offline-only instruction.
