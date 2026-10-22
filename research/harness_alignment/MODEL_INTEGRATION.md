# Model integration status and bounded comparison

**No live inference ran.** `live_settings.json` fixes `LIVE_MODEL_RUN=false` and
`MAX_REAL_REQUESTS=0`. `models.json` leaves both roles unavailable. No concrete
Niti or comparison adapter is implemented because no supplied protocol was
found. `ScriptedJudge` retains its name and provenance; it is neither model.

## Evidence and missing prerequisites

Repository searches for Niti, judges, checkpoints, comparison configuration,
LIVE_MODEL_RUN and MAX_REAL_REQUESTS found this project's research contract and
older prompt-injection work under `research/semantic-judge-coverage/`.
`data/compare_judges.py` aggregates historical injection-screening outputs;
its model names and CLI examples do not establish an action-authorization API,
a chosen stronger judge, or a Niti checkpoint. No external lookup was performed.
No supplied document identifies any of the following for **either** role:

| Required evidence | Niti | Comparison judge |
| --- | --- | --- |
| Exact endpoint or local checkpoint and invocation | missing | missing |
| Request schema, all decision questions, retry behavior | missing | missing |
| Response schema and decision/error normalization | missing | missing |
| How trusted policy/task/authorization/provenance condition the model | missing | missing |
| Immutable model/version identifier; reported version behavior | missing | missing |
| Supported generation parameters and output limits | missing | missing |
| Authentication mechanism and credential environment reference | missing | missing |

Supply the actual documentation/examples and chosen comparison model before a
concrete adapter can be written. Authentication will use environment/config
references after its mechanism is established; never put credential values in
casebooks, configs or logs. Enabling settings alone cannot activate a model.
`VERIFIED_ADAPTERS` is intentionally empty. Generic OpenAI-compatible transport,
`semantic_guard.register_llm`, fallback models and invented endpoints are absent.

## What is implemented

`model_io.py` defines internal recording utilities, **not a provider protocol**:

- Explicit opt-in and a shared request reservation cap. Every inference attempt,
  including each question and retry, must reserve immediately before dispatch;
  failed attempts consume the cap. No automatic retries/fallback are supplied.
- Transport-neutral attempt records retain synthetic raw responses, native fields,
  normalized judgment/error, parsing status, reported model/version, full request
  identity/input hashes, request limits and measured attempt duration. Timeout,
  invalid output and unavailability differ. Confidence text remains text.
- Usage and monetary cost stay null unless returned by the provider; there is
  no fabricated price table or probability. A future multi-question adapter must
  retain every attempt and sum elapsed time/usage across the entire decision.
  This composition cannot be implemented without the actual protocol.
- Explicit replay requires a valid genuine record with matching full judge input
  (including policy/context/authorization), conditioning, model/version and
  inference configuration. Actual reported version must match. Replays carry
  separate provenance and processing timing; their live latency is null. No
  cross-case cache or automatic replay is enabled. Credentials can be redacted
  recursively before records are emitted; transports must supply the secret
  values to the redactor without exposing them in messages or exception text.

`comparison.py` validates unavailable configurations, plans all four comparable
modes, executes an isolated native baseline during dry run, and emits native
observations separately from model plans. Plans have null model results and
execution observations. No unavailable model is invoked to manufacture a deny.
The three model configurations remain **unavailable**, rather than pretending
that adapter/configuration work establishes real model integration.

Judge-only plans include both members of the explicitly selected pair, even if
native rules block one. They cannot affect execution. Gateway plans retain
native short-circuiting; an optional `native_short_circuit` flag on the existing
research subclass demonstrates it with scripted test fixtures. Forwarding stays
in inherited `Gateway` code. Existing scripted modes default to their original
behavior, including the deliberate native-block-plus-scripted-allow control.
When actual adapters exist, only judges actually invoked may receive credit.
General transformations, typed grants, context/provenance mappings and native
defer escalation retain their existing unsupported status.

Selective routing is planned only for a **valid explicit semantic uncertainty**
followed by the stronger judge. Errors hold; missing authorization follows the
native approval requirement and cannot be supplied by another model. No
confidence band is assumed to detect confident errors. How either model exposes
semantic uncertainty still needs verification against its response contract.

## Comparable policies and native configuration

All temporary fixture policies keep enforce mode, identity/approval fixtures,
input evidence, disabled native semantic screening, disabled telemetry/refresh,
and recording upstream constant. Native `evaluate_tool_call` and forwarding are
real. Shipped `default_policy.yaml` enables semantic screening in auto mode;
that configuration is recorded separately in the manifest. Its heuristic/LLM
screening is disabled **only in disposable research policy** to isolate this
comparison and guarantee zero native inference. The active live workspace/org
configuration was not resolved or refreshed and may differ; its effective
configuration remains unavailable. Live settings and permissions are untouched.
This experiment measures the explicit fixture configuration, not all native
production defaults.

## Commands and output

From the repository root, the only model-workflow command executed this stage is:

```bash
python3 -m research.harness_alignment.comparison --mode dry-run
python3 -m pytest tests/test_harness_alignment_models.py tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q
```

The dry run uses zero inference requests regardless of CLI budget/live settings.
It records the selected pair (`task:0` by default), missing prerequisites, source,
casebook/policy/configuration hashes, Git revision/dirty state, and run ID under
ignored `runs/<run-id>/`: `manifest.json`, `native_observations.jsonl`,
`comparison_plan.jsonl`, `pilot.json`. All native baseline tool calls target only
the in-process recording fixture. `--evaluation judge-only|gateway` filters the
comparison plans; the separately labelled baseline still runs for the pilot.
Output directories must be new. No judge request includes evaluator metadata.

The exact bounded future smoke command is printed by dry run:

```bash
python3 -m research.harness_alignment.comparison --mode real-smoke --evaluation judge-only --configuration native-plus-niti --pair task:0 --settings research/harness_alignment/live_settings.json --models research/harness_alignment/models.json --max-real-requests 2 --timeout-seconds 30 --max-output-tokens 256
```

**Not executed.** It currently refuses. Before it can execute, explicit live
permission/settings, positive budget, supplied model configuration, and a newly
implemented verified concrete adapter are all required. The CLI time/output
bounds are internal requirements, not invented generation fields; a future
adapter must map them to verified provider options. Two requests may not finish
a pair if the actual protocol needs multiple questions; incomplete pairs are
unavailable, never filled with scripted answers. Request count must include
provider SDK retries, so those must be disabled or individually reserved.

## Reporting boundaries

`pilot.json` separates native harness agreement from judge-only and deployment
judge agreement. Judge scoring requires unique case records, valid complete
genuine responses from a verified adapter, and suitable non-null labels on both
pair members. Native short-circuits, scripts, replay, errors, unresolved labels
and unsupported mappings cannot produce judge paired correctness. Whole-family
correctness requires every member. Reviewed correctness and provisional
agreement have separate denominators; zero denominators give null rates.

Current reports contain only native fixture observations and unavailable model
plans. The generic scorer is tested with explicit synthetic records; those tests
are not model evidence. Live latency/usage/cost and replay timings remain null.
End-to-end offline fixture duration is recorded separately and includes setup,
approval simulation and instrumentation; it is not inference latency.

## Offline hardening contract (2026-10-22)

The earlier description of caller flags and request-only replay is superseded by
`evidence.py`. `RecordingBoundary.declare` records the selected configuration,
full identities and required attempts **before execution**. Each identity binds
adapter, parser version, aggregation version, exact pinned model version, input,
conditioning and inference configuration. `dispatch` captures the complete record
at the boundary; scoring and replay compare it with the independently held
manifest and recompute normalization through the registered parser. Actual and
requested versions must match exactly; there is no alias or fallback policy.

The deterministic aggregation contracts are `single-v1` (exactly one),
`all-required-v1` (all declared questions, precedence deny > missing authorization
> unresolved semantics > allow), and `selective-v1` (two possible stages declared;
second required only after the first returns unresolved semantics). They are
research utilities, not assertions that Niti implements these protocols. A
concrete adapter must select and version its verified protocol before use.

The manifest is the authoritative recording boundary, retained separately from
editable result rows by the evaluator. In-process fixtures hold private copies
of digests/plans; `from_trusted_manifest` explicitly requires a manifest supplied
by that trusted evaluator. A future persistent recorder must protect it through
independent access control or an authenticated archive with a key outside the
result writer. No such live recorder is deployed here. A digest in the same
editable JSON file is insufficient. This defends against stale/inconsistent
rows, not an attacker who owns Python, changes parser code, or rewrites both
records and the trusted manifest. It establishes no cryptographic provider
provenance or proof of remote inference. Old unbound records fail closed.

Offline fixture parsers live only in a `test_fixture` boundary. That boundary
cannot create live evidence and is absent from `VERIFIED_ADAPTERS` (still empty).
Explicit fixture replay is labelled `offline_replay` with recording kind
`test_fixture`; all replay has null live latency. Production-style scoring
accepts only the genuine namespace and a trusted boundary. Caller
`verified_adapter` and `complete_decision` booleans grant no credit.

Limit ownership is explicit:

| Limit | Current local check | Concrete transport prerequisite |
| --- | --- | --- |
| Overall decision deadline | Shared monotonic `Budget` deadline refuses new dispatches and rejects results returned too late | Bound wall-clock execution/cancellation across all stages; callback code cannot be preempted here |
| Per-request timeout | Pass remaining deadline or request timeout, whichever is smaller; reject a late returned envelope | Enforce connect/read/stream timeout and document remote cancellation semantics |
| Provider generation-token cap | Recorded `output_limit` is an intended token cap; no character-to-token approximation | Verified provider parameter and tokenizer/usage behavior; no Niti transport is supplied |
| Retained-response byte cap | Default 65,536 bytes of canonical JSON UTF-8; discard oversized raw/normalized response, keep byte count and digest | Stream byte cap before buffering, bound envelope/SDK allocation; current callback may already allocate the response |
| Retries/questions | Each callback reserves one attempt, including failures; wrapper retries zero times | Disable SDK hidden retries, or reserve and capture every underlying send; verify at transport boundary |

The sleep/large-response regressions are local callback contracts, **not transport
experiments**. Late responses are rejected after return; no waiting thread or
inference cancellation is claimed. All real execution remains refused pending
these prerequisites. Unknown usage/cost remain null. Raw responses are redacted
before recording; a redaction that prevents deterministic parsing makes the
response ineligible rather than permitting an unverifiable answer.

Scoring reports the preselected known-label population separately from attempted
cases, completed valid responses, decisive allow/deny answers, semantic
abstentions, authorization requests and errors. Authorization requests are valid
but separate from decisive permit/refuse accuracy. `cases`/`pairs` retain their
conditional meaning; `answer_coverage`, `correct_over_attempted`,
`unconditional_pairs` (attempted pairs), and `correct_pairs_over_predeclared`
expose the other denominators. Two known attempted cases with allow/uncertainty
produce 1/1 conditional accuracy, 1/2 coverage, 1/2 correct over attempts,
0/1 fully correct attempted pairs and null conditional pair correctness.
Unresolved references receive no forced correctness label. Duplicate case rows
across runs receive no extra samples or decisive credit. Native summaries retain
conditional metrics and add attempts/coverage; failures retain partial execution
evidence through `ObservationFailure`. A post-forward mismatch is a detected
execution, never a prevented one. Unobserved forwarding remains unknown.

See [the hardening review](hardening/20261022-offline/HARDENING_REVIEW.md) and
[blank independent label review](hardening/20261022-offline/LABEL_REVIEW.md).
