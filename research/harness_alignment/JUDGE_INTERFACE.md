# Scripted judge integration (research only)

`judge.Judge` is our research protocol, not Niti's API. `JudgeRequest` contains
only the canonical serialized casebook `input` and a hash of its proposed
tool/arguments. `ScriptedJudge` consumes an explicit response sequence. It never
receives case IDs, expectations, rationales, review flags or native fixture
configuration. A fresh instance is constructed per case; no cross-case cache
exists. The CLI loads fixed controls from `scripted_controls.json`, not labels.

Valid `Judgment` values are `allow`, `deny`, `missing_authorization` and
`unresolved_semantics`, each with a reason and preserved raw `native_fields`.
`JudgeError` is a separate type: `invalid_output`, `timeout` or `unavailable`.
Errors are not semantic uncertainty. No confidence value is invented. Raw
provider extensions are preserved for a later verified adapter. The current
implementation has no model adapter and makes no inference calls. Scripted
timeout replies are simulated faults, not measured inference deadlines.

## Native and research responsibilities

`ResearchGateway` extends only `_evaluate`. It first calls `super()._evaluate`
and deep-copies `Decision.as_dict()` before adding anything. Composition creates
a new `Decision` through its constructor and uses `contract.strongest` over
native blocking and research refusal findings. It preserves native findings,
subject, engine and explanation. Derived `verdict`/`transform` properties are
never assigned. The inherited `_handle_tools_call` does all forwarding,
transformation handling and native headless approval processing.

The research layer is active only inside the explicit action context and only
for the fixture's `PreToolUse` echo call. Discovery probes and `PostToolUse`
scans still use native evaluation and never invoke a judge.
The runner drives calls synchronously; this subclass is not a production
concurrent-gateway extension.

| Research result | Composition |
| --- | --- |
| allow | Retain every native restriction; never manufacture permission |
| deny | Add an enforce-mode block, stronger than native step_up/modify |
| missing_authorization | Refuse; no verified research authorization-grant route exists |
| unresolved_semantics | Selective mode may invoke the stronger script; otherwise refuse |
| error or unresolved stronger result | Refuse; no allow fallback |

Native `step_up` remains native: full simulated approval may permit unchanged
arguments, while missing/declined approval refuses even after a stronger allow.
Research missing-authorization holds do not masquerade as human approval. All
service outcomes are explicitly simulated; no actual queue is contacted.

Production gateway **does not resolve native defer**. Native defer is reported
unsupported and refused in this research configuration. Selective semantic
escalation is a new research behavior, performed before returning the composed
decision; it is not a claim about production defer support.

## Action binding and limits

The event's actual arguments must match the judge-visible proposal before any
script invocation. Original action, judge-visible action, action hashes,
effective action when observed, and actual forwarded arguments are recorded.
General native `modify` is conservatively unsupported and refused before
forwarding; its original transform and findings remain in native evidence.
Approval responses that may redact/change arguments are likewise unsupported.
The default subclass refuses step_up composition unless the caller establishes
the runner's unchanged-argument approval-fixture property. This property is
verified from our explicit service implementation (full/denied/unavailable),
not inferred from a research allow. These fixtures cannot return a redacted
approval. There is no supported live-approval or arbitrary-transform adapter.
A final binding check also rejects an unexpected observed mismatch from scoring.

## Modes and records

- `native-rules`: original Gateway, no judge.
- `scripted-fast`: one explicit fast-script result.
- `scripted-stronger`: one explicit stronger-script result.
- `scripted-selective`: fast script; only valid semantic uncertainty escalates.

The default stronger script deliberately denies every eligible action; this
is a control, not evidence that a stronger model is better. Policies, cases,
enforcement, disposable state and simulated service configuration are otherwise
the same. Scripted composition is gateway-only. Decision-only scripted requests
are marked unsupported; general model-interface coverage remains zero.

JSONL records keep `native_decision`, each provenance-tagged `judge_results`
entry, `judge_errors`, routing reason, human-approval route,
`composed_pre_action_decision`, final approval resolution, action binding, and
observed forwarding separate. `judge_call_count`/`scripted_call_count` count
script invocations; `model_call_count` is **zero**, and `model_status` remains
`not_run`. Unsupported and judge-error cases remain visible. Scripted judgments
and native-only forwarding labels are excluded from model/forwarding agreement
metrics in scripted configurations. These controls establish no model accuracy,
calibration, attack-success reduction or real inference cost.
