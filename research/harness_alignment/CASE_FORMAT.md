# Casebook format (version 1)

`casebook.schema.json` is the closed JSON Schema. The research validator adds
cross-case/group checks and calls Prismor's real `validate_policy` for fixture
YAML. `casebook.json` is a development set, not a benchmark or reviewed labels.

The top level contains `version`, `synthetic: true`, `families`, and `cases`.
Each family has `id`, `description`, `members` (two or three unique case IDs),
and explicit `scored_pairs`. Every case belongs to exactly one family; pairs
must contain two distinct members of that same family and cannot be repeated.

Every case has exactly two subtrees:

| Subtree | Contents |
| --- | --- |
| `input` | `trusted_task`, `policy`, `authorization_evidence`, `proposed_action`, `contextual_evidence` |
| `evaluator` | `id`, `family`, `expected`, `rationale`, `label_status`, `native_setup`, `integration_support` |

Task, policy and every evidence item have nonempty `text`, `source` and
`provenance`. Sources distinguish `user`, `policy`, `approval_service`,
`tool_output`, `fixture_manifest` and `unknown`. These describe **synthetic**
provenance, not cryptographic proof. Missing authorization/context is an empty
array; missing fields or provenance are invalid. `proposed_action` contains
`tool: echo` and string-valued `arguments`. No tool performs real edits/uploads.

`serialize_judge_request(case)` serializes only `input`, with stable JSON key
ordering. No ID, expectation, rationale, review status or integration hint is
added. This is a research-only serialization contract; it is not sent to Niti.

`expected` has three independent nullable fields:

- `judgment`: `allow`, `block`, `step_up`, or null under the stated rubric.
- `native_requirement`: the native pre-action verdict, or null when unmapped.
- `forwarding`: true means exactly one call, false means zero, null means unknown.

`label_status` is `provisional` or `unresolved`; reviewed statuses are rejected.
Unresolved judgments must be null. Expectations and rationales are used only
for reporting/scoring after observation, never for native execution decisions.

`native_setup` specifies an allowlisted local YAML `policy` reference (or null),
`representation: yaml_fixture|unmapped_context`, and
`approval_source: not_requested|unavailable|approved|denied`. This is explicit
experimental configuration, not an expected answer. Approved/denied service
fixtures require supplied approval evidence; natural-language evidence is not
parsed into an authorization decision. `integration_support` gives independent
`supported`/`reason` entries for `decision_only`, `gateway` and `judge`. A true
native flag requires a validated enforce-mode YAML projection with no judge or
telemetry outputs. A false flag preserves the case without attempting to invent
an interface. Model-judge support remains false; the scripted seam is reported
separately without claiming a verified model interface.

Each JSONL row includes case/family/configuration/run IDs, label/support status,
request hash, native decision, optional research judgment, final pre-action decision,
approval outcome, actual forwarding, post-action scans, response status,
status/error and reason. For approvals, `native_decision` remains `step_up`;
`final_pre_action_decision` is a research description of the observed native
gateway approval branch (`allow`/`block`, with an explicit source label).
Decision-only never resolves approval or populates execution. Unsupported
unmapped cases have null decisions/execution and a precise support reason. A
research composition found unsupported at runtime retains the observed native
decision and observed zero forwarding. Unresolved
labels are visible in rows and counted separately, including when unsupported.

The summary compares native requirements only to native decisions, judgment
only to judge decisions, and forwarding only to observed request counts.
A pair/family enters a denominator only when every member is compatible,
provisional, successfully evaluated and has the relevant observation and label.
The same case may appear in both declared pairs; these are dependent development
observations. Results are not independently validated accuracy.

Scripted modes add `experiment`, provenance-tagged `judge_results`, typed
`judge_errors`, routing/human-approval details, `composed_pre_action_decision`,
action/binding records, and separate script/model call counts. Native evidence
is deep-copied before research findings are composed; approval resolution never
rewrites it. `judge_decision` contains a valid research result or null; errors
are separate. Scripted research decisions use allow/deny/missing_authorization/
unresolved_semantics; no automatic model-rubric mapping is claimed. Scripted
judgments and native-only forwarding expectations are excluded from corresponding
agreement denominators. A `judge_error` status records a refused action with
error details, and general model-interface support remains zero. See
`JUDGE_INTERFACE.md` for the exact contract and unsupported-transform behavior.


## Measurement and review hardening

The pair/family denominators above describe conditional agreement. Scoring also
reports preselected known-label populations, attempted cases/pairs, completed
valid responses, decisive answers, semantic abstentions, authorization requests,
errors, coverage and unconditional correctness. Failed native executions retain
partial observations; unknown execution is not a zero. Duplicate rows do not
create extra samples. See `MODEL_INTEGRATION.md` for the binding contract.

Independent human annotations use the proposed separate
`annotation_sidecar.schema.json`, exported by `annotations.py`. The original
casebook schema and labels are unchanged; blank exports approve nothing. See
`hardening/20261022-offline/LABEL_REVIEW.md` for the later human import procedure.
