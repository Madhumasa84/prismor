# Mentor-facing pilot: comparison infrastructure, no live models

The contribution is an offline, reproducible integration workflow that preserves
Prismor's real evaluator, approval branch and inherited MCP forwarding. It adds
zero-default live/request gates, internal attempt/response recording utilities,
exact replay matching, comparison planning, separate judge/harness scoring and
an independent-evaluation plan. **No Niti or other live model was run.** No
concrete model adapter can be established from the supplied repository evidence.

The four configurations are native rules, rules plus Niti, rules plus a stronger
judge, and rules plus Niti with explicit semantic-uncertainty escalation. The last
three are unavailable plans. Their names do not disguise scripted providers.
The native semantic screen is disabled only in disposable fixtures, equally for
all planned modes; the manifest separately records the shipped auto/enabled
configuration. Effective live workspace/org configuration was not queried and
is not claimed to match the fixture.

## Actual available results

Dry run `20261021T192852Z-f1f7edf1` used starting revision
`583dbfaf5921d2de70babb8884ecfd1c987b29a9` plus dirty research implementation.
Ignored run artifacts retain Git/dirty state and source,
casebook and policy hashes. Repeating the command creates a fresh run ID.

| Observation | Count / denominator or availability |
| --- | --- |
| Development cases | 24 in 8 triples, 16 scored pairs |
| Labels | 22 provisional, 2 unresolved, 0 reviewed |
| Native gateway supported | 15 / 24; 9 unsupported mappings retained |
| Native requirement provisional agreement | 15 / 15 cases, 10 / 10 pairs, 5 / 5 whole families |
| Native observed forwarding provisional agreement | 15 / 15 cases, 10 / 10 pairs, 5 / 5 whole families |
| Recorded upstream tools/call | 10 across 15 native-supported cases |
| Incorrect permits / unnecessary blocks | 0 / 15 and 0 / 15 against compatible provisional forwarding labels |
| Native approval requests | 3 / 15, all service outcomes simulated |
| Real inference requests / stronger-model requests | 0 real requests; 0 stronger requests |
| Genuine responses | 0; invalid-output count 0 observed out of 0 requests, rate unavailable |
| Judge-only and deployment judge paired correctness | unavailable, 0 eligible pairs |
| Correctness against independently reviewed labels | unavailable, 0 reviewed labels |
| Live model latency, usage, monetary cost | unavailable |
| Replay inference latency | unavailable; no model replay executed |

The dry-run plans contain 15 observed native rows, 51 unavailable model-plan
rows and 36 unsupported gateway-plan rows. These are **plan-row counts**, not
102 separate experiments or model requests. Judge-only plans include the two
members of `task:0` under each of the three unavailable model configurations.
An offline fixture elapsed duration is recorded in the manifest; it includes
setup and instrumentation and must not be interpreted as inference latency.

Focused offline validation: **82 passed**, including all 55 preceding harness
tests and 27 new infrastructure tests. Selected repository lint checks passed.
These cover budget gating/failed-attempt counting, raw/normalized records,
version and credential handling, full replay identity, null denominators,
metadata separation, pair completeness, scripted/replay exclusion, unavailable
models and native short-circuiting. No unrelated failures were observed.

## Concrete behaviors and failure examples

- `task-edit`: the real native `casebook-read-only` rule blocks the proposed
  edit before forwarding (0 calls). A deployment-control test configures a
  scripted allow and proves the native block short-circuits with 0 judge calls.
  It is not credited as a correct judge answer.
- `upload-missing`: native decision remains `step_up`; the explicitly simulated
  unavailable approval source returns `request_failed` and forwarding is 0.
  `upload-present` preserves the same requirement, receives an explicitly
  simulated full approval and forwards exactly once with recorded arguments.
  This is not a human approval experiment.
- `provenance-unknown`: no native action-authorization interface carries the
  task/context provenance in its trusted role. It stays unsupported; copying
  that text into tool arguments would not establish equivalent semantics.
- Timeout, malformed response, exhausted budget and unavailable model paths are
  exercised by explicit offline test fixtures. They are failure controls, not
  observed Niti failures. Their test responses are absent from pilot model
  denominators. There are no actual model failure examples to report yet.

## Limits and next experiment

This is provisional development integration agreement, not independently
validated accuracy, calibration, attack-success reduction or safety evidence.
The 9 unsupported cases cover provenance, argument-bound grants and contextual
sufficiency. Native transforms, redacted approval binding and native defer
resolution remain unsupported for research composition. All 22 provisional
labels need mentor review; `provenance-unknown` and `context-missing` need explicit
rubric resolution. A confident wrong model answer would not be caught merely by
routing explicit semantic uncertainty.

Both roles lack endpoint/checkpoint, exact request/response schemas, conditioning
method, immutable version, supported parameters, authentication mechanism and
credential reference. A verified concrete adapter and full multi-question/
retry accounting must follow that evidence. See [integration status](MODEL_INTEGRATION.md)
for exact missing prerequisites and the bounded future smoke command, which is
printed but was not executed and currently refuses even if settings are changed
without an adapter. No fallback or fabricated response fills these gaps.

Next: supply those interface documents and comparison-model selection, review
the development rubric, then explicitly authorize/configure a small bounded
judge-only paired smoke. Inspect real outputs before choosing prompts/routing.
Freeze the resulting configuration before commissioning the fresh independently
reviewed set described in [the separate plan](INDEPENDENT_EVALUATION_PLAN.md).
No final holdout was generated.
