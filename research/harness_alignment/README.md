# Prismor Harness Alignment

An offline research harness around the **full native Prismor evaluator and MCP
gateway**. Synthetic echo tools and simulated approval responses test execution
requirements and evidence handling. Scripted judges are control-flow fixtures,
not Niti. Real inference remains disabled: `LIVE_MODEL_RUN=false`,
`MAX_REAL_REQUESTS=0`, and no live adapter is registered.

## Fresh checkout: setup and reproduce

Run from the full repository root. Use Python 3.10 or newer (the packaging run
uses Python 3.10 on Linux); do not use an installed Prismor package alone.

```bash
python3 -m venv .venv
.venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple -e '.[dev]' -r research/harness_alignment/requirements.txt
.venv/bin/python -m research.harness_alignment.reproduce --output research/harness_alignment/runs/reproduction-01
```

Bootstrap installs the existing runtime/dev definitions plus the existing
research JSON Schema requirement. It requires package-index access or a supplied
wheel cache; **offline evaluation does not mean offline installation**. No model
weights or semantic-provider extras are required. See [REPRODUCE.md](REPRODUCE.md)
for the tested environment, candidate-snapshot procedure and evidence inventory.

The last command refuses an existing output directory. It runs the original five
focused suites (including hardening), the exact selected native regressions, the
four-condition boundary fixture, the supported-casebook dry run, and separate
packaging checks. It uses the selected interpreter, fresh child HOME/XDG/Prismor
state, no inherited credentials/PYTHONPATH, disabled pytest plugin autoload, and
an outbound Python socket guard in addition to the existing fixture service
guards. Native approval/evaluation/forwarding behavior is unchanged. This is a
controlled test harness, not a kernel sandbox for arbitrary code.

Outputs include `summary.json`, `commands.json`, JUnit/logs per suite,
`source_snapshot.json`, per-step environment/network records, and
`native-dry-run/{manifest.json,pilot.json,native_observations.jsonl}`. Logs and
partial observations remain on failure; a failed command, missing result,
failed native case or attempted outbound connection produces a nonzero exit.
Unknown call counts remain null. Skips include their exact reasons; inspect
additional skips or count differences rather than treating them as passes.

### Historical observations (not canned reproduction output)

| Record | Reported observation |
| --- | --- |
| Focused suite at paper revision | 107 passed, including 25 hardening regressions |
| Selected native suite | 33 passed, one missing-demo skip, 48 deselected |
| Original echo boundary | allow / block / unavailable approval / simulated approval: 1,0,0,1 calls |
| Development casebook | 24 cases; 15 native-supported, nine unsupported |
| Supported subset | Ten forwarded calls; three simulated approval outcomes |
| Real external inference | Zero |

The original four tests overlap the 107. New packaging checks are a separate
suite, not additional model-quality samples. The historical runs used 22
provisional expectations, two unresolved references and no independently
reviewed dataset labels. Manuscript review does not change those annotations.
Native fixture agreement is not task-language comprehension or attack success.
Scripts, replay and actual inference retain distinct provenance.

## Historical evidence is separate from execution

Baseline reproduction needs no old logs, paper workspace, archives or hidden
run directories. To check the paper's recorded observations, obtain the selected
private evidence archive separately and verify/extract it to a **new** directory:

```bash
.venv/bin/python -m research.harness_alignment.evidence_package verify /path/to/evidence.tar.gz --extract /path/to/new-evidence-directory
```

`MANIFEST.json` maps Tables 1–3 and the scripted controls to exact original paths,
source revisions and run identities. The verifier rejects unsafe paths, links,
duplicates, missing/extra entries and checksum mismatches, then rechecks extracted
bytes. Hashes establish consistency, not remote-inference authenticity. The
explicit source allowlist is [historical_evidence.json](historical_evidence.json).
Building it requires the owner's historical files; verifying it does not.

## Extend the judge

- `casebook.py:serialize_judge_request` and `judge.py:JudgeRequest`: judge-visible
  input only; labels, family IDs and fixture setup stay evaluator-only.
- `judge.py:Judgment`, `JudgeError`, `ScriptedJudge`: typed outcomes and a runnable
  offline control. [MODEL_INTEGRATION.md](MODEL_INTEGRATION.md) contains the example.
- `model_io.py`: unavailable adapter registry, budget, identity, dispatch/replay.
- `evidence.py:RecordingBoundary`: registered parsing, capture, required-attempt
  aggregation and independent-record validation.
- `comparison.py:judge_agreement`: validity, abstention and coverage denominators.
- `judged_gateway.py:ResearchGateway._evaluate`, `compose`: additional restrictions
  without relaxing native requirements. `missing_authorization` blocks; it does
  not initiate approval. Only a surviving native `step_up` reaches native approval.
- `offline.py` and `runner.py`: disposable fixtures and failure observations.

General transformations, redacted approval binding and native defer composition
remain unsupported. Nine casebook mappings lack native provenance, grant or
context handling. Live transport, production concurrency and Niti effectiveness
remain untested. See [SPEC.md](SPEC.md), [CASE_FORMAT.md](CASE_FORMAT.md) and
[JUDGE_INTERFACE.md](JUDGE_INTERFACE.md) for the unchanged research contracts.
