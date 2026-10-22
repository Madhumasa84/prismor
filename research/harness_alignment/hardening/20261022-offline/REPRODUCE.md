# Offline reproduction

Run from the repository root with the existing Python environment. No dependency
installation, external service, hook or live policy change is required. Preserve
all old reports/runs. Choose a new output path for every CLI/export invocation.

```bash
python3 -m pytest tests/test_harness_alignment_models.py tests/test_harness_alignment_hardening.py tests/test_harness_alignment_judge.py tests/test_harness_alignment_casebook.py tests/test_harness_alignment_gateway.py -q -s

env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/test_mcp_gateway.py tests/test_tool_policy_three_state.py tests/test_surface_conformance.py -q -rs -k 'call_forwarded_on_allow or call_blocked_pre_forward or engine_error_fails_closed or call_step_up or call_modify or gateway_end_to_end_real_engine or three_state or surface_conformance'

python3 -m research.harness_alignment.comparison --mode dry-run --output /tmp/prismor-hardening-native-new
python3 -m research.harness_alignment.annotations --output /tmp/prismor-hardening-review-new
ruff check --select E9,F63,F7,F82 research/harness_alignment/*.py tests/test_harness_alignment_models.py tests/test_harness_alignment_hardening.py tests/test_harness_alignment_casebook.py
git diff --check
```

The first command prints the original native four-case observations (1,0,0,1).
The native dry run retains 15 supported/nine unsupported cases and ten upstream
calls. Its model plan contains no executed model observations. The review export
contains blank forms, never approved labels. Settings stay false/zero.

`before_audit.json` and `before_helpers.json` were produced **before edits** in
the working checkout: the existing timestamped report's `scripts/audit_probes.py`
was invoked with `--repo . --output <new before_audit.json>`; then
`reproduce_before.py` was run. That early helper probe uses fabricated in-memory
metadata and is retained as historical evidence, not current runnable scoring
code. For a stronger valid-abstention reproduction, six pytest probes were also
run against a **full git archive** of the actually observed starting revision:

```bash
mkdir /tmp/prismor-hardening-before-new
git archive 54f99441e038a3501e67a234561bbe133f438d2b | tar -x -C /tmp/prismor-hardening-before-new
cp research/harness_alignment/hardening/20261022-offline/before_regressions.py /tmp/prismor-hardening-before-new/tests/test_hardening_before.py
cd /tmp/prismor-hardening-before-new
python3 -m pytest tests/test_hardening_before.py -q
```

The actual archive extraction used Python `tarfile` with `filter='data'`, without
switching/resetting the shared checkout. These tests **assert old failures** and
must not run against the hardened code. They use full source modules and native
recording-upstream forwarding; they do not extract function definitions. No
`review_checks.py` was found in the checkout or `/tmp`; it was not relied on.
`before_full_checkout_tests.log` records the actual six passing witnesses.

`record_after.py` produced `after_checks.json` with explicit fixture provenance,
A1/A3 rejection, R1 exact counts, R2 mismatch diagnostics, R3 native fault rows and
A2 callback diagnostics. Its default output refuses overwrite; copy the result
or use a fresh directory if extending it. Those are offline fixture observations,
not a model-effectiveness run. The regression tests are the supported repeatable
verification path.

Final logs are named `passing_focused_tests.*`, `selected_existing_tests.log`,
`verified_lint.log`, and `verified_native_dry_run/`. Intermediate logs are retained,
including the old hash-list expectation failure and the deadline-test setup
failure; neither was a genuine model failure. See `hardening_results.json` for
actual outcomes, source/artifact hashes and the final provenance.
