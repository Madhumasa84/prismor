# Prismor Harness Alignment: offline gateway boundary

Scope: establish how trusted fixture policy and simulated authorization govern
execution through Prismor's actual MCP gateway. This is an integration milestone;
`model_status` is `not_run`. Niti's API/checkpoint remain unverified. VLM monitoring
and the Gemma competition project are separate.

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
