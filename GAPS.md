# Open-core / connection — gap register

Findings from a multi-agent review of how the open-source runtime connects to the
platform and to the framework SDKs. Each was verified against code. Items marked
**fixed here** are addressed in this PR with tests; the rest are tracked
follow-ups, ordered by severity.

## Fixed in this PR

| Sev | Gap | Fix |
|---|---|---|
| **Critical** | **Device-key exfiltration via the `prismor` sink `url`.** A local `.prismor-warden/policy.yaml` could set `url:` on a `type: prismor` sink; `_dispatch_prismor` forwarded it to `upload_telemetry`, which sends `Authorization: Bearer <device_key>` — redirecting the device credential to an attacker. | `warden/sinks.py`: the prismor sink is now **pinned to the enrolled `api_base`**; a local `url` override is ignored and warned. Test: `tests/test_prismor_sink_url_pin.py`. |
| **High** | **Enforcement bypass.** The runtime folds the org per-agent control (kill-switch / forced-enforce, `runtime.py:106-107,152-155,214`) into `Decision.allow`, but every adapter re-gated on `if not decision.allow and mode == "enforce"`. An app launched in `observe` silently defeated the org's emergency control. | All 5 adapters now **honor `Decision.allow` directly**. Test: `tests/test_adapter_enforce_regression.py`. |
| Low | Adapter license mismatch — 4 Python adapters declared Apache-2.0 in `pyproject` while `adapters/LICENSE` is MIT. | Flipped the 4 `pyproject` `license` fields to **MIT** (vercel already MIT); matches `adapters/LICENSE`. |
| Low | `OPEN_CORE.md` said "61 default rules". | Corrected to **63** (`warden/default_policy.yaml` has 63 rule ids). |

## Follow-ups (separate PRs)

| Sev | Gap | Plan |
|---|---|---|
| **High** | **Subject is unverified and leaves the box.** `enterprise/telemetry.py` puts `subject` (user/team/org) into telemetry records even in redacted mode and `assert_redacted` doesn't scrub it; over HTTP the subject is client-asserted (`X-Warden-Subject` / body) with no verification. Together: cross-tenant attribution poisoning + PII egress. | Drop/scrub `subject` from redacted records (gate behind `full_capture`); stop trusting client-asserted subject on the eval-server path. |
| **Med** | **eval-server has no auth, `Access-Control-Allow-Origin: *`, no rate limit.** Safe at the default `127.0.0.1` bind; risk spikes when `--host` widens it. | Add a shared-secret/bearer check + rate limit; require it before any non-loopback bind. |
| **Med** | **Premium feed + pipeline are tracked in the PUBLIC repo.** `advisories/immunity-feed.json(.sig)` and `pipeline/` (fetch/merge/**sign**) should be proprietary; `scripts/check_oss_safe.py` `PATH_DENYLIST` does not cover them. | Move feed + pipeline to `PrismorSec/prismor-enterprise` (already mirrored there); ship a small **baseline** feed in the open repo; add the feed/pipeline paths to the leak guard (baseline allowlisted). Done together to avoid breaking `warden/feed.py`. |
| **Med** | **Fail-open is not uniform.** The HTTP (vercel) path fails open on non-2xx; the Python adapters propagate runtime errors (ungraceful fail-closed). Same backend fault → different behavior per language. | Pick one policy across all adapters + the eval-server and document it; the registry's "fails open" note currently only describes the HTTP path. |
| Low | **No single `immunity connect`; token passed via argv** (`immunity enroll <token>`) leaks into shell history. | Add a `connect` alias + `--token-stdin` / `$PRISMOR_ENROLL_TOKEN`; consider device-code enroll. |
| Low | **`warden/enterprise/` reads as "paid code in the open repo."** It is client-only (enroll, verify-only policy, redacted telemetry). | Documented as the client side in `docs/connecting-to-the-platform.md`; consider renaming to `client/` later. |

See `docs/connecting-to-the-platform.md` and `docs/sdk-integration.md` for the
connection design these were found in.
