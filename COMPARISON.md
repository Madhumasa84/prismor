# Open Source vs Enterprise

Prismor is **open-core**. The runtime that guards a single machine is open and
local; governing a fleet of machines across a team is the commercial product.
Every row maps to a real component in this repo or in the proprietary
`prismor-web` / `PrismorSec/prismor-enterprise` repos. See [OPEN_CORE.md](OPEN_CORE.md)
for the boundary, and [docs/connecting-to-the-platform.md](docs/connecting-to-the-platform.md)
for how the open runtime connects to the platform.

## Capability comparison

| Capability | Open Source (`immunity-agent`) | Enterprise (`prismor-web`) |
|---|---|---|
| Tool-call interception | Yes — local hooks (Claude Code, Cursor, Codex, Gemini, Copilot, Hermes) + SDK adapters (`warden/cloaking/hooks/`, `warden/hooks.py`, `warden/runtime.py`) | Same runtime; centrally governed |
| Detection rules | All **63** default rules + the rule format (`warden/default_policy.yaml`, `warden/policy_schema.json`) | Same baseline + signed premium-feed overlay |
| Framework coverage | 5 SDK adapters — LangChain, CrewAI, OpenAI Agents, browser-use, Vercel AI (`adapters/*`, MIT). See [docs/sdk-integration.md](docs/sdk-integration.md) | Same adapters |
| Enforcement modes | Per-rule `observe`/`enforce` + non-overridable floor (`warden/policy_engine.py`) | Org sets modes remotely; approval workflows |
| Policy scope | Local + per-repo/per-workspace (`warden/enterprise/workspace_scope.py`, `warden/scoped_agent.py`) | Org / team / project layers at scale |
| Policy distribution | **Verifies** signed remote policy with the bundled public key, fail-closed to local-only (`warden/enterprise/remote_policy.py`, `keys/public.pub`) | **Signs and pushes** remote policy with the Ed25519 **private** key (`keys/private.pem`, gitignored, private repo) |
| Identity | Per-machine IAM / named agents (`warden/iam.py`, `warden/principal.py`); device-enroll **client** (`warden/enterprise/identity.py`) | SSO / SCIM, org user & device directory |
| Telemetry | Local sinks — webhook, syslog, file, OCSF/CEF (`warden/sinks.py`); redacted client spool (`warden/enterprise/telemetry*.py`) | Cross-device aggregation, org dashboard, fleet view |
| Audit | Local tamper-aware audit log (`warden/audit.py`) | Org-scale tamper-evident audit + SIEM/OCSF export, compliance |
| Visibility | One machine (`warden/server.py`, `warden/dashboard.html`) | Fleet observability across all enrolled devices |
| Threat feed | Bundled baseline advisory feed, consumed locally (`warden/feed.py`) | **Curated, signed, real-time** premium feed (subscription) |
| Deployment | `pip install immunity-agent`, runs locally; Docker | Self-hosted / managed control plane, BYOC / on-prem |
| License | Runtime Apache-2.0 (`LICENSE`); adapters MIT (`adapters/LICENSE`) | Commercial |
| Account needed | None — free forever, offline-capable | Org account + entitlement |

## Repo / package structure

| Open package (this repo) | Enterprise (private repos) |
|---|---|
| `warden/` — runtime, `policy_engine.py`, `runtime.py` | `prismor-web/` — control plane, dashboard, org APIs |
| `warden/default_policy.yaml` — 63 rules, `policy_schema.json` | Signed premium feed + `pipeline/` (NVD merge, signing) |
| `warden/cloaking/` — Cloak secret substitution + agent hooks | `keys/private.pem` — Ed25519 signing key (gitignored) |
| `warden/iam.py`, `scoped_agent.py`, `principal.py` — local identity | SSO/SCIM, org user & policy directory |
| `warden/sinks.py` — webhook / syslog / file / OCSF | Org OCSF/SIEM aggregation + compliance export |
| `warden/enterprise/` — enrolled-device **client** protocol only | Server side of enroll / policy-sign / telemetry-ingest |
| `adapters/` — 5 SDKs (MIT) | `PrismorSec/prismor-enterprise` — feed, pipeline, boundary harness |
| `keys/public.pub` — verify-only key | `keys/private.pem` — sign key |

> `warden/enterprise/` is the **client** side only — it enrolls, *verifies*
> signed policy (holding only the public key), and reports *redacted* telemetry.
> Signing and aggregation live in the proprietary control plane.

## Why paid

The open runtime protects one machine completely and for free. The enterprise
tier exists to **govern many machines as a fleet** — signed central policy,
cross-device telemetry, identity, and a live threat feed that a single local
install structurally cannot provide. Nothing is removed from the open runtime to
push an upgrade.

**Charging:** Enterprise is priced **per enrolled seat/device, never per tool
call** — the runtime intercepts unlimited calls locally at no metered cost.
