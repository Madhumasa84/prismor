# Prismor open-core model

Prismor is **open-core**. The runtime that guards your agents is open source and
runs locally — you can read every line that touches your tool calls and secrets.
Governing agents across a team or organization is the commercial product.

The principle: **single-player is free and open; multiplayer (org governance) is
paid.** Nothing is ever removed from the open runtime to push you to pay — the
paid tier adds the fleet/governance layer that doesn't exist in single-player.

## What's open source (this repo)

| Component | Path | License |
|---|---|---|
| Warden runtime — interception, policy engine, enforcement | `warden/` | Apache-2.0 (root `LICENSE`) |
| All 61 default detection rules + the rule format | `warden/default_policy.yaml`, `warden/policy_schema.json` | Apache-2.0 |
| Coding-agent hooks (Claude Code, Cursor, Codex, …) | `warden/cloaking/hooks/` | Apache-2.0 |
| Cloak — local secret substitution | `warden/cloaking/` | Apache-2.0 |
| Per-machine IAM / scoped access | `warden/iam.py`, `warden/scoped_agent.py` | Apache-2.0 |
| Local telemetry sinks (webhook, syslog, file, OCSF/CEF) | `warden/sinks.py` | Apache-2.0 |
| Framework adapters (LangChain, CrewAI, OpenAI Agents, browser-use, Vercel AI) | `adapters/` | **MIT** (`adapters/LICENSE`) |
| The enrolled-device **client** protocol (so you can audit what leaves the box) | `warden/enterprise/` | Apache-2.0 |
| Public verification key | `keys/public.pub` | Apache-2.0 |
| Eval harness / detection scenarios | `bench/`, `tests/` | Apache-2.0 |

The open runtime enforces all six control dimensions **locally**, on one machine,
with unlimited agents, tool calls, and rules — free forever.

## What's commercial (not in this repo)

The control plane (`prismor-web`) and the assets that anchor trust at scale:

- Org dashboard, fleet observability, and cross-device telemetry aggregation
- **Signed remote policy distribution** and the Ed25519 **signing private key**
- SSO/SCIM, per-user/per-team policy at scale, approval workflows
- Tamper-evident audit + org-scale OCSF/SIEM export, compliance reporting
- The **curated, signed premium threat feed** (the open runtime ships with a
  baseline ruleset; the real-time signed feed is a subscription)
- Roadmap: credential broker, workload attestation

The boundary is enforced by **cryptography and entitlement**, not license terms:
the runtime holds only the *public* key and verifies-before-applies signed
policy (fail-closed to local-only if unsigned). It can never forge policy or mint
identities. CI (`scripts/check_oss_safe.py`) blocks the private key, secrets, and
feed blobs from ever entering this public repo.

## Licensing note (open decision)

The runtime is currently **Apache-2.0**. We are evaluating moving the runtime to
**FSL-1.1-Apache** (Functional Source License — free for all use except building a
directly competing product, converting to Apache-2.0 after two years) to harden
against a platform repackaging the runtime as a competing managed service, while
keeping near-permissive adoption. Adapters stay **MIT** regardless. This is a
deliberate, not-yet-final decision — see the discussion in the PR that added this
file. Until decided, Apache-2.0 is authoritative.
