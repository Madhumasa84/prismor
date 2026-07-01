# CLI Reference

Every capability in the toolkit is reachable through the single `prismor`
command. This page is the **map**: it lists every command, what it does, and
links to the dedicated deep-dive doc for that capability.

```
prismor <command> [options...]
prismor <domain> <action> [options...]
prismor --help               # the same map, in your terminal
prismor <command> --help     # help for one command
```

There are two shapes:

- **Top-level commands** — `prismor status`, `prismor audit`, `prismor check …`
- **Domains** that take an action — `prismor cloak add …`, `prismor canary plant …`

`warden` is a deprecated drop-in alias for `prismor`; it forwards everything
unchanged and prints a migration notice. Use `prismor`.

---

## Quick start

| Command | What it does | Deep dive |
|---|---|---|
| `prismor setup` | Interactive 4-step onboarding wizard: pick mode, select agents, enable cloaking, choose install scope. | [Onboarding](#onboarding--lifecycle) |
| `prismor status` | One-shot health check: workspace, hooks, mode, cloak, latest session, next action. | [Dashboard & sessions](dashboard.md) |
| `prismor audit` | Full security-posture audit across every subsystem. `--fix` auto-remediates. | [Warden](warden.md#security-audit) |
| `prismor --help` | The full command map. | — |

---

## The command map

```
immunity
│
├─ Onboarding & lifecycle
│   ├─ setup                  Interactive onboarding wizard (4-step TUI)
│   ├─ install-hooks          Wire Warden hooks into an agent/IDE
│   ├─ uninstall-hooks        Remove hooks
│   └─ status [--all]         Health check (this workspace / all workspaces)
│
├─ Runtime protection (policy engine)
│   ├─ check                  Pre-check a command or path against policy
│   ├─ semantic-check         Hybrid LLM prompt-injection guard
│   └─ policy <action>        init · validate · show · edit · test
│
├─ Visibility (audit & forensics)
│   ├─ audit                  Full posture audit (--fix to remediate)
│   ├─ scan                   Scan MCP servers & skills for risk
│   ├─ deps                   Check project deps vs. threat feed
│   ├─ analyze / ingest       Run the engine over a JSONL session
│   ├─ sessions / session     List / show stored sessions
│   ├─ status --all           Terminal overview of all workspaces
│   └─ dashboard              Local web dashboard (127.0.0.1:7070, opens browser)
│
├─ Secret prevention
│   ├─ cloak <action>         install · add · list · remove · status · pattern
│   └─ sweep                  Find & vault leaked secrets on disk
│
├─ Identity & scoping
│   ├─ iam <action>           Named agent identities / permission profiles
│   ├─ scope <action>         Session-scoped, task-specific rules
│   └─ canary <action>        Plant & manage honeytoken tripwires
│
├─ Adaptive defense
│   └─ learn                  Mine session history for new rules
│
└─ Supply chain
    └─ supplychain <action>   npm/pip/pnpm/uv/cargo/go install gate · harden
```

---

## Onboarding & lifecycle

| Command | Key flags | Description |
|---|---|---|
| `prismor setup [DIR]` | `--non-interactive`, `--mode`, `--agents`, `--cloak/--no-cloak` | Interactive wizard (or scripted with flags / `PRISMOR_MODE`, `PRISMOR_CLOAK` env vars). Picks mode, toggles rules, selects agents, enables cloaking. |
| `prismor install-hooks` | `--agent <name\|all>` (required), `--mode <observe\|enforce>`, `--scope <project\|user>` | Writes hook config for the chosen agent so Warden sees tool calls. Without hooks, nothing is monitored. |
| `prismor uninstall-hooks` | `--agent <name\|all>`, `--scope` | Removes Prismor hooks for an agent. Clean rollback. |
| `prismor status` | `--workspace`, `--all`, `--days N` | Health check: hooks, mode, cloak state, latest session, and the single next action. Run this first every session. `--all` shows every registered workspace. |
| `prismor info` | `--workspace` | _Deprecated_ alias of `status`. |

Agent → config matrix and per-agent details: [AGENT_INTEGRATIONS.md](../AGENT_INTEGRATIONS.md).
Modes (`observe` vs `enforce`): [Warden](warden.md).

---

## Runtime protection

| Command | Key flags | Description |
|---|---|---|
| `prismor check "<value>"` | `--type <command\|read\|write>`, `--explain`, `--from-log`, `--suggest-allowlist` | Dry-run a command or file path against the active policy. Returns ALLOW / WARN / BLOCK + reason without executing. Exit `2`=block, `1`=warn, `0`=clean. |
| `prismor semantic-check [TEXT]` | `--mode <hybrid\|heuristic\|api>`, `--json`, `--cli-path` | Run the semantic prompt-injection guard on text or stdin. See [Semantic Guard](semantic-guard.md). |
| `prismor policy init` | `--workspace` | Scaffold `.prismor-warden/policy.yaml`. |
| `prismor policy show` | `--workspace` | Print active rules after merging defaults + project overrides. |
| `prismor policy edit` | `--workspace` | Interactive TUI to toggle rules on/off. |
| `prismor policy validate <file>` | — | Static-validate a policy YAML file. |
| `prismor policy test` | `--file` | Run declarative policy tests (falls back to the bundled OWASP LLM starter pack). |

Full policy model, rule schema, and the default rule list: [Warden](warden.md).

---

## Visibility

| Command | Key flags | Description |
|---|---|---|
| `prismor audit` | `--fix`, `--json`, `--workspace` | Posture audit across hooks, policy, cloak, permissions, feed, network, supply chain. `--fix` applies safe remediations. |
| `prismor scan` | `--agent`, `--json` | Scan installed MCP servers and skills for dangerous patterns. See [Skill Scanner](skill-scanner.md). |
| `prismor deps` | `--json`, `--workspace` | Cross-reference project dependencies against the signed IOC feed + lockfile integrity. See [Supply Chain](supply-chain.md). |
| `prismor analyze [FILE]` | `--input`, `--json`, `--sarif` | Run the engine over a JSONL session (or the most recent one). SARIF output feeds GitHub Code Scanning. |
| `prismor ingest --input <file>` | `--session-id`, `--agent` | Analyze a session and store it in the local DB. |
| `prismor sessions` | `--findings-only`, `--global`, `--limit`, `--json` | List stored sessions, optionally only flagged ones, optionally across all workspaces. |
| `prismor session <id>` | `--json` | Drill into one session's tool-call trace + findings. |
| `prismor status --all` | `--days N` | Terminal overview of every registered workspace. See [Dashboard](dashboard.md). |
| `prismor dashboard` | `--port`, `--host`, `--no-open` | Local web dashboard at `http://127.0.0.1:7070` (opens a browser tab). See [Dashboard](dashboard.md). |
| `prismor serve` | `--port`, `--host`, `--no-open` | _Deprecated_ alias of `dashboard --no-open` (headless server only). |

---

## Secret prevention

| Command | Key flags | Description |
|---|---|---|
| `prismor cloak install` | `--scope`, `--no-userprompt-guard`, `--no-secret-guard`, `--sweep-on-stop` | Install cloaking hooks so real secrets stay out of model context. |
| `prismor cloak add <name>` | `--from-file` | Register a secret under a placeholder. Value read from stdin / hidden prompt — never argv. |
| `prismor cloak list` | — | List registered placeholder names (never values). |
| `prismor cloak remove <name>` | — | Delete a registered secret. |
| `prismor cloak status` | `--scope` | Show whether cloaking hooks are installed + secret count. |
| `prismor cloak pattern <list\|add\|remove>` | — | Manage the secret-detection regexes. |
| `prismor sweep` | `--redact`, `--clean`, `--restore`, `--show-vault`, `--purge` | Find secrets already leaked into AI tool configs and vault/redact them. |

Design, setup, best practices, and threat model: [Sweep & Cloak](sweep-and-cloak.md).

---

## Identity & scoping

| Command | Key flags | Description |
|---|---|---|
| `prismor iam init` | `--scope <global\|project>` | Scaffold an `iam.yaml` of agent identities. |
| `prismor iam list` | — | List defined identities; marks the active `WARDEN_AGENT_ID`. |
| `prismor iam show <agent>` | — | Show one identity's permission profile. |
| `prismor iam check <agent> --value "<v>"` | `--type <command\|read\|write\|network>` | Test whether an identity may perform an action. |
| `prismor scope show` | `--session-id` | Show session-scoped rules (all, or one session). |
| `prismor scope list` | — | List sessions with active scoped rules. |
| `prismor scope edit <id>` | — | Edit a session's scoped rules in `$EDITOR`. |
| `prismor scope clear <id>` | — | Remove a session's scoped rules. |
| `prismor canary plant <path>` | `--type <aws\|ssh\|env\|generic>`, `--webhook`, `--force` | Plant a honeytoken credential tripwire. |
| `prismor canary list` | — | List planted canaries (markers redacted). |
| `prismor canary status` | — | Summary of canaries by type. |
| `prismor canary remove <id\|path>` | — | Remove a canary. |

Deep dives: [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Canary](canary.md).

---

## Adaptive defense

| Command | Key flags | Description |
|---|---|---|
| `prismor learn` | `--min-support`, `--fp-threshold`, `--json` | Mine session history for repeated blocked / near-miss patterns and propose new rules. |
| `prismor learn --candidates` | — | List pending candidate rules. |
| `prismor learn --apply <id>` | — | Accept a candidate into project policy. |
| `prismor learn --reject <id>` | — | Reject a candidate. |

Deep dive: [Learning](learning.md).

---

## Supply chain

| Command | Description |
|---|---|
| `prismor supplychain npm install <pkg>` | Score `<pkg>` (age, maintainers, install scripts, IOC match) and block if dangerous before npm runs. |
| `prismor supplychain pip install <pkg>` | Same gate for PyPI. |
| `prismor supplychain <pnpm\|yarn\|uv\|cargo\|go> …` | Same gate per ecosystem. Non-install commands pass through transparently. |
| `prismor supplychain harden [--dry-run] [PATH]` | Write hardening settings (`ignore-scripts`, `save-exact`, pinned fetch) into package-manager configs. |

Scoring table, IOC feed, ecosystem support: [Supply Chain](supply-chain.md).

---

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `PRISMOR_MODE` | `setup --non-interactive` | Default enforcement mode (`observe` / `enforce`). |
| `PRISMOR_CLOAK` | `setup --non-interactive` | Enable cloaking (`1`/`true`/`yes`/`on`). |
| `PRISMOR_WARDEN_WORKSPACE` | all commands | Override the resolved workspace path. |
| `WARDEN_AGENT_ID` | `iam` | Active agent identity for IAM enforcement. See [IAM](iam.md). |
| `PRISMOR_SWEEP_PASS` | `sweep` | Vault passphrase for non-interactive runs. |
| `EDITOR` | `scope edit` | Editor for scoped-rule editing. |

---

## See also

- [Warden](warden.md) — policy engine, session logs, audit, modes
- [Supply Chain](supply-chain.md) — install-time enforcement and scoring
- [Network Isolation](network-isolation.md) — egress allowlists, raw-IP detection
- [Skill Scanner](skill-scanner.md) — MCP + skill risk scanning
- [Sweep & Cloak](sweep-and-cloak.md) — secret prevention
- [Semantic Guard](semantic-guard.md) — LLM-assisted injection defense
- [Canary](canary.md) · [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Learning](learning.md) · [Dashboard](dashboard.md)
- [Docker & Containers](docker.md) · [Architecture](architecture.md)
