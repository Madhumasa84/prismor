# Scoped Agent (Session-Scoped Rules)

The scoped agent **synthesizes a minimal, task-specific rule set at the start of
each session** from the user's first prompt, and enforces it for that session
only. If the task is "fix the failing test in `auth/`", the agent has no business
running `curl | bash` or writing outside the repo — scoped rules encode that
expectation automatically, without you writing a policy by hand.

The active rule set for a session becomes:

```
policy.yaml (base, persistent)  +  scoped_agent rules (this session only)
```

Implementation: [`warden/scoped_agent.py`](../warden/scoped_agent.py).

---

## How it works

```
   session start
        │
        ▼
   UserPromptSubmit: "fix the failing test in auth/"
        │
        ▼
┌────────────────────────────────────────────────────────┐
│  synthesize_scoped_rules(goal, available_tools, ws)    │
│    → allowed_tools: [Read, Edit, Bash]                 │
│    → path scope:    auth/**                            │
│    → network:       denied                             │
└────────────────────────────────────────────────────────┘
        │ saved for this session id
        ▼
   later in the same session:
   agent issues  WebFetch("https://evil.com")
        │
        ▼
   check_scoped_rules(event)  ──►  not in allowed_tools  ──►  BLOCK
```

On the first prompt of a session, Warden derives a tight rule set from the goal
and the tools available, saves it keyed by session id, and then checks every
subsequent tool call against it alongside the base policy. The rules evaporate
when the session ends — they never accumulate into your permanent policy.

This synthesis happens automatically inside the hook dispatcher; you don't run a
command to create scoped rules. The `prismor scope` commands are for
**inspecting and adjusting** them.

---

## Why session scope

A standing policy has to be permissive enough for *every* task you might run. A
single session only needs to do *one* task. Scoped rules close that gap: they
shrink the agent's surface to the job in front of it, so a prompt-injection that
tries to pivot the agent into unrelated, dangerous actions hits a wall that the
broad base policy would have let through.

```
Base policy:    must allow everything you ever do  →  necessarily broad
Scoped rules:   allow only THIS task               →  tight, per-session
Injection that pivots off-task  ──►  outside the scope  ──►  blocked
```

---

## Commands

```bash
# List sessions that currently have scoped rules
prismor scope list

# Show the scoped rules (all active sessions, or one)
prismor scope show
prismor scope show --session-id <id>

# Hand-edit a session's scoped rules in $EDITOR
prismor scope edit <id>

# Drop a session's scoped rules
prismor scope clear <id>
```

`prismor scope` with no action prints the rules for all active sessions.

---

## Relationship to IAM

| | [IAM](iam.md) | Scoped Agent (this doc) |
|---|---|---|
| Lifetime | Persistent, tied to `WARDEN_AGENT_ID` | One session |
| Source | Hand-written `iam.yaml` profile | Auto-synthesized from the task prompt |
| Best for | A standing role (read-only bot, reviewer) | Tightening one run to its actual task |

They stack: IAM sets the floor for an identity; scoped rules tighten it further
for the current session. A tool call must satisfy the base policy, the IAM
profile (if any), *and* the scoped rules.

---

## See also

- [IAM](iam.md) — persistent named identities
- [Warden](warden.md) — the base policy engine
- [CLI Reference](cli-reference.md) — all commands at a glance
