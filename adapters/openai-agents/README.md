# prismor-warden-openai

Prismor Warden adapter for the **OpenAI Agents SDK**. Wrap any agent tool so
every invocation is evaluated against your Warden policy — per user — *before*
the tool runs. A call that violates an enforce-mode rule (or the calling user's
IAM profile) is blocked and the tool never executes.

This is the in-process **SDK adapter** surface from the
[integration registry](../../warden/integrations/registry.yaml): production
framework agents have no hook-config files, so the control point is a thin
wrapper around tool execution that calls the same
`warden.runtime.evaluate_tool_call` pipeline a local coding agent already uses.

## Install

```bash
pip install prismor-warden-openai      # pulls in the Warden runtime (immunity-agent)
pip install "prismor-warden-openai[sdk]"   # also installs openai-agents
```

## Use

```python
from agents import Agent, function_tool
from prismor_warden_openai import warden_guard, WardenBlocked

@function_tool
def run_shell(command: str) -> str:
    ...

# Attribute calls to the end-user driving this run, so policy + telemetry
# scope to that user (not the host device):
guarded = warden_guard(run_shell, subject="user:alice", mode="enforce")

agent = Agent(name="ops", tools=[guarded])
```

If a call is denied, `warden_guard` raises `WardenBlocked` (carrying the
`Decision`). Pass `raise_on_block=False` to get the `Decision` returned instead.

### Per-user policy

`subject` accepts a `Subject`, a `WARDEN_SUBJECT`-style string
(`"user:alice"`, `"user=alice;team=data"`), or `None` (resolved from the
`WARDEN_SUBJECT` env var or the enrolled device identity at call time). The
subject is threaded into policy evaluation, IAM profile selection
(`user:<id>` / `team:<id>` profiles in `iam.yaml`), and telemetry.

## How it maps to Warden

| Concern | Mechanism |
|---|---|
| Interception | `warden_guard(tool)` wraps the callable |
| Canonical event | `build_event(...)` → `{type, agent, command/path/url, metadata}` |
| Decision | `warden.runtime.evaluate_tool_call(...)` → `Decision(allow, blocking, ...)` |
| Block | raise `WardenBlocked` (tool not invoked) |
| Per-user | `warden.principal.Subject` |

By default the emitted event `type` is `shell`, so existing rules like
`destructive-command` and `secret-exfiltration` apply to tool arguments. Pass
`event_type="file_write"` / `"network"` / `"tool_result"` (and a
`command_builder`) for tools whose risk lives in a path, URL, or output.
