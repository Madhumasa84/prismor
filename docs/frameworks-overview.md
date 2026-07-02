# Framework adapters — overview

Prismor Warden intercepts tool calls in production framework agents — not just
local coding agents. The integration is designed to be **a single function call**
on your existing agent or controller object, with no changes to your tool logic.

## UX at a glance

| Framework | Language | Install | Guard | Multi-tenant |
|---|---|---|---|---|
| OpenAI Agents SDK | Python | `pip install prismor-warden-openai` | `guard_agent(agent)` | `use_subject("user:alice")` |
| LangChain / LangGraph | Python | `pip install prismor-warden-langchain` | `guard_tools([...])` | `use_subject("user:alice")` |
| CrewAI | Python | `pip install prismor-warden-crewai` | `guard_tools([...])` | `use_subject("user:alice")` |
| browser-use | Python | `pip install prismor-warden-browser-use` | `guard_controller(controller)` | `use_subject("user:alice")` |
| Vercel AI SDK | TypeScript | `npm install prismor-warden-vercel` | `wardenTools(tools, opts)` | `{ subject: "user:alice" }` |
| Any language | Any | — (HTTP client only) | `POST /v1/evaluate` | `X-Warden-Subject` header |

The Python multi-tenant pattern: guard once at startup with no bound subject,
then wrap each request with `use_subject`. A context var threads the subject
through the evaluation pipeline — thread-safe and async-safe.

For non-Python languages: pass `subject` per call in the request body or
`X-Warden-Subject` header. The eval-server resolves it identically.

## What "guard" does

Regardless of framework, every adapter does the same three things:

1. **Intercept** — wraps the framework's tool execution surface (see table below)
   so the original callable is never reached on a denied call.
2. **Evaluate** — calls `warden.runtime.evaluate_tool_call()` with a canonical
   event and the resolved subject. Same pipeline as coding-agent hooks.
3. **Block or allow** — in `enforce` mode a denied call returns a denial string
   to the model (the run recovers gracefully) or raises `WardenBlocked`. In
   `observe` mode findings are recorded but the call always proceeds.

## Hook points by framework

| Framework | What gets wrapped | When it fires |
|---|---|---|
| OpenAI Agents SDK | `FunctionTool.on_invoke_tool` (async) | after the LLM decides to call a tool, before the function runs |
| LangChain / LangGraph | `tool.func` + `tool.coroutine` | before `tool.invoke()` / `tool.ainvoke()` executes |
| CrewAI | `tool.func` → `tool._run` → `tool.run` (first found) | before the tool implementation runs |
| browser-use | `Registry.execute_action` | before Playwright executes any browser action |
| Vercel AI SDK | `tool.execute` | before the tool body runs, after the LLM emits the tool call |
| HTTP (any language) | caller-side `POST /v1/evaluate` | before calling the tool implementation |

## Eval-server (non-Python languages)

For TypeScript, Go, Ruby, Java, Rust — any language that can make an HTTP request
— run the **eval-server** as a sidecar and call it before executing each tool:

```bash
prismor eval-server --port 7071 --workspace /path/to/project
```

```
POST /v1/evaluate
{
  "tool_name": "run_shell",
  "arguments": { "command": "rm -rf /" },
  "event_type": "shell",
  "mode": "enforce",
  "subject": "user:alice"
}

→ { "allow": false, "reason": "[CRITICAL] ...", "subject": { "user_id": "alice" } }
```

The Python policy engine, IAM, and telemetry run inside the sidecar. Adapters
in other languages are ~25 lines of HTTP client code with no Python dependency.
The adapter **fails open** if the eval-server is down — agents are never broken
by infrastructure issues.

Validated live on an Ubuntu EC2 instance with real OpenAI function calls:

| Language | Adapter size | Dependencies |
|---|---|---|
| TypeScript (Vercel AI SDK) | ~80 lines | `npm install prismor-warden-vercel` |
| Node.js (raw) | ~25 lines | built-in `fetch` |
| Ruby | ~20 lines | stdlib `Net::HTTP` |
| Java 21 | ~25 lines | stdlib `java.net.http` |
| Rust | ~25 lines | `ureq` crate |

See `examples/multilang/` for runnable examples in all four languages.

## Naming agents

Every guard entry point takes an optional `name=` — an **instance label**
distinct from the framework id. Multiple agents on the same framework
("checkout-bot" and "support-bot", both on the OpenAI Agents SDK) become
individually visible and controllable:

```python
guard_agent(agent, name="checkout-bot")            # OpenAI Agents SDK
tools = guard_tools(tools, name="support-bot")     # LangChain / CrewAI
guard_controller(controller, name="browser-bot")   # browser-use
```

```ts
const tools = wardenTools(myTools, { agentName: 'checkout-bot' });  // Vercel AI SDK
```

What a name unlocks:

- **Its own row** in the org dashboard's Connections view (and a per-agent
  activity drill-in), instead of blending into the framework's aggregate.
- **Per-agent runtime control** via `prismor agents set <name>` — kill-switch
  (`--disabled` hard-blocks every call), a mode override, and a forced IAM
  profile. Config lives in `agents.yaml` (global `~/.prismor/` or per-project
  `.prismor-warden/`); agents self-register on first sight.

```bash
prismor agents list                                # every named instance seen
prismor agents set checkout-bot --mode enforce     # this bot only
prismor agents set support-bot --disabled          # kill switch
```

Unnamed agents keep working unchanged — they report under the framework id.

## Modes

```python
guard_agent(agent, mode="observe")   # log findings, never block — safe rollout
guard_agent(agent, mode="enforce")   # block denied calls before execution
```

Start in `observe` to understand blast radius, switch to `enforce` once confident.
Policy is YAML — change it without redeploying agents.

## Per-user IAM

Add `user:<id>` or `team:<id>` keys to `.prismor-warden/iam.yaml`:

```yaml
agents:
  user:bob:
    deny_tools: [Bash]
    deny_network: true
    allowed_paths: ["**"]
```

When a request runs under `use_subject("user:bob")`, bob's profile is selected
automatically — no env var, no code change. Users without a profile get the
org-wide defaults.

## Per-framework guides

- [OpenAI Agents SDK](frameworks-openai-agents.md) — `guard_agent`, `warden_guard`, FunctionTool patching
- [LangChain / LangGraph](frameworks-langchain.md) — `guard_tools`, `WardenCallbackHandler`
- [CrewAI](frameworks-crewai.md) — `guard_tools`, BaseTool and structured tool support
- [browser-use](frameworks-browser-use.md) — `guard_controller`, network/file/shell event mapping
- [Vercel AI SDK](frameworks-vercel-ai.md) — `wardenTools`, TypeScript, eval-server HTTP protocol
