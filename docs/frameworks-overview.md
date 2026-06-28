# Framework adapters — overview

Prismor Warden intercepts tool calls in production framework agents — not just
local coding agents. The integration is designed to be **a single function call**
on your existing agent or controller object, with no changes to your tool logic.

## UX at a glance

| Framework | Install | Guard | Multi-tenant |
|---|---|---|---|
| OpenAI Agents SDK | `pip install prismor-warden-openai` | `guard_agent(agent)` | `use_subject("user:alice")` |
| LangChain / LangGraph | `pip install prismor-warden-langchain` | `guard_tools([...])` | `use_subject("user:alice")` |
| CrewAI | `pip install prismor-warden-crewai` | `guard_tools([...])` | `use_subject("user:alice")` |
| browser-use | `pip install prismor-warden-browser-use` | `guard_controller(controller)` | `use_subject("user:alice")` |

The multi-tenant pattern is identical across all four: guard once at startup
with no bound subject, then wrap each request with `use_subject`. A context var
threads the subject through the evaluation pipeline — thread-safe and async-safe.

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
