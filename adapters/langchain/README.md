# prismor-langchain

Prismor adapter for **LangChain / LangGraph**. Every tool invocation is
routed through Prismor's shared policy pipeline (`prismor.runtime.runtime.evaluate_tool_call`)
before the tool runs — the same engine, observe/enforce model, and per-user
attribution a local coding agent uses.

This is the in-process **SDK adapter** surface from the
[integration registry](../../prismor/runtime/integrations/registry.yaml) (`id: langchain`).

## Install

```bash
pip install "prismor[langchain]"      # Prismor runtime + adapter + langchain-core
```

## Use

```python
from langgraph.prebuilt import create_react_agent
from prismor.langchain import guard_tools

tools = guard_tools([run_shell, fetch_url], subject="user:alice", mode="enforce")
agent = create_react_agent(model, tools)
```

`guard_tools` wraps each tool's implementation (sync `func` and async
`coroutine`), so a denied call never executes. By default a denial string is
returned to the agent (smooth recovery); pass `raise_on_block=True` for a hard
stop. `mode="observe"` is log-only.

### Per-user control

`subject` accepts a `Subject`, a `PRISMOR_SUBJECT`-style string (`"user:alice"`),
or `None` (resolved from `PRISMOR_SUBJECT` / the enrolled device at call time).
It is threaded into policy evaluation, IAM profile selection
(`user:<id>` / `team:<id>`), and telemetry.

### Observability handler

```python
from prismor.langchain import PrismorCallbackHandler

agent.invoke({...}, config={"callbacks": [PrismorCallbackHandler(subject="user:alice")]})
```

Captures and evaluates every tool call via `on_tool_start` even for tools you did
not wrap (raises to abort the call in enforce mode).

## Trace findings to your control plane

Guarding a tool evaluates it, but findings only **upload** to your Prismor
control plane if two things are in place — otherwise `evaluate_tool_call` runs
locally and silently ships nothing:

1. **An enrolled identity** at `~/.prismor/identity.json` (or `$PRISMOR_HOME`),
   written by `prismor enroll <token>`. It carries the `device_key` +
   `api_base` the telemetry sink authenticates with.

2. **The `prismor` telemetry sink** in your workspace policy — this is the
   switch that turns findings into uploads:

   ```yaml
   # .prismor/policy.yaml
   settings:
     outputs:
       - type: prismor        # POSTs each finding to {api_base}/api/telemetry/ingest
   ```

Each finding is then attributed with the framework (`langchain`), the
`subject` (end-user), the device, verdict, and category. Point `api_base` at
`http://localhost:3000` to trace into a local dev control plane instead of prod.

> If your agent runs but nothing shows up in the dashboard, it's almost always a
> missing `outputs: [{type: prismor}]` in the active policy, or an un-enrolled
> machine.
