# prismor-crewai

Prismor adapter for **CrewAI**. Every tool invocation is routed through
Prismor's shared policy pipeline (`prismor.runtime.runtime.evaluate_tool_call`) before the
tool runs — same engine, observe/enforce model, and per-user attribution as the
other adapters. Registry entry: `id: crewai`.

## Install

```bash
pip install "prismor[crewai]"      # Prismor runtime + adapter + crewai
```

## Use

```python
from crewai import Agent
from prismor.crewai import guard_tools

tools = guard_tools([run_shell], subject="user:alice", mode="enforce")
agent = Agent(role="ops", goal="...", backstory="...", tools=tools)
```

`guard_tools` wraps each tool's implementation (`func` / `_run` / `run`), so a
denied call never executes. A denial string is returned to the agent by default
(smooth recovery); pass `raise_on_block=True` for a hard stop. `mode="observe"`
is log-only.

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes policy,
IAM profile selection, and telemetry to the end-user.

## Trace findings to your control plane

Guarding evaluates tool calls, but findings only **upload** when the machine is
enrolled (`~/.prismor/identity.json`) **and** the workspace policy enables the
telemetry sink:

```yaml
# .prismor/policy.yaml
settings:
  outputs:
    - type: prismor        # POSTs each finding to {api_base}/api/telemetry/ingest
```

Set `api_base` to `http://localhost:3000` to trace into a local dev control
plane instead of prod. No sink → the agent runs but nothing reaches the dashboard.
