# prismor-warden-crewai

Prismor Warden adapter for **CrewAI**. Every tool invocation is routed through
Warden's shared policy pipeline (`warden.runtime.evaluate_tool_call`) before the
tool runs — same engine, observe/enforce model, and per-user attribution as the
other adapters. Registry entry: `id: crewai`.

## Install

```bash
pip install prismor-warden-crewai      # + the Warden runtime (immunity-agent)
```

## Use

```python
from crewai import Agent
from prismor_warden_crewai import guard_tools

tools = guard_tools([run_shell], subject="user:alice", mode="enforce")
agent = Agent(role="ops", goal="...", backstory="...", tools=tools)
```

`guard_tools` wraps each tool's implementation (`func` / `_run` / `run`), so a
denied call never executes. A denial string is returned to the agent by default
(smooth recovery); pass `raise_on_block=True` for a hard stop. `mode="observe"`
is log-only.

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes policy,
IAM profile selection, and telemetry to the end-user.
