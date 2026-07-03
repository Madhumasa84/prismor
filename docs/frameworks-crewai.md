# CrewAI integration

Prismor Warden adapter for CrewAI. Ships from
[`adapters/crewai/`](../adapters/crewai/) as `prismor-warden-crewai`.
Registry entry: `id: crewai` in
[`warden/integrations/registry.yaml`](../warden/integrations/registry.yaml).

## Install

> The adapter packages are not on PyPI yet — until they publish, install from
> source (the import paths below are identical either way).

```bash
pip install "prismor @ git+https://github.com/PrismorSec/prismor.git@main"                  # Warden runtime
pip install "prismor-warden-crewai @ git+https://github.com/PrismorSec/prismor.git@main#subdirectory=adapters/crewai"
pip install crewai                             # + crewai itself, if not present
```

## Guard tools (easy path)

```python
from crewai import Agent, Task, Crew
from crewai_tools import tool
from prismor.warden.crewai import guard_tools

@tool("Shell runner")
def run_shell(command: str) -> str:
    """Run a shell command and return its output."""
    ...

tools = guard_tools([run_shell])   # every tool now policy-checked

agent = Agent(
    role="ops",
    goal="...",
    tools=tools,
    llm="gpt-4o-mini",
)
```

`guard_tools` wraps the tool's implementation callable in-place — it tries
`tool.func`, then `tool._run`, then `tool.run` (first found). The tool object
is returned unchanged so CrewAI's introspection and schema generation are
unaffected.

## Guard a single tool

```python
from prismor.warden.crewai import warden_guard_tool

guarded = warden_guard_tool(run_shell, mode="enforce", subject="user:alice")
```

## Per-user control (multi-tenant)

```python
from crewai import Crew
from prismor.warden.crewai import guard_tools, use_subject

tools = guard_tools([run_shell, search])   # once, at startup — no bound subject

agent = Agent(role="ops", tools=tools, llm="gpt-4o-mini", ...)
crew = Crew(agents=[agent], tasks=[...])

# per-request handler
with use_subject("user:alice"):
    result = crew.kickoff(inputs={"prompt": user_prompt})
```

Per-user IAM example (`.prismor-warden/iam.yaml`):

```yaml
agents:
  user:bob:
    deny_tools: [Bash]
    deny_network: true
    allowed_paths: ["**"]
  team:analysts:
    allowed_paths: ["/data/**"]
    deny_network: false
```

Use `"user=alice;team=analysts"` as the subject string to match both
`user:alice` and `team:analysts` profiles simultaneously.

## Tool shapes supported

CrewAI tools come in two shapes; the adapter handles both automatically:

**Structured tools** (decorated with `@tool`):

```python
from crewai_tools import tool

@tool("Shell runner")
def run_shell(command: str) -> str: ...

guard_tools([run_shell])   # wraps tool.func
```

**BaseTool subclasses**:

```python
from crewai.tools import BaseTool

class ShellTool(BaseTool):
    name: str = "Shell runner"
    description: str = "..."

    def _run(self, command: str) -> str: ...

guard_tools([ShellTool()])   # wraps tool._run
```

## Deny behaviour

By default a blocked call returns a denial string to the crew:

```
⛔ Prismor Warden blocked this tool call: [HIGH] destructive-command matched
```

CrewAI surfaces this as the tool's output, and the agent typically reports the
error and moves on. Use `raise_on_block=True` to raise `WardenBlocked` instead,
which halts the task.

## Event mapping

| Tool call type | Event type | Field | Rules that apply |
|---|---|---|---|
| Default | `shell` | `command` | `destructive-command`, `secret-exfiltration`, … |
| Override with `event_type="network"` | `network` | `url` | `suspicious-network`, `secret-in-url-params` |
| Override with `event_type="file_write"` | `file_write` | `path` | path-based rules |

Pass `event_type` to `warden_guard_tool` for tools that make network requests
or write files rather than running shell commands.

## Reference

| Symbol | Purpose |
|---|---|
| `guard_tools(tools, **kwargs)` | Guard a list of CrewAI tools in one call |
| `warden_guard_tool(tool, **kwargs)` | Guard a single tool |
| `use_subject(value)` | Per-request subject contextmanager |
| `WardenBlocked` | Raised on enforce-mode block (when `raise_on_block=True`) |

All functions accept: `subject`, `workspace`, `agent`, `mode`, `session_id`,
`event_type`, `raise_on_block`. See [`adapters/crewai/`](../adapters/crewai/)
for full signatures.
