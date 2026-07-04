# prismor-browser-use

Prismor adapter for [browser-use](https://github.com/browser-use/browser-use).

Intercepts every browser action — navigation, clicks, form input, file ops — before
Playwright executes it, evaluating against the active Prismor policy. Works with the
same observe/enforce model and per-user attribution as the other Prismor adapters.

## Install

```bash
pip install "prismor[browser-use]"   # Prismor runtime + adapter + browser-use
```

## Usage

```python
from browser_use import Agent, Controller
from prismor.browser_use import guard_controller

controller = Controller()
guard_controller(controller, mode="enforce")   # every action now policy-checked

agent = Agent(task="...", llm=llm, controller=controller)
await agent.run()
```

## Per-user (multi-tenant)

```python
from prismor.browser_use import guard_controller, use_subject

controller = Controller()
guard_controller(controller)                   # once at startup, no bound subject

with use_subject("user:alice"):                # per-request
    await agent.run()
```

## What gets blocked

| Action type | Event type | Policy rules that apply |
|---|---|---|
| `go_to_url`, `search_google`, `open_tab` | `network` | `secret-exfiltration`, custom domain rules |
| `upload_file`, `save_pdf` | `file_write` | path-based rules |
| `click_element`, `input_text`, `scroll`, … | `shell` | `destructive-command`, custom rules |

Denied actions return a string to the LLM (`⛔ Prismor blocked …`) so the
agent recovers gracefully. Use `raise_on_block=True` to raise `PrismorBlocked` instead.

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
