# prismor-warden-browser-use

Prismor Warden adapter for [browser-use](https://github.com/browser-use/browser-use).

Intercepts every browser action — navigation, clicks, form input, file ops — before
Playwright executes it, evaluating against the active Warden policy. Works with the
same observe/enforce model and per-user attribution as the other Prismor adapters.

## Install

```bash
pip install prismor-warden-browser-use
pip install "prismor-warden-browser-use[browser]"  # + browser-use itself
```

## Usage

```python
from browser_use import Agent, Controller
from prismor_warden_browser_use import guard_controller

controller = Controller()
guard_controller(controller, mode="enforce")   # every action now policy-checked

agent = Agent(task="...", llm=llm, controller=controller)
await agent.run()
```

## Per-user (multi-tenant)

```python
from prismor_warden_browser_use import guard_controller, use_subject

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

Denied actions return a string to the LLM (`⛔ Prismor Warden blocked …`) so the
agent recovers gracefully. Use `raise_on_block=True` to raise `WardenBlocked` instead.
