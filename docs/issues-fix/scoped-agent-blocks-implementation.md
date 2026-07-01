# Issue: Scoped Agent Blocks Implementation After Planning Prompt

## Summary

When a conversation starts with a **read-only planning request** ("come up with a plan"), the Warden scoped-agent synthesizes a deny list that locks the session to read-only tools. If the same session then shifts to **implementation**, Edit and Bash stay blocked because the synthesized rules are cached for the lifetime of the session.

## Root Cause

**File:** `warden/scoped_agent.py` (installed package at `~/.local/pipx/venvs/immunity-agent/...`)

On the first `UserPromptSubmit` of a session, Warden calls `synthesize_scoped_rules()` which analyzes the prompt intent and returns a `deny_tools` list. That result is cached to:

```
.prismor-warden/scoped/<session-id>.json
```

Every subsequent tool call in the session checks against that cached file. If the first prompt looked read-only, `deny_tools` will include `["Bash", "Edit", "Write", "MultiEdit"]`, and they stay blocked for the entire session — even after the user switches to asking for code changes.

## Observed Behavior

```
PreToolUse:Bash hook error: Prismor blocked this action:
  [HIGH] [scoped agent] Tool 'Bash' is explicitly denied for this session

PreToolUse:Edit hook error: Prismor blocked this action:
  [HIGH] [scoped agent] Tool 'Edit' is explicitly denied for this session
```

The hook command that fires:
```
python3 "/Users/anish/.local/pipx/venvs/immunity-agent/lib/python3.14/site-packages/warden/cli.py" \
  hook-dispatch --agent claude --workspace "/Users/anish/Documents/immunity-agent" --mode observe
```

## Trigger Condition

1. User opens a session and says something like **"come up with a plan"** or **"what do you think about X"**
2. Scoped-agent synthesizes read-only rules and caches them
3. User follows up with **"now implement it"**
4. All write tools are still blocked from the cached synthesis

## Immediate Fix (manual)

Clear the cached scoped rules for the current workspace:

```bash
rm /Users/anish/Documents/immunity-agent/.prismor-warden/scoped/*.json
```

Then start a new Claude Code session — Warden will re-synthesize rules based on the new prompt intent.

## Proper Fix (code change needed)

**Option A — Re-synthesize on intent shift**
Detect when the current prompt's intent diverges significantly from the synthesized rules (e.g., planning → implementation). Re-run synthesis and update the cache rather than holding the first result for the whole session.

**Option B — Scope rules to first N turns only**
Add a `synthesized_at_turn` field to the cached JSON. If the current turn is beyond a threshold (e.g., turn 3+), re-evaluate rather than blindly reusing the first synthesis.

**Option C — Prompt-level override keyword**
Recognize explicit user phrases like "implement", "make the change", "write the code" as signals to clear the synthesized deny list and re-run with a permissive baseline.

**Recommended: Option B** — it is the least disruptive change. The cache file already exists per-session; adding a TTL-by-turn field only requires a small change to `check_scoped_rules()` and the synthesis dispatch in `cli.py`.

## Files to Change

| File | Location | Change |
|------|----------|--------|
| `warden/scoped_agent.py` | `check_scoped_rules()` | Check `synthesized_at_turn`; if stale, return `None` to trigger re-synthesis |
| `warden/cli.py` | hook-dispatch, scoped synthesis block | Write `turn` counter into cached JSON; pass current turn when calling `check_scoped_rules()` |

## Related

- Scoped session cache: `.prismor-warden/scoped/<session-id>.json`
- Global IAM profiles: `~/.prismor/iam.yaml`
- Hook install config: `.claude/settings.json`
