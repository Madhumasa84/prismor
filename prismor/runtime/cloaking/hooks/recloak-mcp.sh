#!/usr/bin/env bash
# Prismor — cloaking PostToolUse hook (Claude Code, mcp__.* matcher).
#
# Scrubs any registered real secret value out of MCP tool responses, replacing
# it with the corresponding `@@SECRET:name@@` placeholder before the model
# sees it. Only MCP tools support `hookSpecificOutput.updatedMCPToolOutput` —
# built-in Bash uses the in-command sed-wrap from decloak.sh instead.
#
# Stdin:  Claude Code PostToolUse JSON payload
# Stdout: JSON with hookSpecificOutput.updatedMCPToolOutput (if anything was
#         scrubbed). Empty stdout = no-op.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-$HOME/.prismor/secrets}"

if ! command -v jq >/dev/null 2>&1; then
  exit 0  # silent no-op; decloak.sh is the one that fails loud
fi

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ "$tool_name" == mcp__* ]] || exit 0

response="$(printf '%s' "$input" | jq -r '.tool_response // empty')"
[[ -n "$response" ]] || exit 0

# Build a sed expression that substitutes every registered secret's real
# value with its placeholder. Skip missing/empty entries.
sed_filter=""
shopt -s nullglob
for secret_file in "$SECRETS_DIR"/*; do
  [[ -f "$secret_file" ]] || continue
  name="$(basename "$secret_file")"
  real="$(cat "$secret_file")"
  [[ -n "$real" ]] || continue
  esc_real="$(printf '%s' "$real" | sed 's/[\/&|]/\\&/g')"
  sed_filter+="s|$esc_real|@@SECRET:$name@@|g;"
done
[[ -n "$sed_filter" ]] || exit 0

scrubbed="$(printf '%s' "$response" | sed -E "$sed_filter")"

# Only mutate if something actually changed — avoids noisy empty mutations.
if [[ "$scrubbed" != "$response" ]]; then
  jq -n --arg out "$scrubbed" \
    '{hookSpecificOutput:{hookEventName:"PostToolUse",updatedMCPToolOutput:$out}}'
fi
