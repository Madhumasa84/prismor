#!/usr/bin/env bash
# Prismor Warden — cloaking PreToolUse hook (Claude Code, Bash matcher).
#
# Substitutes `@@SECRET:name@@` placeholders in the model's bash command with
# the real value from $PRISMOR_SECRETS_DIR/<name>, then wraps the command so
# that its captured stdout/stderr is piped through `sed` to scrub the real
# value back to the placeholder before Claude Code records it.
#
# Result: the real secret is resident only inside this hook's process and the
# local bash subprocess — never in the model's context, the JSONL transcript,
# or any API request to the upstream provider.
#
# Stdin:  Claude Code PreToolUse JSON payload
# Stdout: JSON with hookSpecificOutput.updatedInput (if substitution occurred)
#         or hookSpecificOutput.permissionDecision=deny (if secret not found).
#         Empty stdout = no-op (command contained no placeholder).
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-$HOME/.prismor/secrets}"

# Require jq — the rest of Warden already depends on Python, but hook scripts
# are shell-only for speed. If jq is missing we fail closed with a clear msg.
if ! command -v jq >/dev/null 2>&1; then
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Prismor cloaking requires jq (brew install jq)"}}\n'
  exit 0
fi

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ "$tool_name" == "Bash" ]] || exit 0

cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty')"
[[ -n "$cmd" ]] || exit 0

# Enumerate unique placeholders in the command.
placeholders="$(printf '%s' "$cmd" | grep -oE '@@SECRET:[a-zA-Z0-9_-]+@@' | sort -u || true)"
[[ -n "$placeholders" ]] || exit 0

new_cmd="$cmd"
sed_filter=""
while IFS= read -r placeholder; do
  [[ -z "$placeholder" ]] && continue
  name="${placeholder#@@SECRET:}"
  name="${name%@@}"
  secret_file="$SECRETS_DIR/$name"

  if [[ ! -f "$secret_file" ]]; then
    # Fail closed: deny the tool call rather than silently leaving the
    # placeholder in, which would confuse downstream commands.
    jq -n --arg reason "Prismor cloaking: secret '$name' not registered. Run: prismor cloak add $name" \
      '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
    exit 0
  fi

  real="$(cat "$secret_file")"
  # Substitute placeholder → real in the command string.
  new_cmd="${new_cmd//"$placeholder"/$real}"

  # Build the sed scrubber: real → placeholder. Escape sed metacharacters.
  esc_real="$(printf '%s' "$real" | sed 's/[\/&|]/\\&/g')"
  sed_filter+="s|$esc_real|$placeholder|g;"
done <<< "$placeholders"

# Wrap the command in a subshell whose combined stdout/stderr is scrubbed.
# The model only ever sees the output of `sed`, never the raw output.
wrapped="( $new_cmd ) 2>&1 | sed -E '$sed_filter'"

# Preserve any other fields of tool_input (e.g., description) and overwrite
# only .command.
new_input="$(printf '%s' "$input" | jq --arg c "$wrapped" '.tool_input | .command = $c')"
jq -n --argjson ni "$new_input" \
  '{hookSpecificOutput:{hookEventName:"PreToolUse",updatedInput:$ni}}'
