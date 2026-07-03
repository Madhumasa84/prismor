#!/usr/bin/env bash
# Prismor Warden — cloaking PreToolUse hook (Claude Code, Read matcher).
#
# The built-in Read tool has no post-hoc output-rewrite channel (unlike Bash,
# whose output decloak.sh scrubs, and MCP tools, whose output recloak-mcp.sh
# scrubs). So a secret read through the Read tool cannot be masked after the
# fact — the only way to keep it out of context is to stop the read.
#
# This hook denies a Read whose target file contains a registered secret value,
# and tells the model to reference the `@@SECRET:name@@` placeholder instead
# (which decloak.sh will substitute at execution time). Files that hold no
# registered secret are unaffected.
#
# Stdin:  Claude Code PreToolUse JSON payload (Read).
# Stdout: JSON permissionDecision=deny (target holds a secret), else empty.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/secrets}"

command -v jq >/dev/null 2>&1 || exit 0   # no jq → silent no-op; decloak fails loud

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ "$tool_name" == "Read" ]] || exit 0

file_path="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')"
[[ -n "$file_path" && -f "$file_path" ]] || exit 0
[[ -d "$SECRETS_DIR" ]] || exit 0

# Does the target file contain any registered secret value verbatim?
shopt -s nullglob
for secret_file in "$SECRETS_DIR"/*; do
  [[ -f "$secret_file" ]] || continue
  name="$(basename "$secret_file")"
  real="$(cat "$secret_file")"
  [[ ${#real} -ge 4 ]] || continue
  if grep -qF -- "$real" "$file_path" 2>/dev/null; then
    reason="Prismor cloaking: '$file_path' contains the registered secret '$name'. Reading it would place the raw value in context. Reference it as @@SECRET:${name}@@ in a Bash command instead — Warden substitutes the real value at execution time and scrubs it from the output."
    jq -n --arg r "$reason" \
      '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
    exit 0
  fi
done

exit 0
