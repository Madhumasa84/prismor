#!/usr/bin/env bash
# Prismor Warden — cloaking output scrubber (stdin filter).
#
# Reads every registered secret from $PRISMOR_SECRETS_DIR and rewrites any
# occurrence of a real value on stdin to its `@@SECRET:name@@` placeholder,
# streaming the result to stdout. Used by decloak.sh to sanitize the combined
# stdout/stderr of *every* Bash command the model runs — so a secret that a
# command reads out of a file (grep, cat, source+echo, an HTTP response body,
# etc.) is masked before Claude Code records the output, even when the model
# never referenced an `@@SECRET@@` placeholder.
#
# Why a separate script instead of an inline `sed` in the wrapped command:
# the real secret values must NOT appear in the command string, or they would
# land in `tool_input.command` (and thus the transcript). This helper reads
# the vault itself at runtime, so only its path — never a secret — is embedded
# in the command Claude Code records.
#
# Stdin:  arbitrary command output.
# Stdout: same output with registered secret values replaced by placeholders.
# On any error (missing vault, no jq/sed) it passes stdin through unchanged:
# a scrub is best-effort defense-in-depth and must never swallow command
# output the agent depends on.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/secrets}"

# No vault, or no secrets registered → nothing to scrub, pass through.
if [[ ! -d "$SECRETS_DIR" ]]; then
  exec cat
fi

# Build a single sed program: real value → placeholder, for each secret.
# Escape sed's `s|...|...|` delimiters and metacharacters in the real value.
sed_filter=""
shopt -s nullglob
for secret_file in "$SECRETS_DIR"/*; do
  [[ -f "$secret_file" ]] || continue
  name="$(basename "$secret_file")"
  real="$(cat "$secret_file")"
  # Skip empty or trivially short values: masking a 1-2 char string would
  # corrupt ordinary output far more than it protects anything.
  [[ ${#real} -ge 4 ]] || continue
  esc_real="$(printf '%s' "$real" | sed 's/[\/&|]/\\&/g')"
  sed_filter+="s|$esc_real|@@SECRET:${name}@@|g;"
done

if [[ -z "$sed_filter" ]]; then
  exec cat
fi

# `sed -E` over the stream. If sed is somehow unavailable, fall back to cat.
if command -v sed >/dev/null 2>&1; then
  exec sed -E "$sed_filter"
else
  exec cat
fi
