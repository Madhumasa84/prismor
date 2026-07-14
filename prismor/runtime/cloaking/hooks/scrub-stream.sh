#!/usr/bin/env bash
# Prismor — cloaking output scrubber (stdin filter).
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

# Whether a raw secret value is distinctive enough to match by substring
# without false positives. Mirrors is_scrubbable_secret() in ../runtime.py:
# eligible if >= 16 chars, or >= 8 chars AND carrying a digit, a symbol, or
# mixed case. A short single-case word is skipped — masking it would corrupt
# ordinary output far more than it protects anything.
_prismor_scrubbable() {
  local v="$1" n=${#1}
  (( n >= 8 )) || return 1
  (( n >= 16 )) && return 0
  [[ "$v" == *[[:digit:]]* ]] && return 0
  [[ "$v" == *[![:alnum:]]* ]] && return 0
  [[ "$v" == *[[:lower:]]* && "$v" == *[[:upper:]]* ]] && return 0
  return 1
}

# Build a single sed program: real value → placeholder, for each secret.
# Escape sed's `s|...|...|` delimiters and metacharacters in the real value.
sed_filter=""
shopt -s nullglob
for secret_file in "$SECRETS_DIR"/*; do
  [[ -f "$secret_file" ]] || continue
  name="$(basename "$secret_file")"
  real="$(cat "$secret_file")"
  _prismor_scrubbable "$real" || continue
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
