#!/usr/bin/env bash
# Prismor Warden — cloaking UserPromptSubmit hook (soft-block).
#
# Scans the user's submitted prompt for recognizable secret patterns. On a
# match, auto-cloaks the value (writes it to $PRISMOR_SECRETS_DIR with a
# hashed name) and BLOCKS the prompt with a reason that shows the sanitized
# version. The user copies the sanitized prompt and resubmits — from that
# point forward, the model only ever sees the `@@SECRET:auto_xxxxxx@@`
# placeholder, never the raw value.
#
# UserPromptSubmit hooks cannot rewrite the prompt (Claude Code exposes only
# block/add-context on this event). One re-paste is the smallest achievable
# UX cost for a leak-proof user-prompt boundary.
#
# Stdin:  Claude Code UserPromptSubmit JSON payload
# Stdout: JSON with decision=block and a reason (if a secret was detected),
#         or empty (no-op) otherwise.
set -uo pipefail

# shellcheck source=_patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_patterns.sh"

SECRETS_DIR="$(prismor_secrets_dir)"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR" 2>/dev/null || true

command -v jq >/dev/null 2>&1 || exit 0

input="$(cat)"
prompt="$(printf '%s' "$input" | jq -r '.prompt // empty')"
[[ -n "$prompt" ]] || exit 0

# Optional user bypass: a prompt starting with `!!allow ` (ignoring leading
# whitespace) is passed through unchanged. Useful when the user is deliberately
# discussing a secret in prose and doesn't want auto-cloaking.
trimmed="$(printf '%s' "$prompt" | sed 's/^[[:space:]]*//')"
if [[ "$trimmed" == "!!allow "* ]]; then
  exit 0
fi

# ── Detection patterns ────────────────────────────────────────────────────
# Loaded from the shared single-source-of-truth file (builtin_patterns.txt)
# plus any org-specific patterns the user added via `prismor cloak pattern add`.
prismor_load_patterns
[[ "${#PATTERNS[@]}" -gt 0 ]] || exit 0

# Strip already-cloaked placeholders before scanning so that @@SECRET:name@@
# syntax in the prompt never triggers a false positive match.
scan_text="$(printf '%s' "$prompt" | sed 's/@@SECRET:[^@]*@@//g')"

# Collect unique matches across all patterns.
matches="$(
  for pat in "${PATTERNS[@]}"; do
    printf '%s' "$scan_text" | grep -oE "$pat" || true
  done | awk 'NF && !seen[$0]++'
)"

[[ -n "$matches" ]] || exit 0

# ── Cloak each match ─────────────────────────────────────────────────────
sanitized="$prompt"
reported_placeholders=""
while IFS= read -r real_value; do
  [[ -z "$real_value" ]] && continue

  # Deterministic placeholder name from value hash (first 8 hex chars).
  # Same value → same placeholder across sessions (no duplicate registration).
  hash="$(printf '%s' "$real_value" | shasum -a 256 | awk '{print $1}' | cut -c1-8)"
  placeholder_name="auto_${hash}"
  placeholder="@@SECRET:${placeholder_name}@@"
  secret_file="$SECRETS_DIR/$placeholder_name"

  # Only write if new — avoid touching mtime on existing entries.
  if [[ ! -f "$secret_file" ]]; then
    printf '%s' "$real_value" > "$secret_file"
    chmod 600 "$secret_file" 2>/dev/null || true
  fi

  # Substitute every occurrence of this value in the sanitized prompt.
  sanitized="${sanitized//"$real_value"/$placeholder}"
  reported_placeholders+="  • $placeholder"$'\n'
done <<< "$matches"

# ── Emit soft-block decision ──────────────────────────────────────────────
reason="Prismor cloaking: detected secret(s) in your prompt.

Stored under ${SECRETS_DIR} as:
${reported_placeholders%$'\n'}

Your original prompt was NOT sent to the model. Resubmit with the sanitized
version below (the model will resolve each placeholder at tool-call time):

---
${sanitized}
---

Prefix your prompt with '!!allow ' to bypass detection for a single message."

jq -n --arg r "$reason" '{decision: "block", reason: $r}'
