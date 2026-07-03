#!/usr/bin/env bash
# Prismor — cloaking Stop hook.
#
# Runs a dry-run `prismor sweep` against ~/.claude after every session ends,
# so the developer sees a warning if any real secret leaked into the JSONL
# transcript despite the cloaking hooks. We intentionally do NOT run
# --redact here because redaction requires an interactive passphrase; the
# dry-run scan is non-interactive and side-effect-free.
#
# Stdin:  Claude Code Stop JSON payload (ignored — sweep scans the cache dir)
# Stdout: empty (no decision); stderr carries any findings surfaced to user.
set -uo pipefail

# Discard stdin — Stop payloads can be large (full assistant response).
cat >/dev/null

PRISMOR_CLI="${PRISMOR_CLI:-}"
if [[ -z "$PRISMOR_CLI" ]]; then
  # Fall back to the standard install location.
  PRISMOR_CLI="$HOME/.prismor/cli.py"
fi

[[ -f "$PRISMOR_CLI" ]] || exit 0

# Run sweep quietly in the background so we don't block the next turn.
# Any findings will be visible in the next `prismor status` or `prismor info`.
(
  python3 "$PRISMOR_CLI" sweep "$HOME/.claude" >/dev/null 2>&1 || true
) &

exit 0
