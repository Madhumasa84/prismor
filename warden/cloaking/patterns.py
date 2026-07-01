"""Secret-detection pattern management for Prismor Warden cloaking.

Two pattern sources, in priority order:

  1. **Built-in** — ``builtin_patterns.txt`` shipped in this package. Conservative,
     known-prefix credential formats. The single source of truth shared with the
     bash hooks (``hooks/_patterns.sh`` reads the same file).
  2. **Custom** — a user-editable file at ``$PRISMOR_HOME/cloak_patterns.txt``
     (override with ``$PRISMOR_CLOAK_PATTERNS``) for org-specific token formats.

Each line is one POSIX-ERE. Blank lines and ``#`` comments are ignored. The
``prismor cloak pattern`` CLI manages the custom file; built-ins are read-only.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

# builtin_patterns.txt lives one directory up from this module.
_BUILTIN_FILE = Path(__file__).resolve().parent / "builtin_patterns.txt"


def builtin_patterns_file() -> Path:
    """Path to the bundled, read-only pattern file."""
    return _BUILTIN_FILE


def custom_patterns_file() -> Path:
    """Path to the user's editable custom-pattern file.

    Honors ``$PRISMOR_CLOAK_PATTERNS``; otherwise ``$PRISMOR_HOME/cloak_patterns.txt``
    (default ``~/.prismor/cloak_patterns.txt``). Mirrors ``hooks/_patterns.sh``.
    """
    override = os.environ.get("PRISMOR_CLOAK_PATTERNS")
    if override:
        return Path(override).expanduser()
    home = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))
    return home / "cloak_patterns.txt"


def _read_patterns(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def builtin_patterns() -> List[str]:
    """Return the bundled built-in patterns."""
    return _read_patterns(_BUILTIN_FILE)


def list_custom_patterns() -> List[str]:
    """Return the user's custom patterns (empty if none registered)."""
    return _read_patterns(custom_patterns_file())


def all_patterns() -> List[str]:
    """Built-ins followed by custom patterns — the effective detection set."""
    return builtin_patterns() + list_custom_patterns()


def add_pattern(regex: str) -> bool:
    """Append ``regex`` to the custom pattern file.

    Validates that the regex compiles before saving. Returns True if added,
    False if it was already present (built-in or custom). Raises ``ValueError``
    on an invalid regex.
    """
    regex = regex.strip()
    if not regex:
        raise ValueError("Pattern is empty.")
    try:
        re.compile(regex)
    except re.error as exc:
        raise ValueError(f"Invalid regex {regex!r}: {exc}") from exc

    if regex in builtin_patterns() or regex in list_custom_patterns():
        return False

    path = custom_patterns_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except PermissionError:
        pass
    if not path.exists():
        header = (
            "# Prismor Warden cloaking — custom (org-specific) secret patterns.\n"
            "# One POSIX ERE per line. Managed by `prismor cloak pattern add/remove`.\n"
        )
        path.write_text(header, encoding="utf-8")
    with path.open("a", encoding="utf-8") as f:
        f.write(regex + "\n")
    return True


def remove_pattern(regex: str) -> bool:
    """Remove ``regex`` from the custom pattern file.

    Returns True if a line was removed. Built-in patterns cannot be removed
    (raises ``ValueError`` if ``regex`` is a built-in).
    """
    regex = regex.strip()
    if regex in builtin_patterns():
        raise ValueError(
            f"{regex!r} is a built-in pattern and cannot be removed."
        )
    path = custom_patterns_file()
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip() != regex]
    if len(kept) == len(lines):
        return False
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return True
