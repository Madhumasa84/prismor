#!/usr/bin/env python3
"""prismor — unified CLI for the Prismor security toolkit.

Every command in the toolkit is reachable as ``prismor <command> [args...]``.
Run ``prismor --help`` for the full map. The umbrella dispatches to the
existing engines:

  - warden.cli:main         runtime / session security, hooks, policy, sweep,
                            cloak, iam, canary, scope, learn, setup, audit ...
  - supplychain.cli:run_supply  package-install interception + project hardening
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import List, Optional, Set

from warden import __version__

# ANSI helpers (mirrors warden/cli.py palette so output is visually consistent)
_BOLD = "\033[1m"
_DIM = "\033[37m"
_RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ── Routing ───────────────────────────────────────────────────────────────────
#
# Routing is fully introspection-driven: `main()` forwards ANY real warden
# command (see `_warden_commands()`), and `_print_usage()` builds the help from
# the live parser (see `_command_table()`), so neither can drift out of sync.
_SUPPLY_DOMAIN = "supplychain"


@lru_cache(maxsize=1)
def _warden_commands() -> Set[str]:
    """Authoritative set of top-level commands ``warden.cli`` accepts.

    Introspected from warden.cli's argparse parser so the umbrella stays a true
    superset automatically — every warden subcommand is reachable as
    ``prismor <command>`` with no hand-maintained list to drift out of sync.
    """
    import argparse
    try:
        from warden.cli import build_parser
        parser = build_parser()
    except Exception:
        return set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices.keys())
    return set()


def _deprecation_notice() -> None:
    """Nudge users off the old `immunity` command and the `immunity-agent`
    package name. Fires once per invocation, only when the binary was called as
    `immunity`. Suppressable with PRISMOR_NO_DEPRECATION=1 for scripts/CI."""
    if os.environ.get("PRISMOR_NO_DEPRECATION"):
        return
    if os.path.basename(sys.argv[0] or "") != "immunity":
        return
    sys.stderr.write(
        "\033[33mnote:\033[0m the 'immunity' command is now 'prismor'. "
        "'immunity' still works for now but will be removed.\n"
        "      Switch with: pip install -U prismor   (then use 'prismor ...')\n"
    )


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    _deprecation_notice()

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_usage()
        return

    if argv[0] in ("-V", "--version"):
        print(f"prismor {__version__}")
        return

    cmd, rest = argv[0], argv[1:]

    # `prismor supplychain ...` — supply-chain enforcement engine.
    if cmd == _SUPPLY_DOMAIN:
        from supplychain.cli import run_supply
        run_supply(rest)
        return

    # `prismor warden <command> ...` — DEPRECATED alias. Every warden command is
    # now a direct prismor command, so the `warden` namespace is redundant.
    if cmd == "warden":
        # Bare `prismor warden` with no subcommand: don't dump warden's noisy
        # argparse usage — point at the unified help instead.
        if not rest:
            sys.stderr.write(
                "'warden' is deprecated — every warden command is now a direct "
                "prismor command.\n"
                "Run 'prismor help' to see all commands.\n"
            )
            return
        # With a subcommand: warn once, then forward so old scripts keep working.
        sys.stderr.write(
            "Warning: 'prismor warden ...' is deprecated — every warden command "
            "is now a direct prismor command.\n"
            f"Use 'prismor {rest[0]}' instead.\n\n"
        )
        from warden.cli import main as warden_main
        warden_main(rest)
        return

    # Any genuine warden top-level command (domains, shortcuts, and any future
    # warden subcommand) forwards straight through: `prismor <cmd> ...`.
    if cmd in _warden_commands():
        from warden.cli import main as warden_main
        warden_main([cmd, *rest])
        return

    sys.stderr.write(
        f"prismor: unknown command '{cmd}'.\n"
        f"  Run 'prismor --help' to see all commands.\n"
    )
    sys.exit(2)


# Ordered grouping for `prismor help`. Every group lists the commands it
# owns; any introspected command NOT named here lands in the "More" catch-all,
# so a new warden.cli subcommand can never silently vanish from help.
_HELP_GROUPS = [
    ("Quick start",          ["setup", "status", "dashboard", "audit", "update"]),
    ("Runtime protection",   ["check", "semantic-check", "scan", "deps", "sandbox", "policy"]),
    ("Sessions & forensics", ["analyze", "ingest", "sessions", "session"]),
    ("Hooks",                ["install-hooks", "uninstall-hooks"]),
    ("Secret prevention",    ["cloak", "sweep", "canary"]),
    ("Identity & scoping",   ["iam", "scope", "learn"]),
    ("Enterprise / org",     ["enroll", "enroll-status", "workspace", "exempt", "logout"]),
    ("Supply chain",         ["supplychain"]),
]

# Commands handled elsewhere in the help (deprecated section) or never shown.
_HELP_HIDDEN = {"hook-dispatch", "info", "serve", "warden"}

# supplychain is dispatched by this umbrella, not a warden.cli subcommand, so it
# is injected manually with its own help + sub-actions.
_SUPPLY_HELP = ("Supply-chain install gating + project hardening", "supplychain")
_SUPPLY_ACTIONS = ["npm", "pip", "pnpm", "yarn", "uv", "cargo", "go", "harden"]


def _command_table():
    """Introspect build_parser() → {name: (help, sub_actions, mode_flags)}.

    Generated from the live parser so help can never drift from the real CLI.
    """
    import argparse
    table = {}
    try:
        from warden.cli import build_parser
        parser = build_parser()
    except Exception:
        return table
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        helps = {ca.dest: (ca.help or "") for ca in action._get_subactions()}
        for name, sub in action.choices.items():
            nested, flags = [], []
            for sa in sub._actions:
                if isinstance(sa, argparse._SubParsersAction):
                    nested = list(sa.choices.keys())
                elif isinstance(sa, argparse._StoreTrueAction):
                    flags += [o for o in sa.option_strings if o.startswith("--")]
            table[name] = (helps.get(name, ""), nested, flags)
        break
    # supplychain isn't in warden.cli — add it so help is complete.
    table["supplychain"] = (_SUPPLY_HELP[0], _SUPPLY_ACTIONS, [])
    return table


def _print_usage() -> None:
    def b(t: str) -> str: return _c(t, _BOLD)
    def d(t: str) -> str: return _c(t, _DIM)

    table = _command_table()
    pad = 16

    def _emit(name: str) -> None:
        if name not in table:
            return
        help_text, nested, flags = table[name]
        full_cmd = f"prismor {name}"
        col = pad + 9
        print(f"    {full_cmd.ljust(col)}{d(help_text)}")
        if nested:
            sub = " · ".join(f"prismor {name} {s}" for s in nested)
            print(f"    {' ' * col}{d('· ' + sub)}")
        elif flags:
            print(f"    {' ' * col}{d('modes:  ' + '  '.join(flags))}")

    print()
    print(f"  {b('prismor')} — runtime security for AI coding agents")
    print()
    print(f"  Usage: {b('prismor')} <command> [options...]")
    print(f"         {b('prismor')} <command> --help   {d('flags + sub-actions for one command')}")

    grouped = set(_HELP_HIDDEN)
    for title, names in _HELP_GROUPS:
        present = [n for n in names if n in table]
        if not present:
            continue
        print()
        print(f"  {b(title)}")
        for n in present:
            _emit(n)
            grouped.add(n)

    # Catch-all: any real command not placed in a group above.
    leftover = [n for n in table if n not in grouped]
    if leftover:
        print()
        print(f"  {b('More')}")
        for n in sorted(leftover):
            _emit(n)

    col = pad + 9
    print()
    print(f"  {b('Help & version')}")
    print(f"    {'prismor --help'.ljust(col)}{d('This message')}")
    print(f"    {'prismor <cmd> --help'.ljust(col)}{d('Flags + sub-actions for one command')}")
    print(f"    {'prismor --version'.ljust(col)}{d('Show version')}")
    print()
    print(f"  {b('Deprecated')}  {d('(kept working; will be removed in a future release)')}")
    print(f"    {'prismor warden <cmd>'.ljust(col)}{d('the standalone warden CLI — use prismor directly')}")
    print(f"    {'prismor info'.ljust(col)}{d('use `prismor status`')}")
    print(f"    {'prismor serve'.ljust(col)}{d('use `prismor dashboard --no-open`')}")
    print()


def _warden_shim() -> None:
    """Deprecation shim installed as the 'warden' entry point.

    Replaces the old standalone binary on upgrade so users who still have
    'warden' in aliases or scripts get a clear migration message instead of
    silently running stale code.  All arguments are forwarded to prismor
    unchanged, so existing invocations keep working.
    """
    import sys
    sys.stderr.write(
        "Warning: 'warden' is deprecated and will be removed in a future release.\n"
        "Use 'prismor' instead — it is a drop-in replacement.\n\n"
    )
    main()


if __name__ == "__main__":
    main()
