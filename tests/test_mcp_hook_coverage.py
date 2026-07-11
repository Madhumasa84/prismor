"""MCP tool calls under Claude are intercepted at the PreToolUse gate.

The Claude hook matcher used to omit ``mcp__.*``, so a raw `mcp__server__tool`
call never fired the dispatcher and slipped past policy entirely — even though
the dispatcher already classifies MCP events (`_classify_mcp_event`). Two tests:

  A. config — install-hooks writes an `mcp__.*` matcher on PreToolUse + PostToolUse.
  B. end-to-end — an MCP pre-call whose arguments trip an enforce rule is blocked
     (SystemExit 2), proving the call is now evaluated, not just logged.

Run:  python3 tests/test_mcp_hook_coverage.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.hooks import _merge_claude  # noqa: E402


class ClaudeMcpMatcher(unittest.TestCase):
    def _matchers(self, event: str):
        cfg = _merge_claude({}, "prismor-dispatch-cmd", Path("/tmp/ws"))
        return [e.get("matcher", "") for e in cfg["hooks"][event]]

    def test_pretooluse_matches_mcp(self):
        self.assertTrue(
            any("mcp__" in m for m in self._matchers("PreToolUse")),
            "PreToolUse matcher must cover mcp__ tools",
        )

    def test_posttooluse_matches_mcp(self):
        self.assertTrue(
            any("mcp__" in m for m in self._matchers("PostToolUse")),
            "PostToolUse matcher must cover mcp__ tools",
        )

    def test_core_tools_still_matched(self):
        # The fix must not drop the existing coverage.
        m = " ".join(self._matchers("PreToolUse"))
        for tool in ("Bash", "Read", "Edit", "Write", "WebFetch"):
            self.assertIn(tool, m)


_POLICY = """
rules:
  - id: mcp-block-test
    severity: HIGH
    category: test_mcp
    title: Block the MCP marker in tool arguments
    event_types: [tool_result]
    fields: [response]
    mode: enforce
    action: block
    patterns:
      - "MCPBLOCK_MARKER"
"""


class ClaudeMcpEndToEnd(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-mcp-home-"))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-mcp-ws-"))
        (self.ws / ".prismor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".prismor" / "policy.yaml").write_text(_POLICY)

    def _dispatch(self, tool_name: str, tool_input: dict):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "session_id": "mcp-test-session",
        }
        env = dict(os.environ)
        env["PRISMOR_HOME"] = str(self.home)
        env["PRISMOR_SECRETS_DIR"] = str(self.home / "secrets")
        env["PYTHONPATH"] = str(_REPO)
        return subprocess.run(
            [
                sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
                "--agent", "claude", "--workspace", str(self.ws), "--mode", "enforce",
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )

    def test_mcp_call_with_bad_args_is_blocked(self):
        # A local MCP pre-call is classified as tool_result carrying its args;
        # the enforce rule fires on the marker → the dispatcher blocks (exit 2).
        proc = self._dispatch("mcp__testsrv__dostuff", {"q": "MCPBLOCK_MARKER here"})
        self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_clean_mcp_call_passes(self):
        proc = self._dispatch("mcp__testsrv__dostuff", {"q": "totally benign"})
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
