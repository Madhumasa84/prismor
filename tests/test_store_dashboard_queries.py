"""Regression tests for the dashboard-facing queries in store.py.

get_findings_page() and get_events_page() had no test coverage at all before
PrismorSec/prismor#129 and #130 — both queries built session data through the
real ingest path (save_session_snapshot + analyze_events) and asserted on the
API-shaped output, the same way `prismor ingest` / the dashboard actually do.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.cli import analyze_events
from prismor.runtime.store import (
    get_events_page,
    get_findings_page,
    save_session_snapshot,
)


class TestDashboardQueries(unittest.TestCase):
    def setUp(self):
        # Patch list_registered_workspaces rather than calling the real
        # register_workspace(), which writes to the real global
        # ~/.prismor/workspaces.json (see PrismorSec/prismor#131) — these
        # tests must not depend on, or pollute, real machine state.
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        patcher = patch("prismor.runtime.store.list_registered_workspaces", return_value=[self.workspace])
        patcher.start()
        self.addCleanup(patcher.stop)

        # A mix of one allowed (benign) and one blocked (destructive) shell
        # event in the same session — the exact shape that exposed both bugs.
        self.events = [
            {"type": "shell", "command": "ls -la", "ts": "2026-01-01T00:00:00Z"},
            {"type": "shell", "command": "rm -rf /", "ts": "2026-01-01T00:00:01Z"},
        ]
        analysis = analyze_events(self.events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(
            workspace=self.workspace,
            session_id="test-session",
            agent="claude",
            source="ingest",
            repo_url=None,
            events=self.events,
            analysis=analysis,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_findings_page_returns_the_stored_finding(self):
        # Regression for #129: a correlated OFFSET subquery made this always
        # raise (silently swallowed), so `items`/`total` were always empty.
        data = get_findings_page()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["category"], "dangerous_command")
        self.assertIn("rm -rf /", data["items"][0]["trigger"]["detail"])

    def test_events_page_marks_only_the_actual_finding_as_blocked(self):
        # Regression for #130: verdict/severity were computed from
        # `s.findings_count > 0` (session-wide), so the benign `ls -la` event
        # also showed up as "blocked"/"critical" just because the session
        # contained an unrelated blocked event.
        data = get_events_page()
        by_action = {item["action"]: item for item in data["items"]}
        self.assertEqual(by_action["shell: ls -la"]["verdict"], "allowed")
        self.assertEqual(by_action["shell: rm -rf /"]["verdict"], "blocked")
        self.assertEqual(by_action["shell: rm -rf /"]["severity"], "critical")

    def test_events_page_verdict_filter_uses_per_event_match(self):
        allowed_only = get_events_page(verdict="allowed")
        actions = [item["action"] for item in allowed_only["items"]]
        self.assertIn("shell: ls -la", actions)
        self.assertNotIn("shell: rm -rf /", actions)

        blocked_only = get_events_page(verdict="blocked")
        actions = [item["action"] for item in blocked_only["items"]]
        self.assertIn("shell: rm -rf /", actions)
        self.assertNotIn("shell: ls -la", actions)


if __name__ == "__main__":
    unittest.main()
