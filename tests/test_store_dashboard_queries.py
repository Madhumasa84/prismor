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
from prismor.runtime.scoped_agent import save_scoped_rules
from prismor.runtime.store import (
    get_events_page,
    get_findings_page,
    get_session_scoped_detail,
    persist_runtime_findings,
    save_session_snapshot,
    write_supply_chain_event,
)
from supplychain.ecosystems.detector import PackageSpec
from supplychain.ecosystems.metadata import PackageMetadata
from supplychain.scoring.engine import PackageVerdict, Signal


class TestDashboardQueries(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._orig_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.workspace / ".prismor-home")
        # Patch list_registered_workspaces rather than calling the real
        # register_workspace(), which writes to global machine state.
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
        if self._orig_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._orig_prismor_home
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

    def test_events_page_infers_scoped_agent_blocks(self):
        session_id = "scoped-session"
        save_scoped_rules(
            self.workspace,
            session_id,
            {
                "allowed_tools": ["Read"],
                "deny_tools": ["Bash"],
                "allowed_paths": ["**"],
                "deny_network": True,
            },
        )
        save_session_snapshot(
            workspace=self.workspace,
            session_id=session_id,
            agent="codex",
            source="hook",
            repo_url=None,
            events=[
                {
                    "type": "shell",
                    "agent_event": "PreToolUse",
                    "command": "prismor status",
                    "ts": "2026-01-01T00:00:02Z",
                    "metadata": {"tool_name": "Bash"},
                }
            ],
            analysis={"summary": {"riskScore": 0, "totalFindings": 0}, "findings": []},
        )

        blocked = get_events_page(verdict="blocked")
        event = next(item for item in blocked["items"] if item["sessionId"] == session_id)
        self.assertEqual(event["verdict"], "blocked")
        self.assertEqual(event["toolTag"], "Bash")
        self.assertEqual(event["policy"]["ruleId"], "scoped-agent")
        self.assertIn("explicitly denied", event["policy"]["evidence"])

        detail = get_session_scoped_detail(self.workspace, session_id)
        self.assertEqual(detail["recent_events"][0]["verdict"], "blocked")
        self.assertEqual(detail["recent_events"][0]["policy"]["ruleId"], "scoped-agent")

    def test_runtime_findings_are_persisted_for_dashboard(self):
        session_id = "runtime-finding-session"
        save_session_snapshot(
            workspace=self.workspace,
            session_id=session_id,
            agent="codex",
            source="hook",
            repo_url=None,
            events=[
                {
                    "type": "shell",
                    "agent_event": "PreToolUse",
                    "command": "prismor status",
                    "ts": "2026-01-01T00:00:03Z",
                    "metadata": {"tool_name": "Bash"},
                }
            ],
            analysis={"summary": {"riskScore": 0, "totalFindings": 0}, "findings": []},
        )
        persist_runtime_findings(
            self.workspace,
            session_id,
            [{
                "id": f"{session_id}:scoped-agent",
                "severity": "HIGH",
                "category": "scoped_agent",
                "title": "[scoped agent] Tool 'Bash' is explicitly denied for this session",
                "evidence": "Tool 'Bash' is explicitly denied for this session",
                "ruleId": "scoped-agent",
                "action": "block",
                "mode": "enforce",
            }],
            0,
        )

        event = next(item for item in get_events_page(verdict="blocked")["items"] if item["sessionId"] == session_id)
        self.assertEqual(event["policy"]["source"], "runtime")
        self.assertEqual(event["policy"]["mode"], "enforce")

        detail = get_session_scoped_detail(self.workspace, session_id)
        self.assertEqual(detail["recent_blocked"][0]["category"], "scoped_agent")


class TestSupplyChainEventIndex(unittest.TestCase):
    """write_supply_chain_event() inserted findings without event_index, so
    the matching event in get_events_page() could never resolve to a
    finding — those events fell back to "allowed" even when a package was
    actually blocked. Discovered while verifying #130's fix.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._orig_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.workspace / ".prismor-home")
        patcher = patch("prismor.runtime.store.list_registered_workspaces", return_value=[self.workspace])
        patcher.start()
        self.addCleanup(patcher.stop)

        spec = PackageSpec(raw="lodash@4.17.19", name="lodash", source="registry", version="4.17.19")
        meta = PackageMetadata(
            name="lodash", ecosystem="npm", version="4.17.19", age_days=5185,
            maintainer_count=1, has_install_script=False, source="registry",
        )
        verdict = PackageVerdict(
            spec=spec, meta=meta, score=75, verdict="block",
            signals=[Signal(id="ioc_ghsa", points=30, description="Command Injection in lodash")],
        )
        write_supply_chain_event(
            workspace=self.workspace,
            session_id="supply-chain-test",
            ts="2026-01-01T00:00:00Z",
            ecosystem="npm",
            install_cmd="supplychain npm install lodash@4.17.19",
            verdicts=[verdict],
        )

    def tearDown(self):
        if self._orig_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._orig_prismor_home
        self._tmp.cleanup()

    def test_blocked_package_event_shows_as_blocked(self):
        data = get_events_page()
        blocked = [i for i in data["items"] if "lodash" in i["action"]]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["verdict"], "blocked")

    def test_finding_is_returned_and_linked_to_its_event(self):
        data = get_findings_page()
        self.assertEqual(data["total"], 1)
        self.assertIn("lodash", data["items"][0]["trigger"]["detail"])


if __name__ == "__main__":
    unittest.main()
