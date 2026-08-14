"""Editing settings.egress from the dashboard.

`prismor egress ...` already does this from a terminal, but its helpers print
and sys.exit, so they cannot back an HTTP endpoint. These are the same
operations as data — same EgressEntry validation, same policy writer, so the
org-managed refusal applies here too.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import store


def _workspace() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / ".prismor").mkdir()
    (d / ".prismor" / "policy.yaml").write_text('version: "1.0"\n')
    return d


def _unmanaged():
    return mock.patch(
        "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False
    )


class TestHostValidation(unittest.TestCase):
    """EgressEntry accepts any non-empty string — to the matcher an unparseable
    host is just one that never matches. Typed into a form that is a silent
    mistake: it saves, looks right, and never fires."""

    def test_accepts_the_real_shapes(self):
        for host in ("api.github.com", "*.githubusercontent.com", "*",
                     "10.0.0.0/8", "192.168.1.5", "2001:db8::1"):
            with self.subTest(host=host):
                self.assertIsNone(store.validate_egress_host(host))

    def test_rejects_what_would_never_match(self):
        for host in ("not a host!!", "bad..dom", "", "   ", "has space.com"):
            with self.subTest(host=host):
                self.assertIsNotNone(store.validate_egress_host(host))

    def test_a_url_says_so_rather_than_complaining_about_cidr(self):
        self.assertIn("not a URL", store.validate_egress_host("https://api.github.com") or "")

    def test_a_bad_cidr_says_cidr(self):
        self.assertIn("CIDR", store.validate_egress_host("10.0.0.0/99") or "")


class TestEgressEditing(unittest.TestCase):
    def test_adding_a_host_turns_screening_on(self):
        # A rule added to a policy nobody enabled is a no-op, which is the one
        # thing worse than no rule. Matches `prismor egress allow`.
        ws = _workspace()
        with _unmanaged():
            result = store.add_egress_host(ws, "api.github.com", "allow", reason="CI")
            self.assertTrue(result["ok"], result.get("error"))
            cfg = store.get_egress_config(ws)
        self.assertTrue(cfg["effective"]["enabled"])
        self.assertEqual(cfg["effective"]["mode"], "observe")
        self.assertEqual([e["host"] for e in cfg["effective"]["allow"]], ["api.github.com"])
        self.assertEqual(cfg["effective"]["allow"][0]["reason"], "CI")

    def test_duplicate_is_refused_rather_than_silently_ignored(self):
        ws = _workspace()
        with _unmanaged():
            store.add_egress_host(ws, "api.github.com")
            again = store.add_egress_host(ws, "api.github.com")
        self.assertFalse(again["ok"])
        self.assertIn("already", again["error"])

    def test_invalid_host_never_reaches_the_file(self):
        ws = _workspace()
        with _unmanaged():
            result = store.add_egress_host(ws, "not a host!!")
            self.assertFalse(result["ok"])
            cfg = store.get_egress_config(ws)
        self.assertEqual(cfg["effective"]["allow"], [])

    def test_remove_takes_it_off_both_lists(self):
        ws = _workspace()
        with _unmanaged():
            store.add_egress_host(ws, "evil.example", "deny")
            removed = store.remove_egress_host(ws, "evil.example")
            self.assertTrue(removed["ok"])
            cfg = store.get_egress_config(ws)
        self.assertEqual(cfg["effective"]["deny"], [])

    def test_removing_something_absent_says_so(self):
        ws = _workspace()
        with _unmanaged():
            self.assertFalse(store.remove_egress_host(ws, "nope.example")["ok"])

    def test_mode_and_default_round_trip(self):
        ws = _workspace()
        with _unmanaged():
            store.set_egress_option(ws, "mode", "enforce")
            store.set_egress_option(ws, "default", "deny")
            cfg = store.get_egress_config(ws)
        self.assertEqual(cfg["effective"]["mode"], "enforce")
        self.assertEqual(cfg["effective"]["default"], "deny")

    def test_nonsense_values_are_refused(self):
        ws = _workspace()
        with _unmanaged():
            self.assertFalse(store.set_egress_option(ws, "mode", "maybe")["ok"])
            self.assertFalse(store.set_egress_option(ws, "default", "sometimes")["ok"])
            self.assertFalse(store.set_egress_option(ws, "not_a_field", True)["ok"])

    def test_editing_does_not_disturb_the_rest_of_the_policy(self):
        ws = _workspace()
        (ws / ".prismor" / "policy.yaml").write_text(
            'version: "1.0"\n'
            "settings:\n  selection: explicit\n  default_mode: observe\n"
            "rules:\n  - id: secret-exfiltration\n    mode: enforce\n"
        )
        with _unmanaged():
            store.add_egress_host(ws, "api.github.com")
            from prismor.runtime.policy_engine import PolicyEngine
            engine = PolicyEngine(workspace=ws)
        self.assertTrue(engine.explicit_selection)
        rule = next(r for r in engine.rules if r.id == "secret-exfiltration")
        self.assertEqual(engine._resolve_mode(rule), "enforce")

    def test_org_managed_workspace_refuses_the_edit(self):
        ws = _workspace()
        signed = Path(tempfile.mkdtemp()) / "remote-policy.yaml"
        signed.write_text("version: '1.0'\n")
        with mock.patch(
            "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=True
        ), mock.patch(
            "prismor.runtime.enterprise.remote_policy.cached_policy_path", return_value=signed
        ):
            result = store.add_egress_host(ws, "api.github.com")
        self.assertFalse(result["ok"])
        self.assertEqual(result.get("reason"), "org_managed")


if __name__ == "__main__":
    unittest.main()
