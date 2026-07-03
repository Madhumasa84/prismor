"""Tests for per-rule pattern customization (add_patterns / disable_patterns)."""
import sys, os, tempfile, unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import CompiledRule, PolicyEngine, validate_policy


def mkraw(patterns, **extra):
    return {"id": "t", "severity": "HIGH", "category": "c", "title": "t",
            "event_types": ["shell"], "patterns": patterns, **extra}


class TestCompiledRulePatterns(unittest.TestCase):
    def test_add_patterns_appends(self):
        cr = CompiledRule(mkraw(["foo"], add_patterns=["baz123"]))
        self.assertTrue(cr.patterns.search("baz123"))
        self.assertTrue(cr.patterns.search("foo"))

    def test_disable_patterns_removes_by_string(self):
        cr = CompiledRule(mkraw(["foo", "bar"], disable_patterns=["foo"]))
        self.assertIsNone(cr.patterns.search("foo"))      # disabled
        self.assertTrue(cr.patterns.search("bar"))         # kept

    def test_disable_all_falls_back_to_defaults(self):
        # Disabling every default with no add must NOT yield an empty matcher.
        cr = CompiledRule(mkraw(["foo"], disable_patterns=["foo"]))
        self.assertTrue(cr.patterns.search("foo"))         # restored

    def test_invalid_add_pattern_dropped_rule_survives(self):
        cr = CompiledRule(mkraw(["foo"], add_patterns=["(unclosed", "good9"]))
        self.assertTrue(cr.patterns.search("foo"))         # defaults intact
        self.assertTrue(cr.patterns.search("good9"))       # valid add kept
        # invalid add did not break compilation (no exception raised)

    def test_stale_disable_is_noop(self):
        cr = CompiledRule(mkraw(["foo"], disable_patterns=["not-a-default"]))
        self.assertTrue(cr.patterns.search("foo"))         # nothing removed


class TestOverlayMerge(unittest.TestCase):
    def _engine(self, overlay_yaml):
        d = tempfile.mkdtemp()
        pp = Path(d) / "policy.yaml"
        pp.write_text(overlay_yaml)
        return PolicyEngine(workspace=Path(d), policy_path=pp)

    def _rule(self, eng, rid):
        return next((r for r in eng.rules if r.id == rid), None)

    def test_noncore_add_and_disable(self):
        eng = self._engine(
            'version: "1.0"\nrules:\n  - id: suspicious-network\n'
            "    add_patterns:\n      - 'evilcorp-exfil\\.example\\.com'\n"
        )
        r = self._rule(eng, "suspicious-network")
        self.assertIsNotNone(r)
        self.assertTrue(r.patterns.search("evilcorp-exfil.example.com"))

    def test_core_disable_is_stripped(self):
        # Trying to disable a core rule's patterns must be ignored — rm -rf / still matches.
        eng = self._engine(
            'version: "1.0"\nrules:\n  - id: destructive-command\n'
            "    disable_patterns:\n      - 'anything'\n"
        )
        r = self._rule(eng, "destructive-command")
        self.assertIsNotNone(r)
        self.assertTrue(r.patterns.search("rm -rf /"))

    def test_core_add_patterns_kept(self):
        eng = self._engine(
            'version: "1.0"\nrules:\n  - id: destructive-command\n'
            "    add_patterns:\n      - 'wipefs9xx'\n"
        )
        r = self._rule(eng, "destructive-command")
        self.assertTrue(r.patterns.search("rm -rf /"))     # default intact
        self.assertTrue(r.patterns.search("wipefs9xx"))    # add applied

    def test_sparse_override_of_unknown_rule_is_noop_not_crash(self):
        # A sparse overlay (e.g. just {id, mode}) whose id matches NO existing
        # rule is a typo/no-op — it must be ignored, not compiled as a malformed
        # new rule (which would KeyError on missing severity and fail-open).
        eng = self._engine(
            'version: "1.0"\nrules:\n  - id: destructive-commands\n    mode: enforce\n'
        )
        # Engine loaded without crashing; the typo'd id created no rule, and the
        # real rule (singular) is untouched and still matches.
        self.assertIsNone(self._rule(eng, "destructive-commands"))
        self.assertTrue(self._rule(eng, "destructive-command").patterns.search("rm -rf /"))

    def test_complete_new_rule_still_added(self):
        eng = self._engine(
            'version: "1.0"\nrules:\n  - id: my-new-rule\n    severity: HIGH\n'
            "    category: custom\n    title: my rule\n    event_types: [shell]\n"
            "    patterns: ['frobnicate']\n    mode: enforce\n"
        )
        r = self._rule(eng, "my-new-rule")
        self.assertIsNotNone(r)
        self.assertTrue(r.patterns.search("frobnicate"))


class TestValidatePolicy(unittest.TestCase):
    def _validate(self, yaml_text):
        d = tempfile.mkdtemp()
        p = Path(d) / "policy.yaml"
        p.write_text(yaml_text)
        return validate_policy(p)

    def test_sparse_overlay_rule_ok(self):
        errs = self._validate('version: "1.0"\nrules:\n  - id: db-access\n    add_patterns:\n      - "foo"\n')
        self.assertEqual([e for e in errs if "missing required" in e], [])

    def test_invalid_add_pattern_flagged(self):
        errs = self._validate('version: "1.0"\nrules:\n  - id: db-access\n    add_patterns:\n      - "(unclosed"\n')
        self.assertTrue(any("add_patterns" in e and "invalid regex" in e for e in errs))

    def test_core_disable_rejected(self):
        errs = self._validate('version: "1.0"\nrules:\n  - id: secret-exfiltration\n    disable_patterns:\n      - "x"\n')
        self.assertTrue(any("core protection" in e and "disable_patterns" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
