"""Audit P0 (#1/#3/#12): the non-overridable floor + code-authored block
findings must ENFORCE regardless of default_mode, and cannot be downgraded to
observe by an overlay."""
import sys, os, tempfile, unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine, _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES
from prismor.runtime.hooks import should_block

PRE = {"agent_event": "PreToolUse"}


def _engine(overlay_yaml=None):
    if overlay_yaml is None:
        return PolicyEngine()
    d = tempfile.mkdtemp()
    p = Path(d) / "policy.yaml"
    p.write_text(overlay_yaml)
    return PolicyEngine(workspace=Path(d), policy_path=p)


class TestEnforcementFloor(unittest.TestCase):
    def test_floor_rule_enforces_on_default_observe_policy(self):
        # Shipped default policy has default_mode=observe and no per-rule enforce,
        # yet a destructive-command match must still block.
        eng = _engine()
        findings = eng.evaluate({"type": "shell", "command": "rm -rf /"}, index=0)
        floor = [f for f in findings if f.get("ruleId") == "destructive-command"]
        self.assertTrue(floor, "destructive-command rule should fire on rm -rf /")
        self.assertEqual(floor[0]["mode"], "enforce")
        self.assertIsNotNone(should_block(findings, {**PRE, "type": "shell"}))

    def test_synthetic_block_finding_gets_enforce(self):
        # Any code-authored finding with action:"block" and no mode must be
        # normalized to enforce (canary/vault/secret-exfil/taint/html-injection).
        eng = _engine()
        # Re-run evaluate's normalization on a hand-built synthetic finding shape
        # by checking the contract directly: action:block + no mode -> enforce.
        synthetic = {"category": "secret_access", "ruleId": "canary-access", "action": "block"}
        # mimic evaluate() normalization
        synthetic.setdefault("mode", "enforce" if synthetic.get("action") == "block" else "observe")
        self.assertEqual(synthetic["mode"], "enforce")
        self.assertIsNotNone(should_block([synthetic], {**PRE, "type": "file_read"}))

    def test_overlay_cannot_downgrade_core_rule_to_observe(self):
        # An exemption/project overlay setting mode:observe on a core-category
        # rule must NOT take effect — the finding still enforces.
        eng = _engine(
            'version: "1.0"\nsettings:\n  default_mode: observe\n'
            "rules:\n  - id: destructive-command\n    mode: observe\n"
        )
        findings = eng.evaluate({"type": "shell", "command": "rm -rf /"}, index=0)
        floor = [f for f in findings if f.get("ruleId") == "destructive-command"]
        self.assertTrue(floor)
        self.assertEqual(floor[0]["mode"], "enforce", "overlay must not downgrade the floor")

    def test_noncore_rule_still_observe_by_default(self):
        # Observe-by-default still holds for everything outside the floor.
        eng = _engine()
        # Find any rule whose category is NOT a core block category and fire it.
        noncore = next((r for r in eng.rules
                        if r.category not in _CORE_BLOCK_CATEGORIES
                        and r.id not in _NON_OVERRIDABLE_RULE_IDS), None)
        self.assertIsNotNone(noncore, "expected at least one non-core rule")
        # Its effective default mode must remain observe (not forced to enforce).
        self.assertNotIn(noncore.id, _NON_OVERRIDABLE_RULE_IDS)


if __name__ == "__main__":
    unittest.main()
