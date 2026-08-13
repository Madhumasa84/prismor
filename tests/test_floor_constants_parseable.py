"""The floor frozensets must survive being parsed out of the source text.

prismor-web does not import this module — it cannot, it is a TypeScript app —
so it regenerates its copy of the security floor by reading the frozenset
literals out of policy_engine.py with a regex
(scripts/generate-default-policy-rules.js) and fails CI on drift.

That makes the *text* of these literals a cross-repo contract, which is an easy
thing to break without noticing: an apostrophe in a comment inside the literal
already did it once. The regex took `# Prismor's self-protection rules` as the
end of one quoted entry and the start of another, so the generated floor gained
two nonsense entries and silently lost `agent-config-tampering` and
`prismor-self-edit` — leaving the console willing to accept an org policy
disabling rules the runtime refuses to disable.

This mirrors that parse and checks it agrees with the real objects.
"""
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import policy_engine

_SOURCE = Path(policy_engine.__file__).read_text(encoding="utf-8")

# Byte-for-byte the generator's own regexes. If prismor-web changes how it
# parses, this should change with it.
_BLOCK_RE = r"^{name}\s*=\s*frozenset\(\{{([\s\S]*?)\}}\)"
_ENTRY_RE = re.compile(r"""["']([^"']+)["']""")


def _parse_like_the_generator(name: str):
    match = re.search(_BLOCK_RE.format(name=name), _SOURCE, re.MULTILINE)
    assert match, f"{name} literal not found"
    return [m.group(1) for m in _ENTRY_RE.finditer(match.group(1))]


class TestFloorConstantsAreParseable(unittest.TestCase):
    def test_non_overridable_rule_ids_parse_to_the_real_set(self):
        self.assertEqual(
            sorted(_parse_like_the_generator("_NON_OVERRIDABLE_RULE_IDS")),
            sorted(policy_engine._NON_OVERRIDABLE_RULE_IDS),
        )

    def test_core_block_categories_parse_to_the_real_set(self):
        self.assertEqual(
            sorted(_parse_like_the_generator("_CORE_BLOCK_CATEGORIES")),
            sorted(policy_engine._CORE_BLOCK_CATEGORIES),
        )

    def test_self_protection_rule_ids_parse_to_the_real_set(self):
        self.assertEqual(
            sorted(_parse_like_the_generator("_SELF_PROTECTION_RULE_IDS")),
            sorted(policy_engine._SELF_PROTECTION_RULE_IDS),
        )

    def test_every_parsed_entry_looks_like_an_identifier(self):
        # The failure mode is prose leaking in, which never looks like a rule id
        # or a category. Catches it even if the sets above happen to line up.
        for name in (
            "_NON_OVERRIDABLE_RULE_IDS",
            "_CORE_BLOCK_CATEGORIES",
            "_SELF_PROTECTION_RULE_IDS",
        ):
            for entry in _parse_like_the_generator(name):
                with self.subTest(literal=name, entry=entry[:40]):
                    self.assertRegex(entry, r"^[a-z0-9]+([_-][a-z0-9]+)*$")

    def test_self_protection_is_a_subset_of_the_non_overridable_floor(self):
        # Always-enforcing only means something if an overlay also cannot
        # disable the rule outright.
        self.assertTrue(
            policy_engine._SELF_PROTECTION_RULE_IDS
            <= policy_engine._NON_OVERRIDABLE_RULE_IDS
        )


if __name__ == "__main__":
    unittest.main()
