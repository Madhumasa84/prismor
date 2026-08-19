"""Policy YAML loading: cached by content, but never shared or stale.

Every PolicyEngine construction parses default_policy.yaml, and one mirrored
tool call builds four engines (pre + post evaluation, each of which builds a
second engine inside the data-boundary classifier). At 114 ms per parse on a
2-core box that was 456 ms of the 670 ms a mirrored call cost. The cache has to
buy that back without ever handing two callers the same mutable structure, and
without serving an edited policy from cache.
"""
from pathlib import Path

import pytest

from prismor.runtime import policy_engine as pe


@pytest.fixture(autouse=True)
def _clear_cache():
    pe._YAML_CACHE.clear()
    yield
    pe._YAML_CACHE.clear()


DEFAULT = Path(pe.__file__).with_name("default_policy.yaml")


def test_repeat_loads_are_equal_but_independent():
    a = pe._load_yaml(DEFAULT)
    b = pe._load_yaml(DEFAULT)
    assert a == b and a is not b
    assert a["rules"] is not b["rules"], "a shared list would let one engine edit another's rules"


def test_a_mutation_never_reaches_the_cache():
    """_load and _apply_override mutate the structure they are handed, so a
    cached parse that was returned by reference would accumulate every
    project override ever applied."""
    first = pe._load_yaml(DEFAULT)
    original = first["rules"][0]["id"]
    first["rules"][0]["id"] = "MUTATED"
    first["rules"].append({"id": "injected"})
    second = pe._load_yaml(DEFAULT)
    assert second["rules"][0]["id"] == original
    assert not any(r.get("id") == "injected" for r in second["rules"])


def test_edited_file_is_never_served_from_cache(tmp_path):
    """Keyed on content, so an edit cannot be missed — no mtime granularity to
    lose a fast rewrite to."""
    p = tmp_path / "policy.yaml"
    p.write_text("version: '1.0'\nrules: []\n")
    assert pe._load_yaml(p)["rules"] == []
    p.write_text("version: '1.0'\nrules:\n  - id: added\n")
    assert pe._load_yaml(p)["rules"] == [{"id": "added"}]
    # ...and reverting hits the original cache entry, still independent.
    p.write_text("version: '1.0'\nrules: []\n")
    assert pe._load_yaml(p)["rules"] == []


def test_missing_file_is_none_and_not_cached(tmp_path):
    assert pe._load_yaml(tmp_path / "nope.yaml") is None
    assert not pe._YAML_CACHE


def test_cache_is_bounded(tmp_path):
    for i in range(pe._YAML_CACHE_MAX + 4):
        p = tmp_path / f"p{i}.yaml"
        p.write_text(f"version: '1.0'\nrules:\n  - id: r{i}\n")
        pe._load_yaml(p)
    assert len(pe._YAML_CACHE) <= pe._YAML_CACHE_MAX


def test_engine_still_reflects_a_policy_edit(tmp_path):
    """The user-visible contract: edit .prismor/policy.yaml, next evaluation
    sees it. Caching must not put a stale rule set behind that."""
    (tmp_path / ".prismor").mkdir()
    pol = tmp_path / ".prismor" / "policy.yaml"
    pol.write_text("version: '1.0'\nsettings:\n  default_mode: observe\nrules: []\n")
    assert pe.PolicyEngine(workspace=tmp_path).default_mode == "observe"
    pol.write_text("version: '1.0'\nsettings:\n  default_mode: enforce\nrules: []\n")
    assert pe.PolicyEngine(workspace=tmp_path).default_mode == "enforce"
