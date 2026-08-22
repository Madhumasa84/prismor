"""Which surfaces govern which agent.

The logic worth testing is the three-way distinction: governed, ungoverned,
and no-surface-exists. Collapsing the last two is the bug this module fixed.
"""
from pathlib import Path

from prismor.runtime import surfaces


def _fake(monkeypatch, cov, gov, mirrored=()):
    monkeypatch.setattr("prismor.runtime.hooks.coverage", lambda ws: cov)
    monkeypatch.setattr(
        "prismor.runtime.integrations.registry.governance",
        lambda a, path=None: gov[a])
    monkeypatch.setattr(surfaces, "_mirror_agents", lambda ws: set(mirrored))


OFF = {"project": False, "global": False}
ON = {"project": False, "global": True}
HOOKABLE = {"hooks": True, "mirror": "verified", "recommended": "hooks"}
MIRROR_ONLY = {"hooks": False, "mirror": "verified", "recommended": "mirror"}
NEITHER = {"hooks": False, "mirror": "unsupported", "recommended": "none"}


def test_hooked_agent_is_governed(monkeypatch, tmp_path):
    _fake(monkeypatch, {"claude": ON}, {"claude": HOOKABLE})
    assert surfaces.resolve(tmp_path)["claude"]["active"] == ["hook"]
    assert surfaces.ungoverned(tmp_path) == []


def test_mirror_governed_agent_is_not_ungoverned(monkeypatch, tmp_path):
    """The bug: an agent with no hook protocol, governed by the mirror, used to
    report as a coverage gap because 'governed' meant 'hooked'."""
    _fake(monkeypatch, {"opencode": OFF}, {"opencode": MIRROR_ONLY},
          mirrored=["opencode"])
    assert surfaces.resolve(tmp_path)["opencode"]["active"] == ["mirror"]
    assert surfaces.ungoverned(tmp_path) == []


def test_agent_with_no_surface_is_not_a_coverage_gap(monkeypatch, tmp_path):
    """Warp/Trae have no interception point at all. Listing them as gaps makes
    the count unactionable — there is nothing to install."""
    _fake(monkeypatch, {"warp": OFF}, {"warp": NEITHER})
    s = surfaces.resolve(tmp_path)["warp"]
    assert s["possible"] == [] and s["active"] == []
    assert surfaces.ungoverned(tmp_path) == []


def test_real_gap_is_still_reported(monkeypatch, tmp_path):
    _fake(monkeypatch, {"claude": OFF}, {"claude": HOOKABLE})
    assert surfaces.ungoverned(tmp_path) == ["claude"]


def test_both_surfaces_on(monkeypatch, tmp_path):
    _fake(monkeypatch, {"claude": ON}, {"claude": HOOKABLE}, mirrored=["claude"])
    assert surfaces.resolve(tmp_path)["claude"]["active"] == ["hook", "mirror"]


def test_self_heal_only_targets_hookable_agents(monkeypatch, tmp_path):
    """ensure_global_coverage installs a HOOK, so a mirror-only gap must not
    reach it — that call could only ever fail."""
    from prismor.runtime import hooks

    _fake(monkeypatch, {"opencode": OFF}, {"opencode": MIRROR_ONLY})
    assert surfaces.ungoverned(tmp_path) == ["opencode"]   # a real gap...
    tried = []
    monkeypatch.setattr(hooks, "install_hooks",
                        lambda **kw: tried.append(kw["agent"]))
    hooks.ensure_global_coverage(repo_root=tmp_path, workspace=tmp_path)
    assert tried == []                                      # ...but not a hookable one
