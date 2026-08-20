"""Regression tests for PrismorSec/prismor#289.

Three separate defects surfaced by one scan of a real repository:

1. Reachability only followed edges declared by *flat* lockfile entries,
   so a hoisted package required only by a nested
   ``node_modules/a/node_modules/b`` record looked unreachable and was
   reported as HIGH "possible lockfile injection".
2. The manifest walkers disagreed: ``find_manifests`` globbed the
   workspace root only while the lockfile checks globbed ``**/``, so the
   same scan reported one manifest and five copies' worth of findings —
   four of them from ``.claude/worktrees/`` checkouts.
3. ``scan`` reads the host's ``~/.claude`` alongside the repo's, with
   nothing in the output separating machine findings from repo findings.
"""
from __future__ import annotations

import json
from pathlib import Path

from prismor.runtime.deps import (
    _reachable_lockfile_names,
    check_lockfile_integrity,
    find_manifests,
)


def _registry_entry(version: str, dependencies: dict | None = None) -> dict:
    entry = {
        "version": version,
        "resolved": f"https://registry.npmjs.org/x/-/x-{version}.tgz",
        "integrity": "sha512-fake==",
    }
    if dependencies is not None:
        entry["dependencies"] = dependencies
    return entry


def _write_project(ws: Path, dependencies: dict, packages: dict) -> None:
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "package.json").write_text(json.dumps({
        "name": "fixture", "version": "0.0.0", "dependencies": dependencies,
    }))
    (ws / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": packages,
    }))


# ── 1. reachability through nested entries ──────────────────────────────

def test_dep_of_a_nested_entry_is_reachable(tmp_path: Path) -> None:
    """The reported shape: jackspeak is required only by the *nested*
    node_modules/rimraf/node_modules/glob, but is itself hoisted flat."""
    _write_project(tmp_path, {"rimraf": "3.0.2"}, {
        "": {"name": "fixture", "dependencies": {"rimraf": "3.0.2"}},
        "node_modules/rimraf": _registry_entry("3.0.2", {"glob": "^7.1.3"}),
        # rimraf pins an older glob, so npm nests it instead of hoisting.
        "node_modules/rimraf/node_modules/glob": _registry_entry(
            "7.2.3", {"jackspeak": "^2.0.0"}
        ),
        "node_modules/jackspeak": _registry_entry("2.3.6", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    assert [f for f in findings if f["issue"] == "lockfile-injection"] == []


def test_optional_and_peer_edges_count_as_reachability(tmp_path: Path) -> None:
    _write_project(tmp_path, {"a": "1.0.0"}, {
        "": {"name": "fixture", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": {
            **_registry_entry("1.0.0", {}),
            "optionalDependencies": {"fsevents": "2.3.3"},
            "peerDependencies": {"react": "18.2.0"},
        },
        "node_modules/fsevents": _registry_entry("2.3.3", {}),
        "node_modules/react": _registry_entry("18.2.0", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    assert [f for f in findings if f["issue"] == "lockfile-injection"] == []


def test_workspace_member_deps_seed_reachability(tmp_path: Path) -> None:
    """In a monorepo the root package.json may declare nothing; the deps
    live in workspace members and are installed into the root."""
    _write_project(tmp_path, {"a": "1.0.0"}, {
        "": {"name": "fixture", "workspaces": ["packages/web"]},
        "packages/web": {"name": "web", "dependencies": {"lodash": "4.17.21"}},
        "node_modules/a": _registry_entry("1.0.0", {}),
        "node_modules/lodash": _registry_entry("4.17.21", {}),
        "node_modules/web": {"resolved": "packages/web", "link": True},
    })
    findings = check_lockfile_integrity(tmp_path)
    assert [f for f in findings if f["issue"] == "lockfile-injection"] == []


def test_injection_still_flagged_with_nested_edges_present(tmp_path: Path) -> None:
    """Following nested edges must not swallow the genuine signal."""
    _write_project(tmp_path, {"rimraf": "3.0.2"}, {
        "": {"name": "fixture", "dependencies": {"rimraf": "3.0.2"}},
        "node_modules/rimraf": _registry_entry("3.0.2", {"glob": "^7.1.3"}),
        "node_modules/rimraf/node_modules/glob": _registry_entry("7.2.3", {}),
        "node_modules/evil-pkg": _registry_entry("6.6.6", {}),
    })
    findings = check_lockfile_integrity(tmp_path)
    injection = [f for f in findings if f["issue"] == "lockfile-injection"]
    assert len(injection) == 1
    assert "evil-pkg" in injection[0]["message"]


def test_reachable_names_follows_nested_entries_directly() -> None:
    packages = {
        "node_modules/rimraf": {"dependencies": {"glob": "^7.1.3"}},
        "node_modules/rimraf/node_modules/glob": {"dependencies": {"jackspeak": "^2"}},
        "node_modules/jackspeak": {"dependencies": {}},
        "node_modules/orphan": {"dependencies": {}},
    }
    reachable = _reachable_lockfile_names({"rimraf"}, packages)
    assert reachable == {"rimraf", "glob", "jackspeak"}
    assert "orphan" not in reachable


# ── 2. one consistent workspace walk ────────────────────────────────────

def test_nested_checkouts_and_agent_dirs_are_not_scanned(tmp_path: Path) -> None:
    """A worktree under .claude/ is a different checkout; its copy of the
    same lockfile must not multiply the findings."""
    injected = {
        "": {"name": "fixture", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": _registry_entry("1.0.0", {}),
        "node_modules/evil-pkg": _registry_entry("6.6.6", {}),
    }
    _write_project(tmp_path, {"a": "1.0.0"}, injected)
    for copy in (
        tmp_path / ".claude" / "worktrees" / "wt1",
        tmp_path / "node_modules" / "a",
        tmp_path / "dist",
    ):
        _write_project(copy, {"a": "1.0.0"}, injected)

    # A real linked worktree elsewhere in the tree (its own .git file).
    worktree = tmp_path / "wt2"
    _write_project(worktree, {"a": "1.0.0"}, injected)
    (worktree / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt2\n")

    findings = check_lockfile_integrity(tmp_path)
    injection = [f for f in findings if f["issue"] == "lockfile-injection"]
    assert len(injection) == 1, [f["lockfile"] for f in injection]
    assert injection[0]["lockfile"] == str(tmp_path / "package-lock.json")


def test_find_manifests_matches_the_lockfile_walk(tmp_path: Path) -> None:
    """`manifests` used to report 1 while the integrity check reported
    findings from five package.json copies."""
    _write_project(tmp_path, {"a": "1.0.0"}, {
        "": {"name": "fixture", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": _registry_entry("1.0.0", {}),
    })
    _write_project(tmp_path / "packages" / "web", {"a": "1.0.0"}, {
        "": {"name": "web", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": _registry_entry("1.0.0", {}),
    })
    _write_project(tmp_path / ".claude" / "worktrees" / "wt1", {"a": "1.0.0"}, {})

    manifests = {Path(m["path"]) for m in find_manifests(tmp_path)}
    assert manifests == {
        tmp_path / "package.json",
        tmp_path / "packages" / "web" / "package.json",
    }


def test_find_manifests_still_classifies_wildcard_patterns(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.txt").write_text("requests==2.31.0\n")
    (tmp_path / "go.mod").write_text("module example.com/x\n")
    found = {Path(m["path"]).name: m["ecosystem"] for m in find_manifests(tmp_path)}
    assert found == {"requirements-dev.txt": "pip", "go.mod": "go"}


# ── 3. project vs user scope in `scan` ──────────────────────────────────

def test_config_scope_separates_host_from_repo(tmp_path: Path) -> None:
    from prismor.runtime.scanner import config_scope

    workspace = tmp_path / "repo"
    (workspace / ".claude").mkdir(parents=True)
    project_cfg = workspace / ".claude" / "settings.json"
    project_cfg.write_text("{}")
    home_cfg = tmp_path / "home" / ".claude" / "settings.json"
    home_cfg.parent.mkdir(parents=True)
    home_cfg.write_text("{}")

    assert config_scope(project_cfg, workspace) == "project"
    assert config_scope(home_cfg, workspace) == "user"


def test_scan_scope_filter_excludes_user_configs(tmp_path: Path, monkeypatch) -> None:
    from prismor.runtime import scanner

    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text("{}")
    workspace = tmp_path / "repo"
    (workspace / ".claude").mkdir(parents=True)
    (workspace / ".claude" / "settings.json").write_text("{}")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))

    everything = scanner.discover_configs(agent="claude", workspace=workspace)
    assert {c["scope"] for c in everything} == {"project", "user"}

    project_only = scanner.discover_configs(
        agent="claude", workspace=workspace, scope="project"
    )
    assert [c["path"] for c in project_only] == [workspace / ".claude" / "settings.json"]

    user_only = scanner.discover_configs(
        agent="claude", workspace=workspace, scope="user"
    )
    assert [c["path"] for c in user_only] == [home / ".claude" / "settings.json"]
