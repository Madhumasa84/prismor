"""Tests for enterprise-link hardening:

  * Offline telemetry spool — bounded, at-least-once drain semantics.
  * Revocation marker — 401/403 from the control plane pauses uploads/pulls
    and surfaces in enroll-status; re-enrollment clears it.
  * block_categories clamp — an override layer cannot drop core categories
    from blocking.
"""
from __future__ import annotations

import json
import time

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    yield


# ── telemetry spool ─────────────────────────────────────────────────────


def test_spool_append_and_drain_fifo():
    from prismor.runtime.enterprise import telemetry_spool as spool

    spool.append([{"n": 1}, {"n": 2}])
    spool.append([{"n": 3}])
    assert spool.pending_count() == 3

    taken = spool.drain(limit=2)
    assert [r["n"] for r in taken] == [1, 2]
    assert spool.pending_count() == 1

    rest = spool.drain(limit=10)
    assert [r["n"] for r in rest] == [3]
    assert spool.pending_count() == 0
    assert spool.drain(limit=5) == []


def test_spool_is_bounded_drops_oldest():
    from prismor.runtime.enterprise import telemetry_spool as spool

    spool.append([{"n": i} for i in range(spool.SPOOL_MAX_RECORDS + 50)])
    assert spool.pending_count() == spool.SPOOL_MAX_RECORDS
    first = spool.drain(limit=1)[0]
    assert first["n"] == 50  # oldest 50 were dropped


def test_spool_survives_corrupt_lines(tmp_path):
    from prismor.runtime.enterprise import telemetry_spool as spool

    spool.append([{"n": 1}])
    with open(spool.spool_path(), "a", encoding="utf-8") as f:
        f.write("not json\n")
    spool.append([{"n": 2}])
    assert [r["n"] for r in spool.drain(limit=10)] == [1, 2]


# ── revocation marker ───────────────────────────────────────────────────


def test_revocation_marker_roundtrip():
    from prismor.runtime.enterprise import identity

    assert identity.revoked_info() is None
    assert not identity.revoked_backoff_active()

    identity.mark_revoked("telemetry upload rejected (401)")
    info = identity.revoked_info()
    assert info and "401" in info["reason"]
    assert identity.revoked_backoff_active()

    identity.clear_revoked()
    assert identity.revoked_info() is None


def test_revocation_backoff_expires(monkeypatch):
    from prismor.runtime.enterprise import identity

    identity.mark_revoked("rejected")
    # Age the marker past the retry window.
    marker = identity._revoked_marker_path()
    data = json.loads(marker.read_text(encoding="utf-8"))
    data["at"] = time.time() - identity.REVOKED_RETRY_SECONDS - 1
    marker.write_text(json.dumps(data), encoding="utf-8")
    assert not identity.revoked_backoff_active()


def test_policy_check_skipped_while_revoked(monkeypatch):
    from prismor.runtime.enterprise import identity, remote_policy

    identity.save_identity({
        "device_id": "d1", "org_id": "o1", "user_id": "u1",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })
    identity.mark_revoked("rejected")

    def _boom(*a, **k):  # any network call would be a bug
        raise AssertionError("network call attempted while revoked")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    assert remote_policy.check_and_refresh(interval=0) is False
    assert remote_policy.fetch(force=True) is False


# ── block_categories clamp ──────────────────────────────────────────────


def test_override_cannot_drop_core_block_categories(tmp_path):
    from prismor.runtime.policy_engine import PolicyEngine, _CORE_BLOCK_CATEGORIES

    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(
        "settings:\n  block_categories: [prompt_injection]\n",
        encoding="utf-8",
    )
    engine = PolicyEngine(workspace=ws)
    assert "prompt_injection" in engine.block_categories  # tightening kept
    for cat in _CORE_BLOCK_CATEGORIES:
        assert cat in engine.block_categories  # core restored
