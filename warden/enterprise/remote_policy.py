"""Remote (org-managed) policy distribution for enterprise control.

When a Warden install is enrolled (see :mod:`warden.identity`), an org admin
can manage policy centrally in prismor-web. This module fetches that policy,
verifies its signature against the bundled trust root (``keys/public.pub`` —
the same Ed25519 key used for the advisory feed), and caches it locally so the
:class:`~warden.policy_engine.PolicyEngine` can merge it as an authoritative
overlay.

Security properties:

* **Signed, fail-closed.** A remote policy is only ever applied if its detached
  signature verifies against the bundled public key. An unsigned, tampered, or
  unverifiable policy is *ignored* — the engine falls back to local policy. A
  compromised control plane cannot inject rules.
* **Tighten-only floor.** The engine enforces ``_NON_OVERRIDABLE_RULE_IDS`` for
  the remote overlay too, so even a valid remote policy can never disable the
  destructive-command / secret-exfiltration protections or turn Warden off.
* **Offline-safe.** If the control plane is unreachable, the last verified
  cached policy keeps applying. Loss of connectivity never weakens protection.

Verification reuses the repo's existing ``openssl`` mechanism (see
``scripts/verify_feed.sh``) rather than adding a crypto dependency — the only
hard dependency stays ``pyyaml``.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from warden.enterprise import identity as _identity


def _public_key_path() -> Path:
    """Bundled Ed25519 trust root (same key that signs the advisory feed).

    Resolved via warden.paths so it works in a git checkout *and* an installed
    wheel (where the key lives at ``warden/data/keys/public.pub``). Resolved at
    call time, not import, so $PRISMOR_HOME overrides are honored.
    """
    from warden.paths import public_key_path
    return public_key_path()

# Full re-fetch backstop (seconds) for the force/legacy path.
DEFAULT_TTL_SECONDS = 300

# How often the runtime does the cheap version check on the hot path. Bounds
# how stale an enrolled device's policy can be after an admin change. Override
# via $PRISMOR_POLICY_REFRESH_SECONDS (per-org tuning can later come from the
# resolved policy settings).
def _refresh_interval() -> float:
    try:
        v = float(os.environ.get("PRISMOR_POLICY_REFRESH_SECONDS", "30"))
    except ValueError:
        return 30.0
    # Clamp (audit #11): a hand-set env must not pin a stale policy indefinitely
    # (admin enforce changes would never reach the device) nor hammer the
    # control plane. Bound to [5s, 600s].
    return max(5.0, min(v, 600.0))


def _check_marker_path() -> Path:
    return _identity.prismor_home() / "remote-policy.check"


def current_version() -> Optional[int]:
    """The policy version currently cached/applied on this device, or None."""
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        v = meta.get("version")
        return int(v) if v is not None else None
    except (OSError, ValueError, TypeError):
        return None


def current_full_capture() -> Optional[bool]:
    """The capture mode (full vs redacted) of the cached policy, or None."""
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        fc = meta.get("full_capture")
        return bool(fc) if fc is not None else None
    except (OSError, ValueError, TypeError):
        return None


def current_profile_id() -> Optional[str]:
    """The id of the policy profile currently cached/applied on this device, or
    None. Lets us detect a scope switchover (e.g. org→device) even when the new
    profile happens to share the old one's version number."""
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        pid = meta.get("profile_id")
        return str(pid) if pid else None
    except (OSError, ValueError, TypeError):
        return None


def _last_checked() -> float:
    try:
        return float(_check_marker_path().read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0.0


def _touch_checked() -> None:
    try:
        _identity.prismor_home().mkdir(parents=True, exist_ok=True)
        _check_marker_path().write_text(str(time.time()), encoding="utf-8")
    except OSError:
        pass


def check_and_refresh(interval: Optional[float] = None) -> bool:
    """Hot-path policy freshness check, debounced and synchronous.

    At most once per ``interval`` seconds, makes a *cheap* GET to
    ``/api/policy/version`` (no signing, no YAML) reporting the version this
    device has applied. Only if the server's version differs do we pull the
    full signed policy via :func:`fetch`. Returns True if a new policy was
    pulled. Never raises — best-effort, never blocks the tool call beyond a
    short timeout. No-op when not enrolled.

    Unlike a fire-and-forget background thread, this runs inline and actually
    completes, so a freshly-applied policy is in effect on the *same* tool call
    that detects the change.
    """
    ident = _identity.load_identity()
    if not ident:
        return False
    if _identity.revoked_backoff_active():
        return False  # key was rejected — back off instead of hammering
    iv = _refresh_interval() if interval is None else interval
    if (time.time() - _last_checked()) < iv:
        return False
    _touch_checked()  # debounce regardless of outcome so we don't hammer on errors

    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    cur = current_version()
    url = (
        f"{base}/api/policy/version?device_id={ident.get('device_id')}"
        f"&org_id={ident.get('org_id')}&applied={cur if cur is not None else ''}"
    )
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {ident.get('device_key')}"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        _identity.clear_revoked()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            _identity.mark_revoked(f"policy version check rejected ({exc.code})")
            sys.stderr.write(
                "[warden] control plane rejected this device's key "
                f"({exc.code}) — keeping last good policy. Re-enroll with: prismor enroll <token>\n"
            )
        return False
    except (urllib.error.URLError, ValueError, OSError):
        return False

    latest = body.get("version")
    version_changed = latest is not None and latest != cur
    # A different profile can become effective without bumping the version number
    # (a fresh device/user profile at v1 shadowing an org profile at v1). Compare
    # the effective profile id too so the scope switchover propagates immediately.
    latest_profile = body.get("profileId")
    profile_changed = (
        latest_profile is not None
        and str(latest_profile) != str(current_profile_id() or "")
    )
    # A full-capture flip doesn't bump the profile version, so compare it
    # separately — otherwise the developer-facing capture notice (and the
    # actual change in what leaves the machine) would lag until the next
    # version bump or TTL.
    latest_capture = body.get("fullCapture")
    capture_changed = (
        latest_capture is not None
        and bool(latest_capture) != bool(current_full_capture())
    )
    # The org's claimed-repo patterns also live in the resolved policy, not the
    # version — so compare their signature too, else a managed-repo change
    # (which repos are governed) would lag until the next version bump.
    latest_repos_sig = body.get("managedReposSig")
    repos_changed = (
        latest_repos_sig is not None
        and str(latest_repos_sig) != str(_current_managed_repos_sig())
    )
    if version_changed or profile_changed or capture_changed or repos_changed:
        return fetch(force=True)
    return False


def _current_managed_repos_sig() -> str:
    """Signature of the cached policy's repo-scoping config — managed_repo_patterns
    AND granted exemptions (id + expiry + overlay_sig) — matching the server's
    managedReposSig so the device re-pulls when either changes. Empty when there
    is no scoping config."""
    try:
        pol = verify_and_load()
        settings = (pol or {}).get("settings") or {}
        pats = sorted(str(p) for p in (settings.get("managed_repo_patterns") or []) if p)
        exemptions = settings.get("repo_exemptions") or []
        ex_parts = sorted(
            f"{ex.get('id')}:{ex.get('expires') or ''}:{ex.get('overlay_sig') or ''}"
            for ex in exemptions if isinstance(ex, dict) and ex.get("id")
        )
        if not pats and not ex_parts:
            return ""
        import hashlib
        sig_input = "\n".join([*pats, "|", *ex_parts])
        return hashlib.sha256(sig_input.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def cached_policy_path() -> Path:
    return _identity.prismor_home() / "remote-policy.yaml"


def _cached_sig_path() -> Path:
    return _identity.prismor_home() / "remote-policy.yaml.sig"


def _meta_path() -> Path:
    return _identity.prismor_home() / "remote-policy.meta.json"


def _verify_signature(payload: bytes, sig_b64: str) -> bool:
    """Verify a detached Ed25519 signature over ``payload`` using openssl and the
    bundled public key. Returns False on any error (fail-closed)."""
    pub_key = _public_key_path()
    if not pub_key.exists() or not sig_b64:
        return False
    try:
        sig_raw = base64.b64decode(sig_b64)
    except Exception:
        return False

    import tempfile
    payload_f = sig_f = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as pf:
            pf.write(payload)
            payload_f = pf.name
        with tempfile.NamedTemporaryFile(delete=False) as sf:
            sf.write(sig_raw)
            sig_f = sf.name
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(pub_key),
                "-rawin", "-in", payload_f,
                "-sigfile", sig_f,
            ],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        for f in (payload_f, sig_f):
            if f:
                try:
                    os.unlink(f)
                except OSError:
                    pass


def verify_and_load() -> Optional[Dict[str, Any]]:
    """Load and verify the cached remote policy. Returns the parsed policy dict
    (with a ``_remote_meta`` key) or None if absent / unverifiable.

    Called by the PolicyEngine on every load — must be cheap and never raise.
    """
    policy_path = cached_policy_path()
    sig_path = _cached_sig_path()
    if not policy_path.exists() or not sig_path.exists():
        return None
    try:
        payload = policy_path.read_bytes()
        sig_b64 = sig_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    if not _verify_signature(payload, sig_b64):
        sys.stderr.write("[warden] remote policy signature INVALID — ignoring\n")
        return None

    try:
        import yaml
        parsed = yaml.safe_load(payload.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None

    meta = {}
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    parsed["_remote_meta"] = meta
    return parsed


def _cache_is_fresh(ttl: float) -> bool:
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        return (time.time() - float(meta.get("fetched_at", 0))) < ttl
    except (OSError, ValueError):
        return False


def fetch(ttl: float = DEFAULT_TTL_SECONDS, force: bool = False) -> bool:
    """Refresh the cached remote policy from the control plane if stale.

    Best-effort and non-blocking semantics: returns True if a fresh, verified
    policy was written; False otherwise (not enrolled, fresh cache, network
    error, or signature failure). Never raises.
    """
    ident = _identity.load_identity()
    if not ident:
        return False
    if _identity.revoked_backoff_active():
        return False  # key was rejected — back off instead of hammering
    if not force and _cache_is_fresh(ttl):
        return False

    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = (
        f"{base}/api/policy/resolve"
        f"?device_id={ident.get('device_id')}&org_id={ident.get('org_id')}"
    )
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {ident.get('device_key')}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        _identity.clear_revoked()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            _identity.mark_revoked(f"policy fetch rejected ({exc.code})")
            sys.stderr.write(
                "[warden] control plane rejected this device's key "
                f"({exc.code}) — keeping last good policy. Re-enroll with: prismor enroll <token>\n"
            )
        else:
            sys.stderr.write(f"[warden] remote policy fetch failed: {exc}\n")
        return False
    except (urllib.error.URLError, ValueError, OSError) as exc:
        sys.stderr.write(f"[warden] remote policy fetch failed: {exc}\n")
        return False

    policy_yaml = body.get("yaml")
    signature = body.get("signature")
    if not policy_yaml or not signature:
        return False
    if not _verify_signature(policy_yaml.encode("utf-8"), signature):
        sys.stderr.write("[warden] fetched remote policy failed verification — discarding\n")
        return False

    # Developer-facing transparency: detect the org flipping capture mode.
    # The resolved policy carries the org's full_capture decision in the
    # forced prismor output entry; surface a notice the moment it changes so
    # a developer always knows when raw detail starts (or stops) leaving
    # their machine.
    full_capture = _extract_full_capture(policy_yaml)
    prev_meta: Dict[str, Any] = {}
    try:
        prev_meta = json.loads(_meta_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    prev_capture = prev_meta.get("full_capture")
    if prev_capture is not None and bool(prev_capture) != full_capture:
        if full_capture:
            sys.stderr.write(
                "[warden] NOTICE: your org admin enabled FULL telemetry capture — "
                "flagged events now include scrubbed content (not just metadata). "
                "Check `prismor enroll-status` for details.\n"
            )
        else:
            sys.stderr.write(
                "[warden] NOTICE: your org switched telemetry back to redacted-only "
                "(metadata + hashes; no content leaves this machine).\n"
            )

    home = _identity.prismor_home()
    home.mkdir(parents=True, exist_ok=True)
    cached_policy_path().write_text(policy_yaml, encoding="utf-8")
    _cached_sig_path().write_text(signature, encoding="utf-8")
    _meta_path().write_text(json.dumps({
        "fetched_at": time.time(),
        "version": body.get("version"),
        "profile_id": body.get("profile_id"),
        "scope": body.get("scope"),
        "full_capture": full_capture,
    }), encoding="utf-8")
    return True


def _extract_full_capture(policy_yaml: str) -> bool:
    """Read the org's full_capture decision from the resolved policy's forced
    prismor output entry. False on any parse problem (the privacy-safe default)."""
    try:
        import yaml
        parsed = yaml.safe_load(policy_yaml)
        outputs = (((parsed or {}).get("settings") or {}).get("outputs")) or []
        for out in outputs:
            if isinstance(out, dict) and str(out.get("type", "")).lower() == "prismor":
                return bool(out.get("full_capture", False))
    except Exception:
        pass
    return False
