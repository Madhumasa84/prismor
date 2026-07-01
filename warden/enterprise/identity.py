"""Device identity for Prismor Warden — enterprise control plane link.

A Warden install can be *enrolled* against an organization in the Prismor
control plane (prismor-web). Enrollment exchanges a short-lived enrollment
token for a long-lived, revocable **device key** and records the
``{org_id, user_id, device_id}`` this machine reports as.

The identity lives at ``$PRISMOR_HOME/identity.json`` (default
``~/.prismor/identity.json``) with ``0600`` permissions — it contains the
device key, which is a bearer credential for telemetry upload and policy
pull. It is intentionally separate from the scan API key and from cloaked
secrets so that revoking a lost laptop never breaks CI scans.

This module is import-safe with no third-party dependencies: enrollment and
control-plane I/O use ``urllib`` from the stdlib, mirroring ``sinks.py``.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional

# Default control-plane base URL. Overridable via $PRISMOR_API_BASE so
# self-hosted / staging deployments can repoint without a rebuild.
DEFAULT_API_BASE = "https://prismor.dev"

_SCHEMA = "warden.identity.v1"


def prismor_home() -> Path:
    """Return the Prismor home dir, honoring $PRISMOR_HOME (default ~/.prismor)."""
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor")))


def identity_path() -> Path:
    return prismor_home() / "identity.json"


def api_base() -> str:
    return os.environ.get("PRISMOR_API_BASE", DEFAULT_API_BASE).rstrip("/")


def load_identity() -> Optional[Dict[str, Any]]:
    """Load the enrolled device identity, or None if this machine is not enrolled.

    Returns a dict with at least ``device_id``, ``org_id``, ``user_id`` and
    ``device_key`` when enrolled. Never raises — a malformed or missing file
    reads as "not enrolled" so the runtime degrades to local-only mode.
    """
    path = identity_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("device_key"):
        return None
    return data


def is_enrolled() -> bool:
    return load_identity() is not None


def save_identity(identity: Dict[str, Any]) -> Path:
    """Persist the device identity with 0600 perms. Returns the path written."""
    home = prismor_home()
    home.mkdir(parents=True, exist_ok=True)
    try:
        home.chmod(0o700)
    except (PermissionError, OSError):
        pass
    record = {"schema": _SCHEMA, **identity}
    path = identity_path()
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except (PermissionError, OSError):
        pass
    return path


def clear_identity() -> bool:
    """Remove the device identity (un-enroll). Returns True if one existed."""
    path = identity_path()
    if path.exists():
        path.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Revocation marker
#
# When the control plane answers 401/403 to a device-key call, the key has
# been revoked (or the device deleted). We record that locally so the runtime
# (a) stops hammering the control plane with doomed requests, and (b) can
# surface "this device was revoked" in `prismor enroll-status`. Local
# protection is unaffected — the last good policy keeps applying.

# After this many seconds we try the control plane again, in case the device
# was un-revoked server-side or the 401 was a transient misconfiguration.
REVOKED_RETRY_SECONDS = 3600.0


def _revoked_marker_path() -> Path:
    return prismor_home() / "device-revoked.json"


def mark_revoked(reason: str = "") -> None:
    """Record that the control plane rejected this device's key. Never raises."""
    import time
    try:
        prismor_home().mkdir(parents=True, exist_ok=True)
        _revoked_marker_path().write_text(
            json.dumps({"at": time.time(), "reason": reason[:300]}), encoding="utf-8"
        )
    except OSError:
        pass


def revoked_info() -> Optional[Dict[str, Any]]:
    """The revocation marker ({at, reason}) if this device has been rejected
    by the control plane, else None. Never raises."""
    try:
        data = json.loads(_revoked_marker_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def revoked_backoff_active() -> bool:
    """True while we should skip control-plane calls after a revocation."""
    import time
    info = revoked_info()
    if not info:
        return False
    try:
        return (time.time() - float(info.get("at", 0))) < REVOKED_RETRY_SECONDS
    except (TypeError, ValueError):
        return False


def clear_revoked() -> None:
    """Drop the revocation marker (successful auth or fresh enrollment)."""
    try:
        _revoked_marker_path().unlink()
    except OSError:
        pass


def _hostname_label() -> str:
    import socket
    try:
        return socket.gethostname()
    except OSError:
        return "unknown-host"


def enroll(token: str, base: Optional[str] = None, label: Optional[str] = None,
           timeout: float = 20.0) -> Dict[str, Any]:
    """Exchange a one-time enrollment token for a device identity and persist it.

    Calls ``POST {base}/api/devices/enroll`` with the enrollment token and a
    human-readable label (defaults to the hostname). On success the response
    carries ``device_id``, ``org_id``, ``user_id`` and ``device_key``; we store
    them and return the saved record. Raises RuntimeError with a readable
    message on any failure (network, non-2xx, malformed response).
    """
    import urllib.request
    import urllib.error
    from warden import __version__ as _ver

    base = (base or api_base()).rstrip("/")
    label = label or _hostname_label()
    payload = json.dumps({
        "token": token,
        "label": label,
        "platform": _platform(),
        "warden_version": _ver,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/api/devices/enroll",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200] if exc.fp else ""
        raise RuntimeError(f"enrollment rejected ({exc.code}): {detail or exc.reason}")
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise RuntimeError(f"enrollment failed: {exc}")

    for field in ("device_id", "org_id", "user_id", "device_key"):
        if not body.get(field):
            raise RuntimeError(f"enrollment response missing {field!r}")

    identity = {
        "device_id": body["device_id"],
        "org_id": body["org_id"],
        "user_id": body["user_id"],
        "device_key": body["device_key"],
        "org_name": body.get("org_name"),
        "label": label,
        "api_base": base,
    }
    save_identity(identity)
    clear_revoked()  # a fresh enrollment supersedes any prior revocation
    return identity


def _platform() -> str:
    import platform
    return platform.system().lower() or "unknown"
