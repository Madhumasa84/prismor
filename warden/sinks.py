"""Telemetry sinks — forward Warden findings to external systems.

Supported sink types (configured under ``settings.outputs`` in policy.yaml):

  outputs:
    - type: webhook
      url: https://siem.example.com/ingest
      headers: { "X-API-Key": "${SIEM_TOKEN}" }
    - type: syslog
      host: siem.example.com
      port: 514
      facility: local7
    - type: file
      path: ~/.prismor/audit.log
      format: json     # or: cef
    - type: prismor              # first-party control-plane sink
      # No config needed — the device key + endpoint come from the enrolled
      # identity at ~/.prismor/identity.json (see `immunity enroll`). Sends a
      # *redacted* telemetry record by default; full content only when the
      # org's resolved policy sets full_capture: true.

Each sink receives one JSON event per finding. Dispatch is best-effort
and non-blocking — a sink failure logs a warning but never blocks the
user's tool call.

The ``prismor`` sink is special: instead of the generic SIEM event built by
``_build_event``, it forwards the privacy-bounded record from
``warden.telemetry`` so raw commands/secrets never leave the machine unless an
org admin has explicitly opted into full capture.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
    "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
_SEVERITY_TO_SYSLOG = {
    "CRITICAL": 2,  # critical
    "HIGH": 3,      # error
    "MEDIUM": 4,    # warning
    "LOW": 6,       # info
}


def _expand_env(value: Any) -> Any:
    """Substitute ${VAR} references in string values with os.environ."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _build_event(finding: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "prismor-warden",
        "hostname": _hostname(),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "rule_id": finding.get("ruleId"),
        "action": finding.get("action"),
        "title": finding.get("title"),
        "evidence": finding.get("evidence"),
        "session_id": (finding.get("id") or "").split(":", 1)[0] if ":" in (finding.get("id") or "") else None,
        "finding_id": finding.get("id"),
    }
    if extra:
        event.update(extra)
    return event


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _dispatch_webhook(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    import urllib.request
    import urllib.error

    url = cfg.get("url")
    if not url:
        return
    headers = {"Content-Type": "application/json"}
    extra_headers = cfg.get("headers") or {}
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            headers[str(k)] = str(v)
    timeout = float(cfg.get("timeout_seconds", 3))
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read(16)  # drain


def _dispatch_syslog(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    host = cfg.get("host", "127.0.0.1")
    port = int(cfg.get("port", 514))
    facility = _FACILITIES.get(str(cfg.get("facility", "local7")).lower(), 23)
    severity_name = str(event.get("severity", "LOW")).upper()
    severity = _SEVERITY_TO_SYSLOG.get(severity_name, 6)
    priority = (facility * 8) + severity
    tag = cfg.get("tag", "prismor-warden")
    msg = json.dumps(event)
    payload = f"<{priority}>{datetime.now().strftime('%b %d %H:%M:%S')} {_hostname()} {tag}: {msg}"

    transport = str(cfg.get("transport", "udp")).lower()
    if transport == "tcp":
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(payload.encode("utf-8") + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(payload.encode("utf-8"), (host, port))


def _dispatch_file(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    raw_path = cfg.get("path")
    if not raw_path:
        return
    path = Path(os.path.expanduser(str(raw_path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = str(cfg.get("format", "json")).lower()
    if fmt == "cef":
        line = _format_cef(event)
    else:
        line = json.dumps(event)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _format_cef(event: Dict[str, Any]) -> str:
    """Minimal ArcSight CEF formatter — enough for Splunk/QRadar ingest."""
    sev_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}
    severity = sev_map.get(str(event.get("severity", "")).upper(), 3)
    header = (
        "CEF:0|Prismor|Warden|1.1.0|"
        f"{event.get('rule_id','unknown')}|"
        f"{event.get('title','finding')}|"
        f"{severity}"
    )
    extensions = {
        "act": event.get("action", ""),
        "cat": event.get("category", ""),
        "msg": event.get("evidence", ""),
        "dhost": event.get("hostname", ""),
        "rt": event.get("@timestamp", ""),
    }
    ext_str = " ".join(f"{k}={v}" for k, v in extensions.items() if v)
    return f"{header}|{ext_str}"


def _dispatch_prismor(
    cfg: Dict[str, Any],
    findings: List[Dict[str, Any]],
    raw_event: Dict[str, Any],
    extra: Dict[str, Any],
) -> None:
    """First-party control-plane sink: batch-upload redacted telemetry records
    to prismor-web using the enrolled device key.

    No-op (silent) when the machine is not enrolled — the sink can be left on
    in default policy without effect until `immunity enroll` runs.
    """
    import urllib.request
    import urllib.error

    from warden.enterprise import identity as _identity
    from warden.enterprise import telemetry as _telemetry

    ident = _identity.load_identity()
    if not ident:
        return  # not enrolled — nothing to upload
    if _identity.revoked_backoff_active():
        return  # device key was rejected — don't hammer a control plane that said no

    full_capture = bool(cfg.get("full_capture", False))
    scrub_patterns: List[str] = []
    if full_capture:
        try:
            from warden.cloaking.patterns import all_patterns
            scrub_patterns = all_patterns()
        except Exception:
            scrub_patterns = []

    device_extra = {
        **extra,
        "device_id": ident.get("device_id"),
    }
    records = []
    for finding in findings:
        rec = _telemetry.build_record(
            finding,
            raw_event,
            extra=device_extra,
            full_capture=full_capture,
            scrub_patterns=scrub_patterns,
        )
        _telemetry.assert_redacted(rec)  # fail closed if redacted path leaks
        records.append(rec)

    if not records:
        return

    # SECURITY: the prismor sink carries the device-key bearer credential
    # (see upload_telemetry's Authorization header). A local policy.yaml could
    # otherwise set `url:` and redirect that credential to an attacker endpoint,
    # so the destination is PINNED to the enrolled identity's api_base and a
    # local `url` override is ignored for type:prismor.
    if cfg.get("url"):
        sys.stderr.write(
            "[warden] ignoring `url` on the prismor sink — telemetry is pinned to the "
            "enrolled control plane (a local url override cannot redirect the device key)\n"
        )
    upload_telemetry(
        records,
        timeout=float(cfg.get("timeout_seconds", 6)),
    )


def upload_telemetry(
    records: List[Dict[str, Any]],
    timeout: float = 6.0,
    url_base: Optional[str] = None,
) -> None:
    """Shared control-plane uploader for telemetry records (findings AND
    agent_activity heartbeats).

    Drains previously-spooled records (offline periods, slow control plane)
    into the batch — at-least-once delivery without a background daemon. On
    network failure the whole batch is spooled and the error re-raised (callers
    log it best-effort). On 401/403 the device is marked revoked and nothing is
    spooled — uploads stay rejected until re-enrollment.

    Short timeout on the hot path: a slow control plane (cold Neon/RDS) must
    never stall a developer's tool call; records that miss the window land in
    the spool and ride along with the next upload, so nothing is lost.
    """
    import urllib.request
    import urllib.error

    from warden.enterprise import identity as _identity
    from warden.enterprise import telemetry_spool as _spool

    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return

    # Server caps batches at 500 events.
    batch = _spool.drain(limit=max(0, 500 - len(records))) + records
    if not batch:
        return

    base = str(url_base or ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = base if base.endswith("/ingest") else f"{base}/api/telemetry/ingest"
    body = json.dumps({
        "org_id": ident.get("org_id"),
        "device_id": ident.get("device_id"),
        "events": batch,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ident.get('device_key')}",
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(16)  # drain
        _identity.clear_revoked()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            # The control plane rejected our device key: revoked (or deleted).
            # Local protection continues with the last good policy.
            _identity.mark_revoked(f"telemetry upload rejected ({exc.code})")
            sys.stderr.write(
                "[warden] control plane rejected this device's key "
                f"({exc.code}) — telemetry paused. Re-enroll with: immunity enroll <token>\n"
            )
            return
        _spool.append(batch)
        raise
    except (urllib.error.URLError, OSError):
        _spool.append(batch)
        raise


_DISPATCHERS = {
    "webhook": _dispatch_webhook,
    "syslog": _dispatch_syslog,
    "file": _dispatch_file,
}


def dispatch(
    findings: List[Dict[str, Any]],
    sinks: List[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
    raw_event: Optional[Dict[str, Any]] = None,
) -> None:
    """Send each finding to each configured sink. Errors are swallowed with
    a warning on stderr so telemetry never blocks the user.

    The ``prismor`` control-plane sink is batched and privacy-bounded — it
    receives the raw event (to build a redacted record) rather than the generic
    SIEM event the other sinks consume.
    """
    if not findings or not sinks:
        return
    extra = extra or {}

    # First-party control-plane sinks are batched separately.
    prismor_sinks = [s for s in sinks if str((s or {}).get("type", "")).lower() == "prismor"]
    generic_sinks = [s for s in sinks if str((s or {}).get("type", "")).lower() != "prismor"]

    for sink_cfg in prismor_sinks:
        sink = _expand_env(sink_cfg)
        try:
            _dispatch_prismor(sink, findings, raw_event or {}, extra)
        except Exception as exc:
            sys.stderr.write(f"[warden] sink 'prismor' failed: {exc}\n")

    for finding in findings:
        event = _build_event(finding, extra=extra)
        for sink_cfg in generic_sinks:
            sink = _expand_env(sink_cfg)
            kind = str(sink.get("type", "")).lower()
            disp = _DISPATCHERS.get(kind)
            if not disp:
                continue
            try:
                disp(sink, event)
            except Exception as exc:
                sys.stderr.write(f"[warden] sink {kind!r} failed: {exc}\n")
