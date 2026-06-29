"""warden/server.py — local HTTP API server for the Prismor Warden dashboard.

Serves a self-contained web dashboard and session/findings data from all
registered workspace DBs.  No external dependencies beyond the stdlib and
a single CDN link (Chart.js) loaded by the browser.

Usage (via CLI):
    python3 warden/cli.py serve [--port 7070] [--host 127.0.0.1]

Endpoints:
    GET /                  → self-hosted HTML dashboard
    GET /health            → {"status": "ok", "ts": "<iso>"}
    GET /api/stats         → aggregate stats for charts/KPIs
    GET /api/sessions      → paginated sessions  (?page&limit&sort&dir)
    GET /api/findings      → paginated findings  (?page&limit&agent&severity&category&q)
    GET /api/events        → paginated events    (?page&limit&verdict&agent)
    GET /api/supply-chain  → supply chain enforcement stats
    OPTIONS *              → 204 CORS preflight
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse, parse_qs

from warden.store import (
    get_aggregate_stats,
    get_sessions_page,
    get_findings_page,
    get_events_page,
    get_supply_chain_stats,
    get_agents_overview,
)

_DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class WardenRequestHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the immunity dashboard API."""

    # Silence the default per-request access log
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def _send_cors(self) -> None:
        for key, value in _CORS_HEADERS.items():
            self.send_header(key, value)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_path: Path) -> None:
        try:
            body = html_path.read_bytes()
        except FileNotFoundError:
            self._send_json({"error": "dashboard.html not found"}, status=500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query, keep_blank_values=False)

        def qstr(key: str, default: str = "") -> str:
            return qs.get(key, [default])[0]

        def qint(key: str, default: int = 1) -> int:
            try:
                return int(qs.get(key, [default])[0])
            except (ValueError, TypeError):
                return default

        if path in ("", "/dashboard"):
            self._send_html(_DASHBOARD_HTML)
            return

        if path == "/health":
            self._send_json({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})
            return

        if path == "/api/stats":
            try:
                days = max(1, qint("days", 7))
                stats = get_aggregate_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(stats)
            return

        if path == "/api/sessions":
            try:
                data = get_sessions_page(
                    page=qint("page", 1),
                    limit=qint("limit", 20),
                    sort=qstr("sort", "updatedAt"),
                    direction=qstr("dir", "desc"),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/findings":
            try:
                data = get_findings_page(
                    page=qint("page", 1),
                    limit=qint("limit", 25),
                    agent=qstr("agent"),
                    severity=qstr("severity"),
                    category=qstr("category"),
                    search=qstr("q"),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/events":
            try:
                data = get_events_page(
                    page=qint("page", 1),
                    limit=qint("limit", 30),
                    verdict=qstr("verdict"),
                    agent=qstr("agent"),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/supply-chain":
            try:
                days = max(1, qint("days", 7))
                data = get_supply_chain_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/agents":
            try:
                from warden.agents import list_agents, load_agents_config
                from warden.iam import list_agent_ids, load_iam_config
                from pathlib import Path as _Path
                workspace = _Path.cwd()

                # Merge store stats with registry config
                store_stats = {a["name"]: a for a in get_agents_overview()}
                registry = {a.name: a for a in list_agents(workspace)}

                # Union of both — include agents seen in store but not configured yet
                all_names = sorted(set(store_stats) | set(registry))
                items = []
                for name in all_names:
                    stats = store_stats.get(name, {})
                    ctrl = registry.get(name)
                    items.append({
                        "name": name,
                        "framework": (ctrl.framework if ctrl else "") or stats.get("framework", ""),
                        "enabled": ctrl.enabled if ctrl else True,
                        "mode": ctrl.mode if ctrl else None,
                        "iam_profile": ctrl.iam_profile if ctrl else None,
                        "last_seen": stats.get("last_seen") or (ctrl.last_seen if ctrl else None),
                        "total_calls": stats.get("total_calls", 0),
                        "blocked_calls": stats.get("blocked_calls", 0),
                    })

                iam_profiles = list_agent_ids(load_iam_config(workspace))
                self._send_json({"agents": items, "iam_profiles": iam_profiles})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # POST /api/agents/<name> — update per-agent control settings
        if path.startswith("/api/agents/"):
            agent_name = path[len("/api/agents/"):]
            if not agent_name:
                self._send_json({"error": "agent name required"}, status=400)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception as exc:
                self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
                return
            try:
                from warden.agents import upsert_agent
                # Resolve the workspace from the server's perspective
                from pathlib import Path as _Path
                workspace = _Path.cwd()
                # Map camelCase keys the UI sends to snake_case
                fields = {}
                if "enabled" in body:
                    fields["enabled"] = bool(body["enabled"])
                if "mode" in body:
                    fields["mode"] = body["mode"] or None
                if "iam_profile" in body or "iamProfile" in body:
                    fields["iam_profile"] = body.get("iamProfile") or body.get("iam_profile") or None
                control = upsert_agent(agent_name, workspace, **fields)
                self._send_json({
                    "name": control.name,
                    "framework": control.framework,
                    "enabled": control.enabled,
                    "mode": control.mode,
                    "iam_profile": control.iam_profile,
                    "last_seen": control.last_seen,
                })
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    # Suppress BrokenPipeError tracebacks when clients disconnect early
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


def run_server(host: str = "127.0.0.1", port: int = 7070, open_browser: bool = False) -> None:
    """Start the warden HTTP API server (blocks until Ctrl-C).

    When ``open_browser`` is set, opens the default browser to the dashboard
    once the listening socket is bound. The socket is bound by the
    ``HTTPServer(...)`` constructor, so the request lands even before
    ``serve_forever()`` starts accepting.
    """
    import errno as _errno
    while True:
        try:
            server = HTTPServer((host, port), WardenRequestHandler)
            break
        except OSError as exc:
            if exc.errno == _errno.EADDRINUSE:
                print(f"[warden] port {port} in use, trying {port + 1}…", flush=True)
                port += 1
            else:
                raise
    url = f"http://{host}:{port}"
    print(f"[warden] dashboard → {url}  (Ctrl-C to stop)", flush=True)
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[warden] server stopped", flush=True)
    finally:
        server.server_close()
