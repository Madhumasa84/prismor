"""Skill / MCP server scanner for Prismor Warden.

Discovers MCP server and skill configurations across supported agents
(Claude Code, Cursor, Windsurf, OpenClaw, Hermes, Codex), synthesizes skill_manifest
events from each entry, and evaluates them through the PolicyEngine.

Usage (from CLI):
    prismor scan                   # scan all discovered configs
    prismor scan --agent claude    # only Claude Code configs
    prismor scan --json            # machine-readable output
"""
from __future__ import annotations

import ast
import json
import re
import shlex
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from warden.policy_engine import PolicyEngine, _has_invisible_chars, _has_suspicious_unicode

# Maximum size of skill source files to read (100 KB).
_MAX_SOURCE_SIZE = 100 * 1024

# File extensions considered readable source code.
_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
    ".rb", ".go", ".rs", ".java", ".php", ".sh", ".bash",
}

# Severity ordering for descending sort.
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# ── AST dangerous-code detection constants ───────────────────────────────────

_DANGEROUS_BUILTINS: frozenset = frozenset({"exec", "eval", "compile", "__import__"})

_SUBPROCESS_METHODS: frozenset = frozenset({
    "run", "Popen", "check_output", "call", "check_call",
    "getoutput", "getstatusoutput",
})

_OS_EXEC_METHODS: frozenset = frozenset({
    "system", "popen",
    "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
})


class _DangerousCallVisitor(ast.NodeVisitor):
    """Walk a Python AST and flag dangerous execution patterns.

    Goes beyond string matching: catches dynamic dispatch via getattr() and
    first-order taint — an unvalidated function parameter flowing directly
    into a dangerous sink (escalated from HIGH to CRITICAL).
    """

    def __init__(self) -> None:
        self.hits: List[Dict[str, Any]] = []
        self._params: set = set()

    def _emit(self, node: ast.AST, rule_id: str, title: str, severity: str = "HIGH") -> None:
        self.hits.append({
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "lineno": getattr(node, "lineno", 0),
        })

    def _param_flows_in(self, call: ast.Call) -> bool:
        """True if any argument is a direct reference to a tracked function parameter."""
        for arg in call.args:
            if isinstance(arg, ast.Name) and arg.id in self._params:
                return True
        for kw in call.keywords:
            if isinstance(kw.value, ast.Name) and kw.value.id in self._params:
                return True
        return False

    def _enter_function(self, node: ast.FunctionDef) -> set:
        prev = self._params.copy()
        all_args = node.args.args + node.args.posonlyargs + node.args.kwonlyargs
        self._params = {a.arg for a in all_args}
        if node.args.vararg:
            self._params.add(node.args.vararg.arg)
        if node.args.kwarg:
            self._params.add(node.args.kwarg.arg)
        return prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # type: ignore[override]
        prev = self._enter_function(node)
        self.generic_visit(node)
        self._params = prev

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
        func = node.func

        # Plain builtins: exec(...), eval(...), compile(...), __import__(...)
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
            tainted = self._param_flows_in(node)
            self._emit(
                node,
                rule_id="ast-dangerous-builtin",
                title=f"Dangerous builtin `{func.id}()` called",
                severity="CRITICAL" if tainted else "HIGH",
            )

        # module.method() calls — subprocess.run(), os.system(), etc.
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in _SUBPROCESS_METHODS:
                tainted = self._param_flows_in(node)
                self._emit(
                    node,
                    rule_id="ast-subprocess-call",
                    title=f"`subprocess.{attr}()` call detected",
                    severity="CRITICAL" if tainted else "HIGH",
                )
            elif attr in _OS_EXEC_METHODS:
                tainted = self._param_flows_in(node)
                self._emit(
                    node,
                    rule_id="ast-os-exec",
                    title=f"`os.{attr}()` execution call detected",
                    severity="CRITICAL" if tainted else "HIGH",
                )

        # Dynamic dispatch: getattr(module, 'dangerous_method')
        if (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
        ):
            attr_arg = node.args[1]
            attr_val = (
                attr_arg.value
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str)
                else None
            )
            if attr_val and (attr_val in _SUBPROCESS_METHODS or attr_val in _OS_EXEC_METHODS):
                self._emit(
                    node,
                    rule_id="ast-dynamic-dispatch",
                    title=f"Dynamic dispatch to dangerous method `getattr(…, {attr_val!r})`",
                    severity="HIGH",
                )

        self.generic_visit(node)


def _ast_scan_python(source: str, entry_name: str) -> List[Dict[str, Any]]:
    """Parse Python source with the AST and return dangerous-code findings.

    Catches patterns the regex rules miss: dynamic dispatch via getattr(),
    and first-order taint (unvalidated parameter flowing into a dangerous sink).
    Fails silently for non-Python or syntax-broken files.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    visitor = _DangerousCallVisitor()
    visitor.visit(tree)

    findings: List[Dict[str, Any]] = []
    for hit in visitor.hits:
        ln = hit["lineno"]
        findings.append({
            "id": f"{hit['rule_id']}-{entry_name}-L{ln}",
            "severity": hit["severity"],
            "category": "skill_risk",
            "title": f"{hit['title']} in '{entry_name}' (line {ln})",
            "evidence": f"line={ln} rule={hit['rule_id']}",
            "eventIndex": 0,
            "ruleId": hit["rule_id"],
            "action": "warn",
            "skillName": entry_name,
        })

    return findings


# ── Config discovery ────────────────────────────────────────────────────────

def _claude_configs(workspace: Path) -> List[Path]:
    """Return Claude Code settings paths (user + project-level)."""
    home = Path.home()
    candidates = [
        home / ".claude" / "settings.json",
        home / ".claude.json",
        workspace / ".claude" / "settings.json",
        workspace / ".claude" / "settings.local.json",
        # Per-project MCP config (Claude Code supports a dedicated file)
        workspace / ".mcp.json",
    ]
    return [p for p in _dedupe(candidates) if p.exists()]


def _cursor_configs(workspace: Path) -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".cursor" / "mcp.json",
        workspace / ".cursor" / "mcp.json",
    ]
    return [p for p in _dedupe(candidates) if p.exists()]


def _windsurf_configs(workspace: Path) -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".codeium" / "windsurf" / "mcp_config.json",
        workspace / ".windsurf" / "mcp.json",
    ]
    return [p for p in _dedupe(candidates) if p.exists()]


def _openclaw_configs(workspace: Path) -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".openclaw" / "config.json",
        home / ".openclaw" / "skills.json",
        workspace / ".openclaw" / "config.json",
        workspace / ".openclaw" / "skills.json",
        workspace / ".openclaw" / "plugins.json",
    ]
    return [p for p in _dedupe(candidates) if p.exists()]


def _hermes_configs(workspace: Path) -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".hermes" / "config.json",
        home / ".hermes" / "skills.json",
        home / ".hermes" / "plugins.json",
        workspace / ".hermes" / "config.json",
        workspace / ".hermes" / "plugins.json",
    ]
    return [p for p in _dedupe(candidates) if p.exists()]


def _codex_configs(workspace: Path) -> List[Path]:
    home = Path.home()
    candidates = [
        home / ".codex" / "config.toml",
        home / ".codex" / "hooks.json",
        workspace / ".codex" / "config.toml",
        workspace / ".codex" / "hooks.json",
    ]
    return [p for p in _dedupe(candidates) if p.exists()]


def _dedupe(paths: List[Path]) -> List[Path]:
    """De-duplicate paths (preserves order). Resolves each path first so
    symlinks and workspace-that-equals-HOME don't produce duplicates."""
    seen: set[str] = set()
    out: List[Path] = []
    for p in paths:
        try:
            key = str(p.resolve())
        except (OSError, ValueError):
            key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


_AGENT_DISCOVERERS = {
    "claude": _claude_configs,
    "cursor": _cursor_configs,
    "windsurf": _windsurf_configs,
    "openclaw": _openclaw_configs,
    "hermes": _hermes_configs,
    "codex": _codex_configs,
}


def discover_configs(
    agent: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Find all agent config files. Returns list of {agent, path}.

    Project-level configs are sourced from ``workspace`` (or CWD if omitted).
    """
    ws = workspace if workspace is not None else Path.cwd()
    agents = [agent] if agent else list(_AGENT_DISCOVERERS.keys())
    results: List[Dict[str, Any]] = []
    for a in agents:
        discoverer = _AGENT_DISCOVERERS.get(a)
        if not discoverer:
            continue
        for p in discoverer(ws):
            results.append({"agent": a, "path": p})
    return results


# ── Config parsing ──────────────────────────────────────────────────────────

def _extract_mcp_servers(data: Dict[str, Any], agent: str) -> List[Dict[str, Any]]:
    """Extract MCP server entries from a parsed config.

    Returns a list of dicts, each with at least {name, raw} where raw is the
    full server config object as a string for pattern matching.
    """
    servers: List[Dict[str, Any]] = []

    # Claude Code: {"mcpServers": {"name": {...}}}
    mcp_block = data.get("mcpServers") or data.get("mcp_servers") or {}
    if isinstance(mcp_block, dict):
        for name, cfg in mcp_block.items():
            servers.append({"name": name, "config": cfg, "raw": json.dumps(cfg, indent=2)})

    # Cursor / Windsurf: {"mcpServers": {"name": {...}}} — same shape
    # Some configs nest under "servers"
    if not servers:
        srv_block = data.get("servers") or {}
        if isinstance(srv_block, dict):
            for name, cfg in srv_block.items():
                servers.append({"name": name, "config": cfg, "raw": json.dumps(cfg, indent=2)})

    # OpenClaw skills: {"skills": [{"name": ..., ...}]}
    skills_list = data.get("skills") or []
    if isinstance(skills_list, list):
        for skill in skills_list:
            if isinstance(skill, dict):
                name = skill.get("name") or skill.get("id") or "unnamed"
                servers.append({"name": name, "config": skill, "raw": json.dumps(skill, indent=2)})

    return servers


def parse_config(config_path: Path) -> List[Dict[str, Any]]:
    """Parse a single config file and return extracted skill/server entries."""
    try:
        text = config_path.read_text(encoding="utf-8")
        if config_path.suffix == ".toml":
            data = tomllib.loads(text)
        else:
            data = json.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError):
        return []

    agent = "unknown"
    path_str = str(config_path)
    for a in _AGENT_DISCOVERERS:
        if a in path_str.lower() or (a == "claude" and ".claude" in path_str):
            agent = a
            break

    entries = _extract_mcp_servers(data, agent)
    for entry in entries:
        entry["source"] = str(config_path)
        entry["agent"] = agent
    return entries


# ── Source code resolution ──────────────────────────────────────────────────

def _resolve_skill_source(entry: Dict[str, Any]) -> Optional[str]:
    """Try to read the source code of a locally-installed MCP server/skill.

    Parses the 'command' field from the config to extract a script path,
    then reads the file if it exists and is a recognized source type.
    Returns the source code as a string, or None.
    """
    cfg = entry.get("config", {})
    if not isinstance(cfg, dict):
        return None

    command = cfg.get("command", "")
    args = cfg.get("args", [])
    if not command:
        return None

    # Build the full command line to extract the script path.
    # Common patterns:
    #   command: "python3", args: ["server.py"]
    #   command: "node",    args: ["/path/to/index.js"]
    #   command: "/usr/bin/python3", args: ["-m", "myserver"]
    #   command: "npx",     args: ["@scope/pkg"]
    script_path = None

    if isinstance(args, list) and args:
        for arg in args:
            arg_str = str(arg)
            # Skip flags
            if arg_str.startswith("-"):
                continue
            # Check if it looks like a file path with a source extension
            p = Path(arg_str)
            if p.suffix in _SOURCE_EXTENSIONS:
                script_path = p
                break
    elif isinstance(command, str) and " " in command:
        # command might be "python3 /path/to/server.py"
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        for part in parts[1:]:
            if part.startswith("-"):
                continue
            p = Path(part)
            if p.suffix in _SOURCE_EXTENSIONS:
                script_path = p
                break

    if script_path is None:
        return None

    # Resolve relative paths against the config's source directory
    if not script_path.is_absolute():
        source_dir = Path(entry.get("source", "")).parent
        if source_dir.exists():
            script_path = source_dir / script_path

    if not script_path.exists() or not script_path.is_file():
        return None

    # Size check
    try:
        size = script_path.stat().st_size
        if size > _MAX_SOURCE_SIZE or size == 0:
            return None
        return script_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ── Schema audit ────────────────────────────────────────────────────────────

# Words in a tool description that strongly suggest the tool can do more than
# it claims — common in tool-poisoning attacks.
_RISKY_DESCRIPTION_TOKENS = (
    "bypass", "all files", "any command", "full access", "unrestricted",
    "ignore", "override", "regardless", "sudo", "root", "admin",
)

# Tool names that imply shell execution — highest-risk category.
_EXEC_TOOL_NAME_HINTS = (
    "exec", "run", "shell", "bash", "system", "command", "subprocess",
)

# Tool names that imply filesystem reach.
_FS_TOOL_NAME_HINTS = (
    "read_file", "write_file", "edit_file", "list_dir", "glob", "delete",
    "unlink", "rm", "copy", "move",
)

# Tool names that imply network reach.
_NET_TOOL_NAME_HINTS = (
    "fetch", "http", "request", "curl", "download", "upload", "send",
    "post", "get_url",
)

# Transport/type values that indicate a remote (non-stdio) MCP server.
_REMOTE_TRANSPORTS = {
    "http", "https", "sse", "streamable-http", "streamable_http",
    "streamablehttp", "ws", "wss", "websocket",
}

# Config keys whose value may carry a remote MCP endpoint.
_URL_KEYS = ("url", "endpoint", "serverUrl", "server_url", "uri", "href")

# Header/env key names that strongly imply a credential.
_SECRET_KEY_RE = re.compile(
    r"(authorization|bearer|api[_-]?key|access[_-]?key|secret|token|"
    r"password|passwd|client[_-]?secret|x-api-key)",
    re.IGNORECASE,
)

# Literal token shapes that look like real secrets regardless of key name.
_SECRET_VALUE_RE = re.compile(
    r"(sk-(?:ant-api03-|proj-)?[A-Za-z0-9_-]{20,}|"
    r"(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}|"
    r"AKIA[A-Z0-9]{16}|"
    r"xox[bpas]-[0-9A-Za-z-]{10,}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)

# Value forms that are NOT hardcoded secrets (env-var refs, cloaking
# placeholders, obvious example/empty values).
_PLACEHOLDER_RE = re.compile(
    r"^\s*$|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|@@SECRET:[^@]+@@|"
    r"<[^>]+>|^(your[_-]|example|changeme|placeholder|xxx+|\*+|redacted)",
    re.IGNORECASE,
)


def _is_raw_ip(host: str) -> bool:
    """True if host is a bare IPv4 literal (not a domain)."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


def _domain_in_allowlist(domain: str, allowlist: List[str]) -> bool:
    """Mirror PolicyEngine._is_domain_allowed: exact + wildcard subdomain."""
    d = (domain or "").lower()
    for pattern in allowlist:
        p = str(pattern).lower()
        if p.startswith("*."):
            suffix = p[2:]
            if d == suffix or d.endswith("." + suffix):
                return True
        elif d == p:
            return True
    return False


def _looks_like_hardcoded_secret(key: str, value: str) -> bool:
    """Decide whether a header/env entry embeds a literal credential.

    Skips env-var references (``${VAR}``), cloaking placeholders
    (``@@SECRET:...@@``), and obvious example values.
    """
    if not value or _PLACEHOLDER_RE.search(value):
        return False
    if _SECRET_VALUE_RE.search(value):
        return True
    # Credential-shaped key name with a non-trivial literal value.
    if _SECRET_KEY_RE.search(key) and len(value.strip()) >= 8:
        return True
    return False


def _audit_remote_transport(
    name: str,
    cfg: Dict[str, Any],
    egress_allowlist: Optional[List[str]],
    action: str = "warn",
) -> List[Dict[str, Any]]:
    """Transport-hygiene checks for remote (HTTP/SSE/streamable-HTTP) MCP servers.

    Flags cleartext transport, raw-IP endpoints, endpoints outside the egress
    allowlist, and hardcoded secrets in headers/env. stdio servers (no url /
    command-based) produce no findings here. ``action`` ("warn" or "block")
    is configured via the ``mcp_transport_action`` policy setting.
    """
    findings: List[Dict[str, Any]] = []

    url = ""
    for k in _URL_KEYS:
        v = cfg.get(k)
        if isinstance(v, str) and v.strip():
            url = v.strip()
            break
    transport = str(cfg.get("type") or cfg.get("transport") or "").lower()
    is_remote = bool(url) or transport in _REMOTE_TRANSPORTS

    if url:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = parsed.hostname or ""

        if scheme in ("http", "ws"):
            findings.append({
                "id": f"mcp-cleartext-{name}",
                "severity": "HIGH",
                "category": "skill_risk",
                "title": f"MCP server '{name}' uses cleartext transport ({scheme}://) — traffic and tokens are unencrypted",
                "evidence": _truncate_url(url),
                "eventIndex": 0,
                "ruleId": "mcp-cleartext-transport",
                "action": action,
                "skillName": name,
            })

        if _is_raw_ip(host):
            findings.append({
                "id": f"mcp-raw-ip-{name}",
                "severity": "HIGH",
                "category": "skill_risk",
                "title": f"MCP server '{name}' points at a raw IP address ({host}) — no TLS hostname trust, common C2 shape",
                "evidence": _truncate_url(url),
                "eventIndex": 0,
                "ruleId": "mcp-remote-raw-ip",
                "action": action,
                "skillName": name,
            })

        if egress_allowlist and host and not _is_raw_ip(host) \
                and not _domain_in_allowlist(host, egress_allowlist):
            findings.append({
                "id": f"mcp-egress-{name}",
                "severity": "MEDIUM",
                "category": "skill_risk",
                "title": f"MCP server '{name}' endpoint '{host}' is not on the egress allowlist",
                "evidence": _truncate_url(url),
                "eventIndex": 0,
                "ruleId": "mcp-remote-not-allowlisted",
                "action": action,
                "skillName": name,
            })

    if is_remote:
        for block_key in ("headers", "env"):
            block = cfg.get(block_key)
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                if _looks_like_hardcoded_secret(str(k), str(v)):
                    findings.append({
                        "id": f"mcp-secret-{name}-{block_key}-{k}",
                        "severity": "MEDIUM",
                        "category": "skill_risk",
                        "title": f"MCP server '{name}' has a hardcoded secret in {block_key} ('{k}') — use ${{ENV}} or cloaking instead",
                        "evidence": f"{block_key}.{k}: [redacted literal value]",
                        "eventIndex": 0,
                        "ruleId": "mcp-hardcoded-secret",
                        "action": action,
                        "skillName": name,
                    })

    return findings


def _truncate_url(url: str, limit: int = 120) -> str:
    """Truncate a URL for evidence, stripping any query string (may carry tokens)."""
    base = url.split("?", 1)[0]
    return base if len(base) <= limit else base[: limit - 3] + "..."


def audit_mcp_schema(
    entry: Dict[str, Any],
    egress_allowlist: Optional[List[str]] = None,
    mcp_action: str = "warn",
) -> List[Dict[str, Any]]:
    """Static analysis of an MCP server / skill config.

    Returns structured findings that complement the regex-based skill_manifest
    evaluation. Each finding has the same shape as policy_engine findings
    (id, severity, category, title, evidence, ruleId, action).

    Checks performed:
      - ``any``-typed parameters on tools whose names imply fs/network/exec
      - Description tokens that suggest over-broad capability
      - Single server offering filesystem AND network AND execution tools
      - ``allowedPaths`` / ``allowedDomains`` using unrestricted wildcards
      - Tool schemas missing ``inputSchema`` entirely
      - Remote-transport hygiene for HTTP/SSE/streamable-HTTP servers:
        cleartext transport, raw-IP endpoints, endpoints outside the egress
        allowlist, and hardcoded secrets in headers/env.
    """
    findings: List[Dict[str, Any]] = []
    cfg = entry.get("config") or {}
    if not isinstance(cfg, dict):
        return findings
    name = entry.get("name", "unnamed")

    # Remote-transport hygiene (HTTP/SSE/streamable-HTTP MCP servers).
    findings.extend(_audit_remote_transport(name, cfg, egress_allowlist, mcp_action))

    # Unicode-confusable checks — homoglyph spoofing in server/tool names and
    # invisible characters embedded in tool descriptions (hidden instructions).
    if _has_suspicious_unicode(name):
        findings.append({
            "id": f"mcp-confusable-name-{name}",
            "severity": "MEDIUM",
            "category": "skill_risk",
            "title": f"MCP server name '{name}' contains Unicode-confusable characters (homoglyph spoofing)",
            "evidence": f"server name: {name!r}",
            "eventIndex": 0,
            "ruleId": "mcp-confusable-name",
            "action": "warn",
            "skillName": name,
        })

    # Over-broad allow-lists
    for list_key in ("allowedPaths", "allowedDomains", "permissions"):
        values = cfg.get(list_key)
        if isinstance(values, list):
            for v in values:
                if str(v).strip() in {"*", "**", "/", "/**", "/*"}:
                    findings.append({
                        "id": f"mcp-broad-{list_key}-{name}",
                        "severity": "HIGH",
                        "category": "skill_risk",
                        "title": f"MCP server '{name}' has unrestricted {list_key}: {v!r}",
                        "evidence": f"{list_key}: [\"{v}\"]",
                        "eventIndex": 0,
                        "ruleId": "mcp-overbroad-allowlist",
                        "action": "warn",
                        "skillName": name,
                    })

    # Description / instructions over-broad claims
    desc = str(cfg.get("description") or cfg.get("instructions") or "").lower()
    for token in _RISKY_DESCRIPTION_TOKENS:
        if token in desc:
            findings.append({
                "id": f"mcp-risky-desc-{name}-{token}",
                "severity": "MEDIUM",
                "category": "skill_risk",
                "title": f"MCP server '{name}' description contains risky language: {token!r}",
                "evidence": desc[:140],
                "eventIndex": 0,
                "ruleId": "mcp-risky-description",
                "action": "warn",
                "skillName": name,
            })
            break  # one finding per server is enough

    # Per-tool schema checks (MCP `tools` list if declared inline)
    tools = cfg.get("tools") or []
    if isinstance(tools, list):
        has_fs = has_net = has_exec = False
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name_raw = str(tool.get("name", ""))
            t_name = t_name_raw.lower()
            t_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            t_desc = str(tool.get("description") or "")

            # Confusable-char checks: homoglyph spoofing in tool names and
            # invisible characters used as hidden instruction separators in descriptions.
            if t_name_raw and _has_suspicious_unicode(t_name_raw):
                findings.append({
                    "id": f"mcp-confusable-tool-{name}-{t_name}",
                    "severity": "MEDIUM",
                    "category": "skill_risk",
                    "title": f"MCP tool '{t_name_raw}' in server '{name}' contains Unicode-confusable characters (homoglyph spoofing)",
                    "evidence": f"tool name: {t_name_raw!r}",
                    "eventIndex": 0,
                    "ruleId": "mcp-confusable-tool-name",
                    "action": "warn",
                    "skillName": name,
                })
            if t_desc and _has_suspicious_unicode(t_desc):
                findings.append({
                    "id": f"mcp-confusable-desc-{name}-{t_name}",
                    "severity": "HIGH",
                    "category": "skill_risk",
                    "title": f"MCP tool '{t_name_raw}' description in server '{name}' contains Unicode-confusable or invisible characters (possible hidden instruction)",
                    "evidence": f"tool description contains suspicious Unicode: {t_name_raw!r}",
                    "eventIndex": 0,
                    "ruleId": "mcp-confusable-tool-desc",
                    "action": "warn",
                    "skillName": name,
                })

            # Categorise this tool's capability
            if any(h in t_name for h in _EXEC_TOOL_NAME_HINTS):
                has_exec = True
            if any(h in t_name for h in _FS_TOOL_NAME_HINTS):
                has_fs = True
            if any(h in t_name for h in _NET_TOOL_NAME_HINTS):
                has_net = True

            # Missing or empty input schema on execution-capable tools
            if not t_schema and any(h in t_name for h in _EXEC_TOOL_NAME_HINTS + _FS_TOOL_NAME_HINTS):
                findings.append({
                    "id": f"mcp-no-schema-{name}-{t_name}",
                    "severity": "HIGH",
                    "category": "skill_risk",
                    "title": f"MCP tool '{t_name}' in server '{name}' has no input schema (accepts anything)",
                    "evidence": f"tool={t_name}",
                    "eventIndex": 0,
                    "ruleId": "mcp-missing-schema",
                    "action": "warn",
                    "skillName": name,
                })

            # `any`-typed parameters on capable tools
            properties = t_schema.get("properties") if isinstance(t_schema, dict) else None
            if isinstance(properties, dict):
                for pname, pspec in properties.items():
                    if not isinstance(pspec, dict):
                        continue
                    ptype = pspec.get("type")
                    if ptype in (None, "any", ["string", "object", "array"]) and any(
                        h in t_name for h in _EXEC_TOOL_NAME_HINTS + _FS_TOOL_NAME_HINTS + _NET_TOOL_NAME_HINTS
                    ):
                        findings.append({
                            "id": f"mcp-any-param-{name}-{t_name}-{pname}",
                            "severity": "MEDIUM",
                            "category": "skill_risk",
                            "title": f"MCP tool '{t_name}' parameter '{pname}' accepts any type",
                            "evidence": f"{t_name}.{pname}: {ptype!r}",
                            "eventIndex": 0,
                            "ruleId": "mcp-permissive-param",
                            "action": "warn",
                            "skillName": name,
                        })

        # Combined capabilities: a server offering fs + net + exec is a
        # full RCE platform. Flag this even if every individual tool
        # looks benign, because the composition is the attack surface.
        capability_count = sum((has_fs, has_net, has_exec))
        if capability_count >= 2 and has_exec:
            findings.append({
                "id": f"mcp-overbroad-capability-{name}",
                "severity": "HIGH",
                "category": "skill_risk",
                "title": f"MCP server '{name}' combines execution with filesystem/network access",
                "evidence": f"fs={has_fs} net={has_net} exec={has_exec}",
                "eventIndex": 0,
                "ruleId": "mcp-capability-combination",
                "action": "warn",
                "skillName": name,
            })

    return findings


# ── Event synthesis ─────────────────────────────────────────────────────────

def _synthesize_event(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a parsed skill/server entry into a skill_manifest event."""
    # Combine all text for pattern matching: name + raw JSON config
    combined = f"name: {entry['name']}\n{entry['raw']}"

    # Also include any nested prompt/description fields
    cfg = entry.get("config", {})
    if isinstance(cfg, dict):
        for key in ("description", "prompt", "system_prompt", "instructions",
                     "command", "args", "url", "env"):
            val = cfg.get(key)
            if val:
                if isinstance(val, list):
                    combined += "\n" + " ".join(str(v) for v in val)
                elif isinstance(val, dict):
                    combined += "\n" + json.dumps(val)
                else:
                    combined += f"\n{val}"

    # Also include source code if the skill is locally installed.
    source_code = _resolve_skill_source(entry)
    if source_code:
        combined += "\n--- source code ---\n" + source_code

    return {
        "type": "skill_manifest",
        "content": combined,
        "prompt": combined,
        "path": entry.get("source", ""),
    }


# ── Main scan entry point ──────────────────────────────────────────────────

def scan_skills(
    workspace: Optional[Path] = None,
    agent: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan all discovered skill/MCP configs and return findings.

    Returns:
        {
            "configs": [...],       # configs that were scanned
            "entries": int,         # total skill/server entries found
            "findings": [...],      # findings sorted by severity (desc)
            "summary": {...},       # counts by severity
        }
    """
    engine = PolicyEngine(workspace=workspace)
    configs = discover_configs(agent=agent, workspace=workspace)

    all_entries: List[Dict[str, Any]] = []
    for cfg in configs:
        entries = parse_config(cfg["path"])
        all_entries.extend(entries)

    findings: List[Dict[str, Any]] = []
    for i, entry in enumerate(all_entries):
        event = _synthesize_event(entry)
        entry_findings = engine.evaluate(event, index=i, session_id="scan")
        # Attach skill context to each finding
        for f in entry_findings:
            f["skillName"] = entry["name"]
            f["skillSource"] = entry.get("source", "")
            f["agent"] = entry.get("agent", "unknown")
        findings.extend(entry_findings)

        # Structural schema audit (complements the regex rules above).
        for sf in audit_mcp_schema(
            entry,
            egress_allowlist=engine.egress_allowlist,
            mcp_action=engine.mcp_transport_action,
        ):
            sf["skillSource"] = entry.get("source", "")
            sf["agent"] = entry.get("agent", "unknown")
            findings.append(sf)

        # AST-level dangerous code detection for Python skill sources.
        # Non-Python files fail ast.parse silently and return [].
        skill_source = _resolve_skill_source(entry)
        if skill_source:
            for af in _ast_scan_python(skill_source, entry["name"]):
                af["skillSource"] = entry.get("source", "")
                af["agent"] = entry.get("agent", "unknown")
                findings.append(af)

    # Sort by severity: CRITICAL first, then HIGH, MEDIUM, LOW
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "UNKNOWN"), 99))

    # Build summary
    summary: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "configs": [{"agent": c["agent"], "path": str(c["path"])} for c in configs],
        "entries": len(all_entries),
        "findings": findings,
        "summary": summary,
    }
