"""Policy-driven network egress control.

Where the rest of the engine asks "is this command dangerous?", this module
asks a narrower question: **where is this call going, and is that destination
allowed?** It turns every network-shaped event — a WebFetch, a remote MCP tool
call, an `ssh`/`curl`/`git push` inside a Bash command — into a concrete list of
:class:`Destination` values and runs them against ``settings.egress``.

Two things make it different from the rest of the rule table:

* **It is destination-driven, not pattern-driven.** A YAML regex rule can say
  "block anything containing webhook.site". Only an egress policy can say "this
  fleet may talk to GitHub, PyPI, and our own API, and nothing else" — the
  useful direction, because the interesting exfil destination is always the one
  nobody thought to blacklist.
* **It is org-manageable.** ``settings.egress`` arrives in the same signed
  policy as everything else, so a fleet admin sets it once. When the org sets
  ``mode: enforce``, findings are marked ``authoritative`` and survive a local
  observe-mode downgrade — a developer cannot opt their machine out of the
  fleet's egress boundary the way they can silence a local detection.

Config shape (see ``settings.egress`` in default_policy.yaml)::

    egress:
      enabled: true
      mode: enforce          # observe | enforce
      default: deny          # allow | deny — verdict when nothing matches
      allow_private: true    # loopback/RFC1918 skip the check (IMDS never does)
      allow:
        - "*.github.com"
        - {host: "api.openai.com", ports: [443], schemes: [https]}
      deny:
        - {host: "*.pastebin.com", reason: "known exfil sink"}
      agents:
        release-bot: {default: deny, allow: ["*.github.com"]}

Evaluation order per destination: explicit ``deny`` wins, then private-network
carve-out, then ``allow``, then ``default``. First match wins within a list.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

__all__ = [
    "Destination",
    "EgressEntry",
    "EgressPolicy",
    "extract_destinations",
]

# Rule ids. `egress-allowlist` is retained for the default-deny verdict so
# existing exemptions, SARIF special-cases, and dashboards keep working; the
# explicit-deny verdict gets its own id so an admin can exempt one without the
# other.
RULE_OFF_ALLOWLIST = "egress-allowlist"
RULE_EXPLICIT_DENY = "egress-deny"

CATEGORY = "network_isolation"

# Destinations that are never treated as "private and therefore safe", even
# when allow_private is on. Link-local metadata is the classic SSRF pivot: it
# is unroutable (so it looks private) but hands out cloud credentials.
_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",
})


# ── Destinations ──────────────────────────────────────────────────────────────

class Destination:
    """One outbound destination extracted from an event."""

    __slots__ = ("host", "port", "scheme", "origin", "evidence")

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        scheme: str = "",
        origin: str = "",
        evidence: str = "",
    ) -> None:
        self.host = host.lower().strip(".")
        self.port = port
        self.scheme = (scheme or "").lower()
        self.origin = origin          # how we found it: "url", "ssh", "raw", …
        self.evidence = evidence      # the text it came from

    # Two destinations are the same finding if they share host+port.
    def key(self) -> Tuple[str, Optional[int]]:
        return (self.host, self.port)

    @property
    def ip(self) -> Optional[Any]:
        try:
            return ipaddress.ip_address(self.host)
        except ValueError:
            return None

    @property
    def is_private(self) -> bool:
        """True for loopback / RFC1918 / link-local / .local destinations.

        Metadata endpoints are excluded on purpose — see ``_METADATA_HOSTS``.
        """
        if self.host in _METADATA_HOSTS:
            return False
        ip = self.ip
        if ip is not None:
            return bool(
                ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            )
        if self.host in ("localhost", "localhost.localdomain", ""):
            return True
        return self.host.endswith(".local") or self.host.endswith(".internal")

    def label(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Destination({self.label()!r}, scheme={self.scheme!r}, origin={self.origin!r})"


# ── Extraction ────────────────────────────────────────────────────────────────

# Any scheme://host — not just http(s), so ssh://, ftp://, ws:// and git:// are
# seen too. Userinfo (user:pass@) is skipped rather than mistaken for the host.
_URL_RE = re.compile(
    r'\b([a-zA-Z][a-zA-Z0-9+.\-]{1,15})://'
    r'(?:[^\s/@"\']*@)?'
    r'(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._\-]+)'
    r'(?::(\d{1,5}))?'
)

# user@host:path (git/scp syntax) — the host half is what we want.
_SCP_RE = re.compile(
    r'(?:^|[\s"\'=])(?:[A-Za-z0-9._%+\-]+)@'
    r'(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.\-]+)'
    r'(?=:|\s|$|["\'])'
)

_SHELL_SEP_RE = re.compile(r'&&|\|\||[;|\n]')
_ENV_ASSIGN_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')

# Commands whose bare positional argument is a network destination.
_HTTP_CMDS = frozenset({"curl", "wget", "http", "https", "httpie", "xh", "aria2c", "lwp-request"})
_SSH_CMDS = frozenset({"ssh", "scp", "sftp", "rsync", "git", "mosh", "autossh"})
# host + port as separate positional arguments.
_HOSTPORT_CMDS = frozenset({"nc", "ncat", "netcat", "telnet", "socat", "nmap", "openssl"})

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?'
                          r'(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*$')

# Extensions that make a dotted token a filename, not a hostname. Without this
# `curl -o report.json` and `scp build.tar.gz host:` would both look like hosts.
_FILE_EXT_RE = re.compile(
    r'\.(json|ya?ml|txt|log|md|csv|tsv|xml|html?|js|ts|py|rb|go|rs|java|c|h|cpp|sh|zsh|bash|'
    r'tar|gz|tgz|bz2|xz|zip|whl|jar|deb|rpm|pkg|dmg|iso|img|png|jpe?g|gif|svg|pdf|env|lock|'
    r'toml|ini|cfg|conf|pem|key|crt|sql|db|sqlite3?|bak|tmp|out|so|dylib|dll|exe)$',
    re.IGNORECASE,
)

# A dotted token is only a hostname if the last label is a plausible TLD.
_TLD_RE = re.compile(r'\.[A-Za-z]{2,63}$')


def _looks_like_host(token: str) -> bool:
    """Conservative hostname test for a bare (schemeless) shell token."""
    if not token or token.startswith("-"):
        return False
    token = token.strip('"\'')
    if _IPV4_RE.match(token):
        return all(0 <= int(o) <= 255 for o in token.split("."))
    if token in ("localhost",):
        return True
    if "/" in token or "\\" in token:
        return False
    if not _TLD_RE.search(token) or _FILE_EXT_RE.search(token):
        return False
    return bool(_HOSTNAME_RE.match(token))


def _split_host_port(raw: str) -> Tuple[str, Optional[int]]:
    """Split ``host:port`` (or ``[v6]:port``) without mangling a bare IPv6."""
    raw = raw.strip().strip('"\'')
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return raw.strip("[]"), None
        host = raw[1:end]
        rest = raw[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if port.isdigit():
            return host, int(port)
        return host, None
    return raw, None


def _tokenize(sub: str) -> List[str]:
    try:
        return shlex.split(sub, posix=True)
    except ValueError:
        return sub.split()


def _add(seen: Dict[Tuple[str, Optional[int]], Destination], dest: Destination) -> None:
    if not dest.host:
        return
    # Keep the richest record for a host: a scheme-bearing URL beats a bare token.
    prior = seen.get(dest.key())
    if prior is None or (not prior.scheme and dest.scheme):
        seen[dest.key()] = dest


def _scan_url_text(text: str, seen: Dict, evidence: str) -> None:
    for m in _URL_RE.finditer(text):
        scheme, host, port = m.group(1), m.group(2), m.group(3)
        host = host.strip("[]")
        _add(seen, Destination(
            host=host,
            port=int(port) if port else _default_port(scheme),
            scheme=scheme,
            origin="url",
            evidence=evidence,
        ))


_DEFAULT_PORTS = {
    "http": 80, "https": 443, "ftp": 21, "ssh": 22, "git": 9418,
    "ws": 80, "wss": 443, "redis": 6379, "postgres": 5432, "mysql": 3306,
}


def _default_port(scheme: str) -> Optional[int]:
    return _DEFAULT_PORTS.get((scheme or "").lower())


def extract_destinations(event: Dict[str, Any]) -> List[Destination]:
    """Pull every outbound destination out of an event.

    Handles the ``url`` field of network events (WebFetch/WebSearch/remote MCP)
    and, for shell events, the destinations hidden inside a command: URLs of any
    scheme, ``user@host:path`` (git/scp), bare hosts passed to curl/wget, and
    ``host port`` pairs passed to nc/telnet/socat.
    """
    seen: Dict[Tuple[str, Optional[int]], Destination] = {}
    etype = str(event.get("type", ""))

    url = str(event.get("url") or "")
    if url:
        parsed_host = ""
        scheme = ""
        port: Optional[int] = None
        try:
            parsed = urlparse(url)
            parsed_host = parsed.hostname or ""
            scheme = parsed.scheme or ""
            port = parsed.port
        except Exception:
            parsed_host = ""
        if parsed_host:
            _add(seen, Destination(
                host=parsed_host,
                port=port or _default_port(scheme),
                scheme=scheme,
                origin="url",
                evidence=url,
            ))
        else:
            # A bare "example.com/path" with no scheme still needs screening.
            _scan_url_text(url, seen, url)
            head = url.split("/")[0]
            h, p = _split_host_port(head)
            if _looks_like_host(h):
                _add(seen, Destination(h, p, "", "url", url))

    if etype != "shell":
        return list(seen.values())

    command = str(event.get("command") or "")
    if not command:
        return list(seen.values())

    # Catch URLs anywhere, including inside quoted strings and heredocs that
    # tokenization would otherwise split apart.
    _scan_url_text(command, seen, command)

    for m in _SCP_RE.finditer(command):
        host = m.group(1).strip("[]")
        if _looks_like_host(host):
            _add(seen, Destination(host, 22, "ssh", "scp", command))

    for sub in _SHELL_SEP_RE.split(command):
        tokens = _tokenize(sub)
        while tokens and _ENV_ASSIGN_RE.match(tokens[0]):
            tokens.pop(0)
        if not tokens:
            continue
        argv0 = tokens[0].rsplit("/", 1)[-1].lower()
        if argv0 in ("sudo", "env", "command", "nohup", "time", "doas"):
            tokens = tokens[1:]
            while tokens and _ENV_ASSIGN_RE.match(tokens[0]):
                tokens.pop(0)
            if not tokens:
                continue
            argv0 = tokens[0].rsplit("/", 1)[-1].lower()
        args = tokens[1:]

        if argv0 in _HTTP_CMDS:
            for tok in args:
                if "://" in tok:
                    continue  # already captured by the URL scan
                head = tok.split("/")[0]
                h, p = _split_host_port(head)
                if _looks_like_host(h):
                    _add(seen, Destination(h, p, "", "http-cmd", sub))
        elif argv0 in _SSH_CMDS:
            for tok in args:
                if "://" in tok or "@" in tok:
                    continue  # URL scan / _SCP_RE already have these
                head = tok.split(":")[0] if ":" in tok and not tok.startswith("[") else tok
                if _looks_like_host(head) and ":" in tok:
                    _add(seen, Destination(head, 22, "ssh", "ssh-cmd", sub))
                elif argv0 in ("ssh", "mosh", "autossh") and _looks_like_host(tok):
                    _add(seen, Destination(tok, 22, "ssh", "ssh-cmd", sub))
        elif argv0 in _HOSTPORT_CMDS:
            positional = [t for t in args if not t.startswith("-")]
            for i, tok in enumerate(positional):
                if "://" in tok:
                    continue
                h, p = _split_host_port(tok)
                if not _looks_like_host(h):
                    continue
                if p is None and i + 1 < len(positional) and positional[i + 1].isdigit():
                    p = int(positional[i + 1])
                _add(seen, Destination(h, p, "", "hostport-cmd", sub))
                break

    return list(seen.values())


# ── Policy ────────────────────────────────────────────────────────────────────

class EgressEntry:
    """One compiled allow/deny entry."""

    __slots__ = ("host", "network", "wildcard_suffix", "any_host",
                 "ports", "schemes", "agents", "reason", "action", "mode", "raw")

    def __init__(self, raw: Any, default_action: str) -> None:
        if isinstance(raw, str):
            raw = {"host": raw}
        if not isinstance(raw, dict):
            raise ValueError(f"egress entry must be a string or mapping, got {type(raw).__name__}")
        host = str(raw.get("host") or raw.get("domain") or raw.get("cidr") or "").strip()
        if not host:
            raise ValueError("egress entry needs a 'host'")
        self.raw = raw
        self.reason = str(raw.get("reason") or "")
        self.action = str(raw.get("action") or default_action).lower()
        _mode = str(raw.get("mode") or "").lower()
        self.mode: Optional[str] = _mode if _mode in ("observe", "enforce") else None

        self.any_host = host == "*"
        self.wildcard_suffix: Optional[str] = None
        self.network: Optional[Any] = None
        self.host = host.lower()

        if host.startswith("*."):
            self.wildcard_suffix = host[2:].lower()
        elif "/" in host:
            try:
                self.network = ipaddress.ip_network(host, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid egress CIDR {host!r}: {exc}") from exc
        else:
            # A bare IP is matched as a /32 (or /128) so v4/v6 forms normalize.
            try:
                self.network = ipaddress.ip_network(host, strict=False)
            except ValueError:
                self.network = None

        ports = raw.get("ports")
        self.ports: Optional[Set[int]] = (
            {int(p) for p in ports} if isinstance(ports, (list, tuple, set)) and ports else None
        )
        schemes = raw.get("schemes")
        self.schemes: Optional[Set[str]] = (
            {str(s).lower() for s in schemes}
            if isinstance(schemes, (list, tuple, set)) and schemes else None
        )
        agents = raw.get("agents")
        self.agents: Optional[Set[str]] = (
            {str(a) for a in agents} if isinstance(agents, (list, tuple, set)) and agents else None
        )

    def matches(self, dest: Destination, agent_name: str = "") -> bool:
        if self.agents is not None and agent_name not in self.agents:
            return False
        if self.ports is not None and (dest.port is None or dest.port not in self.ports):
            return False
        if self.schemes is not None and dest.scheme not in self.schemes:
            return False
        return self._host_matches(dest)

    def _host_matches(self, dest: Destination) -> bool:
        if self.any_host:
            return True
        host = dest.host
        if self.wildcard_suffix is not None:
            return host == self.wildcard_suffix or host.endswith("." + self.wildcard_suffix)
        if self.network is not None:
            ip = dest.ip
            if ip is None:
                return False
            try:
                return ip in self.network
            except TypeError:
                return False  # v4 address vs v6 network
        return host == self.host

    def describe(self) -> str:
        bits = [self.host]
        if self.ports:
            bits.append("ports " + ",".join(str(p) for p in sorted(self.ports)))
        if self.schemes:
            bits.append("schemes " + ",".join(sorted(self.schemes)))
        return " ".join(bits)


class EgressPolicy:
    """Compiled ``settings.egress``. Inert unless enabled."""

    __slots__ = ("enabled", "mode", "default", "allow_private", "allow", "deny",
                 "agents", "source", "legacy", "errors")

    def __init__(self) -> None:
        self.enabled: bool = False
        self.mode: Optional[str] = None       # None -> inherit engine default_mode
        self.default: str = "allow"
        self.allow_private: bool = True
        self.allow: List[EgressEntry] = []
        self.deny: List[EgressEntry] = []
        self.agents: Dict[str, "EgressPolicy"] = {}
        self.source: str = ""                 # which policy layer set this
        self.legacy: bool = False             # built from settings.egress_allowlist
        self.errors: List[str] = []

    # ── construction ──────────────────────────────────────────────────────

    @classmethod
    def from_settings(
        cls,
        settings: Dict[str, Any],
        *,
        source: str = "",
    ) -> "EgressPolicy":
        """Build from a merged settings dict.

        ``settings.egress`` is authoritative. When it is absent or disabled but
        the legacy ``settings.egress_allowlist`` is populated, we synthesize the
        equivalent policy with the historic warn-only semantics so upgrading
        never turns an existing allowlist into a hard block.
        """
        raw = settings.get("egress")
        if isinstance(raw, dict) and raw.get("enabled"):
            pol = cls._from_dict(raw, source=source)
            pol.source = source
            return pol

        legacy_list = settings.get("egress_allowlist") or []
        if isinstance(legacy_list, (list, tuple)) and legacy_list:
            pol = cls()
            pol.enabled = True
            pol.legacy = True
            pol.mode = "observe"      # historic behavior: warn only, never block
            pol.default = "deny"
            pol.allow_private = True
            pol.source = source
            for item in legacy_list:
                try:
                    pol.allow.append(EgressEntry(item, "allow"))
                except ValueError as exc:
                    pol.errors.append(str(exc))
            return pol

        return cls()

    @classmethod
    def _from_dict(cls, raw: Dict[str, Any], *, source: str = "") -> "EgressPolicy":
        pol = cls()
        pol.enabled = bool(raw.get("enabled", False))
        _mode = str(raw.get("mode") or "").lower()
        pol.mode = _mode if _mode in ("observe", "enforce") else None
        _default = str(raw.get("default") or "allow").lower()
        pol.default = _default if _default in ("allow", "deny") else "allow"
        pol.allow_private = bool(raw.get("allow_private", True))
        for key, bucket, act in (("allow", pol.allow, "allow"), ("deny", pol.deny, "deny")):
            for item in raw.get(key) or []:
                try:
                    bucket.append(EgressEntry(item, act))
                except ValueError as exc:
                    pol.errors.append(f"{key}: {exc}")
        agents = raw.get("agents")
        if isinstance(agents, dict):
            for name, sub in agents.items():
                if not isinstance(sub, dict):
                    continue
                # An agent override inherits the parent's posture, then layers
                # its own lists on top — so `agents: {bot: {default: deny}}`
                # tightens one agent without restating the fleet allowlist.
                merged = {
                    "enabled": True,
                    "mode": sub.get("mode", raw.get("mode")),
                    "default": sub.get("default", pol.default),
                    "allow_private": sub.get("allow_private", pol.allow_private),
                    "allow": list(raw.get("allow") or []) + list(sub.get("allow") or []),
                    "deny": list(raw.get("deny") or []) + list(sub.get("deny") or []),
                }
                pol.agents[str(name)] = cls._from_dict(merged, source=source)
        return pol

    def for_agent(self, agent_name: str) -> "EgressPolicy":
        if agent_name and agent_name in self.agents:
            sub = self.agents[agent_name]
            sub.source = self.source
            return sub
        return self

    # ── evaluation ────────────────────────────────────────────────────────

    def verdict(self, dest: Destination, agent_name: str = "") -> Tuple[str, Optional[EgressEntry]]:
        """Return ``(action, matched_entry)`` for one destination.

        Order: explicit deny → private carve-out → allow → default.
        """
        for entry in self.deny:
            if entry.matches(dest, agent_name):
                return (entry.action if entry.action in ("deny", "warn") else "deny", entry)
        if self.allow_private and dest.is_private:
            return ("allow", None)
        for entry in self.allow:
            if entry.matches(dest, agent_name):
                return ("allow", entry)
        return ("allow" if self.default == "allow" else "off-allowlist", None)

    def evaluate(
        self,
        event: Dict[str, Any],
        index: int,
        *,
        session_id: str = "",
        agent_name: str = "",
        default_mode: str = "observe",
        device_mode: Optional[str] = None,
        authoritative_sources: Sequence[str] = ("remote",),
    ) -> List[Dict[str, Any]]:
        """Screen an event's destinations. Returns policy findings."""
        if not self.enabled:
            return []
        etype = str(event.get("type", ""))
        if etype not in ("network", "shell"):
            return []

        pol = self.for_agent(agent_name)
        try:
            destinations = extract_destinations(event)
        except Exception:
            return []
        if not destinations:
            return []

        findings: List[Dict[str, Any]] = []
        for dest in destinations:
            action, entry = pol.verdict(dest, agent_name)
            if action == "allow":
                continue

            explicit = entry is not None
            rule_id = RULE_EXPLICIT_DENY if explicit else RULE_OFF_ALLOWLIST
            # Legacy egress_allowlist stays warn-only forever; a real egress
            # block is an explicit opt-in through settings.egress.
            if pol.legacy or action == "warn":
                mode = "observe"
            else:
                mode = (
                    (entry.mode if entry is not None and entry.mode else None)
                    or pol.mode
                    or device_mode
                    or default_mode
                )
            mode = "enforce" if str(mode).lower() == "enforce" else "observe"

            if explicit:
                title = f"Outbound connection to denied destination: {dest.label()}"
            elif etype == "shell":
                title = f"Shell command contacts destination not on the egress allowlist: {dest.label()}"
            else:
                title = f"Outbound request to destination not on the egress allowlist: {dest.label()}"
            if entry is not None and entry.reason:
                title = f"{title} — {entry.reason}"

            suffix = "" if etype == "network" else f"-{dest.host}"
            finding_id = f"{rule_id}-{index}{suffix}"
            finding: Dict[str, Any] = {
                "id": f"{session_id}:{finding_id}" if session_id else finding_id,
                "severity": "HIGH",
                "category": CATEGORY,
                "title": title,
                "evidence": _truncate(dest.evidence or dest.label()),
                "eventIndex": index,
                "ruleId": rule_id,
                "action": "block" if mode == "enforce" else "warn",
                "mode": mode,
                "remediation": (
                    f"Add '{dest.host}' to settings.egress.allow if this destination is "
                    "expected, or route the call through an approved endpoint."
                ),
                "egressHost": dest.host,
            }
            if dest.port:
                finding["egressPort"] = dest.port
            # Org-set enforce is authoritative: a local observe downgrade must
            # not let a developer step outside the fleet's egress boundary.
            if mode == "enforce" and pol.source in tuple(authoritative_sources):
                finding["authoritative"] = True
            findings.append(finding)

            # One finding per event is enough for a shell command — a compound
            # command with five off-list hosts is still one decision.
            if etype == "shell":
                break

        return findings

    # ── introspection (CLI / audit) ───────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "legacy": self.legacy,
            "mode": self.mode or "(inherit)",
            "default": self.default,
            "allow_private": self.allow_private,
            "allow": [e.describe() for e in self.allow],
            "deny": [e.describe() for e in self.deny],
            "agents": sorted(self.agents),
            "source": self.source or "default",
            "errors": list(self.errors),
        }


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."
