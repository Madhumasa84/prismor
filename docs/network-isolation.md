# Network Isolation

AI agents frequently make outbound network calls by fetching URLs, installing packages, and calling APIs. Without controls, a prompt injection or malicious skill can silently exfiltrate data to an attacker-controlled endpoint. Prismor's network isolation rules make your agent's network activity visible and controllable.

## What it detects at runtime

- Outbound connections to raw IP addresses (not domains). This is often a sign of exfiltration or C2.
- Services binding to `0.0.0.0`. Prismor warns before the agent exposes a port to all network interfaces.
- Reverse tunnels and port forwarding (`ssh -R`, ngrok, cloudflared)
- Data upload patterns (`curl --data`, `wget --post-data`)

## Egress allowlist

Lock down which domains the agent can contact by configuring an allowlist in your project's `.prismor/policy.yaml`:

```yaml
settings:
  egress_allowlist:
    - "*.github.com"
    - "*.googleapis.com"
    - "registry.npmjs.org"
    - "pypi.org"
    - "api.anthropic.com"
    - "api.openai.com"
```

When the allowlist is set, any outbound request to a domain not on the list produces a warning. Wildcards are supported: `*.github.com` matches `api.github.com`, `raw.github.com`, and so on. Leave it empty (the default) to allow all domains.

## Bind detection

The `0.0.0.0` bind detection is particularly important. If an agent starts a dev server bound to all interfaces instead of `127.0.0.1`, it becomes reachable from outside your machine. Prismor catches this at the shell command level, before the port opens.

## MCP tool calls

A call to a remote MCP server (`mcp__<server>__<tool>`) is an outbound network request, but the tool name hides the destination. Prismor resolves the server's endpoint from your MCP config and treats a call to a remote (HTTP/SSE/streamable-HTTP) server as a network event — so the same controls that apply to `WebFetch` and `curl` apply to MCP:

- The **egress allowlist** is enforced against the MCP server's domain. A call to a server not on the list produces a warning, exactly like any other off-allowlist request.
- **Raw-IP** and **suspicious-destination** rules apply to the MCP endpoint.
- **Taint escalation:** if a prompt injection was detected earlier in the session, any subsequent remote MCP call is escalated to a CRITICAL block — this catches response-blind exfiltration where an injected agent quietly ships data out through a tool call.
- The tool's **arguments** are scanned for enrolled cloaking secrets, so a secret sent as an MCP parameter is caught the same way as a secret in a URL.

Local (stdio) MCP servers are not network destinations, so they are not subject to the egress allowlist.

### MCP responses are untrusted input

The output of a remote MCP tool is attacker-influenced content — the primary surface for tool-poisoning and "rug pull" attacks. Prismor scans MCP tool responses with the same prompt-injection rules and HTML sanitizer it uses on fetched web pages, so injected instructions hidden in a tool's output (including inside HTML comments or CSS-hidden elements) are flagged before they reach the agent.
