"""Immunity enterprise control-plane link.

This package groups everything that connects a local Warden install to an
*optional* Prismor control plane (the self-hosted org dashboard). None of it is
active unless the machine is enrolled (``prismor enroll <token>``); on a plain
local install every entry point here is a guarded no-op, so the runtime works
exactly the same with or without an org.

The pieces, and how they fit together:

- ``identity``        — device identity + enrollment. Owns ``~/.prismor/identity.json``
                        and ``DEFAULT_API_BASE``; everything else depends on it
                        (``is_enrolled()`` / ``load_identity()`` are the gates).
- ``remote_policy``   — pulls the org's signed policy and refreshes it on the hot
                        path (debounced ~30s, best-effort). Verifies the Ed25519
                        signature before applying.
- ``telemetry``       — builds a REDACTED telemetry record from a finding
                        (metadata + hashes, never raw commands or secrets).
- ``telemetry_spool`` — offline spool: persists telemetry when the control plane
                        is unreachable and replays it once it's back.
- ``heartbeat``       — per-call volume heartbeat + full-capture notice.
- ``workspace_scope`` — per-repo scoping: maps a workspace to the org/project/repo
                        policy layer (see ``docs/policy-layers-and-exemptions.md``).

Telemetry upload itself lives in ``warden.sinks`` (the generic sink layer);
this package builds the records and owns the device-auth path.
"""

# Imported in dependency order (identity first — the others import it) so that
# `import warden.enterprise` exposes every submodule without circular-import
# surprises. Code on the hot path still imports lazily inside functions.
from warden.enterprise import identity  # noqa: F401
from warden.enterprise import telemetry  # noqa: F401
from warden.enterprise import telemetry_spool  # noqa: F401
from warden.enterprise import heartbeat  # noqa: F401
from warden.enterprise import remote_policy  # noqa: F401
from warden.enterprise import workspace_scope  # noqa: F401

__all__ = [
    "identity",
    "remote_policy",
    "telemetry",
    "telemetry_spool",
    "heartbeat",
    "workspace_scope",
]
