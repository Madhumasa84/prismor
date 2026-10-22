# Portable reproduction and artifact transfer

## Source identity and environment

The paper's historical revision is
`dc5cc7ebd1c3efac001c5c26ea66196cef316eda`; hardening was checkpointed at
`9e2ca79dcf842cdd13d4b1c45c7c2e724d6b7e60`. The packaging branch is
`research/harness-alignment-eval`. `candidate_files.txt` lists the eight packaging
files. The earlier candidate was tested as an uncommitted overlay; verification
of the packaging commit must use a fresh checkout of that exact commit.
Each run's `source_snapshot.json` records actual HEAD, branch, tracked differences,
proposed files and content hashes; its content digest identifies the tested tree.

Use the README's venv and install commands. The supported research packaging
baseline is Python 3.10+ on POSIX. The fresh environment is CPython 3.10.16
on Linux x86_64 (WSL2 Ubuntu 22.04),
with pytest 9.1.1, PyYAML 6.0.3, jsonschema 4.26.0, cryptography 50.0.2 and
PyJWT 2.15.1. These describe the tested environment, not new version constraints.
The exact tested Python/platform and all fresh venv dependency versions are recorded in `focused-environment.json` (and in each
other step's environment record). The environment uses `pyproject.toml` runtime/dev
dependencies and `requirements.txt`; there is no repository lock convention for
this harness. No unrelated package freeze or extra constraint file is needed.

For installation without an index, first supply a complete compatible wheelhouse
including build requirements (`hatchling` and dependencies), runtime/dev packages
and JSON Schema dependencies. Then use pip's `--no-index --find-links` options.
No wheelhouse is supplied with this source artifact; offline installation is not
claimed. Evaluation itself requires neither network access nor historical data.

## What a checkout contains

| Class | Contents and transfer rule |
| --- | --- |
| Tracked execution source | Full Prismor runtime, `pyproject.toml`, five original `tests/test_harness_alignment_*.py` files, native selected tests and `tests/conftest.py`; research modules, schemas, casebook, YAML policies, false/zero settings and unavailable model configuration. All are required from the full checkout. |
| Packaging source | The exact eight paths in `candidate_files.txt`, included in the packaging commit. Existing research behavior and production configuration are unchanged. |
| Historical evidence | Allowlisted paths in `historical_evidence.json`, many ignored/untracked: selected JUnit/logs, raw observations, source/config manifests, before/after witnesses and blank label forms. Ship separately, not by force-adding directories. |
| Private/regenerable material | Older full report bundles, checkout archives, paper workspace, caches and output `runs/` are not execution dependencies. Preserve originals privately; none is deleted by packaging. |

The previous report script required coverage, lived in an untracked report and
omitted hardening. The new entry point imports no report scripts and uses no
`/home` or fixed `/tmp` paths. It inherits the native test skip when the optional
`examples/mcp-block-demo/mcp_server.py` is absent; do not replace it with a stub.
Fresh runs go to an explicitly new directory; `runs/` is already narrowly ignored.

## Evidence bundle

On an owner checkout containing the selected historical files:

```bash
.venv/bin/python -m research.harness_alignment.evidence_package build --output /path/to/private/evidence.tar.gz
.venv/bin/python -m research.harness_alignment.evidence_package verify /path/to/private/evidence.tar.gz --extract /path/to/new-extraction
```

The builder copies only the explicit allowlist, byte-for-byte, and emits a
sidecar manifest plus embedded `MANIFEST.json`. It rejects linked inputs, common
credential patterns, credential-bearing URLs and forbidden file types. This
conservative screen supplements inspection of the selected synthetic records;
it is not a general secret-discovery service. No `.env`, weights, credential
stores or unrelated home files belong in the selection. If future redaction is
necessary, make an explicitly marked derivative with a new hash and provenance.

The manifest maps original forwarding (Table 1), the latest historical cleanup
suite/subset (Table 2), scripted-control observations, and each A1/A3/R2/R1/R3/A2
before/after fault witness (Table 3). Before-repair records identify revision
`54f99441e038a3501e67a234561bbe133f438d2b`; post-repair source bindings and the
hardening checkpoint are separate. Included original checksum lists can refer
to omitted records; only the new package manifest describes the complete selected
bundle. Older archives stay private. There are no genuine Niti response records.

## Validate a candidate from a disposable copy

Clone the full local checkout into a new directory at the recorded HEAD. Do not
use symlinks or PYTHONPATH to the owner's source. For uncommitted changes, overlay
**only** `candidate_files.txt` and the files it lists; record their SHA-256 hashes.
Create a new venv there with no system-site packages and run the README commands.
The worker refuses an imported native gateway outside that copy and records its
resolved module path. Each child receives isolated HOME/XDG/Prismor directories;
no owner credentials or global pytest plugins are copied. Keep the resulting logs
separate from historical runs, and verify the evidence archive independently.

The runner records exact nested pytest/CLI commands. It keeps the historical 107
checks separate from packaging checks and the overlapping boundary invocation.
JUnit records skips/reasons; logs retain deselection counts. Do not sum these
suites or scenario variants as independent samples. If a prerequisite fails,
report the failing command and incomplete outputs; do not substitute an original
checkout run and call it fresh reproduction.
