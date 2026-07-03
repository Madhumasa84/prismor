#!/bin/bash
# Validate the integration registry: schema-checks registry.yaml and confirms
# the AGENT_INTEGRATIONS.md coverage matrix is in sync.
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

REGISTRY="prismor/runtime/integrations/registry.yaml"
SCHEMA="prismor/runtime/integrations/registry.schema.json"

if [ ! -f "$REGISTRY" ]; then
    echo "Error: registry not found at $REGISTRY"
    exit 1
fi

echo "→ Validating $REGISTRY against $SCHEMA ..."
python3 - "$REGISTRY" "$SCHEMA" <<'PY'
import json, sys
import yaml

reg_path, schema_path = sys.argv[1], sys.argv[2]
data = yaml.safe_load(open(reg_path, encoding="utf-8"))
schema = json.load(open(schema_path, encoding="utf-8"))

# Lightweight validation: jsonschema if available, else hand-rolled enum checks
# so the script works in a minimal environment (matches repo's stdlib-first style).
try:
    import jsonschema
    jsonschema.validate(data, schema)
    print("  jsonschema: OK")
except ImportError:
    from prismor.runtime.integrations.registry import (
        BLOCKING, KINDS, STATUSES, SURFACES, load_registry,
    )
    items = load_registry()
    seen = set()
    for i in items:
        assert i.id not in seen, f"duplicate id: {i.id}"
        seen.add(i.id)
        assert i.kind in KINDS, f"{i.id}: bad kind {i.kind!r}"
        assert i.surface in SURFACES, f"{i.id}: bad surface {i.surface!r}"
        assert i.status in STATUSES, f"{i.id}: bad status {i.status!r}"
        assert i.blocking in BLOCKING, f"{i.id}: bad blocking {i.blocking!r}"
    print(f"  enum check: OK ({len(items)} integrations)")
PY

echo "→ Checking AGENT_INTEGRATIONS.md coverage matrix is in sync ..."
python3 scripts/gen_integration_matrix.py --check

echo "✓ registry verified."
