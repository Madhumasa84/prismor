"""Prismor integration registry — the map of agents/frameworks Prismor intercepts."""
from prismor.runtime.integrations.registry import (
    Integration,
    by_status,
    by_surface,
    get,
    load_registry,
    registry_path,
)

__all__ = [
    "Integration",
    "by_status",
    "by_surface",
    "get",
    "load_registry",
    "registry_path",
]
