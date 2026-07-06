"""Top-level Prismor package.

This file makes the source checkout a real package instead of a pure namespace
package so repo-local entry points (for example ``bin/prismor``) cannot be
shadowed by an unrelated installed ``prismor`` distribution earlier on the
import path.
"""

from prismor.runtime import __version__

__all__ = ["__version__"]
