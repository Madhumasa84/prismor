"""immunity-agent has been renamed to **prismor**.

This package is a thin redirect: it installs `prismor` as a dependency, which
provides the full Warden runtime, the supply-chain engine, and the `prismor`
command (with `immunity` kept as a deprecated alias).

Switch your install with:

    pip install -U prismor

then use the ``prismor`` command. See https://prismor.dev for details.
"""

__all__ = ["__version__"]
__version__ = "1.13.0"
