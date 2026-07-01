"""Prismor Warden adapter for browser-use.

Preferred import path::

    from prismor.warden.browser_use import guard_controller, use_subject

Aliases the ``prismor_warden_browser_use`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

import prismor_warden_browser_use as _impl

_sys.modules[__name__] = _impl
