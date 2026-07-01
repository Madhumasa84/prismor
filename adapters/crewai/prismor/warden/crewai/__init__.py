"""Prismor Warden adapter for CrewAI.

Preferred import path::

    from prismor.warden.crewai import guard_tools, use_subject

Aliases the ``prismor_warden_crewai`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

import prismor_warden_crewai as _impl

_sys.modules[__name__] = _impl
