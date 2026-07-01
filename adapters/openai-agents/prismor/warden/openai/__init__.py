"""Prismor Warden adapter for the OpenAI Agents SDK.

Preferred import path::

    from prismor.warden.openai import guard_agent, use_subject

Aliases the ``prismor_warden_openai`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

import prismor_warden_openai as _impl

_sys.modules[__name__] = _impl
