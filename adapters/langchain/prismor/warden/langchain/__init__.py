"""Prismor Warden adapter for LangChain / LangGraph.

Preferred import path::

    from prismor.warden.langchain import guard_tools, use_subject

Aliases the ``prismor_warden_langchain`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

import prismor_warden_langchain as _impl

_sys.modules[__name__] = _impl
