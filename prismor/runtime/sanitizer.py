"""HTML content sanitizer — detects and strips injection vectors from fetched page content."""
from __future__ import annotations

import re
from typing import List, Tuple


# HTML comment blocks
_HTML_COMMENT_RE = re.compile(r'<!--.*?-->', re.DOTALL)

# Opening tag of any element with a style attribute containing a hiding property.
# We match the opening tag only; content is inspected in a forward window.
_HIDDEN_STYLE_OPEN_RE = re.compile(
    r'<[a-zA-Z][a-zA-Z0-9]*[^>]+style\s*=\s*["\'][^"\']*(?:'
    r'display\s*:\s*none'
    r'|visibility\s*:\s*hidden'
    r'|font-size\s*:\s*0(?:px)?'
    r'|color\s*:\s*(?:white|#fff{1,3}|transparent|rgba\s*\([^)]*,\s*0(?:\.0*)?\s*\))'
    r')[^"\']*["\'][^>]*>',
    re.IGNORECASE | re.DOTALL,
)

# Opening tag of any element with aria-hidden="true"
_ARIA_HIDDEN_OPEN_RE = re.compile(
    r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*aria-hidden\s*=\s*["\']true["\'][^>]*>',
    re.IGNORECASE,
)

# Zero-width and invisible Unicode characters commonly used to break up keywords
_INVISIBLE_RE = re.compile(r'[​‌‍⁠﻿]+')

# Semantic injection signals — phrases that constitute a prompt injection attempt
_INJECTION_SIGNALS_RE = re.compile(
    r'ignore\s+(all\s+)?(any\s+)?(previous\s+)?instructions'
    r'|disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)'
    r'|forget\s+(?:everything|all\s+previous|your\s+instructions)'
    r'|new\s+(?:primary\s+)?instruction'
    r'|(?:reveal|print|show|output)\s+(?:your\s+)?(?:system\s+prompt|api\s+key|secret|token)'
    r'|you\s+are\s+now\s+(?:a\s+)?(?:different|new)'
    r'|act\s+as\s+if\s+(?:you|your)'
    r'|exfiltrat(?:e|ion)'
    r'|fetch\s+https?://'
    r'|send\s+(?:a\s+)?(?:get|post|http)\s+request',
    re.IGNORECASE,
)

# Window size (chars) to scan ahead of a hidden-element opening tag for payload text
_LOOKAHEAD = 600


def detect_injections(content: str) -> List[str]:
    """Scan fetched page content for structurally hidden injection patterns.

    Returns a list of human-readable detection descriptions.
    An empty list means no structural injections were found.

    This is a complement to regex-on-plaintext detection — it catches
    payloads hidden via HTML comments, CSS visibility tricks, aria-hidden
    attributes, and zero-width character obfuscation that survive into the
    rendered text visible to the model.
    """
    detections: List[str] = []

    # ── HTML comment injection ──────────────────────────────────────────
    for m in _HTML_COMMENT_RE.finditer(content):
        comment_text = m.group(0)
        if _INJECTION_SIGNALS_RE.search(comment_text):
            snip = comment_text[:140].replace('\n', ' ')
            detections.append(f"injection payload inside HTML comment: {snip!r}")

    # ── CSS-hidden element injection ────────────────────────────────────
    for m in _HIDDEN_STYLE_OPEN_RE.finditer(content):
        window = content[m.end():m.end() + _LOOKAHEAD]
        if _INJECTION_SIGNALS_RE.search(window):
            tag_snip = m.group(0)[:80].replace('\n', ' ')
            pay_snip = window[:100].replace('\n', ' ')
            detections.append(
                f"injection payload in CSS-hidden element ({tag_snip!r}): {pay_snip!r}"
            )

    # ── aria-hidden element injection ───────────────────────────────────
    for m in _ARIA_HIDDEN_OPEN_RE.finditer(content):
        window = content[m.end():m.end() + _LOOKAHEAD]
        if _INJECTION_SIGNALS_RE.search(window):
            pay_snip = window[:120].replace('\n', ' ')
            detections.append(
                f"injection payload in aria-hidden element: {pay_snip!r}"
            )

    # ── Zero-width character obfuscation ───────────────────────────────
    stripped = _INVISIBLE_RE.sub('', content)
    if stripped != content:
        for sig_m in _INJECTION_SIGNALS_RE.finditer(stripped):
            detections.append(
                f"injection keyword obscured by zero-width characters: "
                f"{sig_m.group(0)[:80]!r}"
            )
            break  # one report per page is enough

    return detections


def sanitize(content: str) -> Tuple[str, List[str]]:
    """Strip the most common injection vectors from HTML content.

    Performs a best-effort in-place scrub. Returns the cleaned content
    and a list of change descriptions. Does not require an HTML parser —
    operates purely on the raw string, so it is safe to call on partial
    or malformed HTML.
    """
    changes: List[str] = []

    # Remove invisible/zero-width characters
    cleaned = _INVISIBLE_RE.sub('', content)
    if cleaned != content:
        changes.append("stripped zero-width/invisible Unicode characters")
    content = cleaned

    # Replace HTML comments that contain injection signals with a safe placeholder
    def _scrub_comment(m: re.Match) -> str:
        if _INJECTION_SIGNALS_RE.search(m.group(0)):
            changes.append("redacted HTML comment containing injection payload")
            return '<!-- [redacted by Prismor] -->'
        return m.group(0)

    content = _HTML_COMMENT_RE.sub(_scrub_comment, content)

    return content, changes
