"""Response-body preview and HTML/JS-redirect detection shared by header and HTTP-method analysis (Java ``ah``).

The preview line count is Java's system property ``infrachecker.responseBodyPreviewLines``; here it is read from
the ``INFRACHECKER_RESPONSE_BODY_PREVIEW_LINES`` environment variable (positive int, default 10).
"""
from __future__ import annotations

import os
import re

from ..javacompat.strings import is_blank, java_trim
from ..log import log

EMPTY_BODY = "Empty Response Body"
_DEFAULT_LINES = 10
_PREVIEW_ENV = "INFRACHECKER_RESPONSE_BODY_PREVIEW_LINES"

_SCRIPT_OR_STYLE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.I | re.S | re.A)
_TAG = re.compile(r"<[^>]+>")
_SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.I | re.S | re.A)
_SCRIPT_SRC = re.compile(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I | re.A)
_LINE_BREAK = re.compile("\r\n|[\n\x0b\x0c\r\x85\u2028\u2029]")      # Java \R
_JAVA_SPACES = re.compile(r"[ \t\n\x0b\x0c\r]+")                    # Java \s+
_META_REFRESH = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*content\s*=\s*[\"'][^\"']*\burl\s*=",
                           re.I | re.S | re.A)
_JS_LOCATION = re.compile(r"\b(?:window|document|self|top)?\s*\.?\s*location(?:\s*\.\s*href)?\s*=\s*[\"'][^\"']+[\"']"
                          r"|\blocation\s*\.\s*(?:assign|replace)\s*\(", re.I | re.S | re.A)
_DOCUMENT_MOVED = re.compile(r"the\s+document\s+has\s+moved(?:\s+temporarily)?\s*<a\b[^>]*href\s*=", re.I | re.S | re.A)


def _configured_line_count() -> int:
    raw = os.environ.get(_PREVIEW_ENV)
    if raw is not None and java_trim(raw):
        try:
            value = int(java_trim(raw))
        except ValueError:
            log.warning(f"Invalid value for '{_PREVIEW_ENV}' -> '{raw}'; falling back to default {_DEFAULT_LINES}")
        else:
            if value > 0:
                return value
    return _DEFAULT_LINES


_line_count = _configured_line_count()


def preview_line_count() -> int:
    """Number of preview lines (Java ``ah.a()``; default 10)."""
    return _line_count


def _first_lines(text: str, count: int) -> list[str]:
    lines: list[str] = []
    for part in _LINE_BREAK.split(text):
        line = _JAVA_SPACES.sub(" ", java_trim(part))
        if line:
            lines.append(line)
            if len(lines) >= count:
                break
    return lines


def _unescape_entities(text: str) -> str:
    return (text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&#39;", "'"))


def response_preview(body: str | None, lines: int | None = None) -> str:
    """Java ``ah.a(body, lines)``: the text written to the Response Body column."""
    count = preview_line_count() if lines is None else lines
    if is_blank(body) or count <= 0:
        return EMPTY_BODY
    text = _unescape_entities(_TAG.sub("\n", _SCRIPT_OR_STYLE.sub(" ", body)))
    found = _first_lines(text, count)
    if found:
        return "\n".join(found)
    scripts: list[str] = []
    for match in _SCRIPT.finditer(body):
        src = _SCRIPT_SRC.search(match.group(1))
        if src:
            scripts.append("External Script: " + src.group(1))
        inline = java_trim(match.group(2))
        if inline:
            scripts.append(inline)
    if scripts:
        found = _first_lines("\n".join(scripts), count)
        if found:
            return "\n".join(found)
    found = _first_lines(body, count)
    return "\n".join(found) if found else EMPTY_BODY


def is_html_redirect(body: str | None) -> bool:
    """Meta refresh, JavaScript ``location`` assignment or "the document has moved" link (Java ``ah.a(String)``)."""
    if is_blank(body):
        return False
    lowered = body.lower()
    return bool(_META_REFRESH.search(lowered) or _JS_LOCATION.search(lowered) or _DOCUMENT_MOVED.search(lowered))
