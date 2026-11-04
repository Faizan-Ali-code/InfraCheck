"""Java string semantics that differ from Python's defaults."""
from __future__ import annotations

import re
import unicodedata

_JAVA_WS = "".join(chr(i) for i in range(33))
_HTTP_SCHEME = re.compile(r"(http|https)://.*", re.DOTALL)


def java_trim(text: str | None) -> str:
    """``String.trim()``: strips chars <= U+0020 only (``str.strip`` also strips other Unicode spaces)."""
    return "" if text is None else text.strip(_JAVA_WS)


def is_blank(text: str | None) -> bool:
    return text is None or java_trim(text) == ""


def strip_control_chars(text: str) -> str:
    """Remove every char of Unicode category C (``\\p{C}``)."""
    return "".join(ch for ch in text if not unicodedata.category(ch).startswith("C"))


def has_http_scheme(url: str) -> bool:
    """Java ``url.matches("^(http|https)://.*$")`` (case-sensitive)."""
    return _HTTP_SCHEME.fullmatch(url) is not None


def java_exception_text(exc: BaseException) -> str:
    """Approximates Java ``String.valueOf(exception)``: ``<type>: <message>`` or just ``<type>``.

    Errors that already model a Java exception (``java_class`` attribute) render their own Java text.
    """
    if hasattr(exc, "java_class"):
        return str(exc)
    message = str(exc)
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__
