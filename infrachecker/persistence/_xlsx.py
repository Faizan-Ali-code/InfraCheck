"""Shared pieces of the Java Excel writer (``ak``/``al``): styles, colouring rules, cell text, hyperlinks, saving."""
from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import unicodedata
import warnings
from typing import Callable

from openpyxl import Workbook, load_workbook
from openpyxl.cell.cell import Cell
from openpyxl.styles import Alignment, Color, Font, PatternFill
from openpyxl.utils import get_column_letter

from ..javacompat.strings import java_trim
from ..log import log
from . import _autosize

HEADER = "header"
BASE = "base"
GREEN = "green"
ROSE = "rose"
ORANGE = "orange"

_HEADER_FONT = Font(name="Calibri", sz=11, b=True, color=Color(indexed=9))       # WHITE
_HEADER_FILL = PatternFill(fill_type="solid", fgColor=Color(indexed=18))         # DARK_BLUE
_HEADER_ALIGNMENT = Alignment(horizontal="center", vertical="center", wrap_text=True)
_DATA_ALIGNMENT = Alignment(vertical="top", wrap_text=True)
_FILLS = {GREEN: PatternFill(fill_type="solid", fgColor=Color(indexed=42)),      # LIGHT_GREEN
          ROSE: PatternFill(fill_type="solid", fgColor=Color(indexed=45)),       # ROSE
          ORANGE: PatternFill(fill_type="solid", fgColor=Color(indexed=52))}     # LIGHT_ORANGE

_MAX_CELL_UNITS = 32767
_ILLEGAL_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")


# --------------------------------------------------------------------------------------------- colouring rules

def status_colour(text: str) -> str | None:
    """Rule for the column whose header contains "Vulnerability Status"."""
    value = java_trim(text).lower()
    if not value:
        return None
    if any(word in value for word in ("unable", "unreachable", "failed", "error")):
        return ROSE
    if any(word in value for word in ("not vulnerable", "not-vulnerable", "detected", "protected", "secure")):
        return GREEN
    if any(word in value for word in ("not working", "vulnerable", "warning", "manual", "missing")):
        return ORANGE
    return None


def waf_colour(text: str) -> str | None:
    """Rule for the column whose header contains "WAF Status" or "WAF Detected"."""
    value = java_trim(text).lower()
    if not value:
        return None
    if any(word in value for word in ("not detected", "undetected", "bypassed", "not present")):
        return ROSE
    if any(word in value for word in ("detected", "present", "blocked")):
        return GREEN
    if any(word in value for word in ("unable", "unreachable", "failed")):
        return ORANGE
    return None


def severity_colour(text: str) -> str | None:
    """Rule for the column whose header contains "Severity"."""
    value = java_trim(text).lower()
    if value in ("syntax", "high_maybe"):
        return ORANGE
    if value == "strict_csp":
        return GREEN
    if "critical" in value or "high" in value:
        return ROSE
    if "medium" in value or "low" in value:
        return ORANGE
    if "info" in value:
        return GREEN
    return None


# --------------------------------------------------------------------------------------------- cell text & links

def cell_text(text: str) -> str:
    """Text as stored in the xlsx: illegal XML chars become '?' (POI behaviour) and the length is capped at
    32,767 UTF-16 units (POI throws instead)."""
    text = _ILLEGAL_XML.sub("?", text)
    if len(text) > _MAX_CELL_UNITS // 2 and len(text.encode("utf-16-le")) > 2 * _MAX_CELL_UNITS:
        text = text.encode("utf-16-le")[:2 * _MAX_CELL_UNITS].decode("utf-16-le", errors="ignore")
    return text


def link_for(text: str, warn: bool = True) -> str | None:
    """Hyperlink address for a URL cell: ``http(s)://`` text that ``java.net.URI`` accepts (else skipped)."""
    if not (text.startswith("http://") or text.startswith("https://")):
        return None
    if not is_java_uri(text):
        if warn:
            log.warning(f"Skipping hyperlink for malformed URL '{text}': Address of hyperlink must be a valid URI")
        return None
    return text


_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_HEX = frozenset("0123456789abcdefABCDEF")
_UNRESERVED = _ALNUM | frozenset("-_.!~*'()")
_PATH = _UNRESERVED | frozenset(":@&=+$,;/")
_URIC = _UNRESERVED | frozenset(";/?:@&=+$,[]")
_REG_NAME = _UNRESERVED | frozenset("$,;:@&=+")
_IPV6_AUTHORITY = re.compile(r"(?:[^@\[\]]*@)?\[([0-9A-Fa-f:.]+)(?:%[^\]]+)?\](?::[0-9]*)?")


def _valid_chars(text: str, allowed: frozenset[str]) -> bool:
    """``java.net.URI`` char scan: allowed ASCII, ``%hh`` escapes and visible non-ASCII; a bad escape is fatal."""
    position = 0
    while position < len(text):
        char = text[position]
        if char in allowed:
            position += 1
        elif char == "%":
            if not (position + 2 < len(text) and text[position + 1] in _HEX and text[position + 2] in _HEX):
                return False
            position += 3
        elif ord(char) > 128 and unicodedata.category(char) not in ("Cc", "Zs", "Zl", "Zp"):
            position += 1
        else:
            return False
    return True


def _valid_authority(authority: str) -> bool:
    """Registry-based authority, or a server authority with a bracketed IPv6 literal."""
    if _valid_chars(authority, _REG_NAME):
        return True
    match = _IPV6_AUTHORITY.fullmatch(authority)
    if match is None:
        return False
    try:
        ipaddress.IPv6Address(match.group(1))
    except ValueError:
        return False
    return True


def is_java_uri(address: str) -> bool:
    """Whether ``new java.net.URI(address)`` accepts an ``http(s)://`` address."""
    rest = address.split("://", 1)[1]
    end = min((rest.index(stop) for stop in "/?#" if stop in rest), default=len(rest))
    authority, rest = rest[:end], rest[end:]
    if authority:
        if not _valid_authority(authority):
            return False
    elif not rest:
        return False
    rest, has_fragment, fragment = rest.partition("#")
    path, has_query, query = rest.partition("?")
    return (_valid_chars(path, _PATH) and (not has_query or _valid_chars(query, _URIC))
            and (not has_fragment or _valid_chars(fragment, _URIC)))


# --------------------------------------------------------------------------------------------- sheet building

class CellFactory:
    """Builds cells of one worksheet; the five styles are registered once and shared (no per-row styles)."""

    def __init__(self, ws):
        self._ws = ws
        self._styles = {}
        for kind in (HEADER, BASE, GREEN, ROSE, ORANGE):
            prototype = Cell(ws)
            if kind == HEADER:
                prototype.font = _HEADER_FONT
                prototype.fill = _HEADER_FILL
                prototype.alignment = _HEADER_ALIGNMENT
            else:
                prototype.alignment = _DATA_ALIGNMENT
                if kind in _FILLS:
                    prototype.fill = _FILLS[kind]
            self._styles[kind] = prototype._style      # openpyxl StyleArray, copied by Cell(style_array=...)

    def cell(self, row: int, column: int, value, kind: str | None = None, link: str | None = None) -> Cell:
        cell = Cell(self._ws, row=row, column=column, value=value,
                    style_array=self._styles[kind] if kind is not None else None)
        if link is not None:
            cell.hyperlink = link
        return cell


def set_widths(ws, widths: list[float], best_fit: bool, collapsed: bool = False) -> None:
    """``<col>`` elements for autosized columns (``widths`` in chars, ``-1`` = no cell, column left untouched)."""
    for index, best in enumerate(widths):
        width = _autosize.column_width(best)
        if width is None:
            continue
        dimension = ws.column_dimensions[get_column_letter(index + 1)]
        dimension.width = width
        if best_fit:
            dimension.bestFit = True
        if collapsed:
            dimension.collapsed = True


def range_ref(columns: int, rows: int) -> str:
    """POI ``CellRangeAddress(0, rows - 1, 0, columns - 1).formatAsString()``."""
    last = f"{get_column_letter(max(1, columns))}{max(1, rows)}"
    return "A1" if last == "A1" else f"A1:{last}"


def open_workbook(path: str, read_only: bool = False) -> Workbook:
    """openpyxl load without the warning about POI files having no default cell style."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", "Workbook contains no default style")
        return load_workbook(path, read_only=read_only)


def save_atomic(path: str, suffix: str, build: Callable[[], Workbook]) -> None:
    """Write the workbook returned by ``build`` to ``path + suffix`` and move it over ``path`` (Java: delete the
    original, then atomic move). The temp file is opened first, so an unwritable location fails before any
    sheet data is streamed."""
    temp = path + suffix
    try:
        with open(temp, "wb") as handle:
            build().save(handle)
        try:
            os.replace(temp, path)
        except PermissionError as exc:
            raise OSError(f"Failed to delete original Excel file before rename: {path}") from exc
    finally:
        if os.path.exists(temp):
            with contextlib.suppress(OSError):
                os.remove(temp)
