"""IP/CSP ownership and ignored-domain reference data (Java ``an`` + ownership part of ``am``).
"""
from __future__ import annotations

import io
import threading
import traceback
from dataclasses import dataclass, field

import xlrd

from .. import config
from ..javacompat.strings import java_trim
from ..log import log, thread_name, tinfo, ts

_CSP_HEADERS = ("content-security-policy-report-only", "content-security-policy")


@dataclass
class ReferenceData:
    ip_owner: dict[str, str] = field(default_factory=dict)
    csp_owner: dict[str, str] = field(default_factory=dict)
    ignored_domains: set[str] = field(default_factory=set)


class _NotAStringCell(ValueError):
    """POI ``IllegalStateException`` from ``getStringCellValue()`` on a numeric/boolean/error cell."""


_POI_CELL_TYPES = {xlrd.XL_CELL_NUMBER: "NUMERIC", xlrd.XL_CELL_DATE: "NUMERIC", xlrd.XL_CELL_BOOLEAN: "BOOLEAN",
                   xlrd.XL_CELL_ERROR: "ERROR"}


def _string_value(sheet, row: int, column: int) -> str:
    """POI ``getStringCellValue().trim()``: text as is, blank cell -> "", any other type throws."""
    cell_type = sheet.cell_type(row, column)
    if cell_type in _POI_CELL_TYPES:
        raise _NotAStringCell(f"Cannot get a STRING value from a {_POI_CELL_TYPES[cell_type]} cell")
    return java_trim(sheet.cell_value(row, column) if cell_type == xlrd.XL_CELL_TEXT else "")


def _load_ownership(path: str, label: str) -> dict[str, str]:
    """Column A -> column B of the first sheet, every row (header included), last duplicate wins.

    Rows missing A or B are skipped; reading stops at the first non-text cell (the rows read so far are kept).
    """
    tinfo(f"Going to check the {label} file from path ->'{path}'")
    owners: dict[str, str] = {}
    try:
        with open(path, "rb") as handle:
            content = handle.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        log.error(f"{ts()} {thread_name()} {label} file not found at path ->'{path}'")
        return owners
    try:
        book = xlrd.open_workbook(file_contents=content, formatting_info=True, logfile=io.StringIO())
        sheet = book.sheet_by_index(0)
        for row in range(sheet.nrows):
            if sheet.row_len(row) < 2 or xlrd.XL_CELL_EMPTY in (sheet.cell_type(row, 0), sheet.cell_type(row, 1)):
                continue
            key = _string_value(sheet, row, 0)
            owners[key] = _string_value(sheet, row, 1)
    except Exception:  # Java: printStackTrace() and keep what was read
        traceback.print_exc()
    return owners


def _load_ignored(path: str) -> set[str]:
    """Non-empty, non-comment lines, trimmed and lower-cased."""
    tinfo(f"Going to check the ignored-domains file from path ->'{path}'")
    domains: set[str] = set()
    if not java_trim(path):
        return domains
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = java_trim(line)
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    except FileNotFoundError:
        log.warning(f"{ts()} {thread_name()} Ignored-domains file not found at path ->'{path}'. "
                    "Treating list as empty.")
    except OSError as exc:
        log.error(f"{ts()} {thread_name()} Failed to read ignored-domains file at path ->'{path}': {exc}")
    return domains


def load() -> ReferenceData:
    """Read IP-Ownership.xls, CSP-Ownership.xls and ignored-domains.txt (with the Java log lines)."""
    return ReferenceData(ip_owner=_load_ownership(config.IP_OWNERSHIP_FILE, "IP-Ownership.xls"),
                         csp_owner=_load_ownership(config.CSP_OWNERSHIP_FILE, "CSP-Ownership.xls"),
                         ignored_domains=_load_ignored(config.IGNORED_DOMAINS_FILE))


_lock = threading.Lock()
_current: ReferenceData | None = None


def get() -> ReferenceData:
    """The data loaded for the current run (loads on first use)."""
    global _current
    with _lock:
        if _current is None:
            _current = load()
        return _current


def reload() -> ReferenceData:
    """Re-read the files; called at the start of every header-analysis run."""
    global _current
    data = load()
    with _lock:
        _current = data
    return data


def ownership_for(ip: str, header: str, override: str | None, data: ReferenceData) -> str:
    """Ownership column value (section 4.3): override > CSP map (CSP headers) > IP map > 'Unknown'."""
    owner = data.ip_owner.get(ip, "Unknown")
    if header is not None and header.lower() in _CSP_HEADERS:
        owner = data.csp_owner.get(ip, "") or owner
    if override is not None and java_trim(override):
        owner = java_trim(override)
    return owner
