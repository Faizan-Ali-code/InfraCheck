"""Header-analysis SQLite store, Excel export and stats sheets (Java ``ao``/``ap``/``ak``/``InfraChecker.b``).
"""
from __future__ import annotations

import atexit
import os
import re
import sqlite3
import threading
import time
from decimal import ROUND_HALF_UP, Decimal

from openpyxl import Workbook

from .. import config
from ..config import HEADER_COLUMNS, HEADER_STATS_COLUMNS, OWNERSHIP_STATS_COLUMNS, RESULT_SHEET
from ..javacompat.strings import java_exception_text, java_trim
from ..log import log
from ..models import HeaderRow
from . import _autosize, _locks, _xlsx

_CREATE_TABLE = ("CREATE TABLE IF NOT EXISTS header_results (url TEXT, host TEXT, ip TEXT, ipType TEXT, "
                 "ownership TEXT, header TEXT, value TEXT, statusCode INTEGER, vulnerabilityStatus TEXT, "
                 "recommendation TEXT, severity TEXT, details TEXT, justification TEXT, responseBody TEXT)")
_INSERT = "INSERT INTO header_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
# Java has no ORDER BY (rowid order in practice); CAST mirrors JDBC getInt on the status code.
_EXPORT_QUERY = ("SELECT url, host, ip, ipType, ownership, header, value, CAST(statusCode AS INTEGER), "
                 "vulnerabilityStatus, recommendation, severity, details, justification, responseBody "
                 "FROM header_results ORDER BY rowid")

# Stats queries, verbatim from Java InfraChecker.b(String).
_TOTAL_QUERY = ("SELECT COUNT(DISTINCT host) AS total_vulnerable_urls\r\nFROM header_results\r\n"
                "WHERE vulnerabilityStatus IN ('Vulnerable', 'Deprecated')\r\n  AND COALESCE(TRIM(header), '') <> '';")
_HEADER_QUERY = (
    "SELECT\r\n  all_headers.normalized_header AS normalized_header,\r\n"
    "  COALESCE(vuln_counts.header_count, 0) AS header_count\r\nFROM (\r\n  SELECT DISTINCT\r\n      CASE\r\n"
    "          WHEN LOWER(TRIM(header)) IN ('banner grabbing header', 'banner grabbing') THEN 'banner grabbing'\r\n"
    "          ELSE LOWER(TRIM(header))\r\n      END AS normalized_header\r\n  FROM header_results\r\n"
    "  WHERE COALESCE(TRIM(header), '') <> ''\r\n) all_headers\r\nLEFT JOIN (\r\n  SELECT\r\n      CASE\r\n"
    "          WHEN LOWER(TRIM(header)) IN ('banner grabbing header', 'banner grabbing') THEN 'banner grabbing'\r\n"
    "          ELSE LOWER(TRIM(header))\r\n      END AS normalized_header,\r\n"
    "      COUNT(DISTINCT host) AS header_count\r\n  FROM header_results\r\n"
    "  WHERE vulnerabilityStatus IN ('Vulnerable', 'Deprecated')\r\n    AND COALESCE(TRIM(header), '') <> ''\r\n"
    "  GROUP BY\r\n      CASE\r\n"
    "          WHEN LOWER(TRIM(header)) IN ('banner grabbing header', 'banner grabbing') THEN 'banner grabbing'\r\n"
    "          ELSE LOWER(TRIM(header))\r\n      END\r\n) vuln_counts\r\n"
    "ON all_headers.normalized_header = vuln_counts.normalized_header\r\n"
    "ORDER BY COALESCE(vuln_counts.header_count, 0) DESC, all_headers.normalized_header;")
_OWNER_QUERY = (
    "SELECT\r\n  CASE\r\n    WHEN COALESCE(TRIM(ownership), '') = '' THEN 'Unknown'\r\n    ELSE TRIM(ownership)\r\n"
    "  END AS ownership_name,\r\n  COUNT(DISTINCT host) AS ownership_count\r\nFROM header_results\r\n"
    "WHERE vulnerabilityStatus IN ('Vulnerable', 'Deprecated')\r\n  AND COALESCE(TRIM(header), '') <> ''\r\n"
    "GROUP BY\r\n  CASE\r\n    WHEN COALESCE(TRIM(ownership), '') = '' THEN 'Unknown'\r\n    ELSE TRIM(ownership)\r\n"
    "  END\r\nORDER BY ownership_count DESC, ownership_name;")

_HEADER_STATS_SHEET = "Header Stats"
_TEAMWISE_STATS_SHEET = "Teamwise Stats"
_TOTAL_LABEL = "Total Distinct Vulnerable Domains"


# --------------------------------------------------------------------------------------------- SQLite writer

def _sql_value(value):
    """Strings with lone surrogates are stored with '?' (Java's UTF-8 encoder); sqlite3 would raise."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return value.encode("utf-8", errors="replace").decode("utf-8")
    return value


def _delete_side_files(path: str, deleted: str, failed: str) -> None:
    for kind, suffix in (("WAL", "-wal"), ("SHM", "-shm")):
        side = os.path.abspath(path + suffix)
        if os.path.exists(side):
            try:
                os.remove(side)
                log.info(deleted.format(kind=kind, path=side))
            except OSError:
                log.warning(failed.format(kind=kind, path=side))


class _DbWriter:
    """One open header DB (Java ``ap``): WAL journal, insert + commit per row."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, check_same_thread=False)
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute(_CREATE_TABLE)
            columns = {row[1].lower() for row in self._connection.execute("PRAGMA table_info(header_results)")}
            if "responsebody" not in columns:
                self._connection.execute("ALTER TABLE header_results ADD COLUMN responseBody TEXT")
            self._connection.commit()
        except sqlite3.Error:
            self._connection.close()
            raise

    def insert(self, row: HeaderRow) -> None:
        values = [_sql_value(value) for value in row.as_tuple()]
        if values[13] is None:
            values[13] = ""
        with self._lock:
            try:
                self._connection.execute(_INSERT, values)
                self._connection.commit()
            except sqlite3.Error:
                try:
                    self._connection.rollback()
                except sqlite3.Error as exc:
                    log.warning(f"Rollback failed after insert error for DB -> {self.path} : "
                                f"{java_exception_text(exc)}", exc_info=exc)
                raise

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.execute("PRAGMA wal_checkpoint(RESTART)")
            except sqlite3.Error as exc:
                log.warning(f"WAL checkpoint failed for DB -> {self.path} (WAL file may remain): "
                            f"{java_exception_text(exc)}", exc_info=exc)
            try:
                self._connection.close()
            except sqlite3.Error as exc:
                log.warning(f"Failed to close SQLite connection for DB -> {self.path} : {java_exception_text(exc)}",
                            exc_info=exc)
        time.sleep(0.1)
        _delete_side_files(self.path, "Successfully deleted {kind} file: {path}",
                           "Failed to delete {kind} file (file may be in use): {path}")


_registry: dict[str, _DbWriter] = {}
_registry_lock = threading.Lock()
_exit_hook_registered = False


def _writer_for(sqlite_path: str) -> _DbWriter:
    global _exit_hook_registered
    key = _locks.path_key(sqlite_path)
    writer = _registry.get(key)
    if writer is None:
        with _registry_lock:
            writer = _registry.get(key)
            if writer is None:
                writer = _registry[key] = _DbWriter(sqlite_path)
                if not _exit_hook_registered:
                    atexit.register(close_all)
                    _exit_hook_registered = True
    return writer


def insert(sqlite_path: str, row: HeaderRow) -> None:
    """Raw insert into table ``header_results`` (WAL, commit per row). No normalisation, no dedup. Thread-safe."""
    _writer_for(sqlite_path).insert(row)


def close(sqlite_path: str) -> None:
    """Checkpoint + close the DB for this path and delete its -wal/-shm files (Java ``ai.e``). No-op if not open."""
    if not java_trim(sqlite_path):
        return
    with _registry_lock:
        writer = _registry.pop(_locks.path_key(sqlite_path), None)
        if writer is not None:
            writer.close()
    if writer is not None:
        time.sleep(0.05)
    _delete_side_files(sqlite_path, "Cleaned up remaining {kind} file: {path}",
                       "Unable to delete remaining {kind} file (still locked?): {path}")


def close_all() -> None:
    """Close every open header DB (Java ``ao.a()``, also the shutdown hook)."""
    with _registry_lock:
        writers = list(_registry.values())
        _registry.clear()
        for writer in writers:
            writer.close()
        if writers:
            time.sleep(0.05)
        for writer in writers:
            _delete_side_files(writer.path, "Cleaned up remaining {kind} file: {path}",
                               "Unable to delete remaining {kind} file (still locked?): {path}")


# --------------------------------------------------------------------------------------------- Excel export

_exports: dict[str, tuple[int, int]] = {}   # xlsx written by export_to_xlsx -> (mtime_ns, size) right after it


def _signature(path: str) -> tuple[int, int] | None:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _text(value) -> str:
    """JDBC ``getString`` with null -> ""."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else str(value)


def _record_texts(record: tuple) -> list[str]:
    """Cell texts of one DB row as POI formats them (status code: General number format)."""
    texts = [_text(value) for value in record]
    texts[7] = str(record[7] or 0)
    return texts


def _record_cells(factory: _xlsx.CellFactory, number: int, record: tuple, warn: bool) -> list:
    texts = _record_texts(record)
    cells = []
    for index, text in enumerate(texts):
        kind = _xlsx.BASE
        if index == 8:
            kind = _xlsx.status_colour(text) or kind
        elif index == 10:
            kind = _xlsx.severity_colour(text) or kind
        value = float(record[7] or 0) if index == 7 else _xlsx.cell_text(text)
        link = _xlsx.link_for(text, warn) if index == 0 else None
        cells.append(factory.cell(number, index + 1, value, kind, link))
    return cells


def _add_results_sheet(wb: Workbook, sqlite_path: str, warn: bool = True) -> int:
    """Sheet ``Result ver 4.3.8`` from the DB in two passes (widths first: ``<cols>`` precede the rows)."""
    try:
        connection = sqlite3.connect(sqlite_path)
        try:
            widths = [_autosize.text_width(name, bold=True) for name in HEADER_COLUMNS]
            for record in connection.execute(_EXPORT_QUERY):
                for index, text in enumerate(_record_texts(record)):
                    if not _autosize.is_capped(widths[index]):
                        widths[index] = max(widths[index], _autosize.text_width(text))
            ws = wb.create_sheet(RESULT_SHEET)
            ws.sheet_view.tabSelected = True
            factory = _xlsx.CellFactory(ws)
            _xlsx.set_widths(ws, widths, best_fit=False)
            ws.freeze_panes = "A2"
            ws.append([factory.cell(1, index, name, _xlsx.HEADER) for index, name in enumerate(HEADER_COLUMNS, 1)])
            count = 0
            for count, record in enumerate(connection.execute(_EXPORT_QUERY), start=1):
                ws.append(_record_cells(factory, count + 1, record, warn))
            ws.auto_filter.ref = _xlsx.range_ref(len(HEADER_COLUMNS), count + 1)
            return count
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise OSError(f"Failed to read header results from SQLite for Excel export: {exc}") from exc


def export_to_xlsx(xlsx_path: str) -> int:
    """Stream ``<xlsx>.sqlite`` into ``xlsx_path`` (sheet ``Result ver 4.3.8``). Returns the number of data rows."""
    sqlite_path = config.sqlite_path_for(xlsx_path)
    with _locks.lock_for(xlsx_path):
        if not os.path.isfile(sqlite_path) or os.path.getsize(sqlite_path) == 0:
            log.info(f"SQLite DB not found or empty at '{sqlite_path}'. Skipping Excel export.")
            return 0
        log.info(f"Starting bulk export from SQLite '{sqlite_path}' to Excel '{xlsx_path}'")
        count = 0

        def build() -> Workbook:
            nonlocal count
            wb = Workbook(write_only=True)
            count = _add_results_sheet(wb, sqlite_path)
            log.info(f"Total data rows exported from SQLite to Excel: {count}")
            return wb

        _xlsx.save_atomic(xlsx_path, ".export.tmp", build)
        _exports[_locks.path_key(xlsx_path)] = _signature(xlsx_path)
        log.info(f"Excel export completed successfully: {xlsx_path}")
        return count


# --------------------------------------------------------------------------------------------- stats

def _java_percent(value: float) -> str:
    """Java ``String.format("%.2f%%", value)``: HALF_UP on the shortest decimal representation."""
    return f"{Decimal(repr(value)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%"


def _stats_rows(entries: list[tuple[str, int]], total: int, signals: tuple[str, str, str],
                banner_note: bool) -> list[list]:
    rows = []
    for name, count in entries:
        percent = 0.0 if total <= 0 else count * 100.0 / total
        signal = signals[0] if percent >= 50 else signals[1] if percent >= 20 else signals[2]
        if banner_note and name.lower() == "banner grabbing":
            signal += "; validate version exposure impact"
        rows.append([name, count, _java_percent(percent), signal])
    return rows


def _add_stats_sheet(wb: Workbook, title: str, columns: list[str], rows: list[list], total: int,
                     baseline: str) -> None:
    """A stats sheet: header, data rows, one empty row, the total row (data cells unstyled)."""
    body = rows + [None, [_TOTAL_LABEL, total, "100.00%" if total > 0 else "0.00%", baseline]]
    widths = [_autosize.text_width(name, bold=True) for name in columns]
    for row in filter(None, body):
        for index, value in enumerate(row):
            widths[index] = max(widths[index], _autosize.text_width(str(value)))
    ws = wb.create_sheet(title)
    factory = _xlsx.CellFactory(ws)
    _xlsx.set_widths(ws, widths, best_fit=True)
    ws.freeze_panes = "A2"
    ws.append([factory.cell(1, index, name, _xlsx.HEADER) for index, name in enumerate(columns, 1)])
    for row in body:
        ws.append([] if row is None else [_xlsx.cell_text(row[0]), float(row[1]), row[2], row[3]])
    ws.auto_filter.ref = _xlsx.range_ref(len(columns), len(body) + 1)


def _workbook_for_stats(xlsx_path: str, sqlite_path: str) -> Workbook:
    """Workbook to add the stats sheets to (Java reloads the xlsx; a missing/empty file gives a new workbook).

    A file still exactly as :func:`export_to_xlsx` wrote it is rebuilt by streaming the DB again instead of loading
    it (same content, without holding the whole sheet in memory).
    """
    exported = _exports.get(_locks.path_key(xlsx_path))
    if exported is not None and exported == _signature(xlsx_path):
        wb = Workbook(write_only=True)
        _add_results_sheet(wb, sqlite_path, warn=False)
        return wb
    if not os.path.isfile(xlsx_path) or os.path.getsize(xlsx_path) == 0:
        return Workbook(write_only=True)
    try:
        wb = _xlsx.open_workbook(xlsx_path)
    except Exception as exc:
        log.warning(f"Workbook at ->'{xlsx_path}' is corrupt or unreadable. Skipping stats sheet write to preserve "
                    f"existing data. Error: {exc}")
        raise OSError(f"Workbook at '{xlsx_path}' is corrupt or unreadable. Header Stats sheet not written.") from exc
    for title in (_HEADER_STATS_SHEET, _TEAMWISE_STATS_SHEET):
        if title in wb.sheetnames:
            wb.remove(wb[title])
    return wb


def _write_stats_sheets(xlsx_path: str, sqlite_path: str, total: int, headers: list[tuple[str, int]],
                        owners: list[tuple[str, int]]) -> None:
    if not xlsx_path.lower().endswith(".xlsx"):
        return

    def build() -> Workbook:
        wb = _workbook_for_stats(xlsx_path, sqlite_path)
        _add_stats_sheet(wb, _HEADER_STATS_SHEET, HEADER_STATS_COLUMNS,
                         _stats_rows(headers, total, ("High prevalence", "Moderate prevalence", "Low prevalence"),
                                     banner_note=True),
                         total, "Baseline denominator for coverage percentage.")
        teams = [(java_trim(name) or "Unknown", count) for name, count in owners]
        _add_stats_sheet(wb, _TEAMWISE_STATS_SHEET, OWNERSHIP_STATS_COLUMNS,
                         _stats_rows(teams, total, ("High concentration", "Moderate concentration",
                                                    "Low concentration"), banner_note=False),
                         total, "Baseline denominator for ownership coverage percentage.")
        return wb

    with _locks.lock_for(xlsx_path):
        _xlsx.save_atomic(xlsx_path, ".stats.tmp", build)
        _exports.pop(_locks.path_key(xlsx_path), None)


def _query_stats(sqlite_path: str) -> tuple[int, list[tuple[str, int]], list[tuple[str, int]]]:
    connection = sqlite3.connect(sqlite_path)
    try:
        row = connection.execute(_TOTAL_QUERY).fetchone()
        total = int(row[0] or 0) if row else 0
        headers = [(_text(name), int(count or 0)) for name, count in connection.execute(_HEADER_QUERY)
                   if java_trim(_text(name))]
        owners = [(_text(name) if java_trim(_text(name)) else "Unknown", int(count or 0))
                  for name, count in connection.execute(_OWNER_QUERY)]
    finally:
        connection.close()
    return total, headers, owners


def _collapse(query: str) -> str:
    return re.sub(r"\s+", " ", query)


def write_stats(xlsx_path: str) -> None:
    """Run the 3 stats queries on ``<xlsx>.sqlite``, log them like Java, add 'Header Stats' + 'Teamwise Stats'."""
    sqlite_path = config.sqlite_path_for(xlsx_path)
    try:
        total, headers, owners = _query_stats(sqlite_path)
    except sqlite3.Error as exc:
        log.error(f"Failed to read header analysis summary from SQLite DB -> {sqlite_path} : "
                  f"{java_exception_text(exc)}", exc_info=exc)
        return
    print("\n")
    try:
        _write_stats_sheets(xlsx_path, sqlite_path, total, headers, owners)
    except OSError as exc:
        log.error(f"Failed to write header stats sheet to Excel -> {xlsx_path} : {java_exception_text(exc)}",
                  exc_info=exc)
        return
    if headers:
        print("Please find below the header wise stats:\n\n", end="")
        log.info("Query -> " + _collapse(_HEADER_QUERY))
        log.info("Columns -> " + ", ".join(name for name, _ in headers))
        log.info("Column Values -> " + ", ".join(str(count) for _, count in headers) + ",")
        log.info(f"Total distinct vulnerable domains used for coverage denominator -> {total}")
    if owners:
        print("Please find below the ownership wise stats:\n\n", end="")
        log.info("Teamwise Stats Query -> " + _collapse(_OWNER_QUERY))
        log.info("Teamwise Stats Columns -> " + ", ".join(name for name, _ in owners))
        log.info("Teamwise Stats Values -> " + ", ".join(str(count) for _, count in owners) + ",")
        log.info(f"Total distinct vulnerable domains used for teamwise coverage denominator -> {total}")
