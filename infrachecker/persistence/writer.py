"""Result writer (Java ``ai.a(path,row)`` + ``ak`` append mode).

Every analysis except Headers appends tab-separated rows to its ``.xlsx``. Java re-read and re-wrote the whole
workbook per row; here each open workbook is kept in memory and rewritten atomically (``path + ".tmp"`` then
``os.replace``) from a snapshot of its rows, at most every couple of seconds and always in :func:`flush_all`.
Appending threads never wait for a rewrite. The file is the one Java would produce: same sheet, values, styles,
colours, hyperlinks, freeze pane, autofilter and widths.
"""
from __future__ import annotations

import atexit
import os
import threading
import time
from dataclasses import dataclass

from openpyxl import Workbook

from ..config import RESULT_SHEET
from ..javacompat.strings import java_exception_text, java_trim
from ..log import log
from . import _autosize, _locks, _xlsx

_MIN_SAVE_INTERVAL = 2.0     # seconds between rewrites of one workbook (grows with the workbook's write time)

_guard = threading.Lock()
_books: dict[str, _ResultBook] = {}
_exit_hook_registered = False


@dataclass(frozen=True)
class _Row:
    values: list[str]            # cell texts as stored (sanitised / truncated)
    kinds: list[str | None]      # style per cell (None = unstyled)
    link: str | None             # hyperlink of the URL column


@dataclass(frozen=True)
class _Snapshot:
    rows: list[_Row]
    widths: list[float]
    columns: int
    url_column: int


def _unquote(field: str) -> str:
    """Java: a field wrapped in double quotes loses them and ``""`` becomes ``"``."""
    if len(field) >= 2 and field.startswith('"') and field.endswith('"'):
        return field[1:-1].replace('""', '"')
    return field


def _looks_like_header(fields: list[str]) -> bool:
    for field in fields:
        text = java_trim(field).lower()
        if text == "url" or "status" in text or "severity" in text or "payload" in text:
            return True
    return False


def _find_column(header: list[str], *needles: str) -> int:
    """First column whose header text (trimmed, lower-case) contains one of ``needles``; -1 if none."""
    for index, text in enumerate(header):
        text = java_trim(text).lower()
        if any(needle.lower() in text for needle in needles):
            return index
    return -1


def _workbook(snapshot: _Snapshot) -> Workbook:
    wb = Workbook(write_only=True)
    ws = wb.create_sheet(RESULT_SHEET)
    ws.sheet_view.tabSelected = True
    factory = _xlsx.CellFactory(ws)
    _xlsx.set_widths(ws, snapshot.widths, best_fit=True, collapsed=True)
    ws.freeze_panes = "A2"
    for number, row in enumerate(snapshot.rows, start=1):
        ws.append([factory.cell(number, column, value, kind, row.link if column - 1 == snapshot.url_column else None)
                   for column, (value, kind) in enumerate(zip(row.values, row.kinds), start=1)])
    ws.auto_filter.ref = _xlsx.range_ref(snapshot.columns, len(snapshot.rows))
    return wb


class _ResultBook:
    """In-memory state of one append-mode result workbook. Rows are added under the path lock; writes are
    serialised by the book's own lock."""

    def __init__(self, path: str):
        self.path = path
        self.saved_once = False
        self._rows: list[_Row] = []
        self._written = 0                    # rows in the file on disk
        self._columns = 0                    # header width (Java: header row lastCellNum)
        self._autosized = 0
        self._status = self._waf = self._severity = self._url = -1
        self._settled: list[float] = []      # widths of every row but the last, measured on the stored text
        self._latest: list[float] = []       # widths of the last row, measured on the raw text (like POI)
        self._latest_stored: list[float] = []
        self._next_save = 0.0
        self._write_lock = threading.Lock()

    @property
    def dirty(self) -> bool:
        return self._written < len(self._rows)

    def add(self, raw_fields: list[str], texts: list[str], warn: bool = True) -> None:
        """Add one row, built and styled as Java ``ak.a(path, row)`` does."""
        link = None
        if not self._rows:
            header = _looks_like_header(raw_fields)
            kinds: list[str | None] = [_xlsx.HEADER if header else None] * len(texts)
            self._configure(texts)
        else:
            kinds = [_xlsx.BASE if index < self._columns else None for index in range(len(texts))]
            if 0 <= self._url < len(texts):
                link = _xlsx.link_for(java_trim(texts[self._url]), warn)
            for index, rule in ((self._status, _xlsx.status_colour), (self._waf, _xlsx.waf_colour),
                                (self._severity, _xlsx.severity_colour)):
                if 0 <= index < len(texts):
                    kinds[index] = rule(texts[index]) or kinds[index]
        values = [_xlsx.cell_text(text) for text in texts]
        self._measure(texts, values, kinds)
        self._rows.append(_Row(values, kinds, link))

    def mark_written(self) -> None:
        """The rows added so far are already in the file (seeded from it)."""
        self._written = len(self._rows)
        self.saved_once = True

    def _configure(self, header: list[str]) -> None:
        self._columns = max(1, len(header))
        self._autosized = min(self._columns - 1, 8) + 1
        self._status = _find_column(header, "Vulnerability Status")
        self._waf = _find_column(header, "WAF Status", "WAF Detected")
        self._severity = _find_column(header, "Severity")
        self._url = _find_column(header, "URL")
        self._settled = [-1.0] * self._autosized
        self._latest = [-1.0] * self._autosized
        self._latest_stored = [-1.0] * self._autosized

    def _measure(self, texts: list[str], values: list[str], kinds: list[str | None]) -> None:
        self._settled = [max(a, b) for a, b in zip(self._settled, self._latest_stored)]
        for column in range(self._autosized):
            raw = stored = -1.0
            if column < len(texts) and not _autosize.is_capped(self._settled[column]):
                bold = kinds[column] == _xlsx.HEADER
                raw = _autosize.text_width(texts[column], bold)
                stored = raw if values[column] == texts[column] else _autosize.text_width(values[column], bold)
            self._latest[column] = raw
            self._latest_stored[column] = stored

    def snapshot(self, only_if_due: bool = False) -> _Snapshot | None:
        """Rows and widths to write (caller holds the path lock); ``None`` if nothing is due."""
        if not self.dirty or (only_if_due and self.saved_once and time.monotonic() < self._next_save):
            return None
        self._next_save = float("inf")       # no other snapshot until this write is done
        return _Snapshot(list(self._rows), [max(a, b) for a, b in zip(self._settled, self._latest)],
                         self._columns, self._url)

    def write(self, snapshot: _Snapshot) -> None:
        with self._write_lock:
            started = time.monotonic()
            try:
                if len(snapshot.rows) > self._written:
                    _xlsx.save_atomic(self.path, ".tmp", lambda: _workbook(snapshot))
                    self._written = len(snapshot.rows)
                    self.saved_once = True
            finally:
                finished = time.monotonic()
                self._next_save = finished + max(_MIN_SAVE_INTERVAL, 4 * (finished - started))


def _read_existing(path: str) -> list[list[str]]:
    """Rows of an existing result workbook (first sheet) as strings; unreadable -> Java's warning + error."""
    try:
        wb = _xlsx.open_workbook(path, read_only=True)
        try:
            rows = []
            for values in wb.worksheets[0].iter_rows(values_only=True) if wb.worksheets else ():
                values = list(values)
                while values and values[-1] is None:
                    values.pop()
                rows.append(["" if v is None else str(int(v)) if isinstance(v, float) and v.is_integer()
                             else str(v) for v in values])
            return rows
        finally:
            wb.close()
    except Exception as exc:
        log.warning(f"Workbook at ->'{path}' is corrupt or unreadable. Skipping row to preserve existing data. "
                    f"Error: {exc}")
        raise OSError(f"Workbook at '{path}' is corrupt or unreadable. Row not written.") from exc


def _book_for(path: str) -> _ResultBook:
    """The in-memory workbook of ``path`` (caller holds the path lock), seeded from the file if it exists."""
    global _exit_hook_registered
    key = _locks.path_key(path)
    with _guard:
        book = _books.get(key)
    if book is not None:
        return book
    book = _ResultBook(path)
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        for values in _read_existing(path):
            book.add(values, values, warn=False)
        book.mark_written()
    with _guard:
        _books[key] = book
        if not _exit_hook_registered:
            atexit.register(flush_all)
            _exit_hook_registered = True
    return book


def append_row(path: str, row: str) -> None:
    """Append one tab-separated row.

    ``.xlsx`` (case-insensitive): append to sheet ``Result ver 4.3.8`` (header detection, colouring, hyperlinks,
    freeze A2, autofilter, autosize); the file is rewritten atomically, throttled, and always on :func:`flush_all`.
    Any other path: append ``row + "\\r\\n"`` as UTF-8 text (HTML evidence files).
    Thread-safe; one lock per path.
    """
    with _locks.lock_for(path):
        if not path.lower().endswith(".xlsx"):
            with open(path, "a", encoding="utf-8", errors="replace", newline="") as handle:
                handle.write(("null" if row is None else row) + "\r\n")
            return
        book = _book_for(path)
        fields = (row or "").split("\t")
        book.add(fields, [_unquote(field) for field in fields])
        snapshot = book.snapshot(only_if_due=True)
        first_write = not book.saved_once
    if snapshot is None:
        return
    try:
        book.write(snapshot)
    except OSError as exc:
        if first_write:                      # e.g. missing results folder: fail like Java
            raise
        log.warning(f"Workbook at ->'{path}' could not be written; rows are kept for the next write. "
                    f"Error: {java_exception_text(exc)}")


def init_output(path: str, columns: list[str]) -> None:
    """Write the header row of a result workbook (``append_row(path, "\\t".join(columns))``)."""
    append_row(path, "\t".join(columns))


def flush_all() -> None:
    """Write every workbook that has rows not yet on disk. Called at the end of every run."""
    with _guard:
        books = list(_books.values())
    for book in books:
        with _locks.lock_for(book.path):
            snapshot = book.snapshot()
        if snapshot is None:
            continue
        try:
            book.write(snapshot)
        except OSError as exc:
            log.error(f"Failed to write result workbook ->'{book.path}' : {java_exception_text(exc)}")


def reset() -> None:
    """Flush, then forget the per-run in-memory workbooks. Called at the start of every run."""
    flush_all()
    with _guard:
        _books.clear()
