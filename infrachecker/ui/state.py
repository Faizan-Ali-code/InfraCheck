"""Thread-safe state shared by scan threads and the GUI thread (the Java atomics and concurrent queues).

Worker threads only write here; the GUI drains it on its 250 ms refresh tick.
"""
from __future__ import annotations

import re
import threading
from collections import deque
from dataclasses import dataclass

from ..progress import ProgressListener

QUEUED = "Queued"
RUNNING = "Running"
COMPLETED = "Completed"
FAILED = "Failed"

_TEXT_AREA_INVALID = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # JavaFX TextArea drops these (incl. \r)


@dataclass
class UrlRow:
    """One row of the URL Processing Status table. ``status`` is changed on the GUI thread only."""

    thread: str
    url: str
    status: str = QUEUED


@dataclass(frozen=True)
class Counters:
    total: int
    completed: int
    success: int
    failed: int
    active: int
    pool_size: int
    queued: int
    running: tuple[str, ...]


class RunState(ProgressListener):
    """Progress listener of a GUI run (Java ``ui.a``): counters, new rows and pending status changes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._total = self._completed = self._success = self._failed = 0
            self._active = self._pool_size = self._queued = 0
            self._running: dict[str, None] = {}
            self._rows: dict[str, UrlRow] = {}
            self._new_rows: deque[UrlRow] = deque()
            self._statuses: dict[str, str] = {}

    def preset_total(self, total: int) -> None:
        """Line count of urls.txt, shown until the orchestrator reports the de-duplicated total."""
        with self._lock:
            self._total = total
            self._queued = total

    # ---------------------------------------------------------------- listener events (worker threads)

    def run_started(self, analysis: int, total_urls: int, pool_size: int) -> None:
        with self._lock:
            self._total = total_urls
            self._pool_size = pool_size
            self._queued = total_urls

    def url_queued(self, thread_name: str, url: str) -> None:
        row = UrlRow(thread_name, url)
        with self._lock:
            self._rows[thread_name] = row
            self._new_rows.append(row)

    def url_started(self, thread_name: str, url: str) -> None:
        with self._lock:
            self._running[thread_name] = None
            self._update_load()
            self._statuses[thread_name] = RUNNING

    def url_finished(self, thread_name: str, url: str, success: bool) -> None:
        with self._lock:
            self._running.pop(thread_name, None)
            self._completed += 1
            if success:
                self._success += 1
            else:
                self._failed += 1
            self._update_load()
            self._statuses[thread_name] = COMPLETED if success else FAILED

    def heartbeat(self, done: int, total: int, active: int, queued: int, completed_by_pool: int) -> None:
        with self._lock:
            self._completed = done
            self._active = active
            self._queued = queued

    def run_finished(self) -> None:
        with self._lock:
            self._active = 0
            self._queued = 0
            self._running.clear()

    def _update_load(self) -> None:
        self._active = len(self._running)
        self._queued = max(0, self._total - self._completed - len(self._running))

    # ---------------------------------------------------------------- GUI thread

    def take_new_rows(self, limit: int | None) -> list[UrlRow]:
        """Pop up to ``limit`` queued rows (all when ``None``), applying any status already reported for them."""
        rows: list[UrlRow] = []
        with self._lock:
            while self._new_rows and (limit is None or len(rows) < limit):
                row = self._new_rows.popleft()
                status = self._statuses.pop(row.thread, None)
                if status is not None:
                    row.status = status
                rows.append(row)
        return rows

    def apply_statuses(self, limit: int | None) -> list[UrlRow]:
        """Apply up to ``limit`` pending status changes (all when ``None``); returns the changed rows."""
        changed: list[UrlRow] = []
        with self._lock:
            names = list(self._statuses)[:limit]
            for name in names:
                status = self._statuses.pop(name)
                row = self._rows.get(name)
                if row is not None:
                    row.status = status
                    changed.append(row)
        return changed

    def counters(self) -> Counters:
        with self._lock:
            return Counters(self._total, self._completed, self._success, self._failed, self._active,
                            self._pool_size, self._queued, tuple(self._running))


class LogQueue:
    """Log text from any thread (the ``log.setup`` GUI sink), drained into the Logs tab by the GUI thread."""

    def __init__(self) -> None:
        self._items: deque[str] = deque()

    def put(self, text: str) -> None:
        if text:
            self._items.append(text)

    def clear(self) -> None:
        self._items.clear()

    def drain(self, limit: int | None) -> str:
        """Join up to ``limit`` entries (all when ``None``), each ending in a newline, as the TextArea would show them."""
        parts: list[str] = []
        while limit is None or len(parts) < limit:
            try:
                item = self._items.popleft()
            except IndexError:
                break
            parts.append(item if item.endswith("\n") else item + "\n")
        return _TEXT_AREA_INVALID.sub("", "".join(parts))


def format_elapsed(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def format_throughput(completed: int, seconds: int) -> str:
    return f"{completed * 60 // seconds if seconds > 0 else 0}/min"


def format_percent(completed: int, total: int) -> str:
    return "0%" if total == 0 else f"{completed * 100 // total}%"
