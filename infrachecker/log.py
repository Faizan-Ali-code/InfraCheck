"""Logging that matches the Java tool's log files.

- One logger, ``InfraCheckerLogger``; the formatter writes the bare message, records end with CRLF.
- Call sites add their own ``dd-MM-yyyy HH:mm:ss <thread>`` prefix (see :func:`tinfo`).
- File: ``logs/InfraChecker_<yyyy-MM-dd_HH-mm-ss>.log`` (CLI) or ``logs/InfraChecker_GUI_...`` (GUI).
- CLI mode also prints records to the console; GUI mode sends them to a sink callable instead.
- ``sys.stdout``/``sys.stderr`` are teed into the same file (and the GUI sink).
"""
from __future__ import annotations

import io
import logging
import os
import sys
import threading
import traceback
from datetime import datetime
from typing import Callable

from .config import LOGS_DIR

LOGGER_NAME = "InfraCheckerLogger"
log = logging.getLogger(LOGGER_NAME)

_lock = threading.RLock()
_configured = False
_log_path: str | None = None

_LEVELS = {"OFF": logging.CRITICAL + 10, "SEVERE": logging.ERROR, "WARNING": logging.WARNING, "INFO": logging.INFO,
           "CONFIG": 15, "FINE": logging.DEBUG, "FINER": 7, "FINEST": 5, "ALL": 1}
logging.addLevelName(15, "CONFIG")
logging.addLevelName(7, "FINER")
logging.addLevelName(5, "FINEST")


def ts() -> str:
    """Timestamp prefix used by every message: ``dd-MM-yyyy HH:mm:ss``."""
    return datetime.now().strftime("%d-%m-%Y %H:%M:%S")


def thread_name() -> str:
    return threading.current_thread().name


def tinfo(message: str) -> None:
    """``<timestamp> <thread name> <message>`` at INFO (the most common Java call-site pattern)."""
    log.info(f"{ts()} {thread_name()} {message}")


class _MessageOnly(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        text = record.getMessage()
        if record.exc_info:
            text += "\r\n" + "".join(traceback.format_exception(*record.exc_info)).replace("\n", "\r\n")
        return text


class _CrlfFileHandler(logging.StreamHandler):
    """Appends records to the log file, CRLF-terminated, embedded ``\\n`` left as-is (like Java)."""

    terminator = "\r\n"

    def __init__(self, path: str):
        super().__init__(open(path, "a", encoding="utf-8", newline=""))

    def emit(self, record: logging.LogRecord) -> None:
        with _lock:
            super().emit(record)


class _ConsoleHandler(logging.StreamHandler):
    terminator = "\n"

    def __init__(self):
        super().__init__(sys.__stdout__)


class _SinkHandler(logging.Handler):
    def __init__(self, sink: Callable[[str], None]):
        super().__init__()
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._sink(self.format(record) + "\r\n")
        except Exception:  # never let the GUI break logging
            pass


class _Tee(io.TextIOBase):
    """Line-buffered tee of stdout/stderr into the original stream, the log file and the GUI sink."""

    def __init__(self, original, log_stream, sink: Callable[[str], None] | None):
        self._original = original
        self._file = log_stream
        self._sink = sink
        self._buffer = ""

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        if self._original is not None:
            try:
                self._original.write(text)
            except Exception:
                pass
        self._buffer += text.replace("\r", "")
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._emit_line(line)
        return len(text)

    def flush(self) -> None:
        if self._original is not None:
            try:
                self._original.flush()
            except Exception:
                pass

    def _emit_line(self, line: str) -> None:
        with _lock:
            self._file.write(line + "\r\n")
            self._file.flush()
        if line and self._sink is not None:
            self._sink(line)


def _level_from_env() -> int:
    raw = os.environ.get("INFRACHECKER_LOG_LEVEL", "").strip().upper()
    if not raw:
        return logging.INFO
    if raw in _LEVELS:
        return _LEVELS[raw]
    sys.stderr.write(f"Invalid value for 'INFRACHECKER_LOG_LEVEL' -> '{raw}'; falling back to INFO\n")
    return logging.INFO


def setup(gui_sink: Callable[[str], None] | None = None) -> str:
    """Configure logging once per process. Returns the log file path.

    ``gui_sink`` selects GUI mode: records go to the sink instead of the console and the file name gets ``_GUI_``.
    """
    global _configured, _log_path
    with _lock:
        if _configured:
            return _log_path or ""
        os.makedirs(LOGS_DIR, exist_ok=True)
        prefix = "InfraChecker_GUI_" if gui_sink else "InfraChecker_"
        _log_path = os.path.join(LOGS_DIR, prefix + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".log")

        level = _level_from_env()
        log.setLevel(level)
        log.propagate = False
        formatter = _MessageOnly()

        file_handler = _CrlfFileHandler(_log_path)
        handlers: list[logging.Handler] = [file_handler]
        handlers.append(_SinkHandler(gui_sink) if gui_sink else _ConsoleHandler())
        for handler in handlers:
            handler.setLevel(level)
            handler.setFormatter(formatter)
            log.addHandler(handler)

        tee_stream = open(_log_path, "a", encoding="utf-8", newline="")
        sys.stdout = _Tee(sys.__stdout__, tee_stream, gui_sink)
        sys.stderr = _Tee(sys.__stderr__, tee_stream, gui_sink)
        _configured = True
        return _log_path
