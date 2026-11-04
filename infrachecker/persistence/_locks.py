"""One lock per output path, shared by every writer of that path (Java ``ai.d``)."""
from __future__ import annotations

import os
import threading

_guard = threading.Lock()
_locks: dict[str, threading.RLock] = {}


def path_key(path: str) -> str:
    """Normalised key so that different spellings of one file share a lock and in-memory state."""
    return os.path.normcase(os.path.abspath(path or ""))


def lock_for(path: str) -> threading.RLock:
    key = path_key(path)
    with _guard:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.RLock()
        return lock
