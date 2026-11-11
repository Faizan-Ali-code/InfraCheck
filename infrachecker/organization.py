"""Organization-specific settings read from ``input data\\organization-config.txt`` (every value optional).

The Java tool had these values built in for the company it was written for. Here they are configuration, so the
shipped package holds no company data: with the company's values filled in the results are the same as the Java
tool's, and an empty value switches that feature off.

- ``default_owner``: Ownership forced on the "HTTP to HTTPS Redirection" and "302 Redirect Body" rows and on a
  missing CSP on an HTML redirect page. Empty: those rows take their owner from the ownership files.
- ``acs_domain_markers``: host-name parts of ACS/VBV/virtual-card pages; X-Frame-Options and
  Access-Control-Allow-Origin are not reported on those hosts.
- ``summary_domain``, ``summary_ip_prefix``, ``summary_teams``: shape of the SQL summary queries logged after a
  Header Analysis.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from . import config
from .javacompat.strings import java_trim
from .log import log, ts


@dataclass(frozen=True)
class Organization:
    default_owner: str = ""
    acs_domain_markers: tuple[str, ...] = ()
    summary_domain: str = ""
    summary_ip_prefix: str = ""
    summary_teams: tuple[str, ...] = ()


def _items(value: str) -> tuple[str, ...]:
    """Comma-separated list, trimmed, empty entries dropped."""
    return tuple(item for item in (java_trim(part) for part in value.split(",")) if item)


def load(path: str | None = None) -> Organization:
    """Parse ``key=value`` lines (``#`` comments, blank lines and unknown keys ignored); missing file = all empty."""
    path = path or config.ORGANIZATION_CONFIG_FILE
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return Organization()
    except OSError as exc:
        log.warning(f"{ts()} Failed to read organization config file -> {path} : {exc}")
        return Organization()
    values: dict[str, str] = {}
    for line in lines:
        line = java_trim(line)
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[java_trim(key).lower()] = java_trim(value)
    return Organization(
        default_owner=values.get("default_owner", ""),
        acs_domain_markers=tuple(marker.lower() for marker in _items(values.get("acs_domain_markers", ""))),
        summary_domain=values.get("summary_domain", ""),
        summary_ip_prefix=values.get("summary_ip_prefix", ""),
        summary_teams=_items(values.get("summary_teams", "")),
    )


_lock = threading.Lock()
_current: Organization | None = None


def get() -> Organization:
    """The settings of the current run (loaded on first use)."""
    global _current
    with _lock:
        if _current is None:
            _current = load()
        return _current


def reload() -> Organization:
    """Re-read the file; called at the start of every header-analysis run."""
    global _current
    data = load()
    with _lock:
        _current = data
    return data
