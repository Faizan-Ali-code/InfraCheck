"""Header analysis (option 1).
"""
from __future__ import annotations

from . import fetch, http2
from .scanner import HeaderScanner


def analyze_url(url: str, xlsx_path: str, proxy_host: str | None, proxy_port: int) -> None:
    """Run the HTTPS pass then the HTTP pass for one input URL (Java ``L.a(url, fmt, "HTTPS")`` then ``"HTTP"``).

    Rows go through ``finalize.add_header_result`` into ``<xlsx_path>.sqlite``. May raise; the worker records a
    "Host unreachable" row in that case.
    """
    scanner = HeaderScanner(xlsx_path, proxy_host, proxy_port)
    scanner.analyze(url, "HTTPS")
    scanner.analyze(url, "HTTP")


def reset_run_state() -> None:
    """Clear process-wide caches at the start of a run (Java ``L.b()``): fetch cache, HTTP/2 cache, clients."""
    fetch.reset()
    http2.reset()
