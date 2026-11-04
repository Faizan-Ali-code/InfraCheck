"""IP spoofing analysis (option 4, Java ``as``).

Faithful to Java: no baseline request without the spoofed header, so any page answering 200 is reported as
``Vulnerable to IP Spoofing``; ``HttpsURLConnection`` defaults (certificate validation, same-protocol redirects,
status >= 400 surfaces as an ``IOException`` row).
"""
from __future__ import annotations

import threading

from .. import config
from ..log import tinfo
from ..net import jdk
from ..net.errors import JavaIOError
from ..persistence import writer
from . import _page_checks
from ._page_checks import Page

SPOOF_HEADERS = ("X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP")
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0
VULNERABLE = "Vulnerable to IP Spoofing"
NOT_ACCESSIBLE = "Not Accessible"


def scan_ip(url: str, ip: str, out_path: str, thread_name: str, index: int) -> None:
    """All spoofing headers for one (URL, IP) pair. Runs in a child thread; sets its own thread name.

    A non-HTTPS URL raises (Java's uncaught ``ClassCastException`` ends the child task without rows).
    """
    threading.current_thread().name = thread_name
    tinfo(f"Going to perform Spoofing Analysis on IP->{ip}\tURL->{url}")
    for header in SPOOF_HEADERS:
        _spoof(url, ip, header, out_path)
    tinfo(f"Spoofing Analysis completed on IP->{ip}\tURL->{url}")


def _spoof(url: str, ip: str, header: str, out_path: str) -> None:
    status = 0
    tinfo(f"IP->{ip}\tHeader->{header}\tURL->{url}")
    name = _page_checks.evidence_name(ip)
    try:
        response = jdk.request(jdk.https_url(url), "GET", [(header, ip)], connect_timeout=CONNECT_TIMEOUT,
                               read_timeout=READ_TIMEOUT)
        status = response.status
        tinfo(f"IP->{ip}\tresponseCode->{status}\tURL->{url}\tHeader->{header}")
        body = response.input_text()
    except JavaIOError as exc:
        message = "null" if exc.message is None else exc.message
        tinfo(f"IOException->{message} IP->{ip}\tHeader->{header}\t URL->{url}")
        writer.append_row(out_path, f"{url}\t{ip}\t{header}\t{status}\t{NOT_ACCESSIBLE}\t{message}")
        return
    page = _page_checks.classify(status, body)
    accessible, details = _page_checks.access_details(page, name)
    verdict = VULNERABLE if page is Page.OK else NOT_ACCESSIBLE
    folder = config.ACCESSIBLE_DIR if accessible else config.NON_ACCESSIBLE_DIR
    _page_checks.record(out_path, f"{url}\t{ip}\t{header}\t{status}\t{verdict}\t{details}", folder + name, body)
