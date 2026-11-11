"""IP-spoofing analysis (option 4): does a client-IP header change the server's access decision?

Some servers and proxies decide access from the client address and take that address from a request header such
as ``X-Forwarded-For``. If an outside client can set the header itself, it can pretend to be an internal or
allowlisted address. The test therefore compares two kinds of response:

1. **Baseline**: the URL requested with no client-IP header.
2. **Spoofed**: the same request with one header added, for every header in ``SPOOF_HEADERS`` and every address in
   ``input data/spoof-ips.txt`` (default: loopback and private addresses an allowlist would typically trust).

==========================================  ==========================================  ============================
Baseline                                    Spoofed request                             Result
==========================================  ==========================================  ============================
page served (2xx with real content)         any                                         Not Applicable
denied, redirected or error page            page served                                 Vulnerable to IP Spoofing
denied, redirected or error page            different status, page still not served     Review Manually
denied, redirected or error page            same status                                 Not Vulnerable
request failed                              -                                           Unable to Test
==========================================  ==========================================  ============================

A page that is already public cannot be unlocked by spoofing, so it is reported as Not Applicable rather than
vulnerable. Redirects are not followed, so "redirect to the login page" (denied) and "page served" (granted) stay
distinguishable. The body of every spoofed response is saved as HTML evidence.
"""
from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass

from .. import config
from ..log import log, tinfo
from ..net import jdk
from ..net.errors import JavaClassCastError, JavaIOError
from ..persistence import writer
from . import _page_checks
from ._page_checks import Page

SPOOF_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
                 "True-Client-IP", "X-Cluster-Client-IP", "Forwarded")
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0

VULNERABLE = "Vulnerable to IP Spoofing"
NOT_VULNERABLE = "Not Vulnerable"
NOT_APPLICABLE = "Not Applicable"
REVIEW = "Review Manually"
UNABLE = "Unable to Test"

# Pages that mean "the resource was not served", even when the status code is 2xx.
_NOT_SERVED = frozenset({Page.EMPTY, Page.WRONG_URL, Page.NOT_FOUND, Page.ERROR_DOCUMENT, Page.APP_ERROR,
                         Page.PROXY_ERROR, Page.SERVICE_UNAVAILABLE, Page.WAF_BLOCK, Page.STANDARD_ERROR,
                         Page.INSTANCE_NOT_CONFIGURED})


@dataclass(frozen=True)
class Observation:
    """One response, reduced to what the comparison needs."""

    status: int            # 0 when the request failed
    page: Page | None      # None when the request failed
    body: str = ""
    error: str = ""

    @property
    def failed(self) -> bool:
        return self.page is None

    @property
    def served(self) -> bool:
        """The resource itself was returned (2xx and not an error, block or empty page)."""
        return not self.failed and 200 <= self.status < 300 and self.page not in _NOT_SERVED


def judge(baseline: Observation, spoofed: Observation) -> tuple[str, str]:
    """(Vulnerability Status, Details) for one spoofed request compared with the baseline."""
    if baseline.failed:
        return UNABLE, f"Baseline request failed: {baseline.error}"
    if spoofed.failed:
        return UNABLE, f"Spoofed request failed: {spoofed.error}"
    if baseline.served:
        return NOT_APPLICABLE, (f"The page is served without any client-IP header (baseline status {baseline.status}),"
                                " so spoofing cannot grant extra access here.")
    if spoofed.served:
        return VULNERABLE, (f"Access was refused without the header (baseline status {baseline.status}) but the page "
                            f"was served with it (status {spoofed.status}).")
    if spoofed.status != baseline.status:
        return REVIEW, (f"The response changed from status {baseline.status} to {spoofed.status} when the header was "
                        "sent, without the page being served; check whether the header influences access control.")
    return NOT_VULNERABLE, f"The header was ignored: same response as the baseline (status {baseline.status})."


def header_value(header: str, ip: str) -> str:
    """The header value claiming to come from ``ip`` (RFC 7239 syntax for ``Forwarded``)."""
    if header.lower() != "forwarded":
        return ip
    return f'for="[{ip}]"' if ":" in ip else f"for={ip}"


def load_spoof_values(path: str = config.SPOOF_IPS_FILE) -> list[str]:
    """Addresses to impersonate: valid IPs from ``spoof-ips.txt`` (``#`` comments allowed), else the defaults."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []
    values: list[str] = []
    for line in lines:
        text = line.strip().lstrip("﻿")
        if not text or text.startswith("#"):
            continue
        try:
            values.append(str(ipaddress.ip_address(text)))
        except ValueError:
            log.warning(f"Ignoring '{text}' in {path}: not an IP address")
    return list(dict.fromkeys(values)) or list(config.DEFAULT_SPOOF_IPS)


def _error_text(exc: Exception) -> str:
    message = getattr(exc, "message", None)
    if isinstance(exc, JavaClassCastError):
        return "only HTTPS URLs are supported by this analysis"
    return f"{getattr(exc, 'simple_name', type(exc).__name__)}" + (f": {message}" if message else "")


def fetch(url: str, extra_headers: list[tuple[str, str]]) -> Observation:
    """GET ``url`` without following redirects; never raises for HTTP or network errors."""
    try:
        response = jdk.request(jdk.https_url(url), "GET", [("User-Agent", config.USER_AGENT), *extra_headers],
                               connect_timeout=CONNECT_TIMEOUT, read_timeout=READ_TIMEOUT, follow_redirects=False)
    except (JavaIOError, JavaClassCastError) as exc:
        return Observation(0, None, "", _error_text(exc))
    body = response.any_text()
    return Observation(response.status, _page_checks.classify(response.status, body), body)


def take_baseline(url: str) -> Observation:
    return fetch(url, [])


def scan_ip(url: str, ip: str, out_path: str, thread_name: str, index: int,
            baseline: Observation | None = None) -> None:
    """Every spoofing header for one impersonated address, compared with the baseline. Runs in a child thread."""
    threading.current_thread().name = thread_name
    baseline = baseline if baseline is not None else take_baseline(url)
    tinfo(f"Going to perform Spoofing Analysis with client IP->{ip}\tURL->{url}")
    for header in SPOOF_HEADERS:
        spoofed = fetch(url, [(header, header_value(header, ip))])
        verdict, details = judge(baseline, spoofed)
        tinfo(f"IP->{ip}\tHeader->{header}\tbaseline->{baseline.status}\tresponseCode->{spoofed.status}\t"
              f"verdict->{verdict}\tURL->{url}")
        row = "\t".join((url, ip, header, str(baseline.status), str(spoofed.status), verdict, details))
        if spoofed.failed:
            writer.append_row(out_path, row)
            continue
        folder = config.ACCESSIBLE_DIR if spoofed.served else config.NON_ACCESSIBLE_DIR
        name = _page_checks.evidence_name(f"{ip}-{header}")
        _page_checks.record(out_path, f"{row} {_page_checks.SEE_HTML}{folder}{name}", folder + name, spoofed.body)
    tinfo(f"Spoofing Analysis completed with client IP->{ip}\tURL->{url}")
