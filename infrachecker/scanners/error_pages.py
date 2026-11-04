"""Error page analysis (option 5, Java ``d`` + ``ac.a(URL,String)``).
"""
from __future__ import annotations

import sys
import threading

from .. import config
from ..log import tinfo
from ..net import apache
from ..net.errors import ClientProtocolError, JavaIOError, java_message
from ..net.http import JavaUrl
from ..persistence import writer
from . import _page_checks
from ._page_checks import SEE_HTML, STANDARD_ERROR_TEXT, Page

TIMEOUT_SECONDS = 5.0
EXTRA_PROBE_TIMEOUT_SECONDS = 60.0   # safety limit; Java's extra probes have no timeout at all
MISSING = "Standard Error page is missing"
IMPLEMENTED = "Standard Error page is implemented"
SEE_MANUALLY = "See Manually"

# Page -> (Vulnerability Status, reason, evidence in the standard-error folder)
_OUTCOMES = {
    Page.EMPTY: (MISSING, "Server returned Empty Response, Standard Error page is missing", False),
    Page.WRONG_URL: (MISSING, MISSING, False),
    Page.TECH_DISCLOSED: (MISSING, "Server version/Technology is disclosed, Standard Error page is missing", False),
    Page.NOT_FOUND: (MISSING, MISSING, False),
    Page.ERROR_DOCUMENT: (MISSING, MISSING, False),
    Page.APP_ERROR: (MISSING, MISSING, False),
    Page.PROXY_ERROR: (MISSING, "Proxy Error, Standard Error page is missing", False),
    Page.SERVICE_UNAVAILABLE: (MISSING, "Service Unavailable, Standard Error page is missing", False),
    Page.WAF_BLOCK: (IMPLEMENTED, "WAF message detected", True),
    Page.STANDARD_ERROR: (IMPLEMENTED, IMPLEMENTED, True),
    Page.INSTANCE_NOT_CONFIGURED: (MISSING, "Instance not Configured", False),
    Page.OK: (SEE_MANUALLY, "", False),
    Page.OTHER: (SEE_MANUALLY, "", False),
}


def scan_ip(url: str, ip: str, out_path: str, thread_name: str, index: int) -> None:
    """GET ``url`` with its host pinned to ``ip``; classify the page; save the body as HTML evidence."""
    threading.current_thread().name = thread_name
    tinfo(f"Going to perform Error Pages Analysis on IP->{ip}\tURL->{url}")
    try:
        response = apache.get(url, pinned_host=JavaUrl.parse(url).host, pinned_ip=ip, timeout=TIMEOUT_SECONDS)
        body = response.entity_text()
        tinfo(f"IP->{ip}\tstatusCode->{response.status}\tURL->{url}")
        row, evidence_path = outcome_row(url, ip, response.status, body, _page_checks.evidence_name(ip))
        _page_checks.record(out_path, row, evidence_path, body)
    except ClientProtocolError as exc:
        _unable_to_connect(url, ip, out_path, f"ClientProtocolException->{java_message(exc)}")
    except JavaIOError as exc:
        _unable_to_connect(url, ip, out_path, f"IOException->{java_message(exc)} IP->{ip} URL->{url}")
    except Exception as exc:
        _unable_to_connect(url, ip, out_path, f"Unexpected exception->{java_message(exc)}")
    tinfo(f"Error Pages Analysis completed on IP->{ip}\tURL->{url}")


def outcome_row(url: str, ip: str, status: int, body: str, name: str) -> tuple[str, str]:
    """Result row and evidence path for one fetched page (Java ``d.a(g, ...)``)."""
    verdict, reason, standard = _OUTCOMES[_page_checks.classify(status, body)]
    folder = config.STANDARD_ERROR_DIR if standard else config.NON_STANDARD_ERROR_DIR
    details = f"{reason}, {SEE_HTML}{folder}{name}" if reason else f"{SEE_HTML}{folder}{name}"
    return f"{url}\t{ip}\t{status}\t{verdict}\t{details}", folder + name


def _unable_to_connect(url: str, ip: str, out_path: str, details: str) -> None:
    tinfo(details)
    writer.append_row(out_path, f"{url}\t{ip}\t0\tUnable to Connect\t{details}")


def extra_probes(url: str, out_path: str, thread_name: str) -> None:
    """The two follow-up probes after the IP fan-out: ``https://<host>/InvalidContext/`` (Apache) and
    ``https://<host><path>invalid`` (Tomcat). Port and query of ``url`` are dropped, as in Java."""
    try:
        parsed = JavaUrl.parse(url)
    except JavaIOError as exc:
        print(exc, file=sys.stderr)
        return
    _extra_probe(f"https://{parsed.host}/InvalidContext/", "Apache", out_path, thread_name)
    _extra_probe(f"https://{parsed.host}{parsed.path}invalid", "Tomcat", out_path, thread_name)


def extra_probe_row(probe_url: str, status: int, body: str, label: str, name: str) -> tuple[str, str]:
    """Result row and evidence path of one extra probe (Java ``ac.a(URL,String)``, including its doubled
    "See html file for details-> " in two branches)."""
    if STANDARD_ERROR_TEXT in body:
        folder = config.STANDARD_ERROR_DIR
        details = f"{IMPLEMENTED}, Error Pages missing on {label}, {SEE_HTML}{SEE_HTML}{folder}{name}"
        return f"{probe_url}\t-\t{status}\t{IMPLEMENTED}\t{details}", folder + name
    folder = config.NON_STANDARD_ERROR_DIR
    if status == 200 and any(text in body for text in _page_checks.INSTANCE_NOT_CONFIGURED):
        details = f"Instance not Configured, Error Pages missing on {label}, {SEE_HTML}{SEE_HTML}{folder}{name}"
    else:
        details = f"Error Pages missing on {label}, {SEE_HTML}{folder}{name}"
    return f"{probe_url}\t-\t{status}\t{MISSING}\t{details}", folder + name


def _extra_probe(probe_url: str, label: str, out_path: str, thread_name: str) -> None:
    """No pinning (Java leaves the client defaults; the timeout is a safety limit Java lacks). Only
    ``ClientProtocolException`` yields a row, any other failure is just printed like ``printStackTrace()``."""
    try:
        response = apache.get(probe_url, timeout=EXTRA_PROBE_TIMEOUT_SECONDS)
        body = response.entity_text()
        row, evidence_path = extra_probe_row(probe_url, response.status, body, label,
                                             _page_checks.evidence_name(thread_name))
        _page_checks.record(out_path, row, evidence_path, body)
    except ClientProtocolError as exc:
        tinfo(f"ClientProtocolException->{_null(exc.message)}")
        writer.append_row(out_path, f"{probe_url}\t-\t\t0\tUnable to Connect\t{_null(exc.message)}")
    except Exception as exc:
        print(exc if isinstance(exc, JavaIOError) else repr(exc), file=sys.stderr)


def _null(message: str | None) -> str:
    return "null" if message is None else message
