"""Response-body classification and HTML evidence shared by IP spoofing, error pages and exposure (Java ``as``,
``d``, ``h``): the same substring checks in the same order, first match wins."""
from __future__ import annotations

import enum
import time
from datetime import datetime

from .. import config
from ..log import tinfo
from ..persistence import writer

SEE_HTML = "See html file for details-> "
STANDARD_ERROR_TEXT = ("We apologies for the inconvenience caused. Please try again or contact our "
                       "Administrator/Support service")
INSTANCE_NOT_CONFIGURED = ("Instance not Configured", "Instance is Not Configured")


class Page(enum.Enum):
    EMPTY = enum.auto()
    WRONG_URL = enum.auto()
    TECH_DISCLOSED = enum.auto()
    NOT_FOUND = enum.auto()
    ERROR_DOCUMENT = enum.auto()
    APP_ERROR = enum.auto()
    PROXY_ERROR = enum.auto()
    SERVICE_UNAVAILABLE = enum.auto()
    WAF_BLOCK = enum.auto()
    STANDARD_ERROR = enum.auto()
    INSTANCE_NOT_CONFIGURED = enum.auto()
    OK = enum.auto()
    OTHER = enum.auto()


_CHECKS: list[tuple[Page, tuple[str, ...]]] = [
    (Page.WRONG_URL, ("Wrong URL",)),
    (Page.TECH_DISCLOSED, ("Tomcat", "nginx", "Apache")),
    (Page.NOT_FOUND, ("The origin server did not find a current representation for the target resource or is not "
                      "willing to disclose that one exists", "The requested URL was not found on this server",
                      "The page you have requested does not exist")),
    (Page.ERROR_DOCUMENT, ("error was encountered while trying to use an ErrorDocument to handle the request",)),
    (Page.APP_ERROR, ("There may be some Server/Application Side Error. Please Contact Administrator/Support",)),
    (Page.PROXY_ERROR, ("The proxy server received an invalid response from an upstream server",)),
    (Page.SERVICE_UNAVAILABLE, ("The server is temporarily unable to service your request due to maintenance "
                                "downtime or capacity problems",)),
    (Page.WAF_BLOCK, ("The requested URL was rejected. Please consult with your administrator",)),
    (Page.STANDARD_ERROR, (STANDARD_ERROR_TEXT,)),
]

# Reason prefix for every "Not Accessible" page (IP spoofing and exposure word their Details identically).
_ACCESS_REASONS = {
    Page.EMPTY: "Server returned Empty Response, Standard Error page is missing",
    Page.WRONG_URL: "Standard Error page is missing",
    Page.TECH_DISCLOSED: "Server version/Technology is disclosed, Standard Error page is missing",
    Page.NOT_FOUND: "Standard Error page is missing",
    Page.ERROR_DOCUMENT: "Standard Error page is missing",
    Page.APP_ERROR: "Standard Error page is missing",
    Page.PROXY_ERROR: "Proxy Error, Standard Error page is missing",
    Page.SERVICE_UNAVAILABLE: "Service Unavailable, Standard Error page is missing",
    Page.WAF_BLOCK: "WAF message detected",
    Page.STANDARD_ERROR: "Standard Error page is implemented",
    Page.INSTANCE_NOT_CONFIGURED: "Instance not Configured",
}


def classify(status: int, body: str) -> Page:
    if not body:
        return Page.EMPTY
    for page, needles in _CHECKS:
        if any(needle in body for needle in needles):
            return page
    if status == 200:
        return Page.INSTANCE_NOT_CONFIGURED if any(n in body for n in INSTANCE_NOT_CONFIGURED) else Page.OK
    return Page.OTHER


def access_details(page: Page, name: str) -> tuple[bool, str]:
    """(accessible, Details) for IP spoofing / exposure; the evidence folder follows ``accessible``."""
    if page is Page.OK:
        return True, SEE_HTML + config.ACCESSIBLE_DIR + name
    reason = _ACCESS_REASONS.get(page)
    if reason is None:
        return False, SEE_HTML.strip() + config.NON_ACCESSIBLE_DIR + name
    return False, f"{reason}, {SEE_HTML}{config.NON_ACCESSIBLE_DIR}{name}"


def java_local_time(epoch_ns: int | None = None) -> str:
    """``LocalTime.now().toString()``: ``HH:mm[:ss[.SSS|.SSSSSS|.SSSSSSSSS]]``."""
    epoch_ns = time.time_ns() if epoch_ns is None else epoch_ns
    now = datetime.fromtimestamp(epoch_ns // 1_000_000_000)
    nanos = epoch_ns % 1_000_000_000
    text = f"{now.hour:02d}:{now.minute:02d}"
    if now.second or nanos:
        text += f":{now.second:02d}"
        if nanos:
            if nanos % 1_000_000 == 0:
                text += f".{nanos // 1_000_000:03d}"
            elif nanos % 1_000 == 0:
                text += f".{nanos // 1_000:06d}"
            else:
                text += f".{nanos:09d}"
    return text


def evidence_name(prefix: str) -> str:
    """``(prefix + "-" + LocalTime.now() + ".html").replace(":", "")``."""
    return f"{prefix}-{java_local_time()}.html".replace(":", "")


def record(out_path: str, row: str, evidence_path: str, body: str) -> None:
    """Append the result row, log it, then save the response body as HTML evidence (Java order)."""
    writer.append_row(out_path, row)
    tinfo(row)
    writer.append_row(evidence_path, body)
