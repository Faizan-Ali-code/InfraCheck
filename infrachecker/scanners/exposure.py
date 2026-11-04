"""Exposure check (option 7, Java ``h``).
"""
from __future__ import annotations

import threading

from .. import config
from ..log import tinfo
from ..net import apache
from ..net.errors import ClientProtocolError, JavaIOError, java_message
from ..net.http import JavaUrl
from ..persistence import writer
from . import _page_checks

TIMEOUT_SECONDS = 5.0
PUBLICLY_ACCESSIBLE = "Publicly Accessible"
NOT_ACCESSIBLE = "Not Accessible"


def scan_ip(url: str, ip: str, out_path: str, thread_name: str, index: int) -> None:
    """GET ``url`` with its host pinned to ``ip``; record Publicly Accessible / Not Accessible; save HTML evidence."""
    threading.current_thread().name = thread_name
    tinfo(f"Going to perform Exposure Analysis on IP->{ip}\tURL->{url}")
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
    tinfo(f"Exposure Analysis completed on IP->{ip}\tURL->{url}")


def outcome_row(url: str, ip: str, status: int, body: str, name: str) -> tuple[str, str]:
    """Result row and evidence path for one fetched page (Java ``h.a(k, ...)``)."""
    accessible, details = _page_checks.access_details(_page_checks.classify(status, body), name)
    verdict = PUBLICLY_ACCESSIBLE if accessible else NOT_ACCESSIBLE
    folder = config.ACCESSIBLE_DIR if accessible else config.NON_ACCESSIBLE_DIR
    return f"{url}\t{ip}\t{status}\t{verdict}\t{details}", folder + name


def _unable_to_connect(url: str, ip: str, out_path: str, details: str) -> None:
    tinfo(details)
    writer.append_row(out_path, f"{url}\t{ip}\t0\tUnable to Connect\t{details}")
