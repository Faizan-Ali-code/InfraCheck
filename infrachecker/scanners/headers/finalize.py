"""Header row finalisation + dedup (Java ``ai.a`` 13-arg / ``am`` / ``aj`` / ``C``).
"""
from __future__ import annotations

import re
import sqlite3
import threading
import traceback

from ... import config
from ...javacompat.java_uri import JavaURI, URISyntaxError
from ...javacompat.java_url import url_host_or_raw
from ...javacompat.strings import is_blank, java_trim
from ...log import tinfo
from ...models import HeaderRow
from ...persistence import header_store, reference_data
from .recommendations import recommendation

SEVERITY_TAGS = ("CRITICAL", "HIGH", "SYNTAX", "MEDIUM", "LOW", "HIGH_MAYBE", "STRICT_CSP", "MEDIUM_MAYBE", "INFO",
                 "NONE")
IGNORED_JUSTIFICATION = "This domain is mentioned in ignored list."
REMEDIATE = "All Critical, High and Medium severity findings must be remediated."
_REMEDIATE_CSP = ("Marked vulnerable because Critical/High/Medium/Low findings are there. "
                  "All Critical, High, Medium and Low severity findings must be remediated.")
_REMEDIATE_CSP_SYNTAX = ("Marked vulnerable because Critical/High/Syntax/Medium/Low findings are there. "
                         "All Critical, High, Syntax, Medium and Low severity findings must be remediated.")
_TAG = re.compile(r"\[(" + "|".join(SEVERITY_TAGS) + r")\]", re.I | re.A)
_RANK = {tag: len(SEVERITY_TAGS) - index for index, tag in enumerate(SEVERITY_TAGS)}
_IPV4 = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_STATUS_SEVERITY = {"vulnerable": "MEDIUM", "analyze manually": "LOW", "deprecated": "INFO"}

_dedup: set[str] = set()
_dedup_lock = threading.Lock()


def is_csp_header(header: str | None) -> bool:
    return header is not None and header.lower() in ("content-security-policy", "content-security-policy-report-only")


def normalize_url(url: str) -> str:
    """Drop a lone "/" path (Java ``aj.b``); the 7-arg URI constructor re-quotes the decoded query and fragment."""
    try:
        uri = JavaURI(url)
        if uri.get_path() != "/":
            return url
        return str(JavaURI.from_components(uri.scheme, uri.get_user_info(), uri.host, uri.port, None,
                                           uri.get_query(), uri.get_fragment()))
    except URISyntaxError:
        return url


def ip_type(ip: str) -> str:
    """Classful label of a dotted IPv4 address (Java ``aj.d``; reproduced as-is, e.g. 8.8.8.8 is "Private")."""
    if not _IPV4.fullmatch(ip):
        return ""
    first = int(ip.split(".", 1)[0])
    if 1 <= first <= 126:
        return "Class A-Private IP"
    if 128 <= first <= 191:
        return "Class B-Private IP"
    if 192 <= first <= 223:
        return "Class C-Public IP"
    if 224 <= first <= 239:
        return "Class D-Multicast IP"
    if 240 <= first <= 255:
        return "Class E-Experimental IP"
    return "Unknown"


def is_ignored_host(host: str | None, ignored: set[str]) -> bool:
    if is_blank(host) or not ignored:
        return False
    host = java_trim(host).lower()
    return host in ignored or any(entry and host.endswith("." + entry) for entry in ignored)


def normalize_details(details: str | None) -> str:
    """Group tagged segments by severity (CRITICAL first), untagged prefix last, joined by newlines."""
    if details is None:
        return ""
    if is_blank(details):
        return details
    matches = list(_TAG.finditer(details))
    if not matches:
        return java_trim(details)
    buckets: dict[str, list[str]] = {tag: [] for tag in SEVERITY_TAGS}
    untagged: list[str] = []
    prefix = java_trim(details[:matches[0].start()])
    if prefix:
        untagged.append(prefix)
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(details)
        segment = java_trim(details[match.start():end])
        if segment:
            buckets[match.group(1).upper()].append(segment)
    return "\n".join([segment for tag in SEVERITY_TAGS for segment in buckets[tag]] + untagged)


def derive_severity(details: str | None, status: str) -> str:
    best = None
    for match in _TAG.finditer(details or ""):
        tag = match.group(1).upper()
        if best is None or _RANK[tag] > _RANK[best]:
            best = tag
    if best is not None:
        return best
    return _STATUS_SEVERITY.get(status.lower(), "NONE")


def post_justification(details: str | None, justification: str | None, header: str | None) -> str:
    text = details or ""
    syntax = "[SYNTAX]" in text
    critical_high_medium = "[CRITICAL]" in text or "[HIGH]" in text or "[MEDIUM]" in text
    csp = is_csp_header(header)
    if not (critical_high_medium or syntax or (csp and "[LOW]" in text)):
        return java_trim(justification)
    if csp:
        return _REMEDIATE_CSP_SYNTAX if syntax else _REMEDIATE_CSP
    trimmed = java_trim(justification)
    if REMEDIATE in trimmed:
        return trimmed
    return f"{trimmed} {REMEDIATE}" if trimmed else REMEDIATE


def build_row(ip: str, url: str, header: str, value: str | None, status_code: int, vulnerability_status: str,
              details: str | None, justification: str | None, ownership_override: str | None,
              response_body: str | None, data: reference_data.ReferenceData) -> HeaderRow:
    """Java ``am.a``: normalised URL, host, IP type, ownership, ignored-domain handling, severity, recommendation."""
    url_column = normalize_url(url)
    host = url_host_or_raw(url_column)
    ownership = reference_data.ownership_for(ip, header, ownership_override, data)
    if is_ignored_host(host, data.ignored_domains):
        tinfo(f"This Host found in ignored list: {host} for header: {header} - marking as Not Vulnerable")
        status, details_column, justification_column = "Not Vulnerable", "", IGNORED_JUSTIFICATION
        severity, recommendation_column, body = "NONE", "", ""
    else:
        status = vulnerability_status
        details_column = normalize_details(details)
        justification_column = post_justification(details_column, justification, header)
        severity = derive_severity(details_column, vulnerability_status)
        recommendation_column = recommendation(header) if vulnerability_status.lower() == "vulnerable" else ""
        body = response_body or ""
    return HeaderRow(url=url_column, host=host, ip=ip, ip_type=ip_type(ip), ownership=ownership, header=header,
                     value="" if value is None else value, status_code=status_code, vulnerability_status=status,
                     recommendation=recommendation_column, severity=severity, details=details_column,
                     justification=justification_column, response_body=body)


def add_header_result(xlsx_path: str, ip: str, url: str, header: str, value: str, status_code: int,
                      vulnerability_status: str, details: str, justification: str,
                      ownership_override: str | None, response_body: str) -> None:
    """Normalise, dedup (global, first writer wins) and insert one header row into ``<xlsx_path>.sqlite``."""
    row = build_row(ip, url, header, value, status_code, vulnerability_status, details, justification,
                    ownership_override, response_body, reference_data.get())
    key = row.dedup_key()
    with _dedup_lock:
        if key in _dedup:
            return
        _dedup.add(key)
        try:
            header_store.insert(config.sqlite_path_for(xlsx_path), row)
        except sqlite3.Error:  # Java prints the stack trace; the row is lost and its key stays in the set
            traceback.print_exc()


def reset_dedup() -> None:
    """Clear the dedup set (start of every run)."""
    with _dedup_lock:
        _dedup.clear()
