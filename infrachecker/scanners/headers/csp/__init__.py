"""Content-Security-Policy evaluation (Java ``w`` wrapper around package ``a``, a port of google/csp-evaluator).
"""
from __future__ import annotations

from ....javacompat.java_uri import JavaURI, URISyntaxError
from ....javacompat.strings import is_blank
from ....log import log
from ..verdict import ANALYZE_MANUALLY, NOT_VULNERABLE, VULNERABLE, Verdict
from . import checks
from .policy import CSP3, SEVERITY, Csp, Finding, parse_csp, render

_EMPTY = "[CRITICAL] CSP header value is empty; no policy is enforced. \n"
_INVALID = "[CRITICAL] CSP header value is invalid or empty; no policy is enforced. \n"
_FAILED = "[INFO] CSP evaluation could not be completed automatically; review the policy manually. \n"


def _findings(csp: Csp, reporting_endpoints: str | None, report_to: str | None) -> list[Finding]:
    """Ignored-entry findings of the CSP3 effective policy, internal checks on the raw policy, then the upstream
    checks and the strict-dynamic check on the effective policy."""
    findings: list[Finding] = []
    effective = csp.effective_csp(CSP3, findings)
    findings += checks.frame_ancestors(csp)
    findings += checks.report_to(csp)
    findings += checks.reporting_endpoints(csp, reporting_endpoints, report_to)
    for check in checks.DEFAULT_CHECKS:
        findings += check(effective)
    findings += checks.strict_dynamic(effective)
    return findings


def evaluate(value: str | None, reporting_endpoints: str | None, report_to: str | None) -> Verdict:
    """Vulnerable when any finding is LOW or worse; details are the distinct rendered findings in order."""
    if is_blank(value):
        return Verdict(VULNERABLE, _EMPTY)
    csp = parse_csp(value)
    if not csp.directives:
        return Verdict(VULNERABLE, _INVALID)
    try:
        findings = _findings(csp, reporting_endpoints, report_to)
    except Exception:  # Java catches RuntimeException from the evaluator
        log.warning(f"Google CSP Evaluator failed for CSP value ->'{value}'", exc_info=True)
        return Verdict(ANALYZE_MANUALLY, _FAILED)
    status = NOT_VULNERABLE
    lines: dict[str, None] = {}
    for finding in findings:
        lines.setdefault(render(finding))
        if SEVERITY[finding.severity] <= SEVERITY["LOW"]:
            status = VULNERABLE
    return Verdict(status, "".join(lines))


def _host_for_message(url: str) -> str:
    try:
        host = JavaURI(url).host
    except URISyntaxError:
        return url.lower()
    return url if host is None else host.lower()


def ownership_justification(url: str, ip: str, status: str, csp_owners: dict[str, str]) -> str:
    """Justification of an analysed CSP row: who owns the CSP of this IP (Java ``w.a(url, ..., ai)``)."""
    host = _host_for_message(url)
    owner = csp_owners.get(ip, "")
    if is_blank(owner):
        return f"No CSP ownership mapping found for host '{host}'; findings reflect direct header analysis."
    if status == NOT_VULNERABLE:
        return f"CSP header for '{host}' is owned by '{owner}' and meets the required configuration."
    return (f"CSP header for '{host}' is owned by '{owner}' and does not meet the required configuration; "
            "see detail column for findings.")
