"""Header analysis of one input URL (Java ``L``): URL discovery for each pass and the rows of every discovered URL.

Row order per response: list headers / banners / deprecated headers in received order, duplicate headers, missing
headers (case-insensitive name order), the 302 body, HTTP-to-HTTPS redirection (HTTP pass), HTTP/2 (HTTPS pass).
"""
from __future__ import annotations

from typing import Callable

from ...javacompat.java_url import MalformedURLError, parse_url, url_host_or_raw
from ...javacompat.strings import is_blank, java_trim
from ...javacompat.utf16 import java_length
from ...log import tinfo
from ...persistence import reference_data
from ..preview import is_html_redirect, response_preview
from . import analyzers, csp, discovery, finalize, http2
from .banner import BannerAnalyzer
from .discovery import Page, RedirectOutcome
from .fetch import Fetcher, Headers, first_header
from .http2 import Http2Support
from .verdict import ANALYZE_MANUALLY, DEPRECATED, NOT_VULNERABLE, VULNERABLE, Verdict

HTTPS_HEADERS = ("Content-Security-Policy", "X-Permitted-Cross-Domain-Policies", "Set-Cookie", "Referrer-Policy",
                 "Strict-Transport-Security", "Cache-Control", "Expires", "X-Content-Type-Options", "X-Frame-Options",
                 "Access-Control-Allow-Origin")
HTTP_HEADERS = ("Referrer-Policy", "Strict-Transport-Security", "Cache-Control", "X-Content-Type-Options", "Expires")
_DEPRECATED_HEADERS = ("Feature-Policy", "Expect-CT", "Public-Key-Pins", "X-XSS-Protection", "Pragma")
_DEPRECATED = frozenset(name.lower() for name in _DEPRECATED_HEADERS)
_CANONICAL = {name.lower(): name for name in HTTPS_HEADERS + _DEPRECATED_HEADERS}
_ANALYZE_ON_REDIRECT = frozenset({"strict-transport-security", "cache-control", "pragma", "expires", "referrer-policy",
                                  "x-content-type-options", "set-cookie"})
_PERMANENT_REDIRECTS = frozenset({301, 308})

NOT_FOUND = "Not Found"
HEADER_MISSING = "Header Is Missing."
BANNER_HEADER = "Banner Grabbing Header"
BANNER_IDENTIFIED = "Banner Grabbing Identified."
REDIRECT_BODY_HEADER = "302 Redirect Body"
HTTPS_REDIRECT_HEADER = "HTTP to HTTPS Redirection"
HTTP2_HEADER = "HTTP2 Protocol"
APP_TEAM = "Application Team"  # default ownership of app-level findings

_REDIRECT_SKIP = "3xx redirection found, skipping analysis for this header"
_REDIRECT_NOT_REQUIRED = "3xx redirection found, This header is not required to be present."
_CSP_NON_HTML = ("The CSP header is present; however, the response does not serve HTML content. Therefore, it is "
                 "marked as not vulnerable.")
_CSP_MISSING_NON_HTML = ("The CSP header is not present; however, the response does not serve HTML content. "
                         "Therefore, it is marked as not vulnerable.")
_CSP_MISSING_REDIRECT = "Marked as vulnerable due to HTML-based redirection and the absence of CSP header."
_CSP_MISSING_HTML = ("Marked as vulnerable because the response serves HTML content (or an unspecified Content-Type) "
                     "without CSP header.")
_CORS_MISSING = ("A payment application that does not send CORS headers is typically viewed as having a restrictive "
                 "cross-origin policy.")
_HSTS_NOT_APPLICABLE = ("The URL uses HTTP, not HTTPS; Strict-Transport-Security is not applicable to plain HTTP "
                        "responses.")
_REDIRECT_BODY = ("A 302 redirect response should not contain a response body. The presence of a response body "
                  "alongside a redirect may expose sensitive content, internal error details, or application "
                  "internals to the client before it follows the Location header. The server should return an empty "
                  "body with the 302 redirect response.")
_CLIENT_SIDE_ONLY = (" A client-side redirect is present in the response body, but the response itself is still "
                     "delivered over plain HTTP; a server-side 301/308 redirect to HTTPS is required.")

# Value, status, details, justification of the HTTP2 Protocol row per detection outcome.
_HTTP2_ROWS = {
    Http2Support.SUPPORTED: ("Supported", NOT_VULNERABLE, "", "HTTP/2 protocol is supported."),
    Http2Support.NOT_SUPPORTED: ("Not Supported", VULNERABLE, "HTTP2 is not supported",
                                 "HTTP/2 protocol is not supported. The server responded with HTTP/1.1 or lower."),
    Http2Support.IO_FAILURE: ("Unable to Determine", ANALYZE_MANUALLY, "IO Exception during HTTP/2 detection.",
                              "IO exception occurred while checking HTTP/2 support. This could indicate network issues "
                              "or server misconfiguration. Retry recommended."),
    Http2Support.OTHER_FAILURE: ("Unable to Determine", ANALYZE_MANUALLY,
                                 "Unexpected failure during HTTP/2 detection. Fallback methods did not provide "
                                 "conclusive results.",
                                 "Multiple detection attempts and fallback mechanisms (including ALPN-based checks) did "
                                 "not yield conclusive results. The server may be using non-standard configurations. "
                                 "Manual verification with HTTP/2-specific tools is strongly recommended."),
}

_ANALYZERS: dict[str, Callable[[str, str], Verdict]] = {
    "x-permitted-cross-domain-policies": lambda value, url: analyzers.cross_domain_policies(value),
    "expires": lambda value, url: analyzers.expires(value),
    "access-control-allow-origin": analyzers.allow_origin,
    "cache-control": analyzers.cache_control,
    "referrer-policy": lambda value, url: analyzers.referrer_policy(value),
    "x-content-type-options": lambda value, url: analyzers.content_type_options(value),
    "x-frame-options": analyzers.frame_options,
    "strict-transport-security": analyzers.strict_transport_security,
    "set-cookie": analyzers.set_cookie,
}


def display_name(header: str) -> str:
    """Canonical spelling for the Header column (Java ``L.b``)."""
    return _CANONICAL.get(header.lower(), header)


def auto_justification(header: str, value: str | None, details: str) -> str:
    """Justification for a Vulnerable row that has none (Java ``L.a(String, String, String)``)."""
    if not is_blank(details):
        text = java_trim(details)
        return "Marked vulnerable because " + (text if text.endswith(".") else text + ".")
    if is_blank(header):
        return "Marked vulnerable because a required security control is missing or misconfigured in the HTTP response."
    if value is not None and value.lower() == NOT_FOUND.lower():
        return f"Marked vulnerable because '{header}' header is missing in the HTTP response."
    return f"Marked vulnerable because '{header}' header value is not configured with a secure value."


def _non_html(content_type: str | None) -> bool:
    if is_blank(content_type):
        return False
    lowered = java_trim(content_type.lower())
    return not (lowered.startswith("text/html") or lowered.startswith("application/xhtml+xml"))


def _joined(headers: Headers, name: str) -> str | None:
    values = [value for key, value in headers if key.lower() == name.lower()]
    return ", ".join(values) if values else None


def _in_list(header_list: tuple[str, ...], name: str) -> bool:
    return any(item.lower() == name.lower() for item in header_list)


class HeaderScanner:
    """Analyses one input URL; rows go through :func:`finalize.add_header_result`."""

    def __init__(self, xlsx_path: str, proxy_host: str | None, proxy_port: int):
        self._xlsx_path = xlsx_path
        self._fetcher = Fetcher(proxy_host, proxy_port)
        self._banner = BannerAnalyzer()

    def _row(self, ip: str, url: str, header: str, value: str | None, code: int, status: str, details: str,
             justification: str, ownership_override: str | None, body: str | None) -> None:
        name = display_name(header)
        if status == VULNERABLE and is_blank(justification):
            justification = auto_justification(name, value, details)
        finalize.add_header_result(self._xlsx_path, ip, url, name, value, code, status, details, justification,
                                   ownership_override, response_preview(body))

    def _report(self, url: str, code: int, protocol: str, details: str, level: str, justification: str,
                body: str | None) -> None:
        self._row("", url, "", "", code, NOT_VULNERABLE, details, justification, None, body)

    def analyze(self, url: str, protocol: str) -> None:
        """One pass ("HTTPS" or "HTTP") over the URL and everything discovered from it."""
        if protocol.lower() == "http" and url.startswith("https://"):
            url = "http://" + url[len("https://"):]
        try:
            parse_url(url)
        except MalformedURLError as exc:
            self._row("", url, "", "", 0, NOT_VULNERABLE, "Invalid URL Format", "URL is not properly formatted: " + url,
                      None, None)
            tinfo(f"Malformed URL exception for URL: {url}, Exception: {exc}")
            return
        header_list = HTTPS_HEADERS if protocol.lower() == "https" else HTTP_HEADERS
        for page in discovery.collect(self._fetcher, url, protocol, self._report):
            self.analyze_response(page, header_list, protocol)

    def analyze_response(self, page: Page, header_list: tuple[str, ...], protocol: str) -> None:
        tinfo(f"Going to start Header Analysis on url ->'{page.url}'")
        found: set[str] = set()
        content_type = first_header(page.headers, "Content-Type")
        for name, value in page.headers:
            if _in_list(header_list, name):
                self._list_header(page, name, value, content_type)
                found.add(name.lower())
            if self._banner.is_banner_header(name):
                self._banner_header(page, name, value)
                found.add(name.lower())
            if java_trim(name).lower() in _DEPRECATED and not _in_list(header_list, name):
                self._row(page.ip, page.url, name, value, page.code, DEPRECATED, "Deprecated header identified.",
                          "The header is deprecated and should be removed rather than used as a primary control.",
                          None, page.body)
                found.add(name.lower())
        for duplicate in analyzers.duplicates(list(page.headers)):
            verdict = duplicate.verdict
            self._row(page.ip, page.url, duplicate.name, " | ".join(duplicate.values), page.code, verdict.status,
                      verdict.details, verdict.justification, None, page.body)
        for name in sorted(header_list, key=str.lower):
            if name.lower() not in found:
                self._missing_header(page, name, content_type)
        if page.code == 302:
            self._redirect_body(page)
        if protocol.lower() == "http" and analyzers.is_http(page.url):
            self._https_redirection(page, protocol)
        if protocol.lower() == "https":
            self._http2(page)
        tinfo(f"Header Analysis completed on url ->'{page.url}'")

    def _list_header(self, page: Page, name: str, value: str, content_type: str | None) -> None:
        if page.code in discovery.REDIRECT_CODES and java_trim(name).lower() not in _ANALYZE_ON_REDIRECT:
            self._row(page.ip, page.url, name, value, page.code, NOT_VULNERABLE, "", _REDIRECT_SKIP, None, page.body)
            return
        is_csp = finalize.is_csp_header(name)
        if is_csp and _non_html(content_type):
            self._row(page.ip, page.url, name, value, page.code, NOT_VULNERABLE, "", _CSP_NON_HTML, None, page.body)
            return
        if name.lower() == "content-security-policy":
            verdict = csp.evaluate(value, _joined(page.headers, "Reporting-Endpoints"),
                                   _joined(page.headers, "Report-To"))
        else:
            verdict = _ANALYZERS[name.lower()](value, page.url)
        justification = verdict.justification
        if is_csp:
            justification = csp.ownership_justification(page.url, page.ip, verdict.status,
                                                        reference_data.get().csp_owner)
        self._row(page.ip, page.url, name, value, page.code, verdict.status, verdict.details, justification, None,
                  page.body)

    def _banner_header(self, page: Page, name: str, value: str) -> None:
        identified = f"{BANNER_IDENTIFIED} ({name}: {value})"
        if self._banner.is_ignored(value):
            self._row(page.ip, page.url, BANNER_HEADER, value, page.code, NOT_VULNERABLE, identified,
                      "Not a banner grabbing finding as the header value is in the ignore list.", None, page.body)
        elif not is_blank(value):
            assessment = self._banner.assess(name, value)
            details, justification = identified, ""
            if assessment.has_version:
                justification = self._banner.justification(assessment)
                if assessment.vulnerable:
                    details = f"{BANNER_IDENTIFIED} {assessment.message} ({name}: {value})"
            self._row(page.ip, page.url, BANNER_HEADER, value, page.code, VULNERABLE, details, justification, None,
                      page.body)
        else:
            self._row(page.ip, page.url, BANNER_HEADER, value, page.code, NOT_VULNERABLE, identified, "", None,
                      page.body)

    def _missing_header(self, page: Page, name: str, content_type: str | None) -> None:
        lowered = name.lower()

        def row(status: str, details: str, justification: str, override: str | None = None) -> None:
            self._row(page.ip, page.url, name, NOT_FOUND, page.code, status, details, justification, override,
                      page.body)

        if page.code in discovery.REDIRECT_CODES and lowered not in _ANALYZE_ON_REDIRECT:
            row(NOT_VULNERABLE, "", _REDIRECT_NOT_REQUIRED)
        elif lowered == "set-cookie":
            row(NOT_VULNERABLE, "", "")
        elif lowered == "access-control-allow-origin":
            row(NOT_VULNERABLE, "", _CORS_MISSING)
        elif not finalize.is_csp_header(name):
            if lowered == "strict-transport-security" and not analyzers.is_https(page.url):
                row(NOT_VULNERABLE, "", _HSTS_NOT_APPLICABLE)
            elif lowered == "x-frame-options" and analyzers.is_acs_domain(page.url):
                row(NOT_VULNERABLE, "", analyzers.ACS_PREFIX + "X-Frame-Options is ignored.")
            else:
                row(VULNERABLE, HEADER_MISSING, "")
        elif _non_html(content_type):
            row(NOT_VULNERABLE, "", _CSP_MISSING_NON_HTML)
        elif is_html_redirect(page.body):
            row(VULNERABLE, f"[CRITICAL] {HEADER_MISSING} No policy is enforced. \n", _CSP_MISSING_REDIRECT, APP_TEAM)
        else:
            row(VULNERABLE, f"[CRITICAL] {HEADER_MISSING} No policy is enforced. \n", _CSP_MISSING_HTML)

    def _redirect_body(self, page: Page) -> None:
        if not is_blank(page.body):
            self._row(page.ip, page.url, REDIRECT_BODY_HEADER, f"{java_length(page.body)} bytes", page.code,
                      VULNERABLE, "302 Redirect Response Contains Body.", _REDIRECT_BODY, APP_TEAM, page.body)
        else:
            self._row(page.ip, page.url, REDIRECT_BODY_HEADER, "Empty", page.code, NOT_VULNERABLE, "",
                      "302 redirect response does not contain a response body.", APP_TEAM, None)

    def _https_redirection(self, page: Page, protocol: str) -> None:
        chain = discovery.follow_redirects(self._fetcher, page.url, protocol)
        described, last, outcome = chain.describe(), chain.last, chain.outcome

        def row(value: str, status: str, details: str, justification: str) -> None:
            self._row(page.ip, page.url, HTTPS_REDIRECT_HEADER, value, page.code, status, details, justification, APP_TEAM,
                      page.body)

        if outcome is RedirectOutcome.HTTPS:
            source_host, target_host = url_host_or_raw(page.url).lower(), url_host_or_raw(last).lower()
            details = "" if source_host == target_host else f"Redirects to HTTPS on a different host ({target_host})."
            justification = f"The HTTP request is redirected to HTTPS: {described}."
            if chain.last_code not in _PERMANENT_REDIRECTS:
                justification += (f" The redirect to HTTPS uses a temporary status code ({chain.last_code}); a "
                                  "permanent redirect (301/308) is recommended.")
            row(last, NOT_VULNERABLE, details, justification)
        elif outcome is RedirectOutcome.NOT_REDIRECTED:
            direct = len(chain.chain) == 1
            details = "[MEDIUM] HTTP request is not redirected to HTTPS."
            if direct:
                justification = f"The server responded with {chain.last_code} over plain HTTP instead of redirecting to HTTPS."
            else:
                justification = f"The redirect chain ends on plain HTTP without reaching HTTPS: {described}."
            if is_html_redirect(chain.final_body):
                details += " Only a client-side (HTML/JavaScript) redirect is present."
                justification += _CLIENT_SIDE_ONLY
            row("No Redirect" if direct else last, VULNERABLE, details, justification)
        elif outcome is RedirectOutcome.NO_LOCATION:
            row("No Location Header", VULNERABLE,
                "[MEDIUM] HTTP request is not redirected to HTTPS; the redirect response has no Location header.",
                f"Redirect chain: {described}.")
        elif outcome is RedirectOutcome.INVALID_LOCATION:
            row(chain.raw_location, VULNERABLE,
                "[MEDIUM] HTTP request is not redirected to HTTPS; the Location header is not a valid HTTP(S) URL.",
                f"Redirect chain: {described}, Location: '{chain.raw_location}'.")
        elif outcome is RedirectOutcome.LOOP:
            row("Redirect Loop", VULNERABLE,
                "[MEDIUM] HTTP request is not redirected to HTTPS; the redirect chain loops over plain HTTP.",
                f"Redirect chain: {described}.")
        elif outcome is RedirectOutcome.OPEN_FAILED:
            row("Unable to Determine", ANALYZE_MANUALLY, "Redirect chain could not be followed.",
                f"'{last}' could not be opened while following the redirect chain: {described}. "
                "Manual verification recommended.")
        else:
            row("Unable to Determine", ANALYZE_MANUALLY, "Redirect chain did not reach HTTPS within the hop limit.",
                f"Redirect chain: {described}. Manual verification recommended.")

    def _http2(self, page: Page) -> None:
        if page.url.startswith("https://"):
            value, status, details, justification = _HTTP2_ROWS[http2.cached_detect(page.url)]
        else:
            value, status, details, justification = (
                "Not Applicable", NOT_VULNERABLE, "HTTP2 is not applicable for non-HTTPS URLs",
                "The URL is not HTTPS, hence HTTP2 protocol is not required. HTTP/2 is exclusively defined for HTTPS "
                "connections.")
        self._row(page.ip, page.url, HTTP2_HEADER, value, page.code, status, details, justification, None, page.body)
