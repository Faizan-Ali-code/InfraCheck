"""Per-header analyzers (Java ``G``, ``x``, ``D``, ``H``, ``I``, ``J``, ``A``, ``m``, ``F``), duplicate-header detection
(``y``) and the ACS/VBV/Virtual-Card domain test (``a``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from ...javacompat.java_date import day_number, parse_dd_mm_yyyy
from ...javacompat.java_uri import JavaURI
from ...javacompat.strings import is_blank, java_trim
from .verdict import NOT_VULNERABLE, PASS, Verdict, vulnerable

ACS_PREFIX = "The domain is related to ACS/VBV/Virtual Card; "
_ACS_MARKERS = ("-acs", "-midc", "-vbv", "-msc", "paxum-upi", "-virtual")
_HTTP_ONLY_HSTS = "The URL uses HTTP, not HTTPS; Strict-Transport-Security is not applicable to plain HTTP responses."
_HTTP_ONLY_CACHE = "The URL uses HTTP, not HTTPS; Cache-Control is not applicable to plain HTTP responses."
_STRONG_REFERRER = frozenset({"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"})
_EXPIRES_FUTURE = "'Expires' header is misconfigured, Value should be in past date, or 0 or -1  "
_EXPIRES_INVALID = "'Expires' header is misconfigured, Value should be in past date, or 0 or -1"
_WILDCARD_ORIGIN = ("Using 'Access-Control-Allow-Origin: *' allows any domain to access the resource and should be "
                    "restricted to explicitly trusted domains wherever possible. This header is appropriate only for "
                    "publicly accessible CDN-hosted static resources, not for application endpoints. If cross-origin "
                    "access is not required, omitting the header provides a more secure configuration.")
_CSRF_COOKIES = frozenset({"xsrf-token", "csrf-token", "csrf_token", "_csrf", "_csrf_token", "anti-csrf-token",
                           "antiforgerytoken", "x-csrf-token", "x-xsrf-token", "csrftoken"})
_SAMESITE = re.compile(r"samesite\s*=\s*([a-z]+)", re.A)
_DUPLICATE_CHECKED = frozenset({"content-security-policy", "x-permitted-cross-domain-policies", "referrer-policy",
                                "strict-transport-security", "cache-control", "expires", "x-content-type-options",
                                "x-frame-options", "access-control-allow-origin"})
_LIST_SEPARATOR = re.compile(r"[,;]")
_JAVA_SPACES = re.compile(r"[ \t\n\x0b\x0c\r]+")


def is_https(url: str | None) -> bool:
    return url is not None and java_trim(url).lower().startswith("https://")


def is_http(url: str | None) -> bool:
    return url is not None and java_trim(url).lower().startswith("http://")


def is_acs_domain(url: str | None) -> bool:
    """Host contains an ACS/VBV/Virtual-Card marker (Java ``a.a``); registry-based hosts never match."""
    if is_blank(url):
        return False
    try:
        host = JavaURI.create(java_trim(url)).host
    except ValueError:
        return False
    if host is None or not host.strip():
        return False
    host = host.lower()
    return any(marker in host for marker in _ACS_MARKERS)


def strict_transport_security(value: str, url: str) -> Verdict:
    if not is_https(url):
        return Verdict(NOT_VULNERABLE, "", _HTTP_ONLY_HSTS)
    lowered = value.lower()
    max_age = "max-age=31536000" in lowered or "max-age=63072000" in lowered
    subdomains = "includesubdomains" in lowered
    preload = "preload" in lowered
    if max_age and subdomains and preload:
        return PASS
    details = ""
    if not max_age:
        details += "'max-age' attribute is missing/misconfigured. "
    if not subdomains:
        details += "'includesubdomains' attribute is missing. "
    if not preload:
        details += "'preload' attribute is missing. "
    return vulnerable(details)


def cache_control(value: str, url: str) -> Verdict:
    if not is_https(url):
        return Verdict(NOT_VULNERABLE, "", _HTTP_ONLY_CACHE)
    lowered = value.lower()
    no_cache, no_store = "no-cache" in lowered, "no-store" in lowered
    if no_cache and no_store:
        return PASS
    return vulnerable(("" if no_cache else "'no-cache' attribute is missing. ")
                      + ("" if no_store else "'no-store' attribute is missing. "))


def referrer_policy(value: str) -> Verdict:
    if is_blank(value):
        return vulnerable("Header Is Missing.")
    if java_trim(value.lower()) in _STRONG_REFERRER:
        return PASS
    return vulnerable(f"'{value}' is a weak or non-restrictive Referrer-Policy value.")


def content_type_options(value: str) -> Verdict:
    return PASS if "nosniff" in value.lower() else vulnerable("'nosniff' value is missing. ")


def frame_options(value: str, url: str) -> Verdict:
    lowered = value.lower()
    if "sameorigin" in lowered or "deny" in lowered:
        return PASS
    if is_acs_domain(url):
        return Verdict(NOT_VULNERABLE, "", ACS_PREFIX + "X-Frame-Options is ignored.")
    return vulnerable("'sameorigin' or 'deny' value is missing. ")


def cross_domain_policies(value: str) -> Verdict:
    if is_blank(value):
        return vulnerable("Header Is Missing.")
    if java_trim(value.lower()) == "none":
        return PASS
    return vulnerable(f"'{value}' permits broader cross-domain policy file access than recommended.")


def expires(value: str, today: date | None = None) -> Verdict:
    """Past ``dd-MM-yyyy`` dates pass; anything unparseable passes when it contains "-1" or "0" (Java ``A``)."""
    try:
        parsed = parse_dd_mm_yyyy(value)
    except ValueError:
        lowered = value.lower()
        return PASS if "-1" in lowered or "0" in lowered else vulnerable(_EXPIRES_INVALID)
    return PASS if parsed < day_number(today or date.today()) else vulnerable(_EXPIRES_FUTURE)


def allow_origin(value: str, url: str) -> Verdict:
    if is_blank(value):
        return PASS
    origin = java_trim(value)
    if origin == "*":
        if is_acs_domain(url):
            return Verdict(NOT_VULNERABLE, "", ACS_PREFIX + "Access-Control-Allow-Origin is ignored.")
        return vulnerable("Wildcard origin is configured.", _WILDCARD_ORIGIN)
    if origin.lower() == "null":
        return vulnerable("Origin 'null' is allowed.")
    if not (origin.startswith("http://") or origin.startswith("https://")):
        return vulnerable("Header value is invalid.")
    return PASS


def _cookie_name(value: str) -> str:
    pair = value.split(";", 1)[0]
    equals = pair.find("=")
    return java_trim(pair[:equals]) if equals > 0 else ""


def _is_csrf_cookie(name: str) -> bool:
    if is_blank(name):
        return False
    lowered = java_trim(name).lower()
    return lowered in _CSRF_COOKIES or any(token in lowered for token in _CSRF_COOKIES)


def set_cookie(value: str, url: str) -> Verdict:
    if is_blank(value):
        return PASS
    lowered = value.lower()
    name = _cookie_name(value)
    secure, httponly, samesite = "secure" in lowered, "httponly" in lowered, "samesite" in lowered
    match = _SAMESITE.search(lowered)
    samesite_none_insecure = (java_trim(match.group(1)) if match else "") == "none" and not secure
    csrf = _is_csrf_cookie(name)
    missing_secure = is_https(url) and not secure
    missing_httponly = not httponly and not csrf
    acceptable = not missing_secure and not missing_httponly and samesite and not samesite_none_insecure
    if acceptable and httponly:
        return PASS
    details = ""
    if missing_secure:
        details += "'secure' attribute is missing. "
    if not httponly:
        if csrf:
            details += (f"[INFO] HttpOnly not set on cookie '{java_trim(name)}' - expected behavior for CSRF "
                        "double-submit pattern; verify Secure and SameSite are still enforced. ")
        else:
            details += "'httponly' attribute is missing. "
    if not samesite:
        if "TS01" in value:
            details += "'samesite' attribute is missing on Load Balancer Cookie (TS01). "
        else:
            details += "'samesite' attribute is missing. "
    elif samesite_none_insecure:
        details += "'samesite=none' is set without 'secure'; modern browsers will reject this cookie entirely. "
    if not is_blank(name):
        details += f"(Cookie: '{name}') "
    return Verdict(NOT_VULNERABLE, java_trim(details)) if acceptable else vulnerable(java_trim(details))


@dataclass(frozen=True)
class Duplicate:
    name: str
    values: list[str]
    verdict: Verdict


def _normalized_list(value: str) -> str:
    items = (_JAVA_SPACES.sub(" ", java_trim(part)) for part in _LIST_SEPARATOR.split(value.lower()))
    return ",".join(sorted((item for item in items if item), key=lambda s: s.encode("utf-16-be", "surrogatepass")))


def duplicates(headers: list[tuple[str, str]]) -> list[Duplicate]:
    """Security headers that occur more than once (Java ``y``); Set-Cookie is not checked."""
    names: dict[str, str] = {}
    groups: dict[str, list[str]] = {}
    for name, value in headers:
        key = name.lower()
        if key in _DUPLICATE_CHECKED:
            names.setdefault(key, name)
            groups.setdefault(key, []).append(value)
    found = []
    for key, values in groups.items():
        if len(values) < 2:
            continue
        name = names[key]
        joined = " | ".join(values)
        first = _normalized_list(values[0])
        if all(_normalized_list(v) == first for v in values):
            verdict = vulnerable(
                f"[INFO] '{name}' header appears {len(values)} times in the response with identical values "
                f"({joined}). \n",
                f"The '{name}' header is duplicated, but all occurrences carry the identical value, so severity is "
                "INFO as there is no impact.")
        else:
            verdict = vulnerable(
                f"[HIGH] '{name}' header appears {len(values)} times in the response with differing values "
                f"({joined}). \n",
                f"The '{name}' header is duplicated and the occurrences carry different values, which can be "
                "interpreted inconsistently by browsers/proxies and may result in the weaker or unintended value "
                "being enforced; severity is HIGH.")
        found.append(Duplicate(name, values, verdict))
    return found
