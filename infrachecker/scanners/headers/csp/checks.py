"""CSP checks (Java ``a.b.*``): upstream security and parser checks, the strict-dynamic check and the
custom frame-ancestors / reporting checks.
"""
from __future__ import annotations

import re
from typing import Callable

from ....javacompat.strings import java_trim
from ....javacompat.utf16 import java_length
from .bypass_lists import ANGULAR_URLS, FLASH_URLS, JSONP_NEEDS_EVAL, JSONP_URLS
from .policy import (DIRECTIVES, KEYWORDS, NONE, SELF, STRICT_DYNAMIC, TRUSTED_TYPES_SCRIPT, UNSAFE_EVAL,
                     UNSAFE_HASHES, UNSAFE_INLINE, Csp, Finding, is_hash, is_keyword, is_nonce, is_url_scheme,
                     nonce_value)
from .urls import get_hostname, match_wildcard_urls, scheme_free_url

Check = Callable[[Csp], list[Finding]]

_XSS_DIRECTIVES = ["script-src", "script-src-attr", "script-src-elem", "object-src", "base-uri"]
_XSS_SCHEMES = ("data:", "http:", "https:")
_SCRIPT_DIRECTIVES = ["script-src", "script-src-attr", "script-src-elem"]
_IPV4ISH = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_KEYWORDS_WITHOUT_TICKS = [keyword.replace("'", "") for keyword in KEYWORDS]
_HASH_PREFIX = re.compile(r"^(sha256|sha384|sha512)-")
_REPORT_TO_GROUP = re.compile(r'"group"\s*:\s*"((?:[^"\\]|\\.)*)"', re.A)
_ENDPOINT_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")


# ---------------------------------------------------------------------------------------- upstream DEFAULT_CHECKS

def script_unsafe_inline(csp: Csp) -> list[Finding]:
    found = []
    for directive in csp.effective_directives(_SCRIPT_DIRECTIVES):
        values = csp.values(directive)
        if UNSAFE_INLINE in values:
            found.append(Finding("'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers.",
                                 "HIGH", directive, UNSAFE_INLINE))
        if UNSAFE_HASHES in values:
            found.append(Finding("'unsafe-hashes', while safer than 'unsafe-inline', allows the execution of unsafe "
                                 "in-page scripts and event handlers as long as their hashes appear in the CSP. "
                                 "Please refactor them to no longer use inline scripts if possible.",
                                 "MEDIUM_MAYBE", directive, UNSAFE_HASHES))
    return found


def script_unsafe_eval(csp: Csp) -> list[Finding]:
    return [Finding("'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().",
                    "MEDIUM_MAYBE", directive, UNSAFE_EVAL)
            for directive in csp.effective_directives(_SCRIPT_DIRECTIVES) if UNSAFE_EVAL in csp.values(directive)]


def plain_url_schemes(csp: Csp) -> list[Finding]:
    return [Finding(value + " URI in " + directive + " allows the execution of unsafe scripts.", "HIGH", directive,
                    value)
            for directive in csp.effective_directives(_XSS_DIRECTIVES) for value in csp.values(directive)
            if value in _XSS_SCHEMES]


def wildcards(csp: Csp) -> list[Finding]:
    return [Finding(directive + " should not allow '*' as source", "HIGH", directive, value)
            for directive in csp.effective_directives(_XSS_DIRECTIVES) for value in csp.values(directive)
            if scheme_free_url(value) == "*"]


def missing_directives(csp: Csp) -> list[Finding]:
    found = []
    restriction: list[str] | None = []
    if "object-src" in csp.directives:
        restriction = csp.get("object-src")
    elif "default-src" in csp.directives:
        restriction = csp.get("default-src")
    if not restriction:
        found.append(Finding("Missing object-src allows the injection of plugins which can execute JavaScript. "
                             "Can you set it to 'none'?", "HIGH", "object-src"))
    if "script-src" not in csp.directives and "default-src" not in csp.directives:
        found.append(Finding("script-src directive is missing.", "HIGH", "script-src"))
    needs_base_uri = csp.has_script_nonces() or (csp.has_script_hashes() and csp.has_strict_dynamic())
    if needs_base_uri and "base-uri" not in csp.directives:
        found.append(Finding("Missing base-uri allows the injection of base tags. They can be used to set the base "
                             "URL for all relative (script) URLs to an attacker controlled domain. Can you set it "
                             "to 'none' or 'self'?", "HIGH", "base-uri"))
    return found


def script_allowlist_bypass(csp: Csp) -> list[Finding]:
    found = []
    for directive in csp.effective_directives(["script-src", "script-src-elem"]):
        values = csp.values(directive)
        if NONE in values:
            continue
        for value in values:
            if value == SELF:
                found.append(Finding("'self' can be problematic if you host JSONP, AngularJS or user uploaded "
                                     "files.", "MEDIUM_MAYBE", directive, value))
                continue
            if value.startswith("'") or is_url_scheme(value) or "." not in value:
                continue
            url = "//" + scheme_free_url(value)
            angular = match_wildcard_urls(url, ANGULAR_URLS)
            jsonp = match_wildcard_urls(url, JSONP_URLS)
            if jsonp is not None and jsonp.hostname in JSONP_NEEDS_EVAL and UNSAFE_EVAL not in values:
                jsonp = None
            if jsonp is None and angular is None:
                found.append(Finding("No bypass found; make sure that this URL doesn't serve JSONP replies or "
                                     "Angular libraries.", "MEDIUM_MAYBE", directive, value))
                continue
            domain, text = "", ""
            if jsonp is not None:
                domain, text = jsonp.hostname, " JSONP endpoints"
            if angular is not None:
                domain = angular.hostname
                text += "" if java_trim(text) == "" else " and"
                text += " Angular libraries"
            found.append(Finding(domain + " is known to host" + text + " which allow to bypass this CSP.", "HIGH",
                                 directive, value))
    return found


def flash_object_allowlist_bypass(csp: Csp) -> list[Finding]:
    found = []
    directive = csp.effective_directive("object-src")
    plugin_types = csp.get("plugin-types")
    if plugin_types is not None and "application/x-shockwave-flash" not in plugin_types:
        return []
    for value in csp.values(directive):
        if value == NONE:
            return []
        bypass = match_wildcard_urls("//" + scheme_free_url(value), FLASH_URLS)
        if bypass is not None:
            found.append(Finding(bypass.hostname + " is known to host Flash files which allow to bypass this CSP.",
                                 "HIGH", directive, value))
        elif directive == "object-src":
            found.append(Finding("Can you restrict object-src to 'none' only?", "MEDIUM_MAYBE", directive, value))
    return found


def _looks_like_ip(host: str) -> bool:
    return (host.startswith("[") and host.endswith("]")) or _IPV4ISH.fullmatch(host) is not None


def ip_source(csp: Csp) -> list[Finding]:
    found = []
    for directive, values in csp.directives.items():
        for value in values:
            host = get_hostname(value)
            if not _looks_like_ip(host):
                continue
            if host == "127.0.0.1":
                found.append(Finding(directive + " directive allows localhost as source. Please make sure to remove "
                                     "this in production environments.", "INFO", directive, value))
            else:
                found.append(Finding(directive + " directive has an IP-Address as source: " + host + " (will be "
                                     "ignored by browsers!). ", "INFO", directive, value))
    return found


def deprecated_directives(csp: Csp) -> list[Finding]:
    found = []
    if "reflected-xss" in csp.directives:
        found.append(Finding("reflected-xss is deprecated since CSP2. Please, use the X-XSS-Protection header "
                             "instead.", "INFO", "reflected-xss"))
    if "referrer" in csp.directives:
        found.append(Finding("referrer is deprecated since CSP2. Please, use the Referrer-Policy header instead.",
                             "INFO", "referrer"))
    if "disown-opener" in csp.directives:
        found.append(Finding("disown-opener is deprecated since CSP3. Please, use the Cross Origin Opener Policy "
                             "header instead.", "INFO", "disown-opener"))
    if "prefetch-src" in csp.directives:
        found.append(Finding("prefetch-src is deprecated since CSP3. Be aware that this feature may cease to work "
                             "at any time.", "INFO", "prefetch-src"))
    return found


def nonce_length(csp: Csp) -> list[Finding]:
    found = []
    for directive, values in csp.directives.items():
        for value in values:
            nonce = nonce_value(value)
            if nonce is None:
                continue
            if java_length(nonce) < 8:
                found.append(Finding("Nonces should be at least 8 characters long.", "MEDIUM", directive, value))
            if not is_nonce(value, True):
                found.append(Finding("Nonces should only use the base64 charset.", "INFO", directive, value))
    return found


def src_http(csp: Csp) -> list[Finding]:
    found = []
    for directive, values in csp.directives.items():
        description = ("Use HTTPS to send violation reports securely." if directive == "report-uri"
                       else "Allow only resources downloaded over HTTPS.")
        found.extend(Finding(description, "MEDIUM", directive, value) for value in values
                     if value.startswith("http://"))
    return found


def unknown_directives(csp: Csp) -> list[Finding]:
    found = []
    for directive in csp.directives:
        if directive in DIRECTIVES:
            continue
        if directive.endswith(":"):
            found.append(Finding("CSP directives don't end with a colon.", "SYNTAX", directive))
        else:
            found.append(Finding('Directive "' + directive + '" is not a known CSP directive.', "SYNTAX", directive))
    return found


def missing_semicolon(csp: Csp) -> list[Finding]:
    return [Finding('Did you forget the semicolon? "' + value + '" seems to be a directive, not a value.', "SYNTAX",
                    directive, value)
            for directive, values in csp.directives.items() for value in values if value in DIRECTIVES]


def invalid_keywords(csp: Csp) -> list[Finding]:
    found = []
    for directive, values in csp.directives.items():
        for value in values:
            if value in _KEYWORDS_WITHOUT_TICKS or value.startswith("nonce-") or _HASH_PREFIX.search(value):
                found.append(Finding('Did you forget to surround "' + value + '" with single-ticks?', "SYNTAX",
                                     directive, value))
                continue
            if not value.startswith("'"):
                continue
            if directive == "require-trusted-types-for":
                if value == TRUSTED_TYPES_SCRIPT:
                    continue
            elif directive == "trusted-types":
                if value in ("'allow-duplicates'", "'none'"):
                    continue
            elif is_keyword(value) or is_hash(value, True) or is_nonce(value, True):
                continue
            found.append(Finding(value + " seems to be an invalid CSP keyword.", "SYNTAX", directive, value))
    return found


DEFAULT_CHECKS: list[Check] = [
    script_unsafe_inline, script_unsafe_eval, plain_url_schemes, wildcards, missing_directives,
    script_allowlist_bypass, flash_object_allowlist_bypass, ip_source, nonce_length, src_http,
    deprecated_directives, unknown_directives, missing_semicolon, invalid_keywords]


def strict_dynamic(csp: Csp) -> list[Finding]:
    """Upstream strict-CSP check (the only one of that list the wrapper runs)."""
    directive = csp.effective_directive("script-src")
    values = csp.values(directive)
    if any(not value.startswith("'") for value in values) and STRICT_DYNAMIC not in values:
        return [Finding("Host allowlists can frequently be bypassed. Consider using 'strict-dynamic' in combination "
                        "with CSP nonces or hashes.", "STRICT_CSP", directive)]
    return []


# ---------------------------------------------------------------------------------------- custom checks

def frame_ancestors(csp: Csp) -> list[Finding]:
    values = csp.get("frame-ancestors")
    if not values:
        return [Finding("frame-ancestors is missing, so any site can frame this page (clickjacking). "
                        "frame-ancestors does not fall back to default-src; set it to 'self' or 'none'.", "MEDIUM",
                        "frame-ancestors")]
    found = []
    for value in values:
        if value.startswith("'"):
            continue
        if value == "*" or is_url_scheme(value):
            found.append(Finding("Any site can frame this page (clickjacking). Use 'self' or 'none'.", "MEDIUM",
                                 "frame-ancestors", value))
        elif not value.startswith("http://"):
            found.append(Finding("Internal policy allows only 'self' or 'none'; make sure this origin is trusted to "
                                 "frame this page.", "INFO", "frame-ancestors", value))
    return found


def report_to(csp: Csp) -> list[Finding]:
    values = csp.get("report-to")
    if values is None:
        if "report-uri" in csp.directives:
            return [Finding("report-uri is deprecated in CSP3. Add report-to (with a matching Reporting-Endpoints "
                            "header) and keep report-uri as a fallback for browsers without report-to support.",
                            "LOW", "report-to")]
        return [Finding("No reporting destination is configured, so CSP violations are not monitored. Add report-to "
                        "(with a matching Reporting-Endpoints header), and report-uri as a fallback.", "LOW",
                        "report-to")]
    if not values:
        return [Finding("report-to has no reporting group name, so no reports are sent through it.", "LOW",
                        "report-to")]
    return []


def _split_unquoted(text: str, separator: str) -> list[str]:
    """Split on ``separator`` outside double quotes (backslash escapes inside quotes)."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quoted and ch == "\\" and i + 1 < len(text):
            current.append(text[i:i + 2])
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif ch == separator and not quoted:
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def _reporting_endpoints(header: str | None) -> dict[str, str]:
    endpoints: dict[str, str] = {}
    if header is None:
        return endpoints
    for member in _split_unquoted(header, ","):
        first = java_trim(_split_unquoted(member, ";")[0])
        if not first:
            continue
        equals = first.find("=")
        if equals < 0:
            endpoints[first] = ""
        else:
            endpoints[java_trim(first[:equals])] = java_trim(first[equals + 1:])
    return endpoints


def _report_to_groups(header: str | None) -> set[str]:
    """Group names of the top-level JSON objects of a Report-To header ("default" when unnamed)."""
    groups: set[str] = set()
    if header is None:
        return groups
    depth, start, quoted = 0, -1, False
    i = 0
    while i < len(header):
        ch = header[i]
        if quoted:
            if ch == "\\":
                i += 1
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                match = _REPORT_TO_GROUP.search(header[start:i + 1])
                groups.add(match.group(1) if match else "default")
        i += 1
    return groups


def _endpoint_problem(value: str) -> str | None:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        inner = java_trim(value[1:-1])
        if inner == "":
            return "the endpoint URL is empty"
        match = _ENDPOINT_SCHEME.match(inner)
        if match and match.group(1).lower() != "https":
            return "the endpoint URL must use HTTPS (browsers only send reports to secure endpoints)"
        return None
    return "the endpoint URL must be a quoted string (browsers ignore the whole header otherwise)"


def reporting_endpoints(csp: Csp, endpoints_header: str | None, report_to_header: str | None) -> list[Finding]:
    groups = csp.values("report-to")
    if not groups:
        return []
    header_missing = endpoints_header is None or java_trim(endpoints_header) == ""
    endpoints = _reporting_endpoints(endpoints_header)
    legacy_groups = _report_to_groups(report_to_header)
    found = []
    for group in groups:
        example = group + '="https://example.com/csp-reports"'
        endpoint = endpoints.get(group)
        if endpoint is not None:
            problem = _endpoint_problem(endpoint)
            if problem is not None:
                found.append(Finding("Reporting-Endpoints defines this group as " + (endpoint or "no value")
                                     + ", but " + problem + ", so no CSP violation reports are sent. Use e.g. "
                                     + example + ".", "LOW", "report-to", group))
        elif group in legacy_groups:
            found.append(Finding("This group is defined only in the deprecated Report-To header. Define it in a "
                                 "Reporting-Endpoints header as well, e.g. " + example + ".", "INFO", "report-to",
                                 group))
        elif header_missing:
            found.append(Finding("The Reporting-Endpoints header is missing, so this group has no endpoint and no CSP "
                                 "violation reports are sent. Add a Reporting-Endpoints header, e.g. " + example + ".",
                                 "LOW", "report-to", group))
        else:
            found.append(Finding("The Reporting-Endpoints header does not define this group, so no CSP violation "
                                 "reports are sent. Add it to the header, e.g. " + example + ".", "LOW", "report-to",
                                 group))
    return found
