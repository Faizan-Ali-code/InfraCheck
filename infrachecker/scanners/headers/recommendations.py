"""Recommendation column text per header (Java ``C``)."""
from __future__ import annotations

from ...javacompat.strings import java_trim

BANNER_HEADER_NAMES = (
    "$wsep", "Host-Header", "K-Proxy-Request", "Liferay-Portal", "OracleCommerceCloud-Version", "Pega-Host",
    "Powered-By", "Product", "Server", "SourceMap", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Atmosphere-error",
    "X-Atmosphere-first-request", "X-Atmosphere-tracking-id", "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-SpanId",
    "X-B3-TraceId", "X-BEServer", "X-CF-Powered-By", "X-CMS", "X-CalculatedBETarget", "X-Content-Encoded-By",
    "X-DiagInfo", "X-Envoy-Attempt-Count", "X-Envoy-External-Address", "X-Envoy-Internal",
    "X-Envoy-Original-Dst-Host", "X-Envoy-Upstream-Service-Time", "X-FEServer", "X-Framework", "X-Generated-By",
    "X-Generator", "X-LiteSpeed-Cache", "X-LiteSpeed-Purge", "X-LiteSpeed-Tag", "X-LiteSpeed-Vary",
    "X-Litespeed-Cache-Control", "X-Mod-Pagespeed", "X-Nextjs-Cache", "X-Nextjs-Matched-Path", "X-Nextjs-Page",
    "X-Nextjs-Redirect", "X-OWA-Version", "X-Old-Content-Length", "X-OneAgent-JS-Injection", "X-Page-Speed",
    "X-Php-Version", "X-Powered-By", "X-Powered-By-Plesk", "X-Powered-CMS", "X-Redirect-By", "X-Server-Powered-By",
    "X-SourceFiles", "X-SourceMap", "X-Turbo-Charged-By", "X-Umbraco-Version", "X-Varnish-Backend",
    "X-Varnish-Server", "X-dtAgentId", "X-dtHealthCheck", "X-dtInjectedServlet", "X-ruxit-JS-Agent")

_TECHNOLOGY_DISCLOSURE = frozenset(name.lower() for name in BANNER_HEADER_NAMES)
_DISCLOSURE_TEXT = ("Do not expose technology or version details in response headers. "
                    "Remove or obfuscate this header value.")
_DEFAULT = "Review header configuration and align with secure baseline policy"
_BY_HEADER = {
    "x-permitted-cross-domain-policies": "'none' is the most secure value if your application does not require Adobe "
                                         "cross-domain access (which is the case for almost all modern web "
                                         "applications).",
    "expires": "0 or -1 (or a valid date in the past)",
    "access-control-allow-origin": "Set explicit trusted HTTPS origin(s), avoid '*' and 'null'",
    "pragma": "no-cache",
    "x-xss-protection": "1; mode=block",
    "public-key-pins": "Remove deprecated HPKP/Public-Key-Pins; use modern certificate lifecycle controls",
    "cache-control": "no-store, no-cache",
    "expect-ct": "Remove deprecated Expect-CT; rely on Certificate Transparency enforcement by browsers",
    "referrer-policy": "strict-origin-when-cross-origin (or no-referrer for highly sensitive endpoints)",
    "x-content-type-options": "'nosniff' is the recommended value to prevent MIME type sniffing.",
    "x-frame-options": "DENY or SAMEORIGIN. Avoid ALLOW-FROM as it is deprecated. Use Content-Security-Policy "
                       "frame-ancestors directive for more granular control.",
    "feature-policy": "Remove deprecated Feature-Policy and use Permissions-Policy with least privilege",
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "Use a strict, nonce- or hash-based policy: script-src 'nonce-{random}' "
                               "'strict-dynamic' (a new nonce on every response, at least 8 characters, or sha256 "
                               "hashes) with no host allowlist; 'strict-dynamic' makes CSP3 browsers ignore hosts "
                               "and 'self', and https: may be kept only as a fallback for old browsers. No "
                               "'unsafe-eval', and no '*', http: or data: in script-src. Set object-src 'none', "
                               "base-uri 'none' or 'self', and frame-ancestors 'self' or 'none'. Add report-to (with "
                               "a matching Reporting-Endpoints header), keeping report-uri as a fallback. Hardening "
                               "(not scored): form-action 'self' or explicit HTTPS origins",
    "set-cookie": "Use Secure; HttpOnly; SameSite=Strict (or SameSite=Lax where required)",
    "content-security-policy-report-only": "Same rules as Content-Security-Policy (nonce/hash + 'strict-dynamic', no "
                                           "host allowlist, object-src 'none', base-uri restricted, frame-ancestors "
                                           "'self' or 'none'); report-to (or report-uri) is required, since this "
                                           "header only reports and does not enforce",
    "http2 protocol": "HTTP2 should be Supported",
}


def recommendation(header: str | None) -> str:
    key = java_trim(header).lower()
    if not key:
        return ""
    if key in _TECHNOLOGY_DISCLOSURE:
        return _DISCLOSURE_TEXT
    return _BY_HEADER.get(key, _DEFAULT)
