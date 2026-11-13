"""Transport security: certificate validity, legacy TLS versions, HTTP to HTTPS redirection, HTTP/2.

Certificates are verified like a browser would (system trust store, plus --ca-file for internal CAs).
A target whose certificate fails is still scanned, unverified, and the failure is reported. This is a
quick check of the most common problems, not a full TLS audit: use testssl.sh or sslyze for cipher
suites, key exchange and known TLS vulnerabilities.
"""

from __future__ import annotations

import datetime as _dt
import socket
import ssl
import warnings
from urllib.parse import urlsplit, urlunsplit

from infracheck.context import TargetContext
from infracheck.http import RequestError
from infracheck.model import Rule

TLS_REF = "RFC 8996 (TLS 1.0/1.1 deprecated); NIST SP 800-52 Rev. 2; OWASP Transport Layer Security Cheat Sheet"
CERT_REF = "OWASP Transport Layer Security Cheat Sheet; OWASP ASVS 4.0.3 V9.1"

RULES = {r.id: r for r in (
    Rule("tls-certificate-invalid", "transport", "high", "TLS certificate does not verify", CERT_REF),
    Rule("tls-certificate-expiring", "transport", "low", "TLS certificate expires within 30 days", CERT_REF),
    Rule("tls-legacy-protocol", "transport", "medium", "Server accepts TLS 1.0 or TLS 1.1", TLS_REF),
    Rule("tls13-unsupported", "transport", "info", "Server does not offer TLS 1.3", TLS_REF),
    Rule("http-no-redirect", "transport", "medium", "Plain HTTP is served without a redirect to HTTPS",
         "OWASP Transport Layer Security Cheat Sheet; OWASP ASVS 4.0.3 V9.1.1"),
    Rule("http-only", "transport", "high", "Target is served over plain HTTP", "OWASP ASVS 4.0.3 V9.1.1"),
)}


def _handshake(host: str, port: int, timeout: float, *, minimum=None, maximum=None, alpn=None) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if minimum or maximum:
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # let this client offer old versions, to see if the server accepts them
        with warnings.catch_warnings():  # offering deprecated versions is the point of this probe
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = minimum or ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = maximum or ssl.TLSVersion.MAXIMUM_SUPPORTED
    if alpn:
        ctx.set_alpn_protocols(alpn)
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except BaseException:
        sock.close()
        raise


def legacy_tls(host: str, port: int, timeout: float) -> str | None:
    """'TLSv1' / 'TLSv1.1' if the server completes a handshake capped at that version, else None.
    Raises RuntimeError when the local OpenSSL cannot offer old versions at all (the test is then impossible)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old_versions = (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
    for version in old_versions:
        try:
            with _handshake(host, port, timeout, minimum=version, maximum=version) as s:
                return s.version()
        except ssl.SSLError as exc:
            if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "NO PROTOCOLS AVAILABLE" in str(exc).upper():
                raise RuntimeError("this OpenSSL build cannot offer TLS 1.0/1.1") from exc
        except (OSError, ValueError):
            continue
    return None


def run(ctx: TargetContext) -> None:
    parts = urlsplit(ctx.url)
    host, timeout = parts.hostname or "", ctx.client.timeout
    if not ctx.https:
        ctx.add(RULES["http-only"], "Everything, including credentials and session cookies, travels unencrypted.",
                ctx.url)
        return
    port = parts.port or 443
    main = ctx.main()  # sets ctx.cert_error when verification failed
    if ctx.cert_error:
        ctx.result.certificate = ctx.cert_error
        ctx.add(RULES["tls-certificate-invalid"], f"{ctx.cert_error}. Browsers show a warning; users who click "
                "through can be intercepted.", ctx.cert_error)
    else:
        ctx.result.certificate = "valid"
        if main.tls and main.tls.not_after:
            days = (main.tls.not_after - _dt.datetime.now(_dt.timezone.utc)).days
            if days < 30:
                ctx.add(RULES["tls-certificate-expiring"], f"The certificate expires on "
                        f"{main.tls.not_after:%Y-%m-%d} ({days} days).", f"notAfter {main.tls.not_after:%Y-%m-%d}")
    if main.tls:
        ctx.result.tls_version = main.tls.version
        if main.tls.version != "TLSv1.3" and not ctx.client.proxy:
            ctx.add(RULES["tls13-unsupported"], f"The connection used {main.tls.version}.", main.tls.version)
    if ctx.client.proxy:
        ctx.result.checks["transport"] = "partial: TLS version and HTTP/2 probes need a direct connection"
    else:
        try:
            old = legacy_tls(host, port, timeout)
            if old:
                ctx.add(RULES["tls-legacy-protocol"], f"A handshake limited to {old} succeeded. TLS 1.0 and 1.1 lack "
                        "modern cipher suites and are deprecated (RFC 8996).", old)
        except RuntimeError as exc:
            ctx.result.checks["transport"] = f"partial: {exc}"
        try:
            with _handshake(host, port, timeout, alpn=["h2", "http/1.1"]) as s:
                ctx.result.http2 = "yes" if s.selected_alpn_protocol() == "h2" else "no"
        except (OSError, ssl.SSLError):
            pass
    if parts.port in (None, 443):  # a non-standard HTTPS port has no plain-HTTP counterpart to test
        check_http_redirect(ctx, urlunsplit(("http", parts.hostname, parts.path or "/", parts.query, "")))


def check_http_redirect(ctx: TargetContext, http_url: str) -> None:
    try:
        resp = ctx.client.request(http_url)
    except RequestError:
        return  # nothing listens on port 80: nothing to redirect
    location = resp.location or ""
    if 300 <= resp.status < 400 and location.lower().startswith("https://"):
        return
    ctx.add(RULES["http-no-redirect"], f"{http_url} answered {resp.status} "
            f"{'redirecting to ' + location if location else 'without redirecting to HTTPS'}.",
            f"HTTP {resp.status} {location}".strip(), resp)
