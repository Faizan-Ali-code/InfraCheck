"""A small HTTP(S) client on the standard library, built for inspection rather than browsing.

- Any method can be sent (PROPFIND, TRACE, made-up verbs), because method probing needs it.
- Redirects are never followed implicitly; `follow()` does it explicitly and keeps every hop.
- Headers are kept as a list, so repeated headers (several Set-Cookie lines) stay separate.
- TLS certificates are verified by default. A verification failure raises CertificateError with the
  reason, and callers may then repeat the request unverified to inspect the site anyway.
- Bodies are read up to a limit; the evidence never needs whole downloads.
"""

from __future__ import annotations

import datetime as _dt
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from email.message import Message
from urllib.parse import urljoin, urlsplit

from infracheck import USER_AGENT

DEFAULT_PORTS = {"http": 80, "https": 443}


class RequestError(Exception):
    """The request could not be completed (DNS, connect, timeout, TLS, protocol error)."""


class CertificateError(RequestError):
    """The server's certificate did not verify; `reason` is OpenSSL's explanation."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"certificate verification failed: {reason}")
        self.reason = reason


@dataclass
class TlsInfo:
    version: str
    cipher: str
    verified: bool
    not_after: _dt.datetime | None = None
    subject: str = ""
    issuer: str = ""


@dataclass
class Response:
    url: str
    method: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool = False
    elapsed: float = 0.0
    tls: TlsInfo | None = None
    request_headers: list[tuple[str, str]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def content_type(self) -> str:
        return (self.header("Content-Type") or "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")

    @property
    def text(self) -> str:
        msg = Message()
        msg["Content-Type"] = self.header("Content-Type") or "text/plain"
        charset = msg.get_content_charset() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def location(self) -> str | None:
        loc = self.header("Location")
        return urljoin(self.url, loc) if loc else None

    def evidence(self, limit: int = 4000) -> str:
        """Request line, response status line, headers and the start of the body, for evidence files."""
        lines = [f"{self.method} {self.url}"]
        lines += [f"{k}: {v}" for k, v in self.request_headers]
        lines += ["", f"HTTP {self.status} {self.reason}"]
        lines += [f"{k}: {v}" for k, v in self.headers]
        body = self.text
        lines += ["", body[:limit] + ("\n[... truncated]" if len(body) > limit or self.truncated else "")]
        return "\n".join(lines)


def _name(parts) -> str:
    return ", ".join("=".join(x) for rdn in parts for x in rdn)


@dataclass
class Client:
    timeout: float = 10.0
    proxy: str | None = None  # host:port of an HTTP proxy (CONNECT is used for https)
    ca_file: str | None = None  # extra trusted CA bundle (internal CAs, test CAs)
    max_body: int = 256 * 1024
    user_agent: str = USER_AGENT

    def tls_context(self, verify: bool = True) -> ssl.SSLContext:
        if verify:
            ctx = ssl.create_default_context(cafile=self.ca_file)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _connection(self, scheme: str, host: str, port: int, verify: bool) -> http.client.HTTPConnection:
        if scheme == "https":
            ctx = self.tls_context(verify)
            if self.proxy:
                ph, _, pp = self.proxy.rpartition(":")
                conn = http.client.HTTPSConnection(ph, int(pp), timeout=self.timeout, context=ctx)
                conn.set_tunnel(host, port)
                return conn
            return http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
        if self.proxy:
            ph, _, pp = self.proxy.rpartition(":")
            return http.client.HTTPConnection(ph, int(pp), timeout=self.timeout)
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def request(self, url: str, method: str = "GET", headers: list[tuple[str, str]] | None = None,
                body: bytes | None = None, verify: bool = True) -> Response:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS or not parts.hostname:
            raise RequestError(f"not an http(s) URL: {url}")
        port = parts.port or DEFAULT_PORTS[scheme]
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        target = url if (self.proxy and scheme == "http") else path
        sent = [("User-Agent", self.user_agent), *(headers or [])]
        started = time.perf_counter()
        conn = self._connection(scheme, parts.hostname, port, verify)
        try:
            conn.putrequest(method, target, skip_accept_encoding=True)
            for k, v in sent:
                conn.putheader(k, v)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            # read TLS details now: http.client drops the socket once a 'Connection: close' response arrives
            tls = self._tls_info(conn.sock, verify) if scheme == "https" else None
            resp = conn.getresponse()
            data = resp.read(self.max_body + 1) if method != "HEAD" else b""
            return Response(url, method, resp.status, resp.reason, resp.getheaders(), data[: self.max_body],
                            len(data) > self.max_body, round(time.perf_counter() - started, 3), tls, sent)
        except ssl.SSLCertVerificationError as exc:
            raise CertificateError(exc.verify_message or str(exc)) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise RequestError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            conn.close()

    @staticmethod
    def _tls_info(sock, verified: bool) -> TlsInfo | None:
        if not isinstance(sock, ssl.SSLSocket):
            return None
        cert = sock.getpeercert() if verified else {}
        not_after = None
        if cert.get("notAfter"):
            not_after = _dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), _dt.timezone.utc)
        cipher = sock.cipher()
        return TlsInfo(sock.version() or "", cipher[0] if cipher else "", verified, not_after,
                       _name(cert.get("subject", ())), _name(cert.get("issuer", ())))

    def follow(self, url: str, max_hops: int = 5, verify: bool = True) -> list[Response]:
        """GET `url` and follow redirects explicitly; returns every hop (the last one is the final page)."""
        chain = [self.request(url, verify=verify)]
        while chain[-1].status in (301, 302, 303, 307, 308) and chain[-1].location and len(chain) <= max_hops:
            nxt = chain[-1].location
            if nxt in (r.url for r in chain):
                break  # redirect loop
            chain.append(self.request(nxt, verify=verify))
        return chain


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
