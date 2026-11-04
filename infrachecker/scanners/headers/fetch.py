"""HTTP fetching for header analysis (Java ``ax.b`` / ``ax.c``): a trust-all HTTP/1.1 client that sends
``Accept-Encoding: gzip, deflate, br`` but only decodes gzip, plus the run-wide response cache.

Client behaviour mirrors Apache HttpClient 4.5.2 as configured by the Java tool: no redirects, no decompression,
no cookies, no ALPN, no certificate or hostname checks, connect/read timeouts 10 s / 15 s, up to 3 retries for
connection resets and empty responses only.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import warnings
import zlib
from dataclasses import dataclass
from typing import Callable

import urllib3
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import (ConnectTimeoutError, InsecureRequestWarning, NameResolutionError, NewConnectionError,
                                ProtocolError, ProxyError, SSLError)

from ...javacompat.java_uri import JavaURI
from ...javacompat.java_url import MalformedURLError, parse_url
from ...javacompat.java_utf8 import java_body_text
from ...javacompat.strings import java_trim
from ...log import tinfo

USER_AGENT = "InfraChecker/4.x (Windows NT 10.0; Win64; x64)"
HOST_UNREACHABLE = "Host unreachable"
CONNECTION_REFUSED = "Connection Refused"
UNABLE_TO_OPEN = "Unable to Open URL"
SSL_HANDSHAKE_FAILED = "SSL Handshake Failed, Server is expecting a valid certificate"
SOCKET_EXCEPTION = "Socket Exception"
NO_HTTP_RESPONSE = "No Http Response"

_TIMEOUT = urllib3.Timeout(connect=10, read=15)
_RETRIES = 3
_RETRIED_FAILURES = frozenset({SOCKET_EXCEPTION, NO_HTTP_RESPONSE})
_NO_ENTITY_CODES = frozenset({204, 205, 304})
_FOLDED_LINE = re.compile(r"\r?\n[ \t]+")
# OpenSSL reasons for a peer that does not speak TLS: Java reports "Unsupported or unrecognized SSL message"
# (a plain SSLException, not a handshake failure).
_NOT_TLS_REASONS = frozenset({"WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "HTTP_REQUEST", "UNKNOWN_PROTOCOL",
                              "PACKET_LENGTH_TOO_LONG"})

# Java has no header-count limit (http.client stops at 100).
http.client._MAXHEADERS = max(http.client._MAXHEADERS, 10_000)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

Headers = tuple[tuple[str, str], ...]
Reporter = Callable[[str, int, str, str, str, str, "str | None"], None]
"""``reportUrlIssue(url, code, protocol, details, level, justification, body)`` (Java ``aB``)."""


def first_header(headers: Headers | None, name: str) -> str | None:
    """Value of the first header with this name (case-insensitive), like Apache ``getFirstHeader``."""
    lowered = name.lower()
    return next((value for key, value in headers or () if key.lower() == lowered), None)


@dataclass(frozen=True)
class FetchResult:
    """Java ``ae``: decoded body (CR/LF removed), headers in received order (``None`` when the fetch failed)."""

    body: str
    headers: Headers | None
    code: int
    ip: str | None


_FAILED = FetchResult("", None, 0, None)
_cache: dict[str, FetchResult] = {}
_clients: dict[str, urllib3.PoolManager] = {}
_lock = threading.Lock()


def reset() -> None:
    """Drop the response cache and the HTTP clients (start of a run)."""
    with _lock:
        _cache.clear()
        clients = list(_clients.values())
        _clients.clear()
    for client in clients:
        client.clear()


class _TlsTransportError(OSError):
    """The connection broke during the TLS handshake (Java: plain ``SSLException``, not retried)."""


class _NoAlpnContext(ssl.SSLContext):
    """urllib3 always offers ALPN "http/1.1"; the Java client offers no ALPN at all."""

    def set_alpn_protocols(self, alpn_protocols) -> None:
        pass


class _HttpsConnection(HTTPSConnection):
    def connect(self) -> None:
        try:
            super().connect()
        except ssl.SSLError:
            raise
        except OSError as exc:
            if str(exc).startswith("Tunnel connection failed"):
                raise
            raise _TlsTransportError(str(exc)) from exc


class _HttpsPool(HTTPSConnectionPool):
    ConnectionCls = _HttpsConnection


def _ssl_context() -> ssl.SSLContext:
    context = _NoAlpnContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _new_client(proxy_host: str | None, proxy_port: int) -> urllib3.PoolManager:
    options = dict(num_pools=300, maxsize=100, ssl_context=_ssl_context(), cert_reqs=ssl.CERT_NONE,
                   assert_hostname=False, retries=False, timeout=_TIMEOUT)
    if proxy_host is None:
        client = urllib3.PoolManager(**options)
    else:
        client = urllib3.ProxyManager(f"http://{proxy_host}:{proxy_port}", proxy_headers={"User-Agent": USER_AGENT},
                                      **options)
    client.pool_classes_by_scheme = {"http": HTTPConnectionPool, "https": _HttpsPool}
    return client


@dataclass(frozen=True)
class _Target:
    """Where and what to request, as Apache HttpClient derives it from ``URI.create(url)``."""

    scheme: str
    host: str
    port: int
    host_header: str
    path: str
    absolute: str

    @classmethod
    def from_uri(cls, uri: JavaURI, url: str) -> "_Target":
        scheme = (uri.scheme or "").lower()
        host, port = uri.host, uri.port
        if host is None and uri.authority:      # registry-based authority (e.g. underscore): split by hand
            host = uri.authority[uri.authority.rfind("@") + 1:]
            colon = host.rfind(":")
            if colon > 0 and host[colon + 1:].isdigit():
                host, port = host[:colon], int(host[colon + 1:])
        if not host:
            raise ValueError("URI does not specify a valid host name: " + url)
        if scheme not in ("http", "https"):
            raise ValueError(scheme + " protocol is not supported")
        raw_path = uri.path or "/"
        path = "/" + raw_path.lstrip("/") if raw_path.startswith("//") else raw_path
        if uri.query is not None:
            path += "?" + uri.query
        explicit_port = "" if port == -1 else f":{port}"
        default_port = 443 if scheme == "https" else 80
        return cls(scheme, host, default_port if port == -1 else port, host + explicit_port, path,
                   f"{scheme}://{host.lower()}{explicit_port}{path}")


def _resolve_ip(host: str) -> str:
    """``InetAddress.getByName(host).getHostAddress()``: first IPv4 address, IPv6 in Java's uncompressed form."""
    if host == "":
        return "127.0.0.1"
    name = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    chosen = next((info for info in infos if info[0] == socket.AF_INET), infos[0])
    address = chosen[4][0]
    if chosen[0] != socket.AF_INET6:
        return address
    groups = ipaddress.IPv6Address(address.split("%", 1)[0]).exploded.split(":")
    text = ":".join(f"{int(group, 16):x}" for group in groups)
    scope = chosen[4][3]
    return f"{text}%{scope}" if scope else text


def _ip_for(url: str) -> str:
    try:
        host = parse_url(url).host
        tinfo(f"Going to get the IP address for this Host->{host}")
        return _resolve_ip(host)
    except MalformedURLError:
        return "Invalid URL"
    except Exception:
        return "IP resolution failed"


def _java_gunzip(data: bytes) -> bytes:
    """``GZIPInputStream``: concatenated members are decoded; empty or truncated input raises."""
    out: list[bytes] = []
    while True:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out.append(decoder.decompress(data))
        out.append(decoder.flush())
        if not decoder.eof:
            raise EOFError("Unexpected end of ZLIB input stream")
        data = decoder.unused_data
        if not data.startswith(b"\x1f\x8b\x08"):
            return b"".join(out)


def _response_headers(response: urllib3.BaseHTTPResponse) -> Headers:
    # http.client's message keeps the received order and duplicate names; urllib3's HTTPHeaderDict regroups them.
    message = response._original_response.msg
    return tuple((name, java_trim(_FOLDED_LINE.sub(" ", value))) for name, value in message.items())


def _find_ssl_error(exc: BaseException) -> ssl.SSLError | None:
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return current
        pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)
    return None


def _inner_error(exc: ProtocolError) -> BaseException | None:
    return next((arg for arg in exc.args if isinstance(arg, BaseException)), exc.__cause__)


def _request_failure(exc: BaseException) -> str:
    """Failure text for an error raised while connecting, sending the request or reading the status line."""
    if isinstance(exc, ProxyError):
        original = exc.original_error
        return _request_failure(original) if isinstance(original, ConnectTimeoutError) else UNABLE_TO_OPEN
    if isinstance(exc, NameResolutionError):
        return HOST_UNREACHABLE
    if isinstance(exc, NewConnectionError):
        cause = exc.__cause__ or exc.__context__
        if isinstance(cause, ConnectionRefusedError):
            return CONNECTION_REFUSED
        return UNABLE_TO_OPEN if isinstance(cause, TimeoutError) else SOCKET_EXCEPTION
    if isinstance(exc, SSLError):
        error = _find_ssl_error(exc)
        return UNABLE_TO_OPEN if error is not None and error.reason in _NOT_TLS_REASONS else SSL_HANDSHAKE_FAILED
    if isinstance(exc, ProtocolError):
        inner = _inner_error(exc)
        if isinstance(inner, http.client.RemoteDisconnected):
            return NO_HTTP_RESPONSE
        if isinstance(inner, OSError) and not isinstance(inner, (_TlsTransportError, TimeoutError, ssl.SSLError)):
            return SOCKET_EXCEPTION
    return UNABLE_TO_OPEN


def _body_failure(exc: BaseException) -> str:
    """Failure text for an error raised while reading or decoding the body."""
    inner = _inner_error(exc) if isinstance(exc, ProtocolError) else exc
    if isinstance(inner, OSError) and not isinstance(inner, (TimeoutError, ssl.SSLError)):
        return SOCKET_EXCEPTION
    return UNABLE_TO_OPEN


class _RequestFailed(Exception):
    def __init__(self, failure: str):
        super().__init__(failure)
        self.failure = failure


class Fetcher:
    """Fetches URLs for one input URL's passes (Java ``ax`` instance); clients and cache are shared by the run."""

    def __init__(self, proxy_host: str | None, proxy_port: int):
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port

    def _client(self) -> urllib3.PoolManager:
        key = "DIRECT" if self._proxy_host is None else f"{java_trim(self._proxy_host).lower()}:{self._proxy_port}"
        with _lock:
            client = _clients.get(key)
            if client is None:
                client = _clients[key] = _new_client(self._proxy_host, self._proxy_port)
            return client

    def _send(self, target: _Target) -> urllib3.BaseHTTPResponse:
        forward_proxy = self._proxy_host is not None and target.scheme == "http"
        headers = {"Accept-Encoding": "gzip, deflate, br", "Host": target.host_header,
                   "Proxy-Connection" if forward_proxy else "Connection": "Keep-Alive", "User-Agent": USER_AGENT}
        pool = self._client().connection_from_host(target.host, target.port, target.scheme)
        attempt = 0
        while True:
            try:
                return pool.urlopen("GET", target.absolute if forward_proxy else target.path, headers=headers,
                                    retries=False, redirect=False, assert_same_host=False, preload_content=False,
                                    decode_content=False, release_conn=False, timeout=_TIMEOUT)
            except Exception as exc:
                failure = _request_failure(exc)
                attempt += 1
                if attempt > _RETRIES or failure not in _RETRIED_FAILURES:
                    raise _RequestFailed(failure) from exc

    def fetch(self, url: str, protocol: str, reporter: Reporter) -> FetchResult:
        """One GET (Java ``ax.b``); a failure is reported through ``reporter`` and returns code 0."""
        try:
            uri = JavaURI.create(url)
        except ValueError:
            return self._fail(url, protocol, UNABLE_TO_OPEN, reporter)
        tinfo(f"Going to hit URL ->{url}")
        try:
            response = self._send(_Target.from_uri(uri, url))
        except _RequestFailed as failed:
            return self._fail(url, protocol, failed.failure, reporter)
        except Exception:
            return self._fail(url, protocol, UNABLE_TO_OPEN, reporter)
        try:
            tinfo(f"Going to fetch response of URL ->{url}")
            code = response.status
            tinfo(f"response Code->{code} URL ->{url}")
            ip = _ip_for(url)
            headers = _response_headers(response)
            raw = response.read(decode_content=False)
            body = ""
            if code >= 200 and code not in _NO_ENTITY_CODES:
                encoding = first_header(headers, "Content-Encoding")
                if encoding is not None and encoding.lower() == "gzip":
                    raw = _java_gunzip(raw)
                body = java_body_text(raw)
        except Exception as exc:
            return self._fail(url, protocol, _body_failure(exc), reporter)
        finally:
            response.release_conn()
        return FetchResult(body, headers, code, ip)

    def cached_fetch(self, url: str, protocol: str, reporter: Reporter) -> FetchResult:
        """Java ``ax.c``: results with a status code are cached per ``protocol|url`` for the whole run."""
        key = java_trim(protocol).lower() + "|" + java_trim(url)
        with _lock:
            cached = _cache.get(key)
        if cached is not None:
            return cached
        result = self.fetch(url, protocol, reporter)
        if result.code == 0:
            return result
        with _lock:
            return _cache.setdefault(key, result)

    @staticmethod
    def _fail(url: str, protocol: str, failure: str, reporter: Reporter) -> FetchResult:
        reporter(url, 0, protocol, failure, "", "", None)
        return _FAILED
