"""Apache HttpClient 4.5.2 ``GET`` as built by Java ``d``/``h`` and ``ac.a(URL,String)``.

Trust-all TLS without hostname verification, optional host-to-IP pinning (``SystemDefaultDnsResolver`` subclass),
default redirect strategy (301/302/303/307, max 50, circular redirects rejected), ``DefaultHttpRequestRetryHandler``
(3 retries, logged to stderr by commons-logging/JUL) and ``EntityUtils.toString`` decoding.
"""
from __future__ import annotations

import codecs
import gzip
import http.client
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..javacompat.java_utf8 import java_utf8_decode
from . import http as rawhttp
from .errors import ClientProtocolError, ExchangeError, JavaIOError, socket_error
from .http import InetAddress, JavaUrl

APACHE_USER_AGENT = "Apache-HttpClient/4.5.2 (Java/25.0.4)"
MAX_REDIRECTS = 50
RETRY_COUNT = 3
_DEFAULT_CHARSET = "ISO-8859-1"
_NON_RETRIABLE = {"SocketTimeoutException", "ConnectTimeoutException", "UnknownHostException", "ConnectException",
                  "HttpHostConnectException", "SSLException", "SSLHandshakeException"}
_CONNECT_WRAPPERS = {"SocketTimeoutException": "org.apache.http.conn.ConnectTimeoutException",
                     "ConnectException": "org.apache.http.conn.HttpHostConnectException"}
_NEXT_ADDRESS_ON = {"ConnectTimeoutException", "HttpHostConnectException"}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


@dataclass
class ApacheResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    body_error: ExchangeError | None
    host: str

    def first(self, name: str) -> str | None:
        lowered = name.lower()
        return next((value for key, value in self.headers if key.lower() == lowered), None)

    def entity_text(self) -> str:
        """``EntityUtils.toString(entity)``: decompressed, Content-Type charset or ISO-8859-1."""
        if self.body_error is not None:
            raise _body_error(self.body_error, self.host)
        data = _decompress(self.body, self.first("Content-Encoding"))
        charset = _charset(self.first("Content-Type")) or _DEFAULT_CHARSET
        try:
            codec = codecs.lookup(charset)
        except LookupError as exc:
            raise JavaIOError("java.io.UnsupportedEncodingException", charset) from exc
        if codec.name == "utf-8":
            return java_utf8_decode(data)
        return data.decode(codec.name, errors="replace")


def get(url: str, *, pinned_host: str | None = None, pinned_ip: str | None = None,
        timeout: float | None = None) -> ApacheResponse:
    """Execute ``GET url``; ``timeout`` is the connect/socket timeout in seconds (``None`` = Java default, none)."""
    current = JavaUrl.parse(url)
    locations: set[str] = set()
    redirects = 0
    while True:
        response = _execute_with_retry(current, pinned_host, pinned_ip, timeout)
        if not _is_redirect(response):
            return response
        if redirects >= MAX_REDIRECTS:
            raise ClientProtocolError()
        redirects += 1
        location = response.first("Location")
        if location is None:
            raise ClientProtocolError()
        next_url = _location_uri(current, location)
        if next_url in locations:
            raise ClientProtocolError()
        locations.add(next_url)
        current = JavaUrl.parse(next_url)


def _is_redirect(response: ApacheResponse) -> bool:
    if response.status == 302:
        return response.first("Location") is not None
    return response.status in (301, 303, 307)


def _location_uri(current: JavaUrl, location: str) -> str:
    """``DefaultRedirectStrategy.getLocationURI``: resolved, host lower-cased, empty path -> ``/``."""
    parts = urlsplit(urljoin(current.spec, location))
    netloc = parts.netloc
    if netloc:
        user, at, host_port = netloc.rpartition("@")
        host, port = rawhttp.split_host_port(host_port)
        netloc = f"{user}{at}{host.lower()}{':' + port if port else ''}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def _route(target: JavaUrl) -> str:
    flags = "{s}" if target.protocol == "https" else "{}"
    return f"{flags}->{target.protocol}://{target.host}:{target.effective_port}"


def _execute_with_retry(target: JavaUrl, pinned_host: str | None, pinned_ip: str | None,
                        timeout: float | None) -> ApacheResponse:
    execution = 0
    while True:
        execution += 1
        try:
            return _execute(target, pinned_host, pinned_ip, timeout)
        except ClientProtocolError:
            raise
        except JavaIOError as exc:
            if exc.simple_name in _NON_RETRIABLE or execution > RETRY_COUNT:
                if exc.simple_name == "NoHttpResponseException":
                    raise JavaIOError(exc.java_class,
                                      f"{target.host}:{target.effective_port} failed to respond") from exc
                raise
            _log_retry(_route(target), exc)


def _log_retry(route: str, exc: JavaIOError) -> None:
    """The two JUL records ``RetryExec`` emits through commons-logging (SimpleFormatter, to stderr)."""
    now = datetime.now()
    stamp = (f"{_MONTHS[now.month - 1]} {now.day:02d}, {now.year} {(now.hour + 11) % 12 + 1}:{now.minute:02d}:"
             f"{now.second:02d} {'AM' if now.hour < 12 else 'PM'} org.apache.http.impl.execchain.RetryExec execute")
    print(f"{stamp}\nINFO: I/O exception ({exc.java_class}) caught when processing request to {route}: "
          f"{exc.message}\n{stamp}\nINFO: Retrying request to {route}", file=sys.stderr)


def _resolve(host: str, pinned_host: str | None, pinned_ip: str | None) -> list[InetAddress]:
    if pinned_host is not None and pinned_ip is not None and host.lower() == pinned_host.lower():
        return [rawhttp.get_by_name(pinned_ip)]
    return rawhttp.get_all_by_name(host)


def _execute(target: JavaUrl, pinned_host: str | None, pinned_ip: str | None,
             timeout: float | None) -> ApacheResponse:
    """One execution; resolved addresses are tried in turn (``DefaultHttpClientConnectionOperator``)."""
    addresses = _resolve(target.host, pinned_host, pinned_ip)
    host_header = target.host if target.port == -1 else f"{target.host}:{target.port}"
    headers = [("Host", host_header), ("Connection", "Keep-Alive"), ("User-Agent", APACHE_USER_AGENT),
               ("Accept-Encoding", "gzip,deflate")]
    tls = rawhttp.trust_all_context() if target.protocol == "https" else None
    for index, address in enumerate(addresses, start=1):
        try:
            raw = rawhttp.exchange("GET", target, headers, address=address.address, port=target.effective_port,
                                   tls=tls, connect_timeout=timeout, handshake_timeout=timeout, read_timeout=timeout)
        except ExchangeError as error:
            failure = _failure(error, target, addresses)
            if index < len(addresses) and failure.simple_name in _NEXT_ADDRESS_ON:
                continue
            raise failure from error
        response = ApacheResponse(raw.status, raw.headers, raw.body, raw.body_error, target.host)
        _check_content_coding(response)
        return response
    raise JavaIOError("java.net.UnknownHostException", target.host)


def _failure(error: ExchangeError, target: JavaUrl, addresses: list[InetAddress]) -> JavaIOError:
    if error.phase in ("connect", "handshake"):
        java = socket_error(error, target.host)
        wrapper = _CONNECT_WRAPPERS.get(java.simple_name)
        if wrapper is None:
            return java
        listed = ", ".join(str(address) for address in addresses)
        return JavaIOError(wrapper, f"Connect to {target.host}:{target.effective_port} [{listed}] failed: "
                                    f"{java.message}")
    cause = error.cause
    if isinstance(cause, http.client.RemoteDisconnected):
        return JavaIOError("org.apache.http.NoHttpResponseException", "The target server failed to respond")
    if isinstance(cause, http.client.HTTPException):
        return ClientProtocolError()
    return socket_error(error, target.host)


def _check_content_coding(response: ApacheResponse) -> None:
    """``ResponseContentEncoding`` rejects unknown codings while executing the request."""
    coding = response.first("Content-Encoding")
    if coding is None or not response.body:
        return
    for codec in (part.strip().lower() for part in coding.split(",")):
        if codec not in ("gzip", "x-gzip", "deflate", "identity", ""):
            raise ClientProtocolError()


def _decompress(data: bytes, coding: str | None) -> bytes:
    if coding is None or not data:
        return data
    for codec in (part.strip().lower() for part in coding.split(",")):
        try:
            if codec in ("gzip", "x-gzip"):
                data = gzip.decompress(data)
            elif codec == "deflate":
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)
        except (OSError, EOFError, zlib.error) as exc:
            raise JavaIOError("java.util.zip.ZipException", "Not in GZIP format" if "gzip" in codec
                              else "invalid block type") from exc
    return data


def _charset(content_type: str | None) -> str | None:
    if not content_type:
        return None
    for parameter in content_type.split(";")[1:]:
        name, _, value = parameter.partition("=")
        if name.strip().lower() == "charset":
            value = value.strip().strip('"')
            return value or None
    return None


def _body_error(error: ExchangeError, host: str) -> JavaIOError:
    cause = error.cause
    if isinstance(cause, http.client.IncompleteRead):
        if cause.expected is None:
            return JavaIOError("org.apache.http.ConnectionClosedException",
                               "Premature end of chunk coded message body: closing chunk expected")
        received = len(cause.partial)
        return JavaIOError("org.apache.http.ConnectionClosedException",
                           f"Premature end of Content-Length delimited message body (expected: "
                           f"{received + cause.expected}; received: {received})")
    return socket_error(error, host)
