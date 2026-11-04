"""``HttpsURLConnection`` behaviour (JDK 25): default headers, redirects, lazy body and exception texts.

Used by HTTP-method analysis, IP spoofing and the SSL Labs client.
"""
from __future__ import annotations

import http.client
from dataclasses import dataclass

from ..javacompat.java_utf8 import java_body_text
from . import http as rawhttp
from .errors import ExchangeError, JavaClassCastError, JavaIOError, socket_error
from .http import JavaUrl

JDK_USER_AGENT = "Java/25.0.4"
_ACCEPT = "*/*"
_REDIRECT_CODES = frozenset({300, 301, 302, 303, 307})
MAX_REDIRECTS = 20


def https_url(url: str) -> JavaUrl:
    """``(HttpsURLConnection) new URL(url).openConnection()``: the URL must parse and be HTTPS."""
    target = JavaUrl.parse(url)
    if target.protocol != "https":
        raise JavaClassCastError()
    return target


@dataclass
class JdkResponse:
    status: int
    headers: list[tuple[str, str]]
    url: JavaUrl
    body: bytes
    body_error: ExchangeError | None

    def first(self, name: str) -> str | None:
        lowered = name.lower()
        return next((value for key, value in self.headers if key.lower() == lowered), None)

    def input_text(self) -> str:
        """``getInputStream()`` read line by line and joined (line breaks dropped); raises for status >= 400."""
        if self.status in (404, 410):
            raise JavaIOError("java.io.FileNotFoundException", self.url.spec)
        if self.status >= 400:
            raise JavaIOError("java.io.IOException",
                              f"Server returned HTTP response code: {self.status} for URL: {self.url.spec}")
        if self.body_error is not None:
            raise _body_error(self.body_error, self.url)
        return java_body_text(self.body)

    def any_text(self) -> str:
        """Error stream if any, else input stream; an unreadable body is treated as empty (Java ``R.a``)."""
        return "" if self.body_error is not None else java_body_text(self.body)


def request(target: JavaUrl, method: str = "GET", headers: list[tuple[str, str]] | None = None, *,
            connect_timeout: float | None = None, read_timeout: float | None = None, follow_redirects: bool = True,
            trust_all: bool = False, proxy: tuple[str, int] | None = None) -> JdkResponse:
    """Run the request like ``getResponseCode()`` and return the final response.

    Redirects (300-303, 307) are followed only within the same protocol; ``timeout`` ``None`` means no timeout.
    """
    redirects = 0
    while True:
        response = _send(target, method, headers or [], connect_timeout, read_timeout, trust_all, proxy)
        if not follow_redirects or response.status not in _REDIRECT_CODES:
            return response
        location = response.first("Location")
        if location is None:
            return response
        next_url = target.resolve(location)
        if next_url.protocol != target.protocol:
            return response
        redirects += 1
        if redirects >= MAX_REDIRECTS:
            raise JavaIOError("java.net.ProtocolException", f"Server redirected too many times ({redirects})")
        target = next_url


def _request_headers(target: JavaUrl, user_headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    default_port = target.port in (-1, rawhttp.DEFAULT_PORTS[target.protocol])
    host = target.host if default_port else f"{target.host}:{target.port}"
    headers = list(user_headers)
    present = {name.lower() for name, _ in headers}
    for name, value in (("User-Agent", JDK_USER_AGENT), ("Host", host), ("Accept", _ACCEPT),
                        ("Connection", "keep-alive")):
        if name.lower() not in present:
            headers.append((name, value))
    return headers


def _send(target: JavaUrl, method: str, user_headers: list[tuple[str, str]], connect_timeout: float | None,
          read_timeout: float | None, trust_all: bool, proxy: tuple[str, int] | None) -> JdkResponse:
    headers = _request_headers(target, user_headers)
    tls = rawhttp.trust_all_context() if trust_all else rawhttp.default_context()
    port = target.effective_port
    if proxy is not None:
        address, connect_port = proxy
        tunnel = (f"{target.host}:{port}", [("User-Agent", JDK_USER_AGENT), ("Host", f"{target.host}:{port}"),
                                             ("Accept", _ACCEPT), ("Proxy-Connection", "keep-alive")])
    else:
        address, connect_port, tunnel = rawhttp.get_by_name(target.host).address, port, None
    retried = False
    while True:
        try:
            raw = rawhttp.exchange(method, target, headers, address=address, port=connect_port, tls=tls,
                                   connect_timeout=connect_timeout, handshake_timeout=read_timeout,
                                   read_timeout=read_timeout, tunnel=tunnel)
            return JdkResponse(raw.status, raw.headers, target, raw.body, raw.body_error)
        except ExchangeError as error:
            # sun.net.www.http.HttpClient.parseHTTP reopens the connection once when reading the status line fails.
            if error.phase == "headers" and not retried and method != "POST" and not isinstance(error.cause,
                                                                                                TimeoutError):
                retried = True
                continue
            raise _connection_error(error, target) from error


def _connection_error(error: ExchangeError, target: JavaUrl) -> JavaIOError:
    cause = error.cause
    if error.phase == "headers" and isinstance(cause, http.client.RemoteDisconnected):
        return JavaIOError("java.net.SocketException", "Unexpected end of file from server")
    if isinstance(cause, http.client.HTTPException) and not isinstance(cause, OSError):
        return JavaIOError("java.io.IOException", "Invalid Http response")
    return socket_error(error, target.host)


def _body_error(error: ExchangeError, target: JavaUrl) -> JavaIOError:
    if isinstance(error.cause, http.client.IncompleteRead):
        return JavaIOError("java.io.IOException", "Premature EOF")
    return socket_error(error, target.host)
