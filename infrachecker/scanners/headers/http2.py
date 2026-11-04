"""HTTP/2 support detection (Java ``O``), cached per host for the run.

Like ``java.net.http.HttpClient`` with a trust-all trust manager: no proxy, any certificate chain is accepted but
the host name is still verified (JSSE endpoint identification). Step 1 is an HTTP/1.1 GET (any failure ->
OTHER_FAILURE); step 2 negotiates ALPN h2/http1.1 and performs one GET (h2 -> SUPPORTED, http/1.1 -> NOT_SUPPORTED,
I/O error -> IO_FAILURE unless its message names a protocol problem). The Java "ALPN fallback" that follows an
OTHER_FAILURE can never succeed (it layers TLS over an unconnected socket); only its log lines are reproduced.
"""
from __future__ import annotations

import enum
import http.client
import ipaddress
import re
import socket
import ssl
import threading
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import NameOID

from ...javacompat.java_uri import JavaURI
from ...javacompat.java_url import MalformedURLError, parse_url, url_host_or_raw
from ...javacompat.strings import is_blank
from ...log import log, thread_name, tinfo, ts

USER_AGENT = "Java-http-client/25"
_CONNECT_TIMEOUT = 10
_REQUEST_TIMEOUT = 30
_NOT_SUPPORTED_HINTS = ("Prohibited header", "keep-alive", "connection", "transfer-encoding", "upgrade", "proxy-",
                        "malformed response")
_SNI_NAME = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*")

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_DATA, _HEADERS, _RST_STREAM, _SETTINGS, _PING, _GOAWAY, _WINDOW_UPDATE = 0x0, 0x1, 0x3, 0x4, 0x6, 0x7, 0x8
_END_STREAM = _ACK = 0x1
_END_HEADERS = 0x4


class Http2Support(enum.Enum):
    """Reachable outcomes of Java ``Q`` (a, b, c, e)."""

    SUPPORTED = "a"
    NOT_SUPPORTED = "b"
    IO_FAILURE = "c"
    OTHER_FAILURE = "e"


_cache: dict[str, Http2Support] = {}
_lock = threading.Lock()


def reset() -> None:
    with _lock:
        _cache.clear()


def cached_detect(url: str) -> Http2Support:
    """Detection result for the URL's host, computed once per run (Java ``L.S``)."""
    key = url_host_or_raw(url).lower()
    if is_blank(key):
        return detect(url)
    with _lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached
    result = detect(url)
    with _lock:
        return _cache.setdefault(key, result)


class _ProtocolError(OSError):
    """An HTTP/2 conversation failure (Java ``IOException``)."""


@dataclass(frozen=True)
class _Endpoint:
    host: str
    port: int
    authority: str
    path: str

    @classmethod
    def from_url(cls, url: str) -> "_Endpoint":
        uri = JavaURI.create(url)
        if uri.host is None or (uri.scheme or "").lower() not in ("http", "https"):
            raise ValueError("unsupported URI " + url)
        port = 443 if uri.port == -1 else uri.port
        authority = uri.host if uri.port == -1 else f"{uri.host}:{uri.port}"
        path = (uri.path or "/") + ("?" + uri.query if uri.query is not None else "")
        return cls(uri.host.strip("[]"), port, authority, path)


# ---------------------------------------------------------------------------------------- hostname verification

def _match_label(name: str, template: str) -> bool:
    star = template.find("*")
    if star == -1:
        return name == template
    first = True
    rest = template
    while star != -1:
        before, rest = rest[:star], rest[star + 1:]
        found = name.find(before)
        if found == -1 or (first and found != 0):
            return False
        first = False
        name = name[found + len(before):]
        star = rest.find("*")
    return name.endswith(rest)


def _has_illegal_wildcard(template: str) -> bool:
    if template in ("*", "*."):
        return True
    star = template.rfind("*")
    return star != -1 and "." not in template[star:]


def _name_matches(name: str, template: str) -> bool:
    if _has_illegal_wildcard(template) or not _SNI_NAME.fullmatch(template.replace("*", "z")):
        return False
    names = [label for label in name.lower().split(".") if label]
    templates = [label for label in template.lower().split(".") if label]
    return len(names) == len(templates) and all(map(_match_label, names, templates))


def verify_hostname(certificate: bytes | None, host: str) -> None:
    """JSSE ``HostnameChecker`` (TLS): IP hosts against IP SANs; DNS hosts against DNS SANs, else the subject CN."""
    if not certificate:
        raise ssl.SSLCertVerificationError("No subject alternative names present")
    cert = x509.load_der_x509_certificate(certificate)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        names = None
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        address = None
    if address is not None:
        if names is None:
            raise ssl.SSLCertVerificationError("No subject alternative names present")
        if address in names.get_values_for_type(x509.IPAddress):
            return
        raise ssl.SSLCertVerificationError(f"No subject alternative names matching IP address {host} found")
    dns_names = names.get_values_for_type(x509.DNSName) if names is not None else []
    if dns_names:
        if any(_name_matches(host, template) for template in dns_names):
            return
        raise ssl.SSLCertVerificationError(f"No subject alternative DNS name matching {host} found.")
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if common_names and _name_matches(host, str(common_names[-1].value)):
        return
    raise ssl.SSLCertVerificationError(f"No name matching {host} found")


# ---------------------------------------------------------------------------------------- transport

def _connect(endpoint: _Endpoint, alpn: list[str] | None) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        context.set_alpn_protocols(alpn)
    raw = socket.create_connection((endpoint.host, endpoint.port), timeout=_CONNECT_TIMEOUT)
    try:
        raw.settimeout(_REQUEST_TIMEOUT)
        sock = context.wrap_socket(raw, server_hostname=endpoint.host)
    except BaseException:
        raw.close()
        raise
    try:
        verify_hostname(sock.getpeercert(binary_form=True), endpoint.host)
    except BaseException:
        sock.close()
        raise
    return sock


def _http11_get(sock: ssl.SSLSocket, endpoint: _Endpoint) -> int:
    connection = http.client.HTTPConnection(endpoint.host, endpoint.port)
    connection.sock = sock
    connection.putrequest("GET", endpoint.path, skip_host=True, skip_accept_encoding=True)
    connection.putheader("Host", endpoint.authority)
    connection.putheader("User-Agent", USER_AGENT)
    connection.endheaders()
    response = connection.getresponse()
    response.read()
    return response.status


def _frame(frame_type: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) + stream.to_bytes(4, "big") + payload


def _hpack_string(text: str) -> bytes:
    data = text.encode("utf-8")
    length = len(data)
    if length < 127:
        return bytes((length,)) + data
    out = bytearray((127,))
    length -= 127
    while length >= 128:
        out.append((length & 127) | 128)
        length >>= 7
    out.append(length)
    return bytes(out) + data


def _hpack_literal(name: str, value: str) -> bytes:
    """Literal header field without indexing, new name, no Huffman coding."""
    return b"\x00" + _hpack_string(name) + _hpack_string(value)


def _receive(sock: ssl.SSLSocket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise _ProtocolError("EOF reached while reading")
        data += chunk
    return bytes(data)


def _h2_get(sock: ssl.SSLSocket, endpoint: _Endpoint) -> None:
    """Send one GET on stream 1 and read until the response stream ends."""
    block = b"".join(_hpack_literal(name, value) for name, value in (
        (":method", "GET"), (":scheme", "https"), (":authority", endpoint.authority), (":path", endpoint.path),
        ("user-agent", USER_AGENT)))
    sock.sendall(_PREFACE + _frame(_SETTINGS, 0, 0) + _frame(_HEADERS, _END_STREAM | _END_HEADERS, 1, block))
    while True:
        head = _receive(sock, 9)
        length, frame_type, flags = int.from_bytes(head[:3], "big"), head[3], head[4]
        stream = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
        payload = _receive(sock, length)
        if frame_type == _SETTINGS and not flags & _ACK:
            sock.sendall(_frame(_SETTINGS, _ACK, 0))
        elif frame_type == _PING and not flags & _ACK:
            sock.sendall(_frame(_PING, _ACK, 0, payload))
        elif frame_type == _GOAWAY:
            raise _ProtocolError("GOAWAY received")
        elif frame_type == _RST_STREAM and stream == 1:
            raise _ProtocolError("Stream 1 cancelled")
        elif frame_type == _DATA and stream == 1 and length:
            increment = length.to_bytes(4, "big")
            sock.sendall(_frame(_WINDOW_UPDATE, 0, 0, increment) + _frame(_WINDOW_UPDATE, 0, 1, increment))
        if stream == 1 and frame_type in (_HEADERS, _DATA) and flags & _END_STREAM:
            return


def _negotiated_version(endpoint: _Endpoint) -> str:
    sock = _connect(endpoint, ["h2", "http/1.1"])
    try:
        if sock.selected_alpn_protocol() == "h2":
            _h2_get(sock, endpoint)
            return "HTTP_2"
        _http11_get(sock, endpoint)
        return "HTTP_1_1"
    finally:
        sock.close()


def _io_message(exc: BaseException) -> str | None:
    """The message Java's HttpClient would carry for this I/O failure (``None`` when it has none)."""
    if isinstance(exc, (_ProtocolError, ssl.SSLError)):
        return str(exc)
    if isinstance(exc, http.client.RemoteDisconnected):
        return "HTTP/1.1 header parser received no bytes"
    if isinstance(exc, (ConnectionRefusedError, socket.gaierror)):
        return None
    if isinstance(exc, ConnectionResetError):
        return "Connection reset"
    if isinstance(exc, (ConnectionAbortedError, BrokenPipeError)):
        return "Broken pipe"
    if isinstance(exc, TimeoutError):
        return "request timed out"
    if isinstance(exc, OSError):
        return exc.strerror or str(exc) or None
    return str(exc) or type(exc).__name__


def _is_io_error(exc: BaseException) -> bool:
    return isinstance(exc, (OSError, http.client.HTTPException))


def _standard_check(url: str) -> Http2Support:
    try:
        endpoint = _Endpoint.from_url(url)
        sock = _connect(endpoint, None)
        try:
            status = _http11_get(sock, endpoint)
        finally:
            sock.close()
        tinfo(f"HTTP/1.1 initial check for {url} returned status: {status}")
    except Exception as exc:
        message = _io_message(exc) if _is_io_error(exc) else str(exc)
        tinfo(f"HTTP/1.1 connectivity check failed for {url}: {message}")
        return Http2Support.OTHER_FAILURE
    try:
        version = _negotiated_version(endpoint)
    except Exception as exc:
        if not _is_io_error(exc):
            tinfo(f"Unexpected Exception for HTTP/2 check on {url}: {type(exc).__name__} - {exc}")
            return Http2Support.OTHER_FAILURE
        message = _io_message(exc) or "Unknown IO error"
        if any(hint in message for hint in _NOT_SUPPORTED_HINTS):
            log.debug(f"{ts()} {thread_name()} URL for HTTP/2 ->{url} Server does not properly support HTTP/2: "
                      f"{message}")
            return Http2Support.NOT_SUPPORTED
        tinfo(f"URL for HTTP/2 ->{url} IOException: {message}")
        return Http2Support.IO_FAILURE
    if version == "HTTP_2":
        tinfo(f"HTTP/2 SUCCESS confirmed for {url}")
        return Http2Support.SUPPORTED
    tinfo(f"HTTP/2 NOT_SUPPORTED for {url}, got version: {version}")
    return Http2Support.NOT_SUPPORTED


def _alpn_fallback_log(url: str) -> None:
    try:
        target = parse_url(url)
    except MalformedURLError as exc:
        tinfo(f"ALPN fallback check failed for {url}: MalformedURLException - {exc}")
        return
    tinfo(f"Attempting ALPN fallback for {target.host}:{443 if target.port == -1 else target.port}")
    tinfo(f"ALPN fallback check failed for {url}: SocketException - Underlying socket is not connected")


def detect(url: str) -> Http2Support:
    result = _standard_check(url)
    if result is Http2Support.OTHER_FAILURE:
        tinfo(f"Standard HTTP/2 check returned OTHER_FAILURE for {url}, attempting fallback ALPN detection.")
        _alpn_fallback_log(url)
    return result
