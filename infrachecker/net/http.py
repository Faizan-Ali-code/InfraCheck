"""One HTTP/1.1 request per connection over a socket the caller controls.

The caller chooses the address to connect to (host pinning like Java's custom ``DnsResolver``), the TLS context
(SNI is always the URL host), the proxy tunnel and the per-phase timeouts. Java client behaviour (headers, redirects,
retries, exception texts) lives in :mod:`.jdk` and :mod:`.apache`.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin

from .errors import ExchangeError, JavaIOError

DEFAULT_PORTS = {"http": 80, "https": 443}
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")

_default_context: ssl.SSLContext | None = None
_trust_all_context: ssl.SSLContext | None = None


def default_context() -> ssl.SSLContext:
    """Validating context with hostname verification (the JDK default for ``HttpsURLConnection``)."""
    global _default_context
    if _default_context is None:
        _default_context = ssl.create_default_context()
    return _default_context


def trust_all_context() -> ssl.SSLContext:
    """Trust-all TLS without hostname verification (Java ``S``/``T``; ``TrustStrategy -> true`` with
    ``NoopHostnameVerifier``)."""
    global _trust_all_context
    if _trust_all_context is None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _trust_all_context = context
    return _trust_all_context


@dataclass(frozen=True)
class JavaUrl:
    """``java.net.URL`` view of a URL: host case kept, ``port`` is -1 when absent, fragment dropped."""

    spec: str
    protocol: str
    host: str
    port: int
    path: str
    query: str | None

    @classmethod
    def parse(cls, spec: str) -> JavaUrl:
        match = _SCHEME.match(spec)
        if not match:
            raise JavaIOError("java.net.MalformedURLException", "no protocol: " + spec)
        protocol = match.group(1).lower()
        if protocol not in DEFAULT_PORTS:
            raise JavaIOError("java.net.MalformedURLException", "unknown protocol: " + protocol)
        rest = spec[match.end():].split("#", 1)[0]
        authority = ""
        if rest.startswith("//"):
            rest = rest[2:]
            cut = min((i for i in (rest.find("/"), rest.find("?")) if i != -1), default=len(rest))
            authority, rest = rest[:cut], rest[cut:]
        host, port_text = split_host_port(authority.rsplit("@", 1)[-1])
        if port_text and not port_text.isdigit():
            raise JavaIOError("java.net.MalformedURLException", "Invalid port number :" + port_text)
        path, separator, query = rest.partition("?")
        return cls(spec, protocol, host, int(port_text) if port_text else -1, path, query if separator else None)

    @property
    def effective_port(self) -> int:
        return self.port if self.port != -1 else DEFAULT_PORTS[self.protocol]

    @property
    def file(self) -> str:
        """``URL.getFile()``: path plus query."""
        return self.path if self.query is None else f"{self.path}?{self.query}"

    @property
    def request_target(self) -> str:
        return self.file or "/"

    def resolve(self, location: str) -> JavaUrl:
        """``new URL(this, location)``."""
        return JavaUrl.parse(urljoin(self.spec.split("#", 1)[0], location))


def split_host_port(host_port: str) -> tuple[str, str]:
    """Split ``host[:port]`` (IPv6 hosts keep their brackets)."""
    if host_port.startswith("["):
        end = host_port.find("]")
        if end != -1:
            return host_port[:end + 1], host_port[end + 2:] if host_port[end + 1:end + 2] == ":" else ""
    host, _, port = host_port.partition(":")
    return host, port


@dataclass(frozen=True)
class InetAddress:
    """``java.net.InetAddress``; ``str()`` is Java's ``hostName/address`` form."""

    host_name: str
    address: str

    def __str__(self) -> str:
        return f"{self.host_name}/{self.address}"


def _literal(name: str) -> str | None:
    try:
        return str(ipaddress.ip_address(name[1:-1] if name.startswith("[") and name.endswith("]") else name))
    except ValueError:
        return None


def get_by_name(name: str) -> InetAddress:
    """``InetAddress.getByName``: an empty name is the loopback address; literals are not looked up."""
    if name == "":
        return InetAddress("localhost", "127.0.0.1")
    return get_all_by_name(name)[0]


def get_all_by_name(name: str) -> list[InetAddress]:
    """``InetAddress.getAllByName`` (IPv4 addresses first, like Java's default ``preferIPv6Addresses=false``)."""
    literal = _literal(name)
    if literal is not None:
        return [InetAddress("", literal)]
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise JavaIOError("java.net.UnknownHostException", name) from exc
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    addresses.sort(key=lambda address: ":" in address)
    return [InetAddress(name, address) for address in addresses]


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes = b""
    body_error: ExchangeError | None = None

    def first(self, name: str) -> str | None:
        lowered = name.lower()
        return next((value for key, value in self.headers if key.lower() == lowered), None)


def exchange(method: str, url: JavaUrl, headers: list[tuple[str, str]], *, address: str, port: int,
             tls: ssl.SSLContext | None, connect_timeout: float | None, handshake_timeout: float | None,
             read_timeout: float | None, tunnel: tuple[str, list[tuple[str, str]]] | None = None) -> Response:
    """Send one request and read the whole response.

    ``tunnel`` = (``host:port``, CONNECT headers) when ``address``/``port`` is an HTTP proxy. Failures before the
    body raise :class:`ExchangeError`; a failure while reading the body is kept in ``Response.body_error`` because
    Java reads the body lazily.
    """
    phase = "connect"
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((address, port), connect_timeout)
        if tunnel is not None:
            phase = "tunnel"
            sock.settimeout(read_timeout)
            _open_tunnel(sock, *tunnel)
        if tls is not None:
            phase = "handshake"
            sock.settimeout(handshake_timeout)
            sock = tls.wrap_socket(sock, server_hostname=url.host.strip("[]") or None)
        sock.settimeout(read_timeout)
        phase = "send"
        connection = http.client.HTTPConnection(address, port)
        connection.sock = sock
        connection.putrequest(method, url.request_target, skip_host=True, skip_accept_encoding=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders()
        phase = "headers"
        raw = connection.getresponse()
        response = Response(raw.status, raw.reason, raw.getheaders())
        try:
            response.body = raw.read()
        except (OSError, http.client.HTTPException) as exc:
            response.body_error = ExchangeError("body", exc)
        return response
    except (OSError, http.client.HTTPException) as exc:
        raise ExchangeError(phase, exc) from exc
    finally:
        if sock is not None:
            sock.close()


def _open_tunnel(sock: socket.socket, target: str, headers: list[tuple[str, str]]) -> None:
    lines = [f"CONNECT {target} HTTP/1.1"] + [f"{name}: {value}" for name, value in headers]
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    with sock.makefile("rb") as reader:
        status_line = reader.readline(65537).decode("latin-1").rstrip("\r\n")
        while reader.readline(65537) not in (b"\r\n", b"\n", b""):
            pass
    if not status_line:
        raise http.client.RemoteDisconnected("Proxy closed the connection without a response")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or parts[1] != "200":
        raise JavaIOError("java.io.IOException", f'Unable to tunnel through proxy. Proxy returns "{status_line}"')
