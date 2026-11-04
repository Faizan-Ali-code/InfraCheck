"""Subset of ``java.net.URL``: validation and ``getHost()`` (lenient, unlike ``java.net.URI``).

``new URL(spec)`` accepts hosts that ``URI`` rejects (underscores etc.) and keeps the host's case.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# Protocols with a stream handler in the JDK; anything else is "unknown protocol".
_KNOWN_PROTOCOLS = frozenset({"file", "ftp", "http", "https", "jar", "jrt", "mailto"})
_JAVA_INT = re.compile(r"[+-]?[0-9]+")


class MalformedURLError(Exception):
    """``java.net.MalformedURLException``."""

    java_class = "java.net.MalformedURLException"


@dataclass(frozen=True)
class JavaURL:
    protocol: str
    host: str
    port: int


def _is_valid_protocol(text: str) -> bool:
    if not text or not text[0].isalpha():
        return False
    return all(ch.isalnum() or ch in ".+-" for ch in text[1:])


def _parse_port(text: str) -> int:
    if not _JAVA_INT.fullmatch(text) or not -2147483648 <= int(text) <= 2147483647:
        raise MalformedURLError(f'For input string: "{text}"')
    return int(text)


def _is_ipv6_literal(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text.split("%", 1)[0])
    except ValueError:
        return False
    return True


def parse_url(spec: str) -> JavaURL:
    """``new URL(spec)``; raises :class:`MalformedURLError`."""
    limit = len(spec)
    while limit > 0 and spec[limit - 1] <= " ":
        limit -= 1
    start = 0
    while start < limit and spec[start] <= " ":
        start += 1
    if spec[start:start + 4].lower() == "url:":
        start += 4
    protocol = None
    if not spec[start:start + 1] == "#":
        i = start
        while i < limit and spec[i] != "/":
            if spec[i] == ":":
                candidate = spec[start:i].lower()
                if _is_valid_protocol(candidate):
                    protocol = candidate
                    start = i + 1
                break
            i += 1
    if protocol is None:
        raise MalformedURLError("no protocol: " + spec)
    if protocol not in _KNOWN_PROTOCOLS:
        raise MalformedURLError("unknown protocol: " + protocol)
    hash_at = spec.find("#", start)
    if hash_at >= 0:
        limit = hash_at
    host, port = "", -1
    if start < limit:
        query_at = spec.find("?")
        if 0 <= query_at < limit:
            limit = query_at
            spec = spec[:query_at]
    unc = spec.startswith("////", start) and start <= limit - 4
    if not unc and start <= limit - 2 and spec.startswith("//", start):
        start += 2
        end = spec.find("/", start)
        if end < 0 or end > limit:
            end = spec.find("?", start)
            if end < 0 or end > limit:
                end = limit
        authority = spec[start:end]
        at = authority.find("@")
        if at != -1 and at != authority.rfind("@"):
            host = ""
        else:
            host = authority[at + 1:]
            if host.startswith("["):
                close = host.find("]")
                if close <= 2:
                    raise MalformedURLError("Invalid authority field: " + authority)
                rest = host[close + 1:]
                host = host[:close + 1]
                if not _is_ipv6_literal(host[1:close]):
                    raise MalformedURLError("Invalid host: " + host)
                if rest:
                    if not rest.startswith(":"):
                        raise MalformedURLError("Invalid authority field: " + authority)
                    if len(rest) > 1:
                        port = _parse_port(rest[1:])
            else:
                colon = host.find(":")
                if colon >= 0:
                    if len(host) > colon + 1:
                        port = _parse_port(host[colon + 1:])
                    host = host[:colon]
        if port < -1:
            raise MalformedURLError(f"Invalid port number :{port}")
    return JavaURL(protocol, host, port)


def url_host_or_raw(url: str) -> str:
    """``new URL(url).getHost()``, or the raw url when it is malformed (Java ``ax.d`` / ``aj.c``)."""
    try:
        return parse_url(url).host
    except MalformedURLError:
        return url
