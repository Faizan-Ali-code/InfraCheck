"""URL helpers of the CSP evaluator (Java ``a.e`` / ``a.f``): scheme-free URLs, hostnames,
wildcard allowlist matching and a small non-throwing WHATWG-like URL parser.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_SCHEME_FREE = re.compile(r"^\w[+\w.\-]*://", re.I | re.A)
_IPV6ISH = re.compile(r"^\[[\d:]+\]", re.A)
_WILDCARD_PREFIX = re.compile(r"^\wildcard_placeholder", re.I | re.A)   # upstream bug kept: \w + "ildcard_placeholder"
_SCHEME = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*:")
_LONG_MAX = (1 << 63) - 1
_PLACEHOLDER = "wildcard_placeholder"


@dataclass(frozen=True)
class ParsedUrl:
    hostname: str
    pathname: str


def _replace_first(text: str, old: str, new: str) -> str:
    index = text.find(old)
    return text if index < 0 else text[:index] + new + text[index + len(old):]


def scheme_free_url(url: str) -> str:
    url = _SCHEME_FREE.sub("", url, count=1)
    return url[2:] if url.startswith("//") else url


def _ipv4_number(part: str) -> int:
    if part == "":
        return -1
    radix, digits = 10, part
    if len(part) >= 2 and (part.startswith("0x") or part.startswith("0X")):
        radix, digits = 16, part[2:]
    elif len(part) >= 2 and part.startswith("0"):
        radix, digits = 8, part[1:]
    if digits == "":
        return 0
    allowed = "0123456789abcdefghijklmnopqrstuvwxyz"[:radix]
    if any(ord(ch) >= 128 or ch.lower() not in allowed for ch in digits):
        return -1
    value = int(digits, radix)
    return -1 if value > _LONG_MAX else value


def _normalize_host(host: str) -> str:
    parts = host.split(".")
    if parts[-1] == "":
        if len(parts) == 1:
            return host
        parts.pop()
    last = parts[-1]
    ends_in_number = (last != "" and all("0" <= ch <= "9" for ch in last)) or _ipv4_number(last) >= 0
    if not ends_in_number or len(parts) > 4:
        return host
    numbers = []
    for index, part in enumerate(parts):
        value = _ipv4_number(part)
        if value < 0 or (index < len(parts) - 1 and value > 255):
            return host
        numbers.append(value)
    if numbers[-1] >= (1 << (8 * (5 - len(numbers)))):
        return host
    address = numbers[-1]
    for index in range(len(numbers) - 1):
        address += numbers[index] << (8 * (3 - index))
    return f"{(address >> 24) & 255}.{(address >> 16) & 255}.{(address >> 8) & 255}.{address & 255}"


def _normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    if path == "":
        return "/"
    segments = path[1:].split("/")
    out: list[str] = []
    for index, segment in enumerate(segments):
        lowered = segment.lower()
        last = index == len(segments) - 1
        if lowered in ("..", ".%2e", "%2e.", "%2e%2e"):
            if out:
                out.pop()
            if last:
                out.append("")
        elif lowered in (".", "%2e"):
            if last:
                out.append("")
        else:
            out.append(segment)
    return "/" + "/".join(out)


def parse_url(text: str) -> ParsedUrl | None:
    """Hostname and normalized path; ``None`` where the upstream WHATWG ``URL`` constructor throws."""
    match = _SCHEME.match(text)
    if not match:
        return None
    i, n = match.end(), len(text)
    while i < n and text[i] in "/\\":
        i += 1
    j = i
    while j < n and text[j] not in "/\\?#":
        j += 1
    authority = text[i:j]
    host_port = authority[authority.rfind("@") + 1:]
    if host_port.startswith("["):
        close = host_port.find("]")
        host = host_port if close < 0 else host_port[:close + 1]
    else:
        colon = host_port.find(":")
        host = host_port if colon < 0 else host_port[:colon]
    if host == "":
        return None
    host = host.lower()
    if not host.startswith("["):
        host = _normalize_host(host)
    k = j
    while k < n and text[k] not in "?#":
        k += 1
    return ParsedUrl(host, _normalize_path(text[j:k]))


def get_hostname(url: str) -> str:
    scheme_free = scheme_free_url(url)
    placeholder = _replace_first(_replace_first(scheme_free, ":*", ""), "*", _PLACEHOLDER)
    parsed = parse_url("https://" + placeholder)
    host = _replace_first(parsed.hostname if parsed else "", _PLACEHOLDER, "*")
    if _IPV6ISH.search(scheme_free) and not _IPV6ISH.search(host):
        return "[" + host + "]"
    return host


def _with_scheme(url: str) -> str:
    return "https:" + url if url.startswith("//") else url


def match_wildcard_urls(csp_url: str, urls: Iterable[str]) -> ParsedUrl | None:
    """First allowlist entry matched by a CSP source expression (with ``*.`` host wildcards and path prefixes)."""
    source = parse_url(_with_scheme(_replace_first(_replace_first(csp_url, ":*", ""), "*", _PLACEHOLDER)))
    if source is None:
        return None
    host = source.hostname.lower()
    has_wildcard = host.startswith(_PLACEHOLDER + ".")
    wildcard_free = _WILDCARD_PREFIX.sub("", host, count=1)
    path = source.pathname
    has_path = path != "/"
    for url in urls:
        parsed = parse_url(_with_scheme(url))
        if parsed is None or not parsed.hostname.endswith(wildcard_free):
            continue
        if not has_wildcard and host != parsed.hostname:
            continue
        if has_path:
            if path.endswith("/"):
                if not parsed.pathname.startswith(path):
                    continue
            elif parsed.pathname != path:
                continue
        return parsed
    return None
