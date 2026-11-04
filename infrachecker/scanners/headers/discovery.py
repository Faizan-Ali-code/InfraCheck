"""URL discovery for one pass (Java ``ax.collectUniqueUrlsRecursive``) and the HTTP-to-HTTPS redirect-chain
follower (Java ``ax.a(String, DateTimeFormatter, String)``).
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from ...javacompat.java_uri import JavaURI, java_exception_string, java_simple_name
from ...javacompat.strings import is_blank, java_trim
from ...log import tinfo
from .analyzers import is_http, is_https
from .fetch import Fetcher, Headers, Reporter, first_header

GIVEN_URL, HOST, CONTEXT, ACTION = "Given URL", "Host", "Context", "Action"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
MAX_DEPTH = 10
MAX_HOPS = 10

_PLEASE_WAIT_URL = re.compile(r"""url=(https?://[^"'>\s]+)""", re.I | re.A)
_JS_LOCATION = re.compile(r"""(?:window\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']""", re.A)
_MOVED_LINK = re.compile(r'<a href="(https?://[^"]+)"')


@dataclass(frozen=True)
class Page:
    """A discovered URL and its response (Java ``aw``)."""

    url: str
    level: str
    code: int
    body: str
    headers: Headers
    ip: str


def _java_str(value: str | None) -> str:
    return "null" if value is None else value


def collect(fetcher: Fetcher, url: str, protocol: str, reporter: Reporter) -> list[Page]:
    """Depth-first discovery from the given URL: redirect targets, host root, context path and body links."""
    pages: list[Page] = []
    visited: set[str] = set()

    def visit(current: str, level: str, depth: int) -> None:
        if current in visited or depth > MAX_DEPTH:
            if depth > MAX_DEPTH:
                tinfo(f"URLs hunting depth limit reached for URL: {current} at depth: {depth}")
            return
        try:
            result = fetcher.cached_fetch(current, protocol, reporter)
            if result.code == 0:
                tinfo(f"Unable to open URL (response code is 0): {current}")
                return
            pages.append(Page(current, level, result.code, result.body, result.headers or (), result.ip or ""))
            visited.add(current)
            if result.code in REDIRECT_CODES:
                location = first_header(result.headers, "Location")
                if location is not None:
                    try:
                        target = str(JavaURI(current).resolve(location))
                        if target not in visited:
                            visit(target, ACTION, depth + 1)
                    except Exception as exc:
                        tinfo(f"URI parsing failure for URL: {current} redirectUrl: {location}, Exception: {exc}")
                        reporter(current, result.code, protocol, "URI Resolution Failed", ACTION,
                                 f"Failed to resolve redirect URL: {exc}", result.body)
            uri = JavaURI(current)
            host_url = f"{_java_str(uri.scheme)}://{_java_str(uri.host)}"
            if host_url not in visited:
                visit(host_url, HOST, depth + 1)
            path = uri.get_path()
            if path is not None and "/" in path:
                context = host_url + path[:path.rfind("/") + 1]
                if context not in visited:
                    visit(context, CONTEXT, depth + 1)
            _follow_body_links(result.body, current, depth)
        except Exception as exc:
            tinfo(f"collectUniqueUrlsRecursive Exception->{java_exception_string(exc)}")
            reporter(current, 0, protocol, "URL Processing Exception", level,
                     f"An error occurred while processing this URL: {java_simple_name(exc)} - {exc}", None)

    def _follow_body_links(body: str, current: str, depth: int) -> None:
        if "please wait" in body or "Please wait" in body:
            match = _PLEASE_WAIT_URL.search(body)
            if match and match.group(1) not in visited:
                visit(match.group(1), ACTION, depth + 1)
        match = _JS_LOCATION.search(body)
        if match:
            link = match.group(1)
            if not (link.startswith("http://") or link.startswith("https://")):
                link = str(JavaURI.create(current).resolve(link))
            if link not in visited:
                visit(link, ACTION, depth + 1)
        if "302 Found" in body or "301 Moved" in body or "has moved" in body:
            match = _MOVED_LINK.search(body)
            if match and match.group(1) not in visited:
                visit(match.group(1), ACTION, depth + 1)

    visit(url, GIVEN_URL, 0)
    return pages


class RedirectOutcome(enum.Enum):
    """Java ``aA``."""

    HTTPS = "a"
    NOT_REDIRECTED = "b"
    NO_LOCATION = "c"
    INVALID_LOCATION = "d"
    LOOP = "e"
    OPEN_FAILED = "f"
    HOP_LIMIT = "g"


@dataclass(frozen=True)
class RedirectChain:
    """Java ``az``: the URLs visited, the status code of each fetched URL and outcome-specific extras."""

    outcome: RedirectOutcome
    chain: list[str]
    codes: list[int]
    final_body: str | None = None
    raw_location: str | None = None

    @property
    def last(self) -> str:
        return self.chain[-1]

    @property
    def last_code(self) -> int:
        return self.codes[-1] if self.codes else 0

    def describe(self) -> str:
        """``url (code) -> url (code) -> url``."""
        return " -> ".join(url + (f" ({self.codes[i]})" if i < len(self.codes) else "")
                           for i, url in enumerate(self.chain))


def _ignore(*_args) -> None:
    pass


def follow_redirects(fetcher: Fetcher, url: str, protocol: str) -> RedirectChain:
    """Follow server-side redirects from an http:// URL until HTTPS is reached (failures are not reported)."""
    chain, codes = [url], []
    seen: set[str] = set()
    current = url
    for _ in range(MAX_HOPS + 1):
        if current in seen:
            return RedirectChain(RedirectOutcome.LOOP, chain, codes)
        seen.add(current)
        result = fetcher.cached_fetch(current, protocol, _ignore)
        if result.code == 0 or result.headers is None:
            return RedirectChain(RedirectOutcome.OPEN_FAILED, chain, codes)
        codes.append(result.code)
        if result.code not in REDIRECT_CODES:
            return RedirectChain(RedirectOutcome.NOT_REDIRECTED, chain, codes, final_body=result.body)
        location = first_header(result.headers, "Location")
        if is_blank(location):
            return RedirectChain(RedirectOutcome.NO_LOCATION, chain, codes)
        location = java_trim(location)
        try:
            target = str(JavaURI(current).resolve(location))
        except Exception:
            return RedirectChain(RedirectOutcome.INVALID_LOCATION, chain, codes, raw_location=location)
        if is_https(target):
            chain.append(target)
            return RedirectChain(RedirectOutcome.HTTPS, chain, codes)
        if not is_http(target):
            return RedirectChain(RedirectOutcome.INVALID_LOCATION, chain, codes, raw_location=location)
        chain.append(target)
        current = target
    return RedirectChain(RedirectOutcome.HOP_LIMIT, chain, codes)
