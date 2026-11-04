"""Subset of ``java.net.URI`` (RFC 2396 parser, decoded accessors, ``resolve``, 7-arg constructor).

Header analysis depends on Java's exact URI semantics: which strings are rejected (and the exception text),
``getHost()`` being ``None`` for registry-based authorities (e.g. underscores), decoded ``getPath()`` and the
RFC 2396 ``resolve`` rules, which differ from ``urllib.parse.urljoin``.
"""
from __future__ import annotations

import unicodedata

from .java_utf8 import java_utf8_decode


class URISyntaxError(Exception):
    """``java.net.URISyntaxException``; ``str()`` is Java's ``getMessage()``."""

    java_class = "java.net.URISyntaxException"

    def __init__(self, text: str, reason: str, index: int = -1):
        super().__init__(text, reason, index)
        self.input = text
        self.reason = reason
        self.index = index

    def __str__(self) -> str:
        where = f" at index {self.index}" if self.index > -1 else ""
        return f"{self.reason}{where}: {self.input}"


class IllegalArgumentError(ValueError):
    """``IllegalArgumentException`` thrown by ``URI.create`` / ``URI.resolve(String)``."""

    java_class = "java.lang.IllegalArgumentException"


def java_exception_string(exc: BaseException) -> str:
    """Java ``String.valueOf(exception)``: ``<qualified class>: <message>``."""
    name = getattr(exc, "java_class", type(exc).__name__)
    message = str(exc)
    return f"{name}: {message}" if message else name


def java_simple_name(exc: BaseException) -> str:
    return getattr(exc, "java_class", type(exc).__name__).rsplit(".", 1)[-1]


class _Chars:
    """A character class of the RFC 2396 grammar; ``escaped`` allows %XX and visible non-ASCII chars."""

    __slots__ = ("chars", "escaped")

    def __init__(self, chars: str, escaped: bool = False):
        self.chars = frozenset(chars)
        self.escaped = escaped

    def __or__(self, other: "_Chars") -> "_Chars":
        return _Chars("".join(self.chars | other.chars), self.escaped or other.escaped)


_DIGIT = _Chars("0123456789")
_ALPHA = _Chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_ALPHANUM = _ALPHA | _DIGIT
_HEX = _DIGIT | _Chars("ABCDEFabcdef")
_ESCAPED = _Chars("", escaped=True)
_UNRESERVED = _ALPHANUM | _Chars("-_.!~*'()")
_RESERVED = _Chars(";/?:@&=+$,[]")
_URIC = _RESERVED | _UNRESERVED | _ESCAPED
_PCHAR = _UNRESERVED | _ESCAPED | _Chars(":@&=+$,")
_PATH = _PCHAR | _Chars(";/")
_DASH = _Chars("-")
_DOT = _Chars(".")
_USERINFO = _UNRESERVED | _ESCAPED | _Chars(";:&=+$,")
_REG_NAME = _UNRESERVED | _ESCAPED | _Chars("$,;:@&=+")
_SERVER = _USERINFO | _ALPHANUM | _DASH | _Chars(".:@[]")
_SERVER_PERCENT = _SERVER | _Chars("%")
_SCHEME = _ALPHA | _DIGIT | _Chars("+-.")
_SCOPE_ID = _ALPHANUM | _Chars("_.")


def _is_space_char(ch: str) -> bool:
    return unicodedata.category(ch) in ("Zs", "Zl", "Zp")


def _is_iso_control(ch: str) -> bool:
    return ord(ch) <= 0x1F or 0x7F <= ord(ch) <= 0x9F


def _utf16_index(text: str, index: int) -> int:
    return len(text[:index].encode("utf-16-le", "surrogatepass")) // 2


class _Parser:
    """Port of ``java.net.URI.Parser``."""

    def __init__(self, uri: "JavaURI", text: str):
        self.uri = uri
        self.input = text
        self.require_server_authority = False
        self.ipv6_byte_count = 0

    def fail(self, reason: str, index: int = -1) -> None:
        java_index = _utf16_index(self.input, index) if index > -1 else -1
        raise URISyntaxError(self.input, reason, java_index)

    def fail_expecting(self, expected: str, index: int) -> None:
        self.fail("Expected " + expected, index)

    def at(self, start: int, end: int, text: str) -> bool:
        return start < end and self.input.startswith(text, start) and start + len(text) <= end

    def scan_char(self, start: int, end: int, ch: str) -> int:
        return start + 1 if start < end and self.input[start] == ch else start

    def scan_stop(self, start: int, end: int, err: str, stop: str) -> int:
        p = start
        while p < end:
            ch = self.input[p]
            if ch in err:
                return -1
            if ch in stop:
                break
            p += 1
        return p

    def scan_escape(self, start: int, end: int, first: str) -> int:
        if first == "%":
            if (start + 3 <= end and self.input[start + 1] in _HEX.chars
                    and self.input[start + 2] in _HEX.chars):
                return start + 3
            self.fail("Malformed escape pair", start)
        elif ord(first) > 128 and not _is_space_char(first) and not _is_iso_control(first):
            return start + 1
        return start

    def scan(self, start: int, end: int, cls: _Chars) -> int:
        p = start
        while p < end:
            ch = self.input[p]
            if ch in cls.chars:
                p += 1
                continue
            if cls.escaped:
                q = self.scan_escape(p, end, ch)
                if q > p:
                    p = q
                    continue
            break
        return p

    def check_chars(self, start: int, end: int, cls: _Chars, what: str) -> None:
        p = self.scan(start, end, cls)
        if p < end:
            self.fail("Illegal character in " + what, p)

    # [<scheme>:]<scheme-specific-part>[#<fragment>]
    def parse(self, require_server_authority: bool) -> None:
        self.require_server_authority = require_server_authority
        uri, text = self.uri, self.input
        n = len(text)
        p = self.scan_stop(0, n, "/?#", ":")
        if p >= 0 and self.at(p, n, ":"):
            if p == 0:
                self.fail_expecting("scheme name", 0)
            self.check_chars(0, 1, _ALPHA, "scheme name")
            self.check_chars(1, p, _SCHEME, "scheme name")
            uri.scheme = text[:p]
            p += 1
            if self.at(p, n, "/"):
                p = self.parse_hierarchical(p, n)
            else:
                q = self.scan_stop(p, n, "", "#")
                if q <= p:
                    self.fail_expecting("scheme-specific part", p)
                self.check_chars(p, q, _URIC, "opaque part")
                uri.scheme_specific_part = text[p:q]
                p = q
        else:
            p = self.parse_hierarchical(0, n)
        if self.at(p, n, "#"):
            self.check_chars(p + 1, n, _URIC, "fragment")
            uri.fragment = text[p + 1:n]
            p = n
        if p < n:
            self.fail("end of URI", p)

    def parse_hierarchical(self, start: int, n: int) -> int:
        uri, text = self.uri, self.input
        p = start
        if self.at(p, n, "/") and self.at(p + 1, n, "/"):
            p += 2
            q = self.scan_stop(p, n, "", "/?#")
            if q > p:
                p = self.parse_authority(p, q)
            elif q >= n:
                self.fail_expecting("authority", p)
        q = self.scan_stop(p, n, "", "?#")
        self.check_chars(p, q, _PATH, "path")
        uri.path = text[p:q]
        p = q
        if self.at(p, n, "?"):
            p += 1
            q = self.scan_stop(p, n, "", "#")
            self.check_chars(p, q, _URIC, "query")
            uri.query = text[p:q]
            p = q
        return p

    def parse_authority(self, start: int, n: int) -> int:
        uri, text = self.uri, self.input
        if self.scan_stop(start, n, "", "]") > start:
            server_chars = self.scan(start, n, _SERVER_PERCENT) == n
        else:
            server_chars = self.scan(start, n, _SERVER) == n
        qreg = self.scan(start, n, _REG_NAME)
        reg_chars = qreg == n
        if reg_chars and not server_chars:
            uri.authority = text[start:n]
            return n
        q = start
        error: URISyntaxError | None = None
        if server_chars:
            try:
                q = self.parse_server(start, n)
                if q < n:
                    self.fail_expecting("end of authority", q)
                uri.authority = text[start:n]
            except URISyntaxError as exc:
                uri.user_info, uri.host, uri.port = None, None, -1
                if self.require_server_authority:
                    raise
                error = exc
                q = start
        if q < n:
            if reg_chars:
                uri.authority = text[start:n]
            elif error is not None:
                raise error
            else:
                self.fail("Illegal character in authority", q if server_chars else qreg)
        return n

    # [<userinfo>@]<host>[:<port>]
    def parse_server(self, start: int, n: int) -> int:
        uri, text = self.uri, self.input
        p = start
        q = self.scan_stop(p, n, "/?#", "@")
        if q >= p and self.at(q, n, "@"):
            self.check_chars(p, q, _USERINFO, "user info")
            uri.user_info = text[p:q]
            p = q + 1
        if self.at(p, n, "["):
            p += 1
            q = self.scan_stop(p, n, "/?#", "]")
            if q > p and self.at(q, n, "]"):
                r = self.scan_stop(p, q, "", "%")
                if r > p:
                    self.parse_ipv6_reference(p, r)
                    if r + 1 == q:
                        self.fail("scope id expected")
                    self.check_chars(r + 1, q, _SCOPE_ID, "scope id")
                else:
                    self.parse_ipv6_reference(p, q)
                uri.host = text[p - 1:q + 1]
                p = q + 1
            else:
                self.fail_expecting("closing bracket for IPv6 address", q)
        else:
            q = self.parse_ipv4_address(p, n)
            if q <= p:
                q = self.parse_hostname(p, n)
            p = q
        if self.at(p, n, ":"):
            p += 1
            q = self.scan(p, n, _DIGIT)
            if q > p:
                port = int(text[p:q])
                if port > 2147483647:
                    self.fail("Malformed port number", p)
                uri.port = port
                p = q
        if p < n:
            self.fail_expecting("port number", p)
        return p

    def scan_byte(self, start: int, n: int) -> int:
        q = self.scan(start, n, _DIGIT)
        if q <= start:
            return q
        return start if int(self.input[start:q]) > 255 else q

    def scan_ipv4_address(self, start: int, n: int, strict: bool) -> int:
        m = self.scan(start, n, _DIGIT | _DOT)
        if m <= start or (strict and m != n):
            return -1
        p = start
        q = p
        for step in range(7):
            q = self.scan_byte(p, m) if step % 2 == 0 else self.scan_char(p, m, ".")
            if q <= p:
                break
            p = q
        else:
            if q >= m:
                return q
        self.fail("Malformed IPv4 address", q)
        return -1

    def take_ipv4_address(self, start: int, n: int, expected: str) -> int:
        p = self.scan_ipv4_address(start, n, True)
        if p <= start:
            self.fail_expecting(expected, start)
        return p

    def parse_ipv4_address(self, start: int, n: int) -> int:
        try:
            p = self.scan_ipv4_address(start, n, False)
        except URISyntaxError:
            return -1
        if start < p < n and self.input[p] != ":":
            p = -1
        if p > start:
            self.uri.host = self.input[start:p]
        return p

    def parse_hostname(self, start: int, n: int) -> int:
        text = self.input
        p = start
        last = -1
        while True:
            q = self.scan(p, n, _ALPHANUM)
            if q <= p:
                break
            last = p
            p = q
            q = self.scan(p, n, _ALPHANUM | _DASH)
            if q > p:
                if text[q - 1] == "-":
                    self.fail("Illegal character in hostname", q - 1)
                p = q
            q = self.scan_char(p, n, ".")
            if q <= p:
                break
            p = q
            if p >= n:
                break
        if p < n and not self.at(p, n, ":"):
            self.fail("Illegal character in hostname", p)
        if last < 0:
            self.fail_expecting("hostname", start)
        if last > start and text[last] not in _ALPHA.chars:
            self.fail("Illegal character in hostname", last)
        self.uri.host = text[start:p]
        return p

    def parse_ipv6_reference(self, start: int, n: int) -> int:
        p = start
        compressed = False
        q = self.scan_hex_seq(p, n)
        if q > p:
            p = q
            if self.at(p, n, "::"):
                compressed = True
                p = self.scan_hex_post(p + 2, n)
            elif self.at(p, n, ":"):
                p = self.take_ipv4_address(p + 1, n, "IPv4 address")
                self.ipv6_byte_count += 4
        elif self.at(p, n, "::"):
            compressed = True
            p = self.scan_hex_post(p + 2, n)
        if p < n:
            self.fail("Malformed IPv6 address", start)
        if self.ipv6_byte_count > 16:
            self.fail("IPv6 address too long", start)
        if not compressed and self.ipv6_byte_count < 16:
            self.fail("IPv6 address too short", start)
        if compressed and self.ipv6_byte_count == 16:
            self.fail("Malformed IPv6 address", start)
        return p

    def scan_hex_post(self, start: int, n: int) -> int:
        if start == n:
            return start
        q = self.scan_hex_seq(start, n)
        if q > start:
            p = q
            if self.at(p, n, ":"):
                p = self.take_ipv4_address(p + 1, n, "hex digits or IPv4 address")
                self.ipv6_byte_count += 4
            return p
        p = self.take_ipv4_address(start, n, "hex digits or IPv4 address")
        self.ipv6_byte_count += 4
        return p

    def scan_hex_seq(self, start: int, n: int) -> int:
        q = self.scan(start, n, _HEX)
        if q <= start or self.at(q, n, "."):
            return -1
        if q > start + 4:
            self.fail("IPv6 hexadecimal digit sequence too long", start)
        self.ipv6_byte_count += 2
        p = q
        while p < n:
            if not self.at(p, n, ":") or self.at(p + 1, n, ":"):
                break
            p += 1
            q = self.scan(p, n, _HEX)
            if q <= p:
                self.fail_expecting("digits for an IPv6 address", p)
            if self.at(q, n, "."):
                p -= 1
                break
            if q > p + 4:
                self.fail("IPv6 hexadecimal digit sequence too long", p)
            self.ipv6_byte_count += 2
            p = q
        return p


def _decode(text: str | None) -> str | None:
    """``URI.decode``: each run of %XX escapes is decoded as UTF-8 with Java replacement semantics."""
    if not text or "%" not in text:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != "%":
            out.append(text[i])
            i += 1
            continue
        raw = bytearray()
        while i < n and text[i] == "%":
            raw.append(int(text[i + 1:i + 3], 16))
            i += 3
        out.append(java_utf8_decode(bytes(raw)))
    return "".join(out)


def _quote(text: str, cls: _Chars) -> str:
    out: list[str] = []
    for ch in text:
        if ord(ch) < 0x80:
            out.append(ch if ch in cls.chars else f"%{ord(ch):02X}")
        elif cls.escaped and (_is_space_char(ch) or _is_iso_control(ch)):
            out.append("".join(f"%{b:02X}" for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


class JavaURI:
    """A parsed ``java.net.URI``. ``JavaURI(text)`` is ``new URI(text)`` (raises :class:`URISyntaxError`)."""

    def __init__(self, text: str | None = None):
        self.scheme: str | None = None
        self.scheme_specific_part: str | None = None
        self.authority: str | None = None
        self.user_info: str | None = None
        self.host: str | None = None
        self.port = -1
        self.path: str | None = None
        self.query: str | None = None
        self.fragment: str | None = None
        self._string: str | None = None
        if text is not None:
            self._string = text
            _Parser(self, text).parse(False)

    @classmethod
    def create(cls, text: str) -> "JavaURI":
        """``URI.create``: like the constructor but raises :class:`IllegalArgumentError`."""
        try:
            return cls(text)
        except URISyntaxError as exc:
            raise IllegalArgumentError(str(exc)) from exc

    @classmethod
    def from_components(cls, scheme: str | None, user_info: str | None, host: str | None, port: int,
                        path: str | None, query: str | None, fragment: str | None) -> "JavaURI":
        """The 7-argument constructor: quotes the decoded components and re-parses with a server authority."""
        parts: list[str] = []
        if scheme is not None:
            parts.append(scheme + ":")
        if host is not None:
            parts.append("//")
            if user_info is not None:
                parts.append(_quote(user_info, _USERINFO) + "@")
            brackets = ":" in host and not host.startswith("[") and not host.endswith("]")
            parts.append(f"[{host}]" if brackets else host)
            if port != -1:
                parts.append(f":{port}")
        if path is not None:
            parts.append(_quote(path, _PATH))
        if query is not None:
            parts.append("?" + _quote(query, _URIC))
        if fragment is not None:
            parts.append("#" + _quote(fragment, _URIC))
        text = "".join(parts)
        if scheme is not None and path and not path.startswith("/"):
            raise URISyntaxError(text, "Relative path in absolute URI")
        uri = cls()
        uri._string = text
        _Parser(uri, text).parse(True)
        return uri

    def is_opaque(self) -> bool:
        return self.path is None

    def is_absolute(self) -> bool:
        return self.scheme is not None

    def get_path(self) -> str | None:
        return _decode(self.path)

    def get_query(self) -> str | None:
        return _decode(self.query)

    def get_fragment(self) -> str | None:
        return _decode(self.fragment)

    def get_user_info(self) -> str | None:
        return _decode(self.user_info)

    def resolve(self, child: "JavaURI | str") -> "JavaURI":
        """``URI.resolve`` (RFC 2396 section 5.2). A string child goes through :meth:`create`."""
        if isinstance(child, str):
            child = JavaURI.create(child)
        if child.is_opaque() or self.is_opaque():
            return child
        if (child.scheme is None and child.authority is None and child.path == "" and child.fragment is not None
                and child.query is None):
            if self.fragment is not None and child.fragment == self.fragment:
                return self
            resolved = self._copy_base()
            resolved.path, resolved.query, resolved.fragment = self.path, self.query, child.fragment
            return resolved
        if child.scheme is not None:
            return child
        resolved = JavaURI()
        resolved.scheme, resolved.query, resolved.fragment = self.scheme, child.query, child.fragment
        if child.authority is None:
            resolved.authority, resolved.host = self.authority, self.host
            resolved.user_info, resolved.port = self.user_info, self.port
            if child.path.startswith("/"):
                resolved.path = child.path
            else:
                resolved.path = _resolve_path(self.path, child.path, self.is_absolute())
        else:
            resolved.authority, resolved.host = child.authority, child.host
            resolved.user_info, resolved.port = child.user_info, child.port
            resolved.path = child.path
        return resolved

    def _copy_base(self) -> "JavaURI":
        copy = JavaURI()
        copy.scheme, copy.authority, copy.user_info = self.scheme, self.authority, self.user_info
        copy.host, copy.port = self.host, self.port
        return copy

    def __str__(self) -> str:
        if self._string is None:
            self._string = self._define_string()
        return self._string

    def __repr__(self) -> str:
        return f"JavaURI({str(self)!r})"

    def _define_string(self) -> str:
        parts: list[str] = []
        if self.scheme is not None:
            parts.append(self.scheme + ":")
        if self.is_opaque():
            parts.append(self.scheme_specific_part or "")
        else:
            if self.host is not None:
                parts.append("//")
                if self.user_info is not None:
                    parts.append(self.user_info + "@")
                brackets = ":" in self.host and not self.host.startswith("[") and not self.host.endswith("]")
                parts.append(f"[{self.host}]" if brackets else self.host)
                if self.port != -1:
                    parts.append(f":{self.port}")
            elif self.authority is not None:
                parts.append("//" + self.authority)
            parts.append(self.path or "")
            if self.query is not None:
                parts.append("?" + self.query)
        if self.fragment is not None:
            parts.append("#" + self.fragment)
        return "".join(parts)


def _resolve_path(base: str, child: str, absolute: bool) -> str:
    i = base.rfind("/")
    if child == "":
        path = base[:i + 1] if i >= 0 else ""
    elif i >= 0 or not absolute:
        path = base[:i + 1] + child
    else:
        path = "/" + child
    return normalize_path(path)


def _needs_normalization(path: str) -> bool:
    end = len(path)
    p = 0
    while p < end and path[p] == "/":
        p += 1
    if p > 1:
        return True
    while p < end:
        if path[p] == "." and (p + 1 == end or path[p + 1] == "/"
                               or (path[p + 1] == "." and (p + 2 == end or path[p + 2] == "/"))):
            return True
        while p < end:
            p += 1
            if path[p - 1] != "/":
                continue
            if p < end and path[p] == "/":
                return True
            break
    return False


def normalize_path(path: str) -> str:
    """``URI.normalize`` path algorithm: drop "." segments, collapse "seg/..", squeeze duplicate slashes."""
    if not _needs_normalization(path):
        return path
    absolute = path.startswith("/")
    segments: list[list] = []          # [text, followed_by_slash, removed]
    p, end = 0, len(path)
    while p < end and path[p] == "/":
        p += 1
    while p < end:
        q = path.find("/", p)
        if q < 0:
            segments.append([path[p:], False, False])
            break
        segments.append([path[p:q], True, False])
        p = q
        while p < end and path[p] == "/":
            p += 1
    for i, segment in enumerate(segments):
        if segment[0] == ".":
            segment[2] = True
        elif segment[0] == "..":
            j = i - 1
            while j >= 0 and segments[j][2]:
                j -= 1
            if j >= 0 and segments[j][0] != "..":
                segment[2] = segments[j][2] = True
    kept = [s for s in segments if not s[2]]
    if not absolute and segments and segments[0][2] and kept and ":" in kept[0][0]:
        kept.insert(0, [".", True, False])
    return ("/" if absolute else "") + "".join(s[0] + ("/" if s[1] else "") for s in kept)
