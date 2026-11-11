"""CSP model, parser and effective policy (Java ``a.b`` / ``a.d``; google/csp-evaluator 1.1.8)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ....javacompat.strings import java_trim

# Finding severities (lower is worse). LOW (35) is an InfraChecker addition.
SEVERITY = {"HIGH": 10, "SYNTAX": 20, "MEDIUM": 30, "LOW": 35, "HIGH_MAYBE": 40, "STRICT_CSP": 45,
            "MEDIUM_MAYBE": 50, "INFO": 60, "NONE": 100}
CSP2, CSP3 = 2, 3

DIRECTIVES = frozenset({
    "child-src", "connect-src", "default-src", "font-src", "frame-src", "img-src", "media-src", "object-src",
    "script-src", "script-src-attr", "script-src-elem", "style-src", "style-src-attr", "style-src-elem",
    "prefetch-src", "manifest-src", "worker-src", "base-uri", "plugin-types", "sandbox", "disown-opener",
    "form-action", "frame-ancestors", "navigate-to", "report-to", "report-uri", "block-all-mixed-content",
    "upgrade-insecure-requests", "reflected-xss", "referrer", "require-sri-for", "trusted-types",
    "require-trusted-types-for", "webrtc"})
FETCH_DIRECTIVES = frozenset({
    "child-src", "connect-src", "default-src", "font-src", "frame-src", "img-src", "manifest-src", "media-src",
    "object-src", "script-src", "script-src-attr", "script-src-elem", "style-src", "style-src-attr",
    "style-src-elem", "worker-src"})
KEYWORDS = ("'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'wasm-eval'", "'wasm-unsafe-eval'",
            "'strict-dynamic'", "'unsafe-hashed-attributes'", "'unsafe-hashes'", "'report-sample'", "'block'",
            "'allow'", "'inline-speculation-rules'")
SELF, NONE, UNSAFE_INLINE, UNSAFE_EVAL = "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'"
STRICT_DYNAMIC, UNSAFE_HASHES, TRUSTED_TYPES_SCRIPT = "'strict-dynamic'", "'unsafe-hashes'", "'script'"
_CSP3_ONLY = ("report-to", "worker-src", "manifest-src", "trusted-types", "require-trusted-types-for",
              "script-src-attr", "script-src-elem", "style-src-attr", "style-src-elem")

_URL_SCHEME = re.compile(r"[a-zA-Z][+a-zA-Z0-9.\-]*:")
_STRICT_NONCE = re.compile(r"'nonce-[a-zA-Z0-9+/_\-]+[=]{0,2}'")
_NONCE = re.compile(r"'nonce-(.+)'")
_STRICT_HASH = re.compile(r"'(sha256|sha384|sha512)-[a-zA-Z0-9+/_\-]+[=]{0,2}'")
_HASH = re.compile(r"'(sha256|sha384|sha512)-(.+)'")
# JavaScript whitespace (String.prototype.trim / \s) separates tokens; Java's '.' excludes these line breaks.
_TOKEN = re.compile("[^\t\n\x0b\x0c\r \xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+")
_JAVA_DOT_EXCLUDED = frozenset("\n\r\x85\u2028\u2029")


@dataclass(frozen=True)
class Finding:
    description: str
    severity: str
    directive: str
    value: str | None = None


def _java_dot_matches(text: str) -> bool:
    return not any(ch in _JAVA_DOT_EXCLUDED for ch in text)


def is_keyword(value: str) -> bool:
    return value in KEYWORDS


def is_url_scheme(value: str) -> bool:
    return _URL_SCHEME.fullmatch(value) is not None


def nonce_value(value: str) -> str | None:
    """The part after ``'nonce-`` when the value is a (loosely formed) nonce, else ``None``."""
    match = _NONCE.fullmatch(value)
    return match.group(1) if match and _java_dot_matches(match.group(1)) else None


def is_nonce(value: str, strict: bool) -> bool:
    if strict:
        return _STRICT_NONCE.fullmatch(value) is not None
    return nonce_value(value) is not None


def is_hash(value: str, strict: bool) -> bool:
    if strict:
        return _STRICT_HASH.fullmatch(value) is not None
    match = _HASH.fullmatch(value)
    return match is not None and _java_dot_matches(match.group(2))


class Csp:
    """Parsed policy: directive name -> values, in header order."""

    def __init__(self, directives: dict[str, list[str]] | None = None):
        self.directives: dict[str, list[str]] = {name: list(values) for name, values in (directives or {}).items()}

    def clone(self) -> "Csp":
        return Csp(self.directives)

    def get(self, directive: str) -> list[str] | None:
        return self.directives.get(directive)

    def values(self, directive: str) -> list[str]:
        return self.directives.get(directive) or []

    def to_string(self) -> str:
        return "".join(name + "".join(" " + value for value in values) + "; "
                       for name, values in self.directives.items())

    def effective_directive(self, directive: str) -> str:
        if directive in self.directives:
            return directive
        if directive in ("script-src-attr", "script-src-elem") and "script-src" in self.directives:
            return "script-src"
        if directive in ("style-src-attr", "style-src-elem") and "style-src" in self.directives:
            return "style-src"
        return "default-src" if directive in FETCH_DIRECTIVES else directive

    def effective_directives(self, directives: list[str]) -> list[str]:
        result: list[str] = []
        for directive in directives:
            effective = self.effective_directive(directive)
            if effective not in result:
                result.append(effective)
        return result

    def has_script_nonces(self, directive: str = "script-src") -> bool:
        return any(is_nonce(v, True) for v in self.values(self.effective_directive(directive)))

    def has_script_hashes(self, directive: str = "script-src") -> bool:
        return any(is_hash(v, True) for v in self.values(self.effective_directive(directive)))

    def has_strict_dynamic(self, directive: str = "script-src") -> bool:
        return STRICT_DYNAMIC in self.values(self.effective_directive(directive))

    def effective_csp(self, version: int, findings: list[Finding]) -> "Csp":
        """The policy as a browser of ``version`` enforces it; "ignored" findings are appended to ``findings``."""
        effective = self.clone()
        for directive in ("script-src", "script-src-attr", "script-src-elem"):
            name = effective.effective_directive(directive)
            original = self.values(name)
            values = effective.directives.get(name)
            if values is not None and (effective.has_script_nonces(name) or effective.has_script_hashes(name)):
                if version >= CSP2:
                    if UNSAFE_INLINE in original:
                        if UNSAFE_INLINE in values:
                            values.remove(UNSAFE_INLINE)
                        findings.append(Finding("unsafe-inline is ignored if a nonce or a hash is present. "
                                                "(CSP2 and above)", "NONE", name, UNSAFE_INLINE))
                else:
                    for value in original:
                        if (value.startswith("'nonce-") or value.startswith("'sha")) and value in values:
                            values.remove(value)
            if values is not None and self.has_strict_dynamic(name):
                if version >= CSP3:
                    for value in original:
                        if not value.startswith("'") or value == SELF or value == UNSAFE_INLINE:
                            if value in values:
                                values.remove(value)
                            findings.append(Finding("Because of strict-dynamic this entry is ignored in CSP3 and "
                                                    "above", "NONE", name, value))
                elif STRICT_DYNAMIC in values:
                    values.remove(STRICT_DYNAMIC)
        if version < CSP3:
            for directive in _CSP3_ONLY:
                effective.directives.pop(directive, None)
        return effective


def _normalize_value(value: str) -> str:
    lowered = value.lower()
    return lowered if is_keyword(lowered) or is_url_scheme(value) else value


def parse_csp(text: str | None) -> Csp:
    """Split on ';', tokens on JavaScript whitespace; the first occurrence of a directive wins."""
    csp = Csp()
    if text is None:
        return csp
    for part in text.split(";"):
        tokens = _TOKEN.findall(part)
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in csp.directives:
            continue
        values: list[str] = []
        for token in tokens[1:]:
            value = _normalize_value(token)
            if value not in values:
                values.append(value)
        csp.directives[name] = values
    return csp


def quote_value(value: str) -> str:
    return value if len(value) >= 2 and value.startswith("'") and value.endswith("'") else "'" + value + "'"


def render(finding: Finding) -> str:
    """One details line: ``[SEV] 'directive' 'value' - description \\n``."""
    text = f"[{finding.severity}] '{finding.directive}'"
    if finding.value is not None:
        text += " " + quote_value(finding.value)
    return text + " - " + java_trim(finding.description) + " \n"
