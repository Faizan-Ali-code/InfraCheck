"""Banner grabbing / version disclosure (Java ``n``): which headers are banners, the ignore list, and the version
assessment against OpenAI (when configured) or the local baseline rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ... import config
from ...javacompat.strings import is_blank, java_trim
from ...log import log, tinfo, ts, thread_name
from . import openai_client
from .recommendations import BANNER_HEADER_NAMES

_BANNER_NAMES = frozenset(name.lower() for name in BANNER_HEADER_NAMES)
_IGNORED_VALUES = frozenset({"cloudflare", "akamaighost", "none", "visp", "atlassianedge", "cloudfront", "redirection",
                             "microsoft-httpapi/2.0"})
_TECH_VERSION = re.compile(r"([a-zA-Z][a-zA-Z0-9.+_-]{1,40})\s*[/ ]\s*(\d+(?:\.\d+){1,3}[a-zA-Z]?)", re.A)
_VERSION = re.compile(r"\b\d+(?:\.\d+){1,3}\b", re.A)
_NOT_ALNUM = re.compile(r"[^a-z0-9]")
_NON_DIGITS = re.compile(r"[^0-9]")
_OPENAI_PREFIX = "openai assessment:"
_SOURCE_LABELS = {"OPENAI": "OpenAI", "BASELINE_FALLBACK": "Baseline Fallback", "UNMAPPED": "Unmapped",
                  "NONE": "Not Available"}
_SOURCE_PART_LABELS = {"OPENAI": "OpenAI API", "BASELINE_FALLBACK": "Local Baseline Fallback",
                       "UNMAPPED": "Unmapped Technology", "NONE": "Not Available"}


@dataclass(frozen=True)
class BaselineRule:
    """``hint|technologyName|minPatchedVersion`` from banner-version-baselines.txt (Java ``p``)."""

    hint: str
    technology: str
    minimum: str


DEFAULT_RULES = (
    BaselineRule("apache", "apache", "2.4.58"), BaselineRule("nginx", "nginx", "1.26.0"),
    BaselineRule("openssl", "openssl", "3.0.13"), BaselineRule("php", "php", "8.3.8"),
    BaselineRule("tomcat", "tomcat", "10.1.34"), BaselineRule("jetty", "jetty", "12.0.14"),
    BaselineRule("iis", "microsoft-iis", "10.0.0"), BaselineRule("microsoft-iis", "microsoft-iis", "10.0.0"),
    BaselineRule("asp.net", "asp.net", "4.8.1"), BaselineRule("aspnet", "asp.net", "4.8.1"),
    BaselineRule("express", "express", "4.21.0"), BaselineRule("node.js", "node.js", "20.17.0"),
    BaselineRule("node", "node.js", "20.17.0"))


@dataclass(frozen=True)
class BannerAssessment:
    """Java ``q``."""

    has_version: bool
    vulnerable: bool
    message: str
    source: str


def load_rules(path: str | None = None) -> tuple[BaselineRule, ...]:
    """Rules in file order (first match wins); the built-in defaults when the file is missing or yields none."""
    try:
        with open(path or config.BANNER_BASELINES_FILE, encoding="utf-8", errors="strict") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        log.warning("Failed to parse configured technology version rules; falling back to built-in defaults",
                    exc_info=True)
        return DEFAULT_RULES
    rules = []
    for line in lines:
        line = java_trim(line)
        if not line or line.startswith("#"):
            continue
        parts = [java_trim(part) for part in line.split("|")]
        if len(parts) >= 3 and all(parts[:3]):
            rules.append(BaselineRule(*parts[:3]))
    return tuple(rules) or DEFAULT_RULES


def load_ignored_banners(path: str) -> frozenset[str]:
    """Lower-cased entries of ignored-banner-grabbing.txt (matched as substrings of the banner value)."""
    tinfo(f"Going to check the ignored-banner-grabbing file from path ->'{path}'")
    if is_blank(path):
        return frozenset()
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        log.warning(f"{ts()} {thread_name()} ignored-banner-grabbing file not found at path ->'{path}'. "
                    "Treating list as empty.")
        return frozenset()
    except OSError as exc:
        log.error(f"{ts()} {thread_name()} Failed to read ignored-banner-grabbing file at path ->'{path}': {exc}")
        return frozenset()
    entries = (java_trim(line) for line in lines)
    return frozenset(entry.lower() for entry in entries if entry and not entry.startswith("#"))


def _normalized(text: str | None) -> str:
    return _NOT_ALNUM.sub("", (text or "").lower())


def _contains(text: str, hint: str) -> bool:
    needle = _normalized(hint)
    return needle != "" and needle in _normalized(text)


def _version_part(part: str) -> int:
    digits = _NON_DIGITS.sub("", part)
    return int(digits) if digits and int(digits) <= 2147483647 else 0


def compare_versions(left: str, right: str) -> int:
    """Numeric part-by-part comparison; missing, non-numeric or overflowing parts count as 0 (Java ``n.g``)."""
    a = [_version_part(p) for p in left.split(".")]
    b = [_version_part(p) for p in right.split(".")]
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else 0
        y = b[index] if index < len(b) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _java_str(value: str | None) -> str:
    return "null" if value is None else value


class BannerAnalyzer:
    """Per input URL (Java ``new n()``): re-reads the baselines, OpenAI config and ignore list."""

    def __init__(self):
        self.rules = load_rules()
        self.openai = openai_client.load_config()
        openai_client.ensure_disk_cache_loaded(self.openai.ttl_days)
        self.ignored = load_ignored_banners(config.IGNORED_BANNER_FILE)

    @staticmethod
    def is_banner_header(name: str) -> bool:
        return name.lower() in _BANNER_NAMES

    def is_ignored(self, value: str) -> bool:
        lowered = java_trim(value).lower()
        return lowered in _IGNORED_VALUES or any(entry in lowered for entry in self.ignored)

    def _rule_for(self, technology: str) -> BaselineRule | None:
        return next((rule for rule in self.rules
                     if _contains(technology, rule.hint) or _contains(rule.hint, technology)), None)

    def _assess_one(self, rule: BaselineRule, version: str) -> tuple[bool, str, str]:
        answer = openai_client.lookup(rule.technology, version, self.openai)
        if answer.ok:
            latest = "Not provided" if is_blank(answer.latest) else answer.latest
            verdict = "is vulnerable." if answer.vulnerable else "is not vulnerable."
            return (answer.vulnerable, f"OpenAI assessment: {rule.technology} version {version} {verdict} "
                                       f"Latest secure version: {latest}.", "OPENAI")
        below = compare_versions(version, rule.minimum) < 0
        relation = "which is below baseline" if below else "which meets baseline"
        return (below, f"Detected {rule.technology} version {version} {relation} {rule.minimum} (fallback baseline "
                       f"used because OpenAI lookup was unavailable: {_java_str(answer.reason)}).",
                "BASELINE_FALLBACK")

    def assess(self, name: str, value: str) -> BannerAssessment:
        """Versions next to a known technology in the value, then baseline hints found in the header name."""
        lowered_name, lowered_value = name.lower(), value.lower()
        messages: list[str] = []
        sources: set[str] = set()
        seen: set[str] = set()
        vulnerable = False

        def add(rule: BaselineRule, version: str) -> None:
            nonlocal vulnerable
            key = rule.technology + "@" + version
            if key in seen:
                return
            seen.add(key)
            result, message, source = self._assess_one(rule, version)
            vulnerable = vulnerable or result
            sources.add(source)
            messages.append(message)

        for match in _TECH_VERSION.finditer(lowered_value):
            rule = self._rule_for(match.group(1))
            if rule is not None:
                add(rule, match.group(2))
        first = _VERSION.search(lowered_value)
        if first is None:
            return BannerAssessment(False, False, "", "NONE")
        for rule in self.rules:
            if _contains(lowered_name, rule.hint):
                near = re.search(re.escape(rule.hint) + r"[^0-9]{0,20}(\d+(?:\.\d+){1,3}[a-zA-Z]?)", lowered_value,
                                 re.A)
                add(rule, near.group(1) if near else first.group(0))
        if messages:
            return BannerAssessment(True, vulnerable, " ".join(messages), "+".join(sorted(sources, key=str.lower)))
        return BannerAssessment(True, False, f"Detected version {first.group(0)} but technology mapping is unavailable; "
                                             "review manually.", "UNMAPPED")

    @staticmethod
    def justification(assessment: BannerAssessment) -> str:
        text = java_trim(assessment.message)
        if text[:len(_OPENAI_PREFIX)].lower() == _OPENAI_PREFIX:
            text = java_trim(text[len(_OPENAI_PREFIX):])
        if not text.endswith("."):
            text += "."
        return f"{text} (Source: {_source_label(assessment.source)})."


def _source_label(source: str) -> str:
    if is_blank(source):
        return "Unknown"
    label = _SOURCE_LABELS.get(java_trim(source).upper())
    if label is not None:
        return label
    parts = source.split("+")
    while len(parts) > 1 and parts[-1] == "":
        parts.pop()
    return " + ".join(_SOURCE_PART_LABELS.get(java_trim(part).upper(), part) for part in parts)
