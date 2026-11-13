"""Findings and per-target results."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

SEVERITIES = ("high", "medium", "low", "info")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    check: str
    severity: str
    title: str
    reference: str


@dataclass
class Finding:
    target: str
    check: str
    rule: str
    severity: str
    title: str
    detail: str
    reference: str
    evidence: str = ""  # a short excerpt (header line, policy, status codes)
    evidence_file: str = ""  # saved response, relative to the report folder

    @classmethod
    def of(cls, rule: Rule, target: str, detail: str, evidence: str = "") -> Finding:
        return cls(target, rule.check, rule.id, rule.severity, rule.title, detail, rule.reference, evidence)


@dataclass
class TargetResult:
    target: str
    final_url: str = ""
    status: int = 0
    reachable: bool = False
    error: str = ""
    tls_version: str = ""
    certificate: str = ""  # "valid", or why it is not
    http2: str = ""  # "yes" / "no" / "" (not tested)
    checks: dict[str, str] = field(default_factory=dict)  # check -> "done" | "skipped: why" | "error: why"
    findings: list[Finding] = field(default_factory=list)
    seconds: float = 0.0


def normalise_target(text: str) -> str | None:
    """`host`, `host:port` or a URL -> an absolute http(s) URL; None for blank lines and comments."""
    t = text.strip().lstrip("﻿")
    if not t or t.startswith("#"):
        return None
    if "://" not in t:
        t = "https://" + t
    parts = urlsplit(t)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not a host or http(s) URL: {text.strip()}")
    return t if parts.path else t + "/"


def load_targets(items: list[str], files: list[str]) -> list[str]:
    raw = list(items)
    for path in files:
        with open(path, encoding="utf-8-sig") as fh:
            raw.extend(fh.read().splitlines())
    out: list[str] = []
    for item in raw:
        url = normalise_target(item)
        if url and url not in out:
            out.append(url)
    return out
