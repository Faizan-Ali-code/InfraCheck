"""Vulnerability status labels and the (status, details, justification) result of an analyzer (Java ``t``/``M``)."""
from __future__ import annotations

from typing import NamedTuple

VULNERABLE = "Vulnerable"
NOT_VULNERABLE = "Not Vulnerable"
ANALYZE_MANUALLY = "Analyze Manually"
DEPRECATED = "Deprecated"


class Verdict(NamedTuple):
    status: str
    details: str = ""
    justification: str = ""


PASS = Verdict(NOT_VULNERABLE)


def vulnerable(details: str, justification: str = "") -> Verdict:
    return Verdict(VULNERABLE, details, justification)
