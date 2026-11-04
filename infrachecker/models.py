"""Shared data types."""
from __future__ import annotations

from dataclasses import astuple, dataclass


@dataclass
class HeaderRow:
    """One final header-analysis row (Java class ``E``), in output column order."""

    url: str
    host: str
    ip: str
    ip_type: str
    ownership: str
    header: str
    value: str
    status_code: int
    vulnerability_status: str
    recommendation: str
    severity: str
    details: str
    justification: str
    response_body: str

    def dedup_key(self) -> str:
        """Key used to drop duplicate rows; details/recommendation/justification/body are not part of it."""
        parts = (self.url, self.host, self.ip, self.ip_type, self.ownership, self.header, self.value,
                 self.status_code, self.vulnerability_status, self.severity)
        return "\t".join("null" if p is None else str(p) for p in parts)

    def as_tuple(self) -> tuple:
        return astuple(self)
