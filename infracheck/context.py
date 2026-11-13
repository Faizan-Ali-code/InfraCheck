"""Per-target state shared by the checks: the main page (fetched once), the HTTP client and findings."""

from __future__ import annotations

import os
import re
import threading
from urllib.parse import urlsplit

from infracheck.config import Config
from infracheck.http import CertificateError, Client, RequestError, Response
from infracheck.model import Finding, Rule, TargetResult


class EvidenceStore:
    """Writes saved responses under <report>/evidence/<host>/; returns paths relative to the report folder."""

    def __init__(self, out_dir: str | None) -> None:
        self.out_dir = out_dir
        self._lock = threading.Lock()
        self._n = 0

    def save(self, target: str, rule: str, text: str) -> str:
        if not self.out_dir:
            return ""
        host = re.sub(r"[^A-Za-z0-9.-]", "_", urlsplit(target).netloc) or "target"
        with self._lock:
            self._n += 1
            n = self._n
        rel = os.path.join("evidence", host, f"{n:04d}-{rule}.txt")
        path = os.path.join(self.out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return rel


class TargetContext:
    def __init__(self, url: str, client: Client, cfg: Config, eol=None, evidence: EvidenceStore | None = None) -> None:
        self.url = url
        self.client = client
        self.cfg = cfg
        self.eol = eol
        self.evidence = evidence or EvidenceStore(None)
        self.result = TargetResult(url)
        self.cert_error: str | None = None
        self.version_hints: list[tuple[str, str, str]] = []  # (product, version, where it was seen)
        self._chain: list[Response] | None = None
        self._main_error: str | None = None

    @property
    def https(self) -> bool:
        return self.url.lower().startswith("https://")

    @property
    def verify(self) -> bool:
        """Verify certificates unless this target's certificate already failed (then inspect it unverified)."""
        return self.cert_error is None

    def chain(self) -> list[Response]:
        """The target URL fetched once with redirects followed. A certificate that fails verification is
        recorded and the page is fetched again without verification, so the other checks can still run."""
        if self._chain is None and self._main_error is None:
            try:
                self._chain = self.client.follow(self.url)
            except CertificateError as exc:
                self.cert_error = exc.reason
                try:
                    self._chain = self.client.follow(self.url, verify=False)
                except RequestError as exc2:
                    self._main_error = str(exc2)
            except RequestError as exc:
                self._main_error = str(exc)
        if self._chain is None:
            raise RequestError(self._main_error or "unreachable")
        return self._chain

    def main(self) -> Response:
        return self.chain()[-1]

    def request(self, url: str, method: str = "GET", headers=None, body=None) -> Response:
        return self.client.request(url, method, headers, body, verify=self.verify)

    def add(self, rule: Rule, detail: str, evidence: str = "", response: Response | None = None) -> Finding:
        f = Finding.of(rule, self.url, detail, evidence)
        if response is not None and self.cfg.save_evidence:
            f.evidence_file = self.evidence.save(self.url, rule.id, response.evidence())
        self.result.findings.append(f)
        return f
