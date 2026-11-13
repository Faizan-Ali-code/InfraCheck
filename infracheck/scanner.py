"""Runs the selected checks for every target; targets are scanned in parallel threads."""

from __future__ import annotations

import datetime as _dt
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from infracheck import __version__
from infracheck.checks import CHECKS
from infracheck.checks.versions import EolData
from infracheck.config import Config
from infracheck.context import EvidenceStore, TargetContext
from infracheck.http import Client, RequestError
from infracheck.model import Finding, TargetResult


@dataclass
class ScanResult:
    started: str
    finished: str
    seconds: float
    checks: list[str]
    targets: list[TargetResult]
    tool: str = f"InfraCheck {__version__}"

    @property
    def findings(self) -> list[Finding]:
        return [f for t in self.targets for f in t.findings]


def client_for(cfg: Config) -> Client:
    return Client(timeout=cfg.timeout, proxy=cfg.proxy or None, ca_file=cfg.ca_file or None)


def scan_target(url: str, cfg: Config, client: Client, eol: EolData | None = None,
                evidence: EvidenceStore | None = None) -> TargetResult:
    started = time.perf_counter()
    ctx = TargetContext(url, client, cfg, eol, evidence)
    result = ctx.result
    try:
        chain = ctx.chain()
        result.reachable, result.final_url, result.status = True, chain[-1].url, chain[-1].status
    except RequestError as exc:
        result.error = str(exc)
    for name, module in CHECKS.items():
        if name not in cfg.checks:
            continue
        if not result.reachable and name != "exposure":  # exposure tests other ports, not the web service
            result.checks[name] = "skipped: target unreachable"
            continue
        try:
            module.run(ctx)
            result.checks.setdefault(name, "done")
        except RequestError as exc:
            result.checks[name] = f"error: {exc}"
        except Exception as exc:  # noqa: BLE001 - one broken check must not lose the other results
            result.checks[name] = f"error: {type(exc).__name__}: {exc}"
    result.seconds = round(time.perf_counter() - started, 2)
    return result


def run_scan(targets: list[str], cfg: Config, out_dir: str | None = None,
             progress: Callable[[TargetResult, int, int], None] | None = None,
             client: Client | None = None, eol: EolData | None = None) -> ScanResult:
    started, t0 = _dt.datetime.now().astimezone(), time.perf_counter()
    client = client or client_for(cfg)
    if eol is None and "versions" in cfg.checks:
        eol = EolData(offline=cfg.offline)
    evidence = EvidenceStore(out_dir if cfg.save_evidence else None)
    results: list[TargetResult] = []
    with ThreadPoolExecutor(max_workers=max(1, min(cfg.concurrency, len(targets)))) as pool:
        futures = [pool.submit(scan_target, url, cfg, client, eol, evidence) for url in targets]
        for i, fut in enumerate(futures, 1):
            results.append(fut.result())
            if progress:
                progress(results[-1], i, len(targets))
    finished = _dt.datetime.now().astimezone()
    return ScanResult(started.isoformat(timespec="seconds"), finished.isoformat(timespec="seconds"),
                      round(time.perf_counter() - t0, 2), [c for c in CHECKS if c in cfg.checks], results)
