"""Runs one analysis over every URL in urls.txt (Java ``InfraChecker.a(...)``). Shared by the CLI and the GUI."""
from __future__ import annotations

import itertools
import os
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import config, organization
from .config import Analysis, OutputPaths
from .javacompat.strings import has_http_scheme, java_exception_text, java_trim, strip_control_chars
from .log import log, ts
from .persistence import header_store, reference_data, writer
from .progress import ProgressListener
from .scanners import headers, ssllabs
from .scanners.headers import finalize
from .worker import run_url

HEARTBEAT_SECONDS = 15
WAF_NOT_AVAILABLE = "WAF Analysis is not available in this build of InfraChecker."

_state_lock = threading.Lock()
_current_pool: ThreadPoolExecutor | None = None
_stop_requested = threading.Event()
current_paths: OutputPaths = config.new_output_paths()

def header_summary_queries(org: organization.Organization) -> list[tuple[str, str]]:
    """(title, SQL) pairs logged after a Header Analysis; the Java tool had one company's values built in.

    With ``summary_domain`` set: one query for that domain's hosts (optionally only IPs starting with
    ``summary_ip_prefix``) and one for all other hosts, as in the Java tool. Without it: one query over all hosts.
    ``summary_teams`` adds a per-ownership count column for each listed team.
    """
    columns = ["COUNT(DISTINCT host) AS unique_hosts_count", "COUNT(*) AS total_vulnerabilities"]
    for team in org.summary_teams:
        quoted, alias = team.replace("'", "''"), re.sub(r"\W", "_", team)
        columns.append(f"SUM(CASE WHEN ownership = '{quoted}' THEN 1 ELSE 0 END) AS total_vulnerabilities_{alias}")
    select = ("SELECT\r\n    " + ",\r\n    ".join(columns) + "\r\nFROM header_results\r\n"
              "WHERE vulnerabilityStatus IN ('Vulnerable', 'Deprecated')")
    domain, prefix = org.summary_domain.replace("'", "''"), org.summary_ip_prefix.replace("'", "''")
    if not domain:
        return [("Please find below the summary of Header Analysis:\n\n", select + ";")]
    ip_filter = f" AND ip LIKE '{prefix}%'" if prefix else ""
    label = org.summary_domain.split(".")[0]
    return [(f"Please find below the summary of Header Analysis(for {label} subdomains):\n\n",
             f"{select}{ip_filter} AND host LIKE '%{domain}' ;"),
            ("Please find below the summary of Header Analysis(for other domains):\n\n",
             f"{select} AND host not LIKE '%{domain}';")]


# --------------------------------------------------------------------------------------------- inputs

def load_urls(path: str = config.URLS_FILE) -> list[str]:
    """Read urls.txt: drop BOM/control chars, trim, skip empty lines, de-duplicate keeping first-seen order."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    seen: dict[str, None] = {}
    for line in lines:
        cleaned = java_trim(strip_control_chars(line.replace("﻿", "")))
        if cleaned:
            seen.setdefault(cleaned, None)
    return list(seen)


def load_ip_list(path: str = config.IPS_FILE) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def ensure_scheme(url: str) -> str:
    if has_http_scheme(url):
        return url
    log.info(f"{ts()} Protocol is not specified in URL -> {url}")
    converted = "https://" + url
    log.info(f"{ts()} Going to convert to https -> {converted}")
    return converted


def prepare_folders(analysis: Analysis) -> None:
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    if analysis.uses_ip_list:
        os.makedirs(config.HTML_DIR, exist_ok=True)
    if analysis in (Analysis.IP_SPOOFING, Analysis.EXPOSURE):
        os.makedirs(config.ACCESSIBLE_DIR, exist_ok=True)
        os.makedirs(config.NON_ACCESSIBLE_DIR, exist_ok=True)
    if analysis is Analysis.ERROR_PAGES:
        os.makedirs(config.STANDARD_ERROR_DIR, exist_ok=True)
        os.makedirs(config.NON_STANDARD_ERROR_DIR, exist_ok=True)
    for path in (config.IPS_FILE, config.URLS_FILE):
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write("\r\n")


def _announce_and_init_output(analysis: Analysis, paths: OutputPaths) -> None:
    out = paths.for_analysis(analysis)
    if analysis is Analysis.HEADERS:
        log.info("\n")
        log.info(f"{ts()} Going to perform Header Analysis")
        reference_data.reload()
        organization.reload()
        return
    if analysis is Analysis.SSL_LABS:
        writer.init_output(out, config.columns_for(analysis))
        log.info(f"{ts()} Going to perform SSL Labs Analysis (Latest Results)")
        return
    title = {Analysis.WAF: "WAF Analysis", Analysis.HTTP_METHODS: "Http Methods Analysis",
             Analysis.IP_SPOOFING: "IP Spoofing Analysis", Analysis.ERROR_PAGES: "Error Pages Analysis",
             Analysis.EXPOSURE: "Exposure Analysis"}[analysis]
    log.info(f"{ts()} Going to perform {title}")
    writer.init_output(out, config.columns_for(analysis))


# --------------------------------------------------------------------------------------------- run

_progress_lock = threading.Lock()


def _print_progress(done: int, total: int) -> None:
    percent = 100 if total == 0 else done * 100 // total
    filled = max(0, min(40, percent * 40 // 100))
    print(f"Progress: [{'=' * filled}{'-' * (40 - filled)}] {percent}% ({done}/{total})")


def _ssl_labs_pacing(first: bool) -> bool:
    """Between SSL Labs submissions wait 5-10 s when the service is up (Java ``InfraChecker.a(int, boolean)``)."""
    try:
        if ssllabs.service_available():
            if first:
                return False
            time.sleep(random.randint(5, 10))
    except Exception as exc:
        log.warning(f"SSL Labs pacing delay was interrupted: {java_exception_text(exc)}")
    return first


def _execute(analysis: Analysis, paths: OutputPaths, proxy_host: str | None, proxy_port: int,
             listener: ProgressListener) -> None:
    global _current_pool
    pool_size = analysis.pool_size
    counter = itertools.count(1)
    pool = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="InfraWorker")
    with _state_lock:
        _current_pool = pool

    log.info(f"{ts()} Going to get URLs list from follwing path ->{config.URLS_FILE}")
    urls = load_urls()
    total = len(urls)
    log.info(f"{ts()} Total distinct URLs found ->{total}")
    listener.run_started(int(analysis), total, pool_size)
    if total == 0:
        print("Progress: [----------------------------------------] 100% (0/0) - No URLs found.")
        listener.run_finished()
        pool.shutdown(wait=False)
        return

    ip_list = None
    if analysis.uses_ip_list:
        log.info(f"{ts()} Going to get IPs list from following path ->{config.IPS_FILE}")
        ip_list = load_ip_list()
        log.info(f"{ts()} Got IPs count ->{len(ip_list)}")

    done = [0]
    _print_progress(0, total)

    def task(thread_name: str, url: str) -> None:
        success = True
        listener.url_started(thread_name, url)
        try:
            run_url(analysis, url, thread_name, ip_list, paths, proxy_host, proxy_port)
        except BaseException as exc:
            success = False
            log.exception(f"{ts()} {thread_name} analysis failed for url ->'{url}' : {java_exception_text(exc)}")
        finally:
            with _progress_lock:
                done[0] += 1
                _print_progress(done[0], total)
            listener.url_finished(thread_name, url, success)

    first = True
    futures = []
    for raw in urls:
        if _stop_requested.is_set():
            break
        url = ensure_scheme(java_trim(raw))
        thread_name = f"Thread_{next(counter)}:"
        listener.url_queued(thread_name, url)
        if analysis is Analysis.SSL_LABS:
            first = _ssl_labs_pacing(first)
        try:
            futures.append(pool.submit(task, thread_name, url))
        except RuntimeError:  # pool shut down by stop()
            break

    last_beat = time.monotonic()
    while any(not f.done() for f in futures):
        time.sleep(1)
        if time.monotonic() - last_beat >= HEARTBEAT_SECONDS:
            running = sum(1 for f in futures if f.running())
            queued = sum(1 for f in futures if not f.running() and not f.done())
            finished = sum(1 for f in futures if f.done())
            beat = (f"Worker completion heartbeat: done={done[0]}/{total}, active={running}, "
                    f"queued={queued}, completedByPool={finished}")
            print(beat)
            log.info(f"{ts()} {beat}")
            listener.heartbeat(done[0], total, running, queued, finished)
            last_beat = time.monotonic()

    pool.shutdown(wait=True)
    with _state_lock:
        _current_pool = None
    listener.run_finished()


def _post_process(analysis: Analysis, paths: OutputPaths) -> None:
    writer.flush_all()
    if analysis is not Analysis.HEADERS:
        return
    sqlite_path = config.sqlite_path_for(paths.headers)
    log.info(f"{ts()} Exporting header analysis results from SQLite to Excel -> {paths.headers}")
    try:
        header_store.export_to_xlsx(paths.headers)
        log.info(f"{ts()} Excel export completed -> {paths.headers}")
    except OSError as exc:
        log.warning(f"{ts()} Failed to export header results to Excel: {exc}. "
                    f"Results remain available in SQLite DB -> {sqlite_path}")
    for index, (title, query) in enumerate(header_summary_queries(organization.get())):
        if index:
            print("\n")
        log.info(title)
        log.info("Query -> " + re.sub(r"\s+", " ", query))
    header_store.write_stats(paths.headers)
    print("\n")


def run_analysis(analysis: Analysis, proxy_host: str | None = None, proxy_port: int = 0,
                 listener: ProgressListener | None = None) -> OutputPaths:
    """Run one analysis end to end. Returns the output paths of this run."""
    global current_paths
    listener = listener or ProgressListener()
    _stop_requested.clear()
    paths = config.new_output_paths()
    current_paths = paths
    if analysis is Analysis.WAF:
        log.info(f"{ts()} {WAF_NOT_AVAILABLE}")
        listener.run_started(int(analysis), 0, 0)
        listener.run_finished()
        return paths
    writer.reset()
    finalize.reset_dedup()
    headers.reset_run_state()
    try:
        prepare_folders(analysis)
        _announce_and_init_output(analysis, paths)
        log.info(f"{ts()} Initialized thread pool with size->{analysis.pool_size}")
        _execute(analysis, paths, proxy_host, proxy_port, listener)
        _post_process(analysis, paths)
    finally:
        writer.flush_all()
        for path in paths.all_paths():
            header_store.close(config.sqlite_path_for(path))
    return paths


def stop() -> None:
    """Cancel queued URLs; running URLs finish their current request (Java ``shutdownNow``)."""
    _stop_requested.set()
    with _state_lock:
        pool = _current_pool
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)
