"""Per-URL task: dispatches one URL to the selected analysis (Java ``ac.run``)."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from . import config
from .config import Analysis, OutputPaths
from .javacompat.strings import java_exception_text, java_trim
from .log import log, tinfo
from .models import HeaderRow
from .persistence import header_store, writer
from .scanners import error_pages, exposure, headers, http_methods, ip_spoofing, ssllabs


def _host_or_raw(url: str) -> str:
    """Java ``new URL(url).getHost()`` (case kept), falling back to the raw URL."""
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return url
    host = netloc.rsplit("@", 1)[-1]
    host = host[:host.find("]") + 1] if host.startswith("[") else host.split(":", 1)[0]
    return host or url


def run_url(analysis: Analysis, url: str, thread_name: str, ip_list: list[str] | None, paths: OutputPaths,
            proxy_host: str | None, proxy_port: int) -> None:
    threading.current_thread().name = thread_name
    if analysis is Analysis.HEADERS:
        _headers(url, paths, proxy_host, proxy_port)
    elif analysis is Analysis.HTTP_METHODS:
        _http_methods(url, paths, proxy_host, proxy_port)
    elif analysis is Analysis.IP_SPOOFING:
        _fan_out(url, ip_list or [], thread_name, paths.ip_spoofing, ip_spoofing.scan_ip,
                 "Going to perform IP Spoofing analysis on url ->'{}'")
    elif analysis is Analysis.ERROR_PAGES:
        _error_pages(url, ip_list or [], thread_name, paths)
    elif analysis is Analysis.SSL_LABS:
        _ssl_labs(url, paths)
    elif analysis is Analysis.EXPOSURE:
        _fan_out(url, ip_list or [], thread_name, paths.exposure, exposure.scan_ip,
                 "Going to perform Exposure analysis on url ->'{}'")


def _headers(url: str, paths: OutputPaths, proxy_host: str | None, proxy_port: int) -> None:
    try:
        tinfo("Started the job.")
        tinfo(f"Going to perform Header analysis on url ->'{url}'")
        headers.analyze_url(url, paths.headers, proxy_host, proxy_port)
        tinfo("Finished the job gracefully.")
    except Exception as exc:
        try:
            header_store.insert(config.sqlite_path_for(paths.headers), HeaderRow(
                url=url, host=_host_or_raw(url), ip="--", ip_type="", ownership="Unknown", header="", value="",
                status_code=0, vulnerability_status="Analyze Manually", recommendation="", severity="LOW",
                details="Host unreachable", justification="", response_body=""))
        except Exception as db_exc:
            log.exception(f"Failed to record unreachable host to SQLite for url ->'{url}' : {db_exc}")
        tinfo(f"{url}\tHost unreachable{java_exception_text(exc)}")


def _http_methods(url: str, paths: OutputPaths, proxy_host: str | None, proxy_port: int) -> None:
    try:
        tinfo(f"Going to perform Http Methods analysis on url ->'{url}'")
        http_methods.scan(url, paths.http_methods, proxy_host, proxy_port)
        tinfo(f"Http Method analysis has been completed on url ->'{url}'")
    except Exception:
        writer.append_row(paths.http_methods, f"{url}\t--\t--\tNA\tHost unreachable\t"
                                              "Unable to complete HTTP method scan due to host/network unreachability")
        tinfo(f"{url}\tHost unreachable")


def _run_children(url: str, ip_list: list[str], thread_name: str, out_path: str, scan_ip) -> None:
    with ThreadPoolExecutor(max_workers=config.CHILD_POOL_SIZE) as pool:
        futures = [pool.submit(scan_ip, url, java_trim(ip), out_path, f"{thread_name}ChildThread_{index}:", index)
                   for index, ip in enumerate(ip_list, start=1)]
    for future in futures:
        if future.exception() is not None:  # Java child runnables swallow their own errors; log anything unexpected
            log.error(f"{thread_name} child task failed: {java_exception_text(future.exception())}")


def _fan_out(url: str, ip_list: list[str], thread_name: str, out_path: str, scan_ip, start_message: str) -> None:
    try:
        tinfo(start_message.format(url))
        _run_children(url, ip_list, thread_name, out_path, scan_ip)
    except Exception:
        writer.append_row(out_path, f"{url}\t--\t--\tHost unreachable")
        tinfo(f"{url}\tHost unreachable")


def _error_pages(url: str, ip_list: list[str], thread_name: str, paths: OutputPaths) -> None:
    try:
        tinfo(f"Going to perform Error Pages analysis on url ->'{url}'")
        _run_children(url, ip_list, thread_name, paths.error_pages, error_pages.scan_ip)
        tinfo(f"Going to perform additional Error Pages analysis on url ->'{url}'")
        error_pages.extra_probes(url, paths.error_pages, thread_name)
    except Exception:
        writer.append_row(paths.error_pages, f"{url}\t--\t--\tHost unreachable")
        tinfo(f"{url}\tHost unreachable")


def _ssl_labs(url: str, paths: OutputPaths) -> None:
    try:
        tinfo(f"Going to perform SSL Labs Analysis on url ->'{url}'")
        if "*" not in url:
            ssllabs.scan(url, paths.ssl_labs)
        else:
            writer.append_row(paths.ssl_labs, f"{url}\t\t\t\t\tInvalid URL, URL contains Asterisk")
            tinfo(f"Invalid url ->'{url}'")
    except Exception as exc:
        tinfo(f"{url}\t##Check Manually##{java_exception_text(exc)}")
