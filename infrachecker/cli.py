"""Terminal mode: ``python -m infrachecker --cli [0-7] [--no-proxy | --proxy host:port]``."""
from __future__ import annotations

import platform
import sys
import time
from dataclasses import dataclass

from . import CREATED_BY, CREATED_ON, LAST_MODIFIED, VERSION, log as logsetup
from . import orchestrator
from .config import Analysis
from .log import log, ts

NOTE = "Note: Use --cli to run terminal mode, otherwise GUI starts by default."
USAGE = "Usage: --cli [analysis number 0-7] [--no-proxy | --proxy <host:port>]"
STARS = "*****************************************************************"

HELP_TEXT = [
    "Header Analysis: To perform header analysis, 'urls.txt' and 'security headers.txt' inputs are mandatory. "
    "Following headers will be analyzed for redirection case: Strict-Transport-Security, Cache-Control, Pragma, "
    "Expires, Referrer-Policy, X-Content-Type-Options",
    "WAF Analysis: Not available in this build of InfraChecker.",
    "HTTP Method Analysis: To perform HTTP method analysis, 'urls.txt' input is mandatory.",
    "IP Spoofing with headers: To perform IP Spoofing with headers analysis, "
    "'ips list-spoofing-errorpage-exposure.txt' and 'urls.txt' input are mandatory.",
    "Error Pages Analysis: To perform Error Pages Analysis, 'ips list-spoofing-errorpage-exposure.txt' is OPTIONAL "
    "and 'urls.txt' input is mandatory. If you give 'ips list-spoofing-errorpage-exposure.txt' input then it will "
    "make sure completeness.",
    "SSL Lab Analysis (Latest Results): To perform SSL Labs method analysis, 'urls.txt' input is mandatory. "
    "Latest results will give current status.",
    "Exposure Check: To perform Exposure analysis, 'ips list-spoofing-errorpage-exposure.txt' and 'urls.txt' "
    "inputs are mandatory. This must be performed outside of your organisation's network.",
]


@dataclass
class CliArgs:
    analysis: int | None = None
    no_proxy: bool = False
    proxy: tuple[str, int] | None = None
    error: str | None = None


def parse_proxy(value: str | None) -> tuple[str, int] | None:
    if value is None:
        return None
    text = value.strip()
    colon = text.rfind(":")
    if colon <= 0 or colon == len(text) - 1:
        return None
    try:
        port = int(text[colon + 1:])
    except ValueError:
        return None
    return (text[:colon], port) if 1 <= port <= 65535 else None


def parse_args(args: list[str]) -> CliArgs:
    """Parse the arguments that follow ``--cli`` (same rules and messages as the Java tool)."""
    result = CliArgs()
    i = 0
    while i < len(args):
        arg = (args[i] or "").strip()
        i += 1
        if not arg:
            continue
        lower = arg.lower()
        if lower in ("--no-proxy", "--skip-proxy"):
            result.no_proxy = True
        elif lower == "--proxy" or lower.startswith("--proxy="):
            if "=" in arg:
                value = arg[arg.index("=") + 1:]
            elif i >= len(args):
                result.error = "--proxy requires a value in host:port form"
                return result
            else:
                value = args[i]
                i += 1
            result.proxy = parse_proxy(value)
            if result.proxy is None:
                result.error = f"Invalid proxy '{value}', expected host:port"
                return result
        elif arg.isascii() and arg.isdigit() and result.analysis is None:
            result.analysis = int(arg)
            if result.analysis != 0 and not 1 <= result.analysis <= 7:
                result.error = f"Invalid analysis number '{arg}', expected 0-7"
                return result
        else:
            result.error = f"Unrecognized argument '{arg}'"
            return result
    if result.no_proxy and result.proxy is not None:
        result.error = "--no-proxy and --proxy cannot be used together"
    return result


def _read_int() -> int:
    line = sys.stdin.readline()
    if not line:
        return -1
    try:
        return int(line.strip())
    except ValueError:
        return -1


def _resolve_proxy(selection: int, args: CliArgs) -> tuple[str | None, int]:
    if args.proxy is not None and selection != 1:
        log.info("Proxy argument is only used by Header Analysis, ignoring it.")
    if selection != 1:
        return None, 0
    if args.proxy is not None:
        log.info(f"Using proxy -> {args.proxy[0]}:{args.proxy[1]}")
        return args.proxy
    if args.no_proxy:
        log.info("Skipping proxy settings as requested by arguments.")
        return None, 0
    log.info("Enter proxy host for header analysis (leave blank for none):")
    host = sys.stdin.readline().strip()
    if not host:
        return None, 0
    log.info("Enter proxy port:")
    try:
        port = int(sys.stdin.readline().strip())
    except ValueError:
        port = 0
    log.info(f"Using proxy -> {host}:{port}")
    return host, port


def _log_duration(seconds: float) -> None:
    millis = int(seconds * 1000)
    secs = millis // 1000
    minutes = millis // 60000
    if millis < 1000:
        log.info(f"Total Execution time-> {millis} Miliseconds")
    elif secs < 60:
        log.info(f"Total Execution time-> {secs} Seconds {millis - secs * 1000} Miliseconds")
    elif secs < 3600:
        log.info(f"Total Execution time-> {minutes} Minutes {secs - minutes * 60} Seconds")
    else:
        log.info(f"Total Execution time-> {minutes // 60} Hours {minutes - minutes // 60 * 60} Minutes")


def main(args: list[str]) -> int:
    started = time.monotonic()
    logsetup.setup()
    log.info("\n")
    log.info(STARS)
    log.info(f"******************** InfraChecker {VERSION} *********************")
    log.info(STARS)
    for line in (CREATED_BY, CREATED_ON, LAST_MODIFIED, NOTE):
        log.info(line)
    log.info(f"Detected python version: {platform.python_version()}")
    log.info("\n")
    log.info(STARS + "\n")
    log.info(f"***** InfraChecker {VERSION} Started *****")
    log.info("\n\n\n")

    parsed = parse_args(args)
    if parsed.error is not None:
        log.error(f"####ERROR: {parsed.error}")
        log.info(USAGE)
        return 1

    exit_code = 0
    if parsed.analysis is not None:
        selection = parsed.analysis
        log.info(f"Selection received from arguments -> {selection}")
    else:
        for analysis in Analysis:
            suffix = " (not available in this build)" if analysis is Analysis.WAF else ""
            log.info(f"{int(analysis)}. {analysis.label}{suffix}")
        log.info("0. Help")
        log.info("Kindly input your selection as indicated above:")
        selection = _read_int()

    if 1 <= selection <= 7:
        proxy_host, proxy_port = _resolve_proxy(selection, parsed)
        try:
            orchestrator.run_analysis(Analysis(selection), proxy_host, proxy_port)
        except PermissionError as exc:
            exit_code = 2
            log.info(f"{ts()} MainThread ####ERROR: File is being used by another process ->'{exc.filename}'")
    elif selection == 0:
        for index, paragraph in enumerate(HELP_TEXT):
            if index:
                log.info("\n")
            log.info(paragraph)
    else:
        exit_code = 1
        print("You Did't enter the correct input.", end="")

    print("\n\n", end="")
    log.info(f"*****InfraChecker {VERSION} Ended*****")
    log.info("\n\n")
    log.info("*********************************************************************************************")
    _log_duration(time.monotonic() - started)
    log.info("*********************************************************************************************")
    return exit_code
