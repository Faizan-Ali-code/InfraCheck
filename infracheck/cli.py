"""Command line: ``infracheck scan`` and ``infracheck checks``.

Exit codes: 0 = no finding at or above --fail-on, 1 = findings at or above --fail-on,
2 = no targets, no reachable target, or invalid options/config.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys

from infracheck import __version__
from infracheck.checks import CHECKS
from infracheck.config import ALL_CHECKS, DEFAULT_CHECKS, REPORT_FORMATS, ConfigError, load_config, load_ip_list
from infracheck.model import SEVERITY_ORDER, load_targets
from infracheck.report import print_summary, write_reports
from infracheck.scanner import run_scan


def _csv(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


def _ports(text: str) -> list[int]:
    try:
        return [int(p) for p in _csv(text)]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("ports must be numbers, e.g. 22,3306") from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="infracheck", description="Check web-facing hosts for common security weaknesses.")
    p.add_argument("--version", action="version", version=f"InfraCheck {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan targets")
    s.add_argument("targets", nargs="*", help="host names or URLs (https:// is assumed)")
    s.add_argument("-f", "--targets-file", action="append", default=[], help="file with one target per line")
    s.add_argument("-c", "--config", help="TOML settings file (see infracheck.example.toml)")
    s.add_argument("--checks", type=_csv, help=f"checks to run (default: {','.join(DEFAULT_CHECKS)}; 'all' adds "
                   "exposure)")
    s.add_argument("--timeout", type=float, help="seconds per request (default 10)")
    s.add_argument("--concurrency", type=int, help="targets scanned in parallel (default 8)")
    s.add_argument("--proxy", help="HTTP proxy host:port")
    s.add_argument("--ca-file", help="extra trusted CA certificates (PEM), e.g. an internal CA")
    s.add_argument("--offline", action="store_true", default=None, help="no end-of-life lookups (endoflife.date)")
    s.add_argument("--allow-write-probes", action="store_true", default=None,
                   help="test PUT/DELETE by uploading and removing one uniquely named text file")
    s.add_argument("--spoof-ips", help="file of client IPs to impersonate in the spoofing check")
    s.add_argument("--expected-error-marker", help="text your standard error page contains")
    s.add_argument("--ports", type=_ports, dest="exposure_ports", help="ports for the exposure check")
    s.add_argument("-o", "--out", help="report folder (default ./infracheck-report-<date-time>)")
    s.add_argument("--formats", type=_csv, help=f"report formats: {', '.join(REPORT_FORMATS)}")
    s.add_argument("--no-evidence", action="store_false", dest="save_evidence", default=None,
                   help="do not save responses as evidence files")
    s.add_argument("--fail-on", default="low", choices=[*SEVERITY_ORDER, "never"],
                   help="exit with 1 when a finding of this severity or higher exists (default: low)")
    s.add_argument("-q", "--quiet", action="store_true")
    sub.add_parser("checks", help="list the checks and their rules")
    return p


def _apply(cfg, args) -> None:
    if args.checks is not None:
        cfg.checks = list(ALL_CHECKS) if args.checks == ["all"] else args.checks
    for name in ("timeout", "concurrency", "proxy", "ca_file", "offline", "allow_write_probes",
                 "expected_error_marker", "exposure_ports", "formats", "save_evidence"):
        value = getattr(args, name)
        if value is not None:
            setattr(cfg, name, value)
    if args.spoof_ips:
        cfg.spoof_ips = load_ip_list(args.spoof_ips)
    if args.out:
        cfg.output_dir = args.out
    cfg.validate()


def cmd_scan(args) -> int:
    try:
        cfg = load_config(args.config)
        _apply(cfg, args)
        targets = load_targets(args.targets, args.targets_file)
    except (ConfigError, ValueError, OSError) as exc:
        print(f"infracheck: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("infracheck: no targets (give host names or URLs, or --targets-file)", file=sys.stderr)
        return 2
    out_dir = cfg.output_dir or f"infracheck-report-{_dt.datetime.now():%Y%m%d-%H%M%S}"
    if not args.quiet:
        print(f"Scanning {len(targets)} target(s) with: {', '.join(c for c in CHECKS if c in cfg.checks)}. "
              "Only scan systems you are authorised to test.", file=sys.stderr)

    def progress(r, done, total):
        if not args.quiet:
            state = f"{len(r.findings)} finding(s)" if r.reachable else f"unreachable ({r.error})"
            print(f"[{done}/{total}] {r.target}: {state}", file=sys.stderr)

    result = run_scan(targets, cfg, out_dir, progress)
    paths = write_reports(result, out_dir, cfg.formats)
    print_summary(result, sys.stdout)
    if "xlsx" in cfg.formats and not any(p.endswith(".xlsx") for p in paths):
        print("  NOTE: Excel report skipped: install openpyxl (pip install openpyxl)")
    for p in paths:
        print(f"Report: {os.path.abspath(p)}")
    if not any(t.reachable for t in result.targets) and "exposure" not in cfg.checks:
        return 2
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in result.findings) else 0


def cmd_checks() -> int:
    for name, module in CHECKS.items():
        state = "" if name in DEFAULT_CHECKS else " (opt-in)"
        print(f"{name}{state}: {(module.__doc__ or '').strip().splitlines()[0]}")
        for rule in module.RULES.values():
            print(f"    {rule.id:<34} {rule.severity:<7} {rule.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 2
    if argv[0] not in ("scan", "checks", "-h", "--help", "--version"):
        argv.insert(0, "scan")  # `infracheck example.com` and `infracheck -f urls.txt` mean `infracheck scan ...`
    args = parser.parse_args(argv)
    return cmd_checks() if args.command == "checks" else cmd_scan(args)
