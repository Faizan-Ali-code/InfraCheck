"""Report files (CSV, JSON, Excel) and the console summary.

Response text from scanned servers is attacker-controllable. Cells starting with = + - @ are written as
text, never as spreadsheet formulas.
"""

from __future__ import annotations

import csv
import json
import os
from collections import Counter
from dataclasses import asdict
from typing import TextIO

from infracheck.model import SEVERITY_ORDER
from infracheck.scanner import ScanResult

COLUMNS = ["severity", "target", "check", "rule", "title", "detail", "evidence", "reference", "evidence_file"]
TARGET_COLUMNS = ["target", "final_url", "status", "reachable", "error", "tls_version", "certificate", "http2",
                  "findings", "checks", "seconds"]
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def _sorted(result: ScanResult):
    return sorted(result.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.target, f.check, f.rule))


def summary(result: ScanResult) -> dict:
    findings = result.findings
    return {
        "targets": len(result.targets),
        "reachable": sum(t.reachable for t in result.targets),
        "total_findings": len(findings),
        "by_severity": {s: n for s in ("high", "medium", "low", "info") if (n := sum(f.severity == s for f in findings))},
        "by_rule": dict(Counter(f.rule for f in findings).most_common()),
        "checks_with_errors": sum(v.startswith("error") for t in result.targets for v in t.checks.values()),
    }


def _target_rows(result: ScanResult) -> list[dict]:
    rows = []
    for t in result.targets:
        d = {k: v for k, v in asdict(t).items() if k != "findings"}
        d["findings"] = len(t.findings)
        d["checks"] = "; ".join(f"{k}: {v}" for k, v in t.checks.items())
        rows.append(d)
    return rows


def write_csv(result: ScanResult, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        for f in _sorted(result):
            w.writerow([safe_cell(getattr(f, c)) for c in COLUMNS])


def write_json(result: ScanResult, path: str) -> None:
    doc = {"tool": result.tool, "started": result.started, "finished": result.finished, "seconds": result.seconds,
           "checks": result.checks, "summary": summary(result), "targets": _target_rows(result),
           "findings": [asdict(f) for f in _sorted(result)]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)


def write_xlsx(result: ScanResult, path: str) -> bool:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        return False
    wb = Workbook()

    def sheet(ws, header, rows, widths):
        ws.append(header)
        for cell in ws[1]:
            cell.font = Font(bold=True)
        for row in rows:
            ws.append(["" if v is None else v for v in row])
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                if cell.data_type == "f" or isinstance(cell.value, str):
                    cell.data_type = "s"
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for col, width in widths.items():
            ws.column_dimensions[col].width = width

    s = summary(result)
    sheet(wb.active, ["Item", "Value"], [[k.replace("_", " "), json.dumps(v) if isinstance(v, dict) else v]
                                        for k, v in s.items()], {"A": 24, "B": 90})
    wb.active.title = "Summary"
    sheet(wb.create_sheet("Findings"), COLUMNS, [[getattr(f, c) for c in COLUMNS] for f in _sorted(result)],
          {"B": 40, "E": 50, "F": 80, "G": 60, "H": 50, "I": 40})
    rows = _target_rows(result)
    sheet(wb.create_sheet("Targets"), TARGET_COLUMNS, [[r[c] for c in TARGET_COLUMNS] for r in rows],
          {"A": 40, "B": 40, "E": 50, "J": 100})
    wb.save(path)
    return True


def write_reports(result: ScanResult, out_dir: str, formats: list[str]) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for fmt, writer in (("csv", write_csv), ("json", write_json)):
        if fmt in formats:
            written.append(os.path.join(out_dir, f"findings.{fmt}"))
            writer(result, written[-1])
    if "xlsx" in formats and write_xlsx(result, os.path.join(out_dir, "findings.xlsx")):
        written.append(os.path.join(out_dir, "findings.xlsx"))
    return written


def print_summary(result: ScanResult, out: TextIO) -> None:
    s = summary(result)
    out.write(f"\n{result.tool}: {s['targets']} target(s), {s['reachable']} reachable, {result.seconds:.1f} s\n")
    if s["total_findings"]:
        sev = ", ".join(f"{n} {k}" for k, n in s["by_severity"].items())
        out.write(f"Findings: {s['total_findings']} ({sev})\n")
        for t in result.targets:
            counts = Counter(f.severity for f in t.findings)
            if t.findings:
                out.write(f"  {t.target}: " + ", ".join(f"{counts[k]} {k}" for k in ("high", "medium", "low", "info")
                                                         if counts[k]) + "\n")
    else:
        out.write("Findings: none\n")
    for t in result.targets:
        if not t.reachable:
            out.write(f"  UNREACHABLE: {t.target}: {t.error}\n")
        for check, state in t.checks.items():
            if state.startswith(("error", "partial")):
                out.write(f"  {check.upper()} {state}: {t.target}\n")
