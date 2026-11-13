"""Scanner orchestration, report files, configuration and the command line."""

import csv
import json
import os
import socket

import pytest

from infracheck import cli
from infracheck.checks import CHECKS, all_rules
from infracheck.config import Config, ConfigError, load_config
from infracheck.model import Finding, TargetResult, load_targets, normalise_target
from infracheck.report import safe_cell, write_reports
from infracheck.scanner import ScanResult, run_scan
from server import TestServer, page

WEAK_PAGE = page("<html>weak</html>", headers=[("Server", "nginx/1.18.0"), ("Set-Cookie", "sessionid=abcdef0123456789abcd")])


def closed_port_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/"


def test_targets():
    assert normalise_target("example.com") == "https://example.com/"
    assert normalise_target("http://a.example:8080/admin") == "http://a.example:8080/admin"
    assert normalise_target("# comment") is None and normalise_target("   ") is None
    with pytest.raises(ValueError):
        normalise_target("ftp://files.example")
    assert load_targets(["a.example", "https://a.example/", "b.example"], []) == ["https://a.example/", "https://b.example/"]


def test_rule_ids_are_unique_and_referenced():
    ids = [r.id for r in all_rules()]
    assert len(ids) == len(set(ids))
    assert all(r.reference and r.severity in ("high", "medium", "low", "info") for r in all_rules())


def test_unreachable_targets_and_broken_checks(monkeypatch):
    def broken(ctx):
        raise RuntimeError("bug in a check")
    monkeypatch.setattr(CHECKS["cors"], "run", broken)
    with TestServer(WEAK_PAGE) as srv:
        result = run_scan([srv.url, closed_port_url()], Config(checks=["headers", "cors", "versions"], offline=True))
    ok, down = result.targets
    assert ok.reachable and ok.checks == {"headers": "done", "cors": "error: RuntimeError: bug in a check",
                                          "versions": "done"}
    assert {f.rule for f in ok.findings} >= {"nosniff-missing", "version-disclosed"}
    assert not down.reachable and set(down.checks.values()) == {"skipped: target unreachable"}


def _result_with(evidence: str) -> ScanResult:
    t = TargetResult("https://x.example/", reachable=True)
    t.findings.append(Finding("https://x.example/", "headers", "nosniff-missing", "low", "t", "d", "ref", evidence))
    return ScanResult("s", "f", 0.1, ["headers"], [t])


def test_reports_neutralise_formulas(tmp_path):
    assert safe_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and safe_cell("ok") == "ok"
    paths = write_reports(_result_with("=cmd|' /C calc'!A0"), str(tmp_path), ["csv", "json"])
    [row] = list(csv.DictReader(open(paths[0], encoding="utf-8-sig")))
    assert row["evidence"] == "'=cmd|' /C calc'!A0"
    doc = json.load(open(paths[1], encoding="utf-8"))
    assert doc["summary"]["total_findings"] == 1 and doc["targets"][0]["findings"] == 1


def test_excel_report(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    [path] = write_reports(_result_with("=cmd"), str(tmp_path), ["xlsx"])
    cell = openpyxl.load_workbook(path)["Findings"]["G2"]
    assert cell.value == "=cmd" and cell.data_type == "s"


def test_config_file(tmp_path):
    path = tmp_path / "infracheck.toml"
    path.write_text('[scan]\nchecks = ["headers"]\ntimeout = 3\n[methods]\nallow_write_probes = true\n'
                    '[spoofing]\nclient_ips = ["10.1.2.3"]\n[exposure]\nports = [22]\n')
    cfg = load_config(str(path))
    assert (cfg.checks, cfg.timeout, cfg.allow_write_probes, cfg.spoof_ips, cfg.exposure_ports) == (
        ["headers"], 3.0, True, ["10.1.2.3"], [22])
    for bad in ('[scan]\nchecks = ["nope"]\n', '[scan]\ntimout = 3\n', '[spoofing]\nclient_ips = ["x"]\n',
                '[scan]\nproxy = "nohostport"\n', "[["):
        path.write_text(bad)
        with pytest.raises(ConfigError):
            load_config(str(path))


def test_example_config_documents_the_defaults():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert load_config(os.path.join(root, "infracheck.example.toml")) == Config()


def test_cli(tmp_path, capsys):
    out = tmp_path / "report"
    with TestServer(WEAK_PAGE) as srv:
        args = [srv.url, "-o", str(out), "-q", "--offline", "--checks", "headers,errors,versions", "--formats", "json"]
        assert cli.main(args) == 1
        assert cli.main(args + ["--fail-on", "never"]) == 0
        assert cli.main(args + ["--fail-on", "high"]) == 0
        targets = tmp_path / "targets.txt"
        targets.write_text(f"# my hosts\n{srv.url}\n")
        assert cli.main(["-f", str(targets), "-o", str(out), "-q", "--offline", "--checks", "headers"]) == 1
    doc = json.load(open(out / "findings.json", encoding="utf-8"))
    assert doc["targets"][0]["reachable"] is True
    assert cli.main([closed_port_url(), "-o", str(out), "-q"]) == 2  # nothing reachable
    assert cli.main(["-q"]) == 2  # no targets
    assert cli.main(["example.test", "--checks", "nope"]) == 2
    assert cli.main(["checks"]) == 0
    assert "spoofing-access-granted" in capsys.readouterr().out


def test_evidence_files_are_saved(tmp_path):
    with TestServer(page("<pre>Cannot GET /x</pre>", 404)) as srv:
        cli.main([srv.url, "-o", str(tmp_path), "-q", "--offline", "--checks", "errors", "--formats", "json"])
    doc = json.load(open(tmp_path / "findings.json", encoding="utf-8"))
    [finding] = doc["findings"]
    assert finding["rule"] == "error-default-page"
    assert os.path.exists(tmp_path / finding["evidence_file"])
    assert "Cannot GET" in open(tmp_path / finding["evidence_file"], encoding="utf-8").read()
