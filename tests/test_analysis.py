"""Golden-file and unit tests of the checks that only analyse a response (review items I2, I4, I5)."""

import datetime as dt
import json
import os

import pytest

from conftest import FIXTURES, response_from, stub_context
from infracheck.checks import cookies, csp, headers, versions
from infracheck.checks.cookies import parse_set_cookie
from infracheck.checks.headers import cacheable, effective_referrer_policy

GOLDEN = {k: v for k, v in json.load(open(os.path.join(FIXTURES, "expected.json"))).items() if not k.startswith("_")}


@pytest.mark.parametrize("fixture", sorted(GOLDEN))
def test_golden_pages(fixture):
    with open(os.path.join(FIXTURES, fixture), encoding="utf-8") as fh:
        page = response_from(fh.read())
    ctx = stub_context(page, offline=True)
    for module in (headers, csp, cookies, versions):
        module.run(ctx)
    assert sorted(f.rule for f in ctx.result.findings) == sorted(GOLDEN[fixture])


# ------------------------------------------------------------------------------------------ I2: Expires

def _resp(*hdrs):
    return response_from("HTTP/1.1 200 OK\n" + "\n".join(f"{k}: {v}" for k, v in hdrs) + "\n\nx")


NOW = dt.datetime(2026, 11, 13, tzinfo=dt.timezone.utc)


@pytest.mark.parametrize("expires,storable", [
    ("Thu, 01 Jan 2099 00:00:00 GMT", True),   # an HTTP-date in the future: cacheable (the old bug said 'pass')
    ("Wed, 21 Oct 2099 07:28:00 GMT", True),
    ("Thu, 01 Jan 1970 00:00:00 GMT", False),
    ("0", False), ("-1", False), ("not a date", False),
])
def test_expires_is_parsed_as_an_http_date(expires, storable):
    assert cacheable(_resp(("Expires", expires)), NOW)[0] is storable


def test_cache_control_overrides_expires():
    assert cacheable(_resp(("Cache-Control", "no-store"), ("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")), NOW)[0] is False
    assert cacheable(_resp(("Cache-Control", "max-age=60"), ("Expires", "0")), NOW)[0] is True
    assert cacheable(_resp(("Cache-Control", "private")), NOW)[0] is False
    assert cacheable(_resp(("Cache-Control", "no-cache")), NOW)[0] is True  # stored, revalidated: not enough


# ------------------------------------------------------------------------------------------ I4: header rules

@pytest.mark.parametrize("value,effective", [
    ("no-referrer, strict-origin-when-cross-origin", "strict-origin-when-cross-origin"),  # fallback list
    ("strict-origin-when-cross-origin, made-up-policy", "strict-origin-when-cross-origin"),
    ("unsafe-url", "unsafe-url"), ("nonsense", None)])
def test_referrer_policy_fallback_lists(value, effective):
    assert effective_referrer_policy(value) == effective


def test_hsts_preload_is_not_required():
    page = _resp(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
    ctx = stub_context(page)
    headers.run(ctx)
    assert not [f for f in ctx.result.findings if f.rule.startswith("hsts")]


def test_hsts_zero_and_garbage():
    for value, rule in (("max-age=0", "hsts-disabled"), ("includeSubDomains", "hsts-invalid")):
        ctx = stub_context(_resp(("Strict-Transport-Security", value)))
        headers.run(ctx)
        assert rule in [f.rule for f in ctx.result.findings]


def test_plain_http_page_gets_no_hsts_finding():
    ctx = stub_context(response_from("HTTP/1.1 200 OK\nContent-Type: text/plain\n\nx", "http://www.example.test/"))
    headers.run(ctx)
    assert not [f for f in ctx.result.findings if f.rule.startswith("hsts")]


# ------------------------------------------------------------------------------------------ I5: cookies parsed

def test_cookie_attributes_are_parsed_not_substring_matched():
    c = parse_set_cookie("secure_id=httponly; Path=/; SameSite=Lax")
    assert c.name == "secure_id" and c.value == "httponly"
    assert not c.has("secure") and not c.has("httponly") and c.attributes["samesite"] == "Lax"
    c = parse_set_cookie("sid=abc;secure;HTTPONLY ; Domain=example.com")
    assert c.has("secure") and c.has("httponly") and c.attributes["domain"] == "example.com"
    assert parse_set_cookie("just-a-value").name == ""


# ------------------------------------------------------------------------------------------ CSP

@pytest.mark.parametrize("policy,expected", [
    ("default-src 'self'; object-src 'none'", []),
    ("img-src *", ["csp-no-script-control", "csp-object-src"]),
    ("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'", ["csp-base-uri"]),
    ("script-src 'self' 'unsafe-eval'; object-src 'none'", ["csp-unsafe-eval"]),
    ("script-src * ; object-src 'none'", ["csp-wildcard-script"]),
    ("script-src 'self' data:; object-src 'none'", ["csp-wildcard-script"]),
    ("script-src 'nonce-a' 'strict-dynamic' https: http:; object-src 'none'; base-uri 'self'", []),
    ("script-src 'self' https://cdn.example.com; object-src 'none'", ["csp-host-allowlist"]),
    ("script-src 'self'; script-src *; object-src 'none'", []),  # a repeated directive is ignored
])
def test_csp_rules(policy, expected):
    assert sorted(r for r, _ in csp.evaluate(policy)) == sorted(expected)


def test_csp_only_for_html():
    ctx = stub_context(response_from("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}"))
    csp.run(ctx)
    assert ctx.result.findings == []


# ------------------------------------------------------------------------------------------ versions

def test_banner_parsing():
    assert versions.parse_versions("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f mod_wsgi/4.6.8 Python/3.8") == [
        ("Apache", "2.4.41"), ("OpenSSL", "1.1.1f"), ("mod_wsgi", "4.6.8"), ("Python", "3.8")]
    assert versions.parse_versions("Jetty(9.4.43.v20210629)") == [("Jetty", "9.4.43")]
    assert versions.parse_versions("Apache Tomcat/9.0.41") == [("Apache Tomcat", "9.0.41")]
    assert versions.parse_versions("nginx") == []
    page = response_from('HTTP/1.1 200 OK\nContent-Type: text/html\nX-AspNet-Version: 4.0.30319\n\n'
                         '<meta name="generator" content="WordPress 6.4.2">')
    assert ("WordPress", "6.4.2", "generator meta tag") in versions.hints_from_response(page)
    assert ("X-AspNet-Version", "4.0.30319", "X-AspNet-Version header") in versions.hints_from_response(page)


CYCLES = {
    "https://endoflife.date/api/nginx.json": [
        {"cycle": "1.26", "eol": False, "latest": "1.26.3"}, {"cycle": "1.18", "eol": "2021-04-20", "latest": "1.18.0"}],
    "https://endoflife.date/api/openssl.json": [
        {"cycle": "3.0", "eol": "2026-09-07", "latest": "3.0.17"}, {"cycle": "1.1.1", "eol": "2023-09-11", "latest": "1.1.1w"}],
}


def test_end_of_life_and_patch_level_are_separate():
    eol = versions.EolData(fetch=CYCLES.get)
    page = response_from("HTTP/1.1 200 OK\nServer: nginx/1.18.0\nX-Powered-By: OpenSSL/1.1.1f, Microsoft-IIS/10.0\n\n")
    ctx = stub_context(page)
    ctx.eol = eol
    versions.run(ctx)
    rules = sorted(f.rule for f in ctx.result.findings)
    assert rules == ["version-disclosed"] * 3 + ["version-end-of-life"] * 2  # IIS: no lifecycle data, disclosed only
    page = response_from("HTTP/1.1 200 OK\nServer: nginx/1.26.1\n\n")
    ctx = stub_context(page)
    ctx.eol = eol
    versions.run(ctx)
    assert sorted(f.rule for f in ctx.result.findings) == ["version-disclosed", "version-not-latest-patch"]


def test_cycle_matching():
    cycles = CYCLES["https://endoflife.date/api/openssl.json"]
    assert versions.match_cycle("1.1.1f", cycles)["cycle"] == "1.1.1"
    assert versions.match_cycle("3.0.13", cycles)["cycle"] == "3.0"
    assert versions.match_cycle("3.10.1", cycles) is None  # 3.10 is not line 3.1 or 3.0
    assert versions.eol_status({"eol": "2030-01-01"}, dt.date(2026, 11, 13)) == (False, "supported until 2030-01-01")
    assert versions.eol_status({"eol": True})[0]


def test_offline_means_no_lookup():
    calls = []
    eol = versions.EolData(offline=True, fetch=lambda url: calls.append(url))
    assert eol.cycles("nginx") is None and calls == []
