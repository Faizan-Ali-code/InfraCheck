"""Software versions disclosed in headers and pages, checked against published end-of-life dates.

Deterministic and verifiable: a version is compared with the release lines on endoflife.date (the
vendors' own support schedules). The check reports three different things and keeps them apart:

- *disclosed*: the exact version is visible (low; it helps an attacker pick exploits);
- *end of life*: the release line no longer receives security fixes (medium);
- *not the latest patch*: newer patches exist in a supported line (info only, because Linux
  distributions backport fixes without changing the version string; Ubuntu's Apache 2.4.41 may be fully
  patched).

It does not claim a version is vulnerable to a particular CVE: banner versions are not reliable enough
for that, and CVE applicability needs the build's actual patches.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import urllib.error
import urllib.request

from infracheck.context import TargetContext
from infracheck.model import Rule

RULES = {r.id: r for r in (
    Rule("version-disclosed", "versions", "low", "Software version disclosed",
         "OWASP WSTG-INFO-02 (Fingerprint Web Server); OWASP ASVS 4.0.3 V14.3.3"),
    Rule("version-end-of-life", "versions", "medium", "Software release line is end-of-life",
         "endoflife.date (vendor support schedules); OWASP Top 10 2021 A06"),
    Rule("version-not-latest-patch", "versions", "info", "Newer patch release exists in this release line",
         "endoflife.date"),
)}

# Product names as they appear in banners -> endoflife.date product ids (only ids that exist there).
EOL_PRODUCTS = {
    "nginx": "nginx", "apache": "apache-http-server", "apache httpd": "apache-http-server",
    "httpd": "apache-http-server", "php": "php", "apache tomcat": "tomcat", "tomcat": "tomcat",
    "jetty": "eclipse-jetty", "node.js": "nodejs", "node": "nodejs", "openssl": "openssl", "python": "python",
    "cpython": "python", "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla", "haproxy": "haproxy",
    "varnish": "varnish", "caddy": "caddy", "envoy": "envoy", "traefik": "traefik",
}
VERSION_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via")
_TOKEN = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9_.-]*(?: [A-Za-z][A-Za-z0-9_.-]*)?)[/ (](?P<version>\d+(?:\.\d+)+[a-z]?\d*)")
_SIMPLE = re.compile(r"^\s*(?P<version>\d+(?:\.\d+)+)\s*$")
_GENERATOR = re.compile(r"""<meta\s[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']"""
                        r"""|<meta\s[^>]*content=["']([^"']+)["'][^>]*name=["']generator["']""", re.IGNORECASE)


def parse_versions(text: str) -> list[tuple[str, str]]:
    """(product, version) pairs in a banner: 'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f', 'Jetty(9.4.43.v2021)'."""
    out = []
    for m in _TOKEN.finditer(text):
        name = m.group("name").strip()
        if name.lower() in ("version", "v", "build"):
            continue
        out.append((name, m.group("version")))
    return out


def hints_from_response(resp) -> list[tuple[str, str, str]]:
    hints = []
    for header in VERSION_HEADERS:
        for value in resp.header_all(header):
            simple = _SIMPLE.match(value)
            if simple:  # X-AspNet-Version: 4.0.30319
                hints.append((header, simple.group("version"), f"{header} header"))
            hints += [(n, v, f"{header} header") for n, v in parse_versions(value)]
    if resp.is_html:
        for m in _GENERATOR.finditer(resp.text[:65536]):
            hints += [(n, v, "generator meta tag") for n, v in parse_versions(m.group(1) or m.group(2))]
    return hints


class EolData:
    """endoflife.date release lines, fetched once per product per run (thread-safe); None when offline."""

    URL = "https://endoflife.date/api/{product}.json"

    def __init__(self, offline: bool = False, timeout: float = 15.0, fetch=None) -> None:
        self.offline = offline
        self.timeout = timeout
        self._fetch = fetch or self._http
        self._cache: dict[str, list | None] = {}
        self._lock = threading.Lock()

    def _http(self, url: str) -> list | None:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "InfraCheck"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed https host
                return json.load(resp)
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def cycles(self, product: str) -> list | None:
        if self.offline:
            return None
        with self._lock:
            if product not in self._cache:
                self._cache[product] = self._fetch(self.URL.format(product=product))
            return self._cache[product]


def match_cycle(version: str, cycles: list[dict]) -> dict | None:
    """The release line a version belongs to: the longest cycle id that equals the version or prefixes it."""
    base = re.match(r"\d+(?:\.\d+)*", version)
    v = base.group(0) if base else version
    best = None
    for c in cycles:
        cid = str(c.get("cycle", ""))
        if (v == cid or v.startswith(cid + ".")) and (best is None or len(cid) > len(str(best["cycle"]))):
            best = c
    return best


def eol_status(cycle: dict, today: _dt.date | None = None) -> tuple[bool, str]:
    today = today or _dt.date.today()
    eol = cycle.get("eol")
    if eol is True:
        return True, "end-of-life"
    if isinstance(eol, str):
        try:
            when = _dt.date.fromisoformat(eol)
        except ValueError:
            return False, f"end-of-life date '{eol}'"
        return when <= today, f"end-of-life since {eol}" if when <= today else f"supported until {eol}"
    return False, "supported"


def _version_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def run(ctx: TargetContext) -> None:
    hints = hints_from_response(ctx.main()) + ctx.version_hints
    seen: dict[tuple[str, str], list[str]] = {}
    for name, version, where in hints:
        seen.setdefault((name, version), [])
        if where not in seen[(name, version)]:
            seen[(name, version)].append(where)
    for (name, version), places in seen.items():
        shown = f"{name} {version} ({', '.join(places)})"
        ctx.add(RULES["version-disclosed"], f"{shown}. Hide version numbers in banners and error pages.", shown)
        product = EOL_PRODUCTS.get(name.lower())
        if not product or ctx.eol is None:
            continue
        cycles = ctx.eol.cycles(product)
        if not cycles:
            continue
        cycle = match_cycle(version, cycles)
        if cycle is None:
            continue
        ended, why = eol_status(cycle)
        source = f"https://endoflife.date/{product}"
        if ended:
            ctx.add(RULES["version-end-of-life"], f"{name} {version} belongs to release line {cycle['cycle']}, "
                    f"{why}: it no longer receives security fixes from the vendor. Distribution packages may "
                    f"have their own support period. Source: {source}", shown)
        elif cycle.get("latest") and _version_key(version) < _version_key(str(cycle["latest"])):
            ctx.add(RULES["version-not-latest-patch"], f"{name} {version}: the latest release in line "
                    f"{cycle['cycle']} is {cycle['latest']} ({why}). This alone does not prove a vulnerability: "
                    f"distributions backport fixes. Source: {source}", shown)
