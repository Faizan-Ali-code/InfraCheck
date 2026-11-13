"""Error pages: do they reveal stack traces, debug output, paths or server versions?

Two error responses are provoked with harmless requests: a random path that does not exist (404) and a
path with a malformed percent-encoding (400 on most servers). Each body is matched against signatures
of debug output and of default server error templates. A page that matches none of them is treated as
custom.

The signatures are patterns of the products' own templates, not single words: "Apache License" in a
page footer is not an Apache error page. If your organisation uses a standard error page, set
`[errors] expected_marker` to a sentence it contains, to also report pages without it.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from infracheck.context import TargetContext
from infracheck.http import RequestError
from infracheck.model import Rule

REF = "OWASP WSTG-ERRH-01 (Improper Error Handling); OWASP ASVS 4.0.3 V7.4.1, V14.3.2"

RULES = {r.id: r for r in (
    Rule("error-stack-trace", "errors", "high", "Error page shows a stack trace or debug output", REF),
    Rule("error-path-disclosure", "errors", "medium", "Error page discloses server file paths", REF),
    Rule("error-default-page", "errors", "low", "Default server error page (product identifiable)", REF),
    Rule("error-unexpected-page", "errors", "info", "Error page is not the expected standard page", REF),
    Rule("error-soft-404", "errors", "info", "Missing pages are answered with 200 (soft 404)", REF),
)}

# (rule, label, pattern). Debug output first: it is the most serious and often contains the others.
SIGNATURES: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple((rule, label, re.compile(rx, re.IGNORECASE)) for rule, label, rx in (
    ("error-stack-trace", "Java stack trace", r"(?:Exception|Error)(?::[^\n]*)?\s*\n?\s*at [\w$.]+\([\w$]+\.java:\d+\)"),
    ("error-stack-trace", "Python traceback", r"Traceback \(most recent call last\):"),
    ("error-stack-trace", ".NET stack trace", r"(?:Stack Trace:|\bat [\w.]+\(.*\) in [A-Z]:\\.*:line \d+)"),
    ("error-stack-trace", "Django debug page", r"You(?:'|&#39;|&#x27;)re seeing this error because you have <code>DEBUG = True</code>"),
    ("error-stack-trace", "Laravel / Whoops debug page", r"Whoops, looks like something went wrong|Ignition|class=\"exception-message"),
    ("error-stack-trace", "Rails debug page", r"<h1>Routing Error</h1>|Action Controller: Exception caught"),
    ("error-stack-trace", "Node.js stack trace", r"at (?:[\w.<>]+ )?\(?(?:/[\w./-]+|[A-Z]:\\[\w.\\-]+)\.js:\d+:\d+\)?"),
    ("error-path-disclosure", "PHP error with file path", r"<b>(?:Fatal error|Warning|Parse error|Notice)</b>:.* in <b>[^<]+</b> on line <b>\d+</b>"),
    ("error-path-disclosure", "ASP.NET error page", r"Server Error in '[^']*' Application"),
    ("error-default-page", "Apache httpd", r"<address>Apache(?:/[\d.]+)?[^<]*Server at [^<]+ Port \d+</address>"),
    ("error-default-page", "nginx", r"<hr><center>nginx(?:/[\d.]+)?</center>"),
    ("error-default-page", "Microsoft IIS", r"<title>IIS \d+(?:\.\d+)? Detailed Error|Internet Information Services|<h2>404 - File or directory not found\.</h2>"),
    ("error-default-page", "Apache Tomcat", r"<h3>Apache Tomcat(?:/[\d.]+)?</h3>|<title>HTTP Status \d{3} . [^<]+</title>"),
    ("error-default-page", "Eclipse Jetty", r"Powered by Jetty://"),
    ("error-default-page", "Spring Boot", r"<h1>Whitelabel Error Page</h1>"),
    ("error-default-page", "Express", r"<pre>Cannot (?:GET|POST) /[^<]*</pre>"),
    ("error-default-page", "Microsoft-HTTPAPI", r"<h2>Bad Request - Invalid URL</h2>|Microsoft-HTTPAPI/\d"),
))
# Versions are only taken from pages already recognised as server or framework templates, in the
# templates' own "Product/1.2.3" form, so "Licensed under Apache 2.0" in a footer is not a version.
_VERSION_IN_PAGE = re.compile(r"\b(Apache Tomcat|Apache|nginx|Microsoft-IIS|PHP|Jetty)(?:/|://\s*)(\d+(?:\.\d+)+)",
                              re.IGNORECASE)


def classify(body: str) -> list[tuple[str, str]]:
    """(rule id, label) for every signature found in an error page body."""
    found = []
    for rule, label, pattern in SIGNATURES:
        if pattern.search(body) and (rule, label) not in found:
            found.append((rule, label))
    return found


def run(ctx: TargetContext) -> None:
    base = ctx.main().url
    probes = (("missing page", urljoin(base, f"/infracheck-{secrets.token_hex(6)}-not-found")),
              ("malformed URL", urljoin(base, "/%%infracheck")))
    reported: set[str] = set()
    for label, url in probes:
        try:
            resp = ctx.request(url)
        except RequestError:
            continue
        body = resp.text
        if label == "missing page" and resp.status == 200:
            ctx.add(RULES["error-soft-404"], "A page that does not exist was answered with 200. Scanners and "
                    "monitoring cannot tell missing pages from real ones.", f"GET {url} -> 200")
        matches = classify(body)
        for rule_id, what in matches:
            key = f"{rule_id}:{what}"
            if key in reported:
                continue
            reported.add(key)
            ctx.add(RULES[rule_id], f"The {label} response ({resp.status}) matches: {what}.",
                    f"GET {url} -> {resp.status}", resp)
        if matches:
            for name, version in _VERSION_IN_PAGE.findall(body):
                hint = (name, version, f"{label} error page")
                if hint not in ctx.version_hints:
                    ctx.version_hints.append(hint)
        marker = ctx.cfg.expected_error_marker
        if marker and resp.status >= 400 and marker not in body and "error-unexpected-page" not in reported:
            reported.add("error-unexpected-page")
            ctx.add(RULES["error-unexpected-page"], f"The {label} response ({resp.status}) does not contain the "
                    f"configured standard error page text.", f"expected: {marker[:80]}", resp)
