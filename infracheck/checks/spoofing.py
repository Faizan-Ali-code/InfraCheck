"""Client-IP spoofing: does a client-IP header change the server's access decision?

Some servers and proxies decide access by client address and take that address from a request header
such as X-Forwarded-For. If an outside client can set the header, it can claim to be an internal or
allow-listed address. The check compares:

1. a baseline request with no client-IP header, and
2. the same request with one header added, for each header below and each address in the spoof list
   (default: loopback and private addresses that allowlists typically trust).

| Baseline | With the header | Result |
|---|---|---|
| page served (2xx) | any | not applicable: already public, nothing to unlock |
| refused (401/403), redirected or error | page served | finding: access granted by the header |
| refused, redirected or error | different status, still not served | finding (low): the header changes behaviour |
| refused, redirected or error | same status | header ignored |

Redirects are not followed, so "redirect to the login page" stays different from "page served".
List the URLs that are meant to be restricted (admin consoles, internal APIs, monitoring endpoints):
a public page can never show this weakness.
"""

from __future__ import annotations

from infracheck.context import TargetContext
from infracheck.http import RequestError, Response
from infracheck.model import Rule

REF = "OWASP WSTG-ATHZ-02 (Bypassing Authorization Schema); RFC 7239 (Forwarded); CWE-290"

RULES = {r.id: r for r in (
    Rule("spoofing-access-granted", "spoofing", "high", "Client-IP header grants access to a restricted page", REF),
    Rule("spoofing-behaviour-changed", "spoofing", "low", "Client-IP header changes the response; review manually",
         REF),
)}
HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
           "True-Client-IP", "X-Cluster-Client-IP", "Forwarded")


def header_value(header: str, ip: str) -> str:
    """The value claiming to come from `ip` (RFC 7239 syntax for Forwarded)."""
    if header.lower() != "forwarded":
        return ip
    return f'for="[{ip}]"' if ":" in ip else f"for={ip}"


def served(resp: Response) -> bool:
    return 200 <= resp.status < 300


def run(ctx: TargetContext) -> None:
    url = ctx.url
    try:
        baseline = ctx.request(url)
    except RequestError as exc:
        ctx.result.checks["spoofing"] = f"error: baseline request failed ({exc})"
        return
    if served(baseline):
        ctx.result.checks["spoofing"] = f"not applicable: the page is served without any header ({baseline.status})"
        return
    changed: list[str] = []
    for header in HEADERS:
        for ip in ctx.cfg.spoof_ips:
            try:
                resp = ctx.request(url, headers=[(header, header_value(header, ip))])
            except RequestError:
                continue
            evidence = f"without header -> {baseline.status}; {header}: {header_value(header, ip)} -> {resp.status}"
            if served(resp):
                ctx.add(RULES["spoofing-access-granted"], f"Refused without the header ({baseline.status}) but served "
                        f"with {header} claiming {ip} ({resp.status}). Access control trusts a client-controlled "
                        "header; only trusted proxies may set it.", evidence, resp)
                return  # one confirmed bypass is enough; further requests would only repeat it
            if resp.status != baseline.status and len(changed) < 3:
                changed.append(evidence)
    if changed:
        ctx.add(RULES["spoofing-behaviour-changed"], "The status changed when a client-IP header was sent, without "
                "the page being served. Check whether the header influences access decisions.", " | ".join(changed))
