"""Cross-origin resource sharing: does the server grant read access to origins it should not trust?

Three requests with an Origin header that no legitimate deployment trusts (".invalid" is reserved by
RFC 2606): an arbitrary origin, the "null" origin (sandboxed frames, local files) and an origin that
merely *starts* with the target's host name (a broken prefix check).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from infracheck.context import TargetContext
from infracheck.http import RequestError
from infracheck.model import Rule

REF = "WHATWG Fetch (CORS protocol); OWASP Web Security Testing Guide WSTG-CLNT-07"

RULES = {r.id: r for r in (
    Rule("cors-reflects-origin-credentials", "cors", "high",
         "CORS trusts any origin and allows credentials", REF),
    Rule("cors-reflects-origin", "cors", "medium", "CORS reflects any origin (without credentials)", REF),
    Rule("cors-null-origin", "cors", "high", "CORS trusts the 'null' origin with credentials", REF),
    Rule("cors-prefix-match", "cors", "high", "CORS trusts origins that only start with the site's host name", REF),
)}


def run(ctx: TargetContext) -> None:
    url = ctx.main().url
    host = urlsplit(url).hostname or ""
    probes = (("arbitrary", "https://infracheck-origin.invalid"), ("null", "null"),
              ("prefix", f"https://{host}.infracheck-origin.invalid"))
    for kind, origin in probes:
        try:
            resp = ctx.request(url, headers=[("Origin", origin)])
        except RequestError:
            continue
        acao = (resp.header("Access-Control-Allow-Origin") or "").strip()
        creds = (resp.header("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        if acao != origin:
            continue
        evidence = f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}; Allow-Credentials: {creds}"
        if kind == "null" and creds:
            ctx.add(RULES["cors-null-origin"], "Sandboxed iframes and local files send Origin: null, so any site can "
                    "read authenticated responses.", evidence, resp)
        elif kind == "prefix":
            ctx.add(RULES["cors-prefix-match"], f"An origin such as {origin} is trusted: the allowlist check only "
                    "compares the beginning of the origin.", evidence, resp)
        elif kind == "arbitrary":
            if creds:
                ctx.add(RULES["cors-reflects-origin-credentials"], "Any website can read this resource with the "
                        "visitor's cookies.", evidence, resp)
            else:
                ctx.add(RULES["cors-reflects-origin"], "Any website can read this resource (without cookies). Fine "
                        "for public data, a leak for anything else.", evidence, resp)
            return  # every origin is trusted: the narrower probes would only repeat this finding
