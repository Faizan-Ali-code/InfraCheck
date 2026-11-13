"""HTTP methods: which methods the server really accepts, judged by their effect.

1. A made-up method is sent first as a control. A server that answers it like GET treats every method
   as GET (common for SPAs and CDNs), so 2xx answers to PUT or DELETE prove nothing there.
2. Read-only probes, always: OPTIONS (Allow header), TRACE with a marker header (Cross-Site Tracing is
   confirmed only if the marker comes back), PROPFIND (WebDAV).
3. Write probes only with --allow-write-probes: PUT of a uniquely named text file, read back with GET
   to confirm it was stored, then removed with DELETE. Nothing else on the server is touched.
   Without the option, PUT, DELETE and other write methods are judged from the Allow header and
   reported as "verify manually", never as confirmed.
"""

from __future__ import annotations

import secrets
from urllib.parse import urljoin

from infracheck.context import TargetContext
from infracheck.http import RequestError, Response
from infracheck.model import Rule

REF = "RFC 9110 section 9; OWASP WSTG-CONF-06 (Test HTTP Methods)"

RULES = {r.id: r for r in (
    Rule("method-trace-enabled", "methods", "medium", "TRACE echoes requests (Cross-Site Tracing)", REF),
    Rule("method-put-writes-files", "methods", "high", "PUT stores files on the server", REF),
    Rule("method-delete-removes-files", "methods", "high", "DELETE removes files on the server", REF),
    Rule("method-webdav-enabled", "methods", "medium", "WebDAV is enabled (PROPFIND answered 207)", REF),
    Rule("method-write-advertised", "methods", "low", "Write methods advertised or accepted; verify manually", REF),
    Rule("method-any-accepted", "methods", "info", "Server answers any method like GET; method results are unreliable",
         REF),
)}
WRITE_METHODS = ("PUT", "DELETE", "PATCH", "MKCOL", "COPY", "MOVE", "PROPPATCH", "LOCK", "UNLOCK")


def _try(ctx: TargetContext, url: str, method: str, headers=None, body=None) -> Response | None:
    try:
        return ctx.request(url, method, headers, body)
    except RequestError:
        return None


def run(ctx: TargetContext) -> None:
    main = ctx.main()
    url = main.url
    control = _try(ctx, url, "INFRACHECK")
    lenient = control is not None and 200 <= control.status < 300
    if lenient:
        ctx.add(RULES["method-any-accepted"], f"A made-up method got {control.status}, like GET. Accepted methods "
                "cannot be inferred from status codes on this server.", f"INFRACHECK -> {control.status}", control)

    options = _try(ctx, url, "OPTIONS")
    allow = ", ".join(v for v in ((options.header("Allow"), options.header("Public")) if options else ()) if v)
    allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

    marker = f"infracheck-{secrets.token_hex(8)}"
    trace = _try(ctx, url, "TRACE", [("X-InfraCheck-Trace", marker)])
    if trace is not None and trace.status == 200 and marker in trace.text:
        ctx.add(RULES["method-trace-enabled"], "The response echoed a request header back. Combined with a "
                "script injection this exposes HttpOnly cookies and Authorization headers.",
                f"TRACE -> 200, marker header echoed", trace)

    propfind = _try(ctx, url, "PROPFIND", [("Depth", "0")])
    if propfind is not None and propfind.status == 207:
        ctx.add(RULES["method-webdav-enabled"], "WebDAV extends the attack surface (file listing, writing, locking).",
                "PROPFIND -> 207 Multi-Status", propfind)

    if ctx.cfg.allow_write_probes and not lenient:
        _write_probe(ctx, url)
        return
    advertised = sorted(allowed & set(WRITE_METHODS))
    if advertised:
        ctx.add(RULES["method-write-advertised"], f"OPTIONS lists {', '.join(advertised)}. Advertised is not the same "
                "as working: confirm with --allow-write-probes on a test system, or manually.",
                f"Allow: {allow}", options)


def _write_probe(ctx: TargetContext, url: str) -> None:
    name = f"infracheck-probe-{secrets.token_hex(6)}.txt"
    probe_url = urljoin(url, name)
    content = f"InfraCheck write probe {name}; safe to delete.".encode()
    put = _try(ctx, probe_url, "PUT", [("Content-Type", "text/plain")], content)
    if put is None or not 200 <= put.status < 300:
        return
    check = _try(ctx, probe_url, "GET")
    stored = check is not None and check.status == 200 and content in check.body
    if not stored:
        ctx.add(RULES["method-write-advertised"], f"PUT answered {put.status} but the file could not be read back; "
                "verify manually.", f"PUT {probe_url} -> {put.status}", put)
        return
    ctx.add(RULES["method-put-writes-files"], f"{probe_url} was created and read back. Anyone can place files (or "
            "web shells) on this server.", f"PUT -> {put.status}, GET -> 200 with the uploaded content", put)
    delete = _try(ctx, probe_url, "DELETE")
    gone = _try(ctx, probe_url, "GET")
    if delete is not None and 200 <= delete.status < 300 and gone is not None and gone.status in (404, 410):
        ctx.add(RULES["method-delete-removes-files"], "The probe file was deleted again with DELETE.",
                f"DELETE -> {delete.status}, GET -> {gone.status}", delete)
    else:
        ctx.result.checks["methods"] = f"done; the probe file {probe_url} could not be removed: delete it by hand"
