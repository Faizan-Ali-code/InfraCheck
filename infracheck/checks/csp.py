"""Content-Security-Policy evaluation.

The rules follow the CSP Level 3 specification and the "strict CSP" approach: an effective policy
restricts scripts with nonces or hashes (optionally with 'strict-dynamic'). Host allowlists are reported
as weak because allowed hosts often serve JSONP endpoints or script gadgets that bypass them
(Weichselbaum et al., "CSP Is Dead, Long Live CSP!", ACM CCS 2016). Allowlist bypasses for specific
hosts are not checked; Google's csp-evaluator does that.
"""

from __future__ import annotations

from infracheck.context import TargetContext
from infracheck.model import Rule

CSP_REF = "W3C CSP Level 3; OWASP Content Security Policy Cheat Sheet"
STRICT_REF = "W3C CSP Level 3; Weichselbaum et al., ACM CCS 2016 (strict CSP)"

RULES = {r.id: r for r in (
    Rule("csp-missing", "csp", "medium", "No Content-Security-Policy on an HTML page", CSP_REF),
    Rule("csp-report-only", "csp", "low", "Content-Security-Policy is only in report-only mode", CSP_REF),
    Rule("csp-no-script-control", "csp", "high", "CSP does not restrict scripts (no script-src or default-src)", CSP_REF),
    Rule("csp-unsafe-inline", "csp", "high", "CSP allows inline scripts ('unsafe-inline' without nonce or hash)", CSP_REF),
    Rule("csp-unsafe-eval", "csp", "medium", "CSP allows eval() ('unsafe-eval')", CSP_REF),
    Rule("csp-wildcard-script", "csp", "high", "CSP allows scripts from any host or scheme (*, https:, data:...)", CSP_REF),
    Rule("csp-insecure-source", "csp", "medium", "CSP allows scripts over plain HTTP", CSP_REF),
    Rule("csp-host-allowlist", "csp", "low", "CSP relies on a host allowlist for scripts", STRICT_REF),
    Rule("csp-object-src", "csp", "low", "CSP does not set object-src 'none'", STRICT_REF),
    Rule("csp-base-uri", "csp", "medium", "CSP uses nonces or hashes but not base-uri", STRICT_REF),
    Rule("csp-unknown-directive", "csp", "info", "CSP contains unknown or deprecated directives", CSP_REF),
)}

KNOWN_DIRECTIVES = frozenset({
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr",
    "img-src", "font-src", "connect-src", "media-src", "object-src", "frame-src", "child-src", "worker-src",
    "manifest-src", "base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to",
    "upgrade-insecure-requests", "require-trusted-types-for", "trusted-types", "fenced-frame-src",
    "webrtc",
})
KEYWORDS = frozenset({"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'",
                      "'report-sample'", "'wasm-unsafe-eval'", "'inline-speculation-rules'"})
_WILDCARD_SCHEMES = frozenset({"*", "http:", "https:", "data:", "blob:", "filesystem:", "ws:", "wss:"})


def parse(policy: str) -> dict[str, list[str]]:
    """Directive name -> source list. A repeated directive is ignored, as the specification requires."""
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            name = tokens[0].lower()
            out.setdefault(name, [t.lower() if t.startswith("'") else t for t in tokens[1:]])
    return out


def evaluate(policy: str) -> list[tuple[str, str]]:
    """(rule id, detail) for one policy."""
    d = parse(policy)
    found: list[tuple[str, str]] = []
    script = d.get("script-src", d.get("default-src"))
    which = "script-src" if "script-src" in d else "default-src"
    if script is None:
        found.append(("csp-no-script-control", "Without script-src or default-src the policy allows scripts from "
                      "anywhere, so it gives no protection against injected scripts."))
    else:
        nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script)
        strict_dynamic = "'strict-dynamic'" in script
        if "'unsafe-inline'" in script and not nonce_or_hash:
            found.append(("csp-unsafe-inline", f"{which} contains 'unsafe-inline', so an injected <script> runs. "
                          "Browsers ignore 'unsafe-inline' when a nonce or hash is present; use those instead."))
        if "'unsafe-eval'" in script:
            found.append(("csp-unsafe-eval", f"{which} contains 'unsafe-eval': strings can be executed as code."))
        if not strict_dynamic:  # 'strict-dynamic' makes browsers ignore host and scheme sources
            wild = [s for s in script if s in _WILDCARD_SCHEMES or s.startswith("*") or "://*" in s]
            if wild:
                found.append(("csp-wildcard-script", f"{which} allows {' '.join(wild)}: an attacker can load a "
                              "script from a host they control."))
            insecure = [s for s in script if s.startswith("http://")]
            if insecure:
                found.append(("csp-insecure-source", f"{which} allows {' '.join(insecure)} over plain HTTP, which "
                              "a network attacker can replace."))
            hosts = [s for s in script if s not in KEYWORDS and not s.startswith("'") and s not in _WILDCARD_SCHEMES
                     and not s.startswith("*") and s not in wild]
            if hosts and not wild:
                found.append(("csp-host-allowlist", f"{which} trusts {', '.join(hosts[:5])}"
                              f"{' ...' if len(hosts) > 5 else ''}. Allowed hosts that serve JSONP or "
                              "user content let attackers bypass the policy; prefer nonces or hashes."))
        if nonce_or_hash and "base-uri" not in d:
            found.append(("csp-base-uri", "An injected <base href> can redirect nonce-protected relative script "
                          "URLs to the attacker's host; add base-uri 'none' or 'self'."))
    obj = d.get("object-src", d.get("default-src"))
    if obj != ["'none'"]:
        found.append(("csp-object-src", "object-src is not 'none'; plugin content (<object>, <embed>) is allowed."))
    unknown = [n for n in d if n not in KNOWN_DIRECTIVES]
    if unknown:
        found.append(("csp-unknown-directive", f"Ignored by browsers: {', '.join(unknown)}."))
    return found


def run(ctx: TargetContext) -> None:
    resp = ctx.main()
    if not resp.is_html:
        return  # CSP protects documents; it is not needed on APIs, images or downloads
    enforced = resp.header_all("Content-Security-Policy")
    report_only = resp.header_all("Content-Security-Policy-Report-Only")
    if not enforced and not report_only:
        ctx.add(RULES["csp-missing"], "Nothing limits what an injected script could load or do on this page.")
        return
    if not enforced:
        ctx.add(RULES["csp-report-only"], "Violations are only reported, never blocked.",
                f"Content-Security-Policy-Report-Only: {report_only[0][:300]}")
    policy = enforced[0] if enforced else report_only[0]
    for rule_id, detail in evaluate(policy):
        ctx.add(RULES[rule_id], detail + (" (policy from a later header is also enforced)" if len(enforced) > 1 else ""),
                f"Content-Security-Policy: {policy[:300]}")
