"""HTTP security response headers.

Each rule cites its source. Missing headers that only harden a page are *info*, not vulnerabilities:
only a missing control that leaves a real attack open (HSTS, clickjacking protection) is rated higher.
"""

from __future__ import annotations

import datetime as _dt
import re
from email.utils import parsedate_to_datetime

from infracheck.context import TargetContext
from infracheck.http import Response
from infracheck.model import Rule

HSTS_CS = "OWASP HTTP Strict Transport Security Cheat Sheet; RFC 6797"
HEADERS = "OWASP Secure Headers Project; OWASP ASVS 4.0.3 V14.4"

RULES = {r.id: r for r in (
    Rule("hsts-missing", "headers", "medium", "HSTS header missing", HSTS_CS),
    Rule("hsts-disabled", "headers", "medium", "HSTS max-age is 0 (HSTS switched off)", HSTS_CS),
    Rule("hsts-short", "headers", "low", "HSTS max-age shorter than one year", HSTS_CS),
    Rule("hsts-invalid", "headers", "medium", "HSTS header cannot be parsed", HSTS_CS),
    Rule("hsts-no-subdomains", "headers", "info", "HSTS does not include subdomains", HSTS_CS),
    Rule("nosniff-missing", "headers", "low", "X-Content-Type-Options: nosniff missing", HEADERS),
    Rule("clickjacking", "headers", "medium", "Page can be framed by other sites (no frame-ancestors or X-Frame-Options)",
         "OWASP Clickjacking Defense Cheat Sheet; CSP Level 3 frame-ancestors"),
    Rule("xfo-allow-from", "headers", "low", "X-Frame-Options ALLOW-FROM is obsolete and ignored by browsers",
         "OWASP Clickjacking Defense Cheat Sheet"),
    Rule("referrer-unsafe", "headers", "low", "Referrer-Policy sends full URLs to other sites",
         "W3C Referrer Policy; OWASP Secure Headers Project"),
    Rule("referrer-missing", "headers", "info", "Referrer-Policy not set (browser default applies)",
         "W3C Referrer Policy; OWASP Secure Headers Project"),
    Rule("permissions-policy-missing", "headers", "info", "Permissions-Policy not set", HEADERS),
    Rule("xss-protection-deprecated", "headers", "info", "X-XSS-Protection enabled (deprecated; set 0 or remove)",
         "OWASP Secure Headers Project"),
    Rule("cacheable-with-cookies", "headers", "low", "Response that sets cookies may be stored by caches",
         "OWASP ASVS 4.0.3 V8.2.1; RFC 9111"),
)}

_MAX_AGE = re.compile(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?\s*(?:;|$)", re.IGNORECASE)
_REFERRER_POLICIES = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin",
                      "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}


def effective_referrer_policy(value: str) -> str | None:
    """Browsers use the last policy token they recognise, so a list such as
    'no-referrer, strict-origin-when-cross-origin' is a deliberate fallback, not an error."""
    tokens = [t.strip().lower() for t in value.split(",")]
    known = [t for t in tokens if t in _REFERRER_POLICIES]
    return known[-1] if known else None


def frame_ancestors(resp: Response) -> str | None:
    for policy in resp.header_all("Content-Security-Policy"):
        for directive in policy.split(";"):
            parts = directive.strip().split(None, 1)
            if parts and parts[0].lower() == "frame-ancestors":
                return parts[1] if len(parts) > 1 else ""
    return None


def http_date(value: str) -> _dt.datetime | None:
    try:
        d = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)


def cacheable(resp: Response, now: _dt.datetime | None = None) -> tuple[bool, str]:
    """Whether a shared cache may store the response (RFC 9111), and why.

    Expires is an HTTP-date ('Thu, 01 Dec 2094 16:00:00 GMT'). A date in the past, 0, -1 or any other
    invalid date means 'already expired' (RFC 9111 section 5.3); Cache-Control takes precedence over it.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    cc = ",".join(resp.header_all("Cache-Control")).lower()
    directives = {d.strip().split("=")[0] for d in cc.split(",") if d.strip()}
    if "no-store" in directives:
        return False, "Cache-Control: no-store"
    if "private" in directives:
        return False, "Cache-Control: private (shared caches must not store it)"
    if "no-cache" in directives or "max-age=0" in cc.replace(" ", ""):
        return True, "Cache-Control: no-cache / max-age=0 allows storing (revalidated before reuse); use no-store"
    if "max-age" in directives or "s-maxage" in directives:
        return True, f"Cache-Control: {cc}"
    expires = resp.header("Expires")
    if expires is not None:
        when = http_date(expires)
        if when is None or when <= now:
            return False, f"Expires: {expires.strip()} (already expired)"
        return True, f"Expires: {expires.strip()} (in the future)"
    return True, "no Cache-Control or Expires (heuristic caching allowed)"


def run(ctx: TargetContext) -> None:
    resp = ctx.main()
    if ctx.https:
        _hsts(ctx, resp)
    if (resp.header("X-Content-Type-Options") or "").strip().lower() != "nosniff":
        ctx.add(RULES["nosniff-missing"], "Browsers may guess (sniff) the content type of responses.",
                f"X-Content-Type-Options: {resp.header('X-Content-Type-Options') or '(absent)'}")
    if resp.is_html:
        _framing(ctx, resp)
        _referrer(ctx, resp)
        if resp.header("Permissions-Policy") is None:
            ctx.add(RULES["permissions-policy-missing"],
                    "Powerful browser features (camera, geolocation, ...) are not restricted for this page.")
        xss = resp.header("X-XSS-Protection")
        if xss is not None and xss.strip()[:1] == "1":
            ctx.add(RULES["xss-protection-deprecated"],
                    "The XSS auditor it enables was removed from browsers and could itself be abused.",
                    f"X-XSS-Protection: {xss}")
    if resp.header_all("Set-Cookie"):
        storable, why = cacheable(resp)
        if storable:
            ctx.add(RULES["cacheable-with-cookies"],
                    f"The response sets cookies but caches may keep it: {why}. Use Cache-Control: no-store on "
                    "responses that carry session data.", why)


def _hsts(ctx: TargetContext, resp: Response) -> None:
    value = resp.header("Strict-Transport-Security")
    if value is None:
        ctx.add(RULES["hsts-missing"], "Without HSTS a first visit or a typed http:// link can be downgraded "
                "to plain HTTP by a network attacker.")
        return
    m = _MAX_AGE.search(value)
    if not m:
        ctx.add(RULES["hsts-invalid"], "max-age is missing or malformed, so browsers ignore the header.",
                f"Strict-Transport-Security: {value}")
        return
    age = int(m.group(1))
    if age == 0:
        ctx.add(RULES["hsts-disabled"], "max-age=0 tells browsers to forget HSTS for this host.",
                f"Strict-Transport-Security: {value}")
    elif age < 31_536_000:
        ctx.add(RULES["hsts-short"], f"max-age={age} s ({age // 86400} days); the cheat sheet recommends one year "
                "(31536000).", f"Strict-Transport-Security: {value}")
    if age and "includesubdomains" not in value.lower():
        ctx.add(RULES["hsts-no-subdomains"], "Subdomains can still be reached over plain HTTP and set cookies for "
                "this domain.", f"Strict-Transport-Security: {value}")


def _framing(ctx: TargetContext, resp: Response) -> None:
    fa = frame_ancestors(resp)
    xfo = (resp.header("X-Frame-Options") or "").strip().lower()
    if fa is not None or xfo in ("deny", "sameorigin"):
        return
    if xfo.startswith("allow-from"):
        ctx.add(RULES["xfo-allow-from"], "Use CSP frame-ancestors to allow specific framing sites.",
                f"X-Frame-Options: {resp.header('X-Frame-Options')}")
    ctx.add(RULES["clickjacking"], "Any site can embed this page in a frame and trick users into clicking it.",
            "no CSP frame-ancestors, X-Frame-Options: " + (resp.header("X-Frame-Options") or "(absent)"))


def _referrer(ctx: TargetContext, resp: Response) -> None:
    value = resp.header("Referrer-Policy")
    if value is None:
        ctx.add(RULES["referrer-missing"], "Browsers default to strict-origin-when-cross-origin, which is safe; "
                "setting it explicitly documents the intent.")
        return
    policy = effective_referrer_policy(value)
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        ctx.add(RULES["referrer-unsafe"], f"Effective policy '{policy}' sends the full URL, including paths and "
                "query strings, to other HTTPS sites.", f"Referrer-Policy: {value}")
