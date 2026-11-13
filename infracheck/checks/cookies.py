"""Set-Cookie attributes, parsed attribute by attribute (RFC 6265 and its RFC 6265bis update).

A cookie *named* secure_id is not a Secure cookie: names, values and attributes are separated before any
attribute is tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from infracheck.context import TargetContext
from infracheck.model import Rule

REF = "RFC 6265bis; OWASP Session Management Cheat Sheet; OWASP ASVS 4.0.3 V3.4"

RULES = {r.id: r for r in (
    Rule("cookie-no-secure", "cookies", "medium", "Cookie sent over HTTPS without the Secure attribute", REF),
    Rule("cookie-no-httponly", "cookies", "medium", "Session cookie readable by JavaScript (no HttpOnly)", REF),
    Rule("cookie-samesite-none-insecure", "cookies", "medium", "SameSite=None without Secure (browsers reject it)", REF),
    Rule("cookie-no-samesite", "cookies", "info", "Cookie without an explicit SameSite attribute", REF),
    Rule("cookie-prefix-violation", "cookies", "medium", "__Host- / __Secure- cookie breaks its prefix rules", REF),
)}

_SESSION_NAME = re.compile(r"sess|sid|auth|token|jwt|login|remember|identity|\.aspxauth|connect\.sid", re.IGNORECASE)


@dataclass
class Cookie:
    name: str
    value: str
    attributes: dict[str, str] = field(default_factory=dict)  # lower-case attribute name -> value ('' if none)

    def has(self, attribute: str) -> bool:
        return attribute in self.attributes

    @property
    def session_like(self) -> bool:
        persistent = self.has("expires") or self.has("max-age")
        return bool(_SESSION_NAME.search(self.name)) or (not persistent and len(self.value) >= 16)


def parse_set_cookie(header: str) -> Cookie:
    pair, *attrs = header.split(";")
    name, sep, value = pair.partition("=")
    if not sep:  # a nameless cookie: the whole pair is the value
        name, value = "", name
    attributes = {}
    for attr in attrs:
        key, _, val = attr.partition("=")
        if key.strip():
            attributes.setdefault(key.strip().lower(), val.strip())
    return Cookie(name.strip(), value.strip(), attributes)


def run(ctx: TargetContext) -> None:
    seen: set[str] = set()
    for resp in ctx.chain():
        https = resp.url.lower().startswith("https://")
        for header in resp.header_all("Set-Cookie"):
            c = parse_set_cookie(header)
            if c.name in seen:
                continue
            seen.add(c.name)
            shown = f"Set-Cookie: {c.name}=...; " + "; ".join(k if not v else f"{k}={v}" for k, v in c.attributes.items())
            samesite = c.attributes.get("samesite", "").lower()
            if https and not c.has("secure"):
                ctx.add(RULES["cookie-no-secure"], f"Cookie '{c.name}' would also be sent over plain HTTP and can be "
                        "captured by a network attacker.", shown)
            if c.session_like and not c.has("httponly"):
                ctx.add(RULES["cookie-no-httponly"], f"Cookie '{c.name}' looks like a session or auth cookie and "
                        "can be stolen by injected scripts.", shown)
            if samesite == "none" and not c.has("secure"):
                ctx.add(RULES["cookie-samesite-none-insecure"], f"Cookie '{c.name}' is rejected by current browsers.",
                        shown)
            elif not c.has("samesite"):
                ctx.add(RULES["cookie-no-samesite"], f"Cookie '{c.name}' relies on the browser default (Lax in most "
                        "browsers); set SameSite explicitly.", shown)
            if c.name.startswith("__Host-") and (not c.has("secure") or c.has("domain")
                                                 or c.attributes.get("path") != "/"):
                ctx.add(RULES["cookie-prefix-violation"], f"'{c.name}' needs Secure, Path=/ and no Domain; browsers "
                        "reject it otherwise.", shown)
            elif c.name.startswith("__Secure-") and not c.has("secure"):
                ctx.add(RULES["cookie-prefix-violation"], f"'{c.name}' needs the Secure attribute.", shown)
