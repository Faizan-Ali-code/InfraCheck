"""HTTP method analysis (option 3, Java ``R``).

Faithful to Java: only the seven verbs ``HttpsURLConnection`` accepts are actively probed; the others are judged on
the OPTIONS evidence alone (status ``-1``). Redirects are not followed; a proxy switches TLS to trust-all.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import config
from ..javacompat.strings import is_blank, java_trim
from ..log import log
from ..net import jdk
from ..net.errors import JavaClassCastError, JavaIOError
from ..net.http import JavaUrl
from ..persistence import writer
from . import preview

ACTIVE_VERBS = ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE")
CHECKED_METHODS = ("HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                   "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH")
SAFE_METHODS = ("GET", "POST", "HEAD", "OPTIONS")
POLICY = ",".join(SAFE_METHODS)
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 15.0
_ADVERTISING_HEADERS = ("allow", "access-control-allow-methods")
_SKIPPED_NOTE = "Active probe skipped (JDK client does not directly support this verb); header evidence used."


@dataclass
class _Probe:
    """Java ``U``: one active probe."""

    attempted: bool = False
    status: int = -1
    exposed: bool = False
    waf: bool = False
    note: str = ""
    body: str = ""


def scan(url: str, out_path: str, proxy_host: str | None, proxy_port: int) -> None:
    """Write one row per checked method (15 rows) to ``out_path``. May raise (worker writes the failure row)."""
    proxy = None if is_blank(proxy_host) else (proxy_host, proxy_port)
    advertised = _advertised_methods(url, proxy)
    if is_blank(url):
        return
    for method in CHECKED_METHODS:
        marker = config.USER_AGENT if method == "TRACE" else "delete" if method == "DELETE" else None
        _check(url, out_path, method, marker, advertised, proxy)


def _check(url: str, out_path: str, method: str, marker: str | None, advertised: list[str],
           proxy: tuple[str, int] | None) -> None:
    probe = _probe(url, method, marker, proxy)
    is_advertised = method in advertised
    exposed = is_advertised or probe.exposed
    vulnerable = _vulnerable(method, exposed, advertised)
    details = _details(method, advertised, is_advertised, probe, exposed, vulnerable)
    body_preview = preview.response_preview(probe.body, preview.preview_line_count())
    writer.append_row(out_path, "\t".join((url, method, str(probe.status), "Yes" if probe.waf else "No",
                                           "Vulnerable" if vulnerable else "Not Vulnerable", details, body_preview)))


def _vulnerable(method: str, exposed: bool, advertised: list[str]) -> bool:
    if not exposed or method == "HEAD":
        return False
    if method == "OPTIONS":
        return any(item not in SAFE_METHODS for item in advertised)
    return True


def _probe(url: str, method: str, marker: str | None, proxy: tuple[str, int] | None) -> _Probe:
    probe = _Probe()
    if method not in ACTIVE_VERBS:
        probe.note = _SKIPPED_NOTE
        return probe
    try:
        target = jdk.https_url(url)
        probe.attempted = True
        response = _send(target, method, proxy)
        probe.status = response.status
        probe.body = response.any_text()
        probe.waf = config.WAF_BLOCK_PAGE_1 in probe.body
        echoed = 200 <= probe.status < 500 and marker is not None and marker.lower() in probe.body.lower()
        probe.exposed = echoed or 200 <= probe.status < 300
    except (JavaIOError, JavaClassCastError) as exc:
        probe.note = "Active probe error: " + exc.simple_name
    return probe


def _send(target: JavaUrl, method: str, proxy: tuple[str, int] | None) -> jdk.JdkResponse:
    return jdk.request(target, method, [("User-Agent", config.USER_AGENT)], connect_timeout=CONNECT_TIMEOUT,
                       read_timeout=READ_TIMEOUT, follow_redirects=False, trust_all=proxy is not None, proxy=proxy)


def _advertised_methods(url: str, proxy: tuple[str, int] | None) -> list[str]:
    """Union of ``Allow`` and ``Access-Control-Allow-Methods`` from an OPTIONS request (insertion-ordered set)."""
    methods: dict[str, None] = {}
    try:
        response = _send(jdk.https_url(url), "OPTIONS", proxy)
    except JavaIOError as exc:
        log.debug(f"Unable to fetch advertised methods via OPTIONS: {'null' if exc.message is None else exc.message}")
        return []
    except JavaClassCastError as exc:
        log.debug(f"Unable to fetch advertised methods via OPTIONS: {exc}")
        return []
    for name, values in java_header_fields(response.headers):
        if name is not None and name.lower() in _ADVERTISING_HEADERS:
            for value in values:
                for item in value.split(","):
                    token = java_trim(item).upper()
                    if token:
                        methods.setdefault(token, None)
    return list(methods)


def java_header_fields(headers: list[tuple[str, str]]) -> list[tuple[str | None, list[str]]]:
    """``HttpURLConnection.getHeaderFields()`` iteration order: a ``HashMap`` keyed by header name as received
    (the status line under ``null``), values in arrival order."""
    fields: dict[str | None, list[str]] = {None: []}
    for name, value in headers:
        fields.setdefault(name, []).append(value)
    capacity = 16
    while len(fields) > capacity * 3 // 4:
        capacity *= 2
    return sorted(fields.items(), key=lambda item: _bucket(item[0], capacity))


def _bucket(key: str | None, capacity: int) -> int:
    if key is None:
        return 0
    h = 0
    for unit in memoryview(key.encode("utf-16-le")).cast("H"):
        h = (31 * h + unit) & 0xFFFFFFFF
    return (h ^ (h >> 16)) & (capacity - 1)


def _details(method: str, advertised: list[str], is_advertised: bool, probe: _Probe, exposed: bool,
             vulnerable: bool) -> str:
    parts = [f"Policy={POLICY}", "HeaderEvidence=" + ("Advertised" if is_advertised else "Not Advertised")]
    if advertised:
        parts.append(f"AdvertisedMethods=[{', '.join(advertised)}]")
    parts.append(f"ActiveProbeCode={probe.status if probe.attempted else 'NA'}")
    if probe.waf:
        parts.append("WAF=Detected")
    if probe.attempted and 300 <= probe.status < 400:
        parts.append("Redirect=Not Followed")
    parts.append("Exposure=" + ("Detected" if exposed else "Not Detected"))
    if exposed and not vulnerable:
        parts.append(f"Note=Method responds but is not treated as a vulnerability for {method}")
    if probe.note:
        parts.append(f"Note={probe.note}")
    return "; ".join(parts)
