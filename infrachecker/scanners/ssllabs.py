"""SSL Labs analysis (option 6, Java ``au``/``at``).

Flow: ``info`` (wait while the assessment limit is reached) -> ``analyze?clearCache=on`` -> poll ``analyze`` every
5 s until READY/ERROR (HTTP 429/529: wait 5 min, up to 10 times) -> ``getEndpointData`` (grade, TLS versions, weak
ciphers) -> scrape ``analyze.html`` (saved under ``SSL-Lab-Reports``) for orange/red cells. Requests use
``HttpsURLConnection`` defaults: no timeouts, certificate validation, JDK User-Agent except for the HTML page.
"""
from __future__ import annotations

import json
import os
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime
from time import sleep

from .. import config
from ..javacompat.strings import java_trim
from ..log import log, thread_name
from ..net import jdk
from ..net.errors import JavaIOError
from ..net.http import JavaUrl
from ..persistence import writer

API_BASE = "https://api.ssllabs.com/api/v3/"
ANALYZE_PAGE = "https://www.ssllabs.com/ssltest/analyze.html"
POLL_SECONDS = 5
SETTLE_SECONDS = 2
THROTTLE_SECONDS = 300
MAX_THROTTLE_ATTEMPTS = 10
# Safety limits (Java has none, so one stuck host could block a worker forever).
REQUEST_TIMEOUT_SECONDS = 60
MAX_ANALYZE_POLLS = 720      # 1 hour at POLL_SECONDS
MAX_ENDPOINT_POLLS = 120     # 10 minutes at POLL_SECONDS
ORANGE = "<font color=#F88017>"
RED = "<font color=red>"
_LABEL = '<td class="tableLabel">{}</td>'
_CELL = '<td class="tableCell">'
_ENDPOINT_FAILURES = ("Unable to connect to the server", "No secure protocols supported",
                      "IP address is from private address space (RFC 1918)",
                      "Unexpected failure [RenegotiationTest]: Connection failed")
SCRAPED_LABELS = tuple(config.SSL_LABS_COLUMNS[7:])
# Labels that also count red cells; the value is what a red cell yields (orange always yields "Vulnerable").
_RED_ALSO = {"Chain issues": "Vulnerable", "Subject": "Vulnerable", "Common names": "Vulnerable",
             "Alternative names": "Certificate Mismatch", "Trusted": "Not Trusted", "POODLE (SSLv3)": "Vulnerable",
             "POODLE (TLS)": "Vulnerable", "RC4": "Vulnerable"}
# Labels judged on the exact cell text instead of the colour.
_EXACT_TEXT = {"PQC Key Exchange": "Not Supported"}


@dataclass
class _State:
    """Java ``at``: the per-host assessment record."""

    max_assessments: int = 0
    current_assessments: int = 0
    status: str | None = ""
    status_message: str | None = ""
    ip: str | None = ""
    grade: str | None = ""
    tls_versions: str = ""
    weak_ciphers: str = ""
    scraped: dict[str, str] = field(default_factory=lambda: dict.fromkeys(SCRAPED_LABELS, ""))

    def fail(self, message: str | None) -> None:
        self.status = "ERROR"
        self.status_message = _or_default(message, "Unknown SSL Labs failure")

    def vulnerable(self) -> bool:
        return bool(self.tls_versions or self.weak_ciphers or any(self.scraped.values()))

    def row(self, host: str, verdict: str, comments: str) -> str:
        return "\t".join([host, verdict, _s(self.ip), _s(self.grade), self.tls_versions, self.weak_ciphers,
                          comments, *self.scraped.values()])


def _s(value: str | None) -> str:
    return "" if value is None else value


def _or_default(value: str | None, default: str) -> str:
    return default if _s(value).strip() == "" else value


def _log(message: str) -> None:
    log.info(f"{thread_name()} {message}")


def service_available() -> bool:
    """``GET /api/v3/info`` (waits while the assessment limit is reached). Used for pacing between URLs."""
    return _info(_State())


def scan(url: str, out_path: str) -> None:
    """Assess one host and append one row (``aq.D`` columns) to ``out_path``."""
    host = _host(url)
    state = _State()
    written = False

    def fail_row(default: str) -> None:
        writer.append_row(out_path, state.row(host, "Not Vulnerable", "SSL Lab Error: " +
                                              _or_default(state.status_message, default)))

    try:
        if not _info(state):
            _log("SSL Lab is not working, method sslLabMain.getSSLLabInfo()")
            fail_row("SSL Labs info call failed")
            written = True
            return
        if not _assess(state, host):
            _log(f"SSL Labs could not perform analysis on host-> {host}, SSL Labs status message->"
                 f"{_null(state.status_message)}")
            fail_row("SSL Labs analysis failed")
            written = True
            return
        _endpoint_data(state, host)
        sleep(SETTLE_SECONDS)
        _scrape(state, host)
        verdict = "Vulnerable" if state.vulnerable() else "Not Vulnerable"
        comments = ("Successfully Executed" if _s(state.status).upper() == "READY"
                    else _or_default(state.status, "Completed With Warnings"))
        writer.append_row(out_path, state.row(host, verdict, comments))
        written = True
    except Exception as exc:
        state.fail(f"SSL Labs exception: {exc}")
        _log(f"Exception->{exc}")
        if not written:
            fail_row("SSL Labs exception")
            written = True
        raise
    finally:
        if not written:
            fail_row("SSL Labs execution ended without a result")


def _null(value: str | None) -> str:
    return "null" if value is None else value


def _host(url: str) -> str:
    if "://" in url:
        try:
            return JavaUrl.parse(url).host
        except JavaIOError:
            log.debug(f"Unable to extract host from url ->'{url}'; using the raw url instead")
    return url


def _get(url: str, user_agent: str | None = None) -> jdk.JdkResponse:
    headers = [] if user_agent is None else [("User-Agent", user_agent)]
    return jdk.request(jdk.https_url(url), "GET", headers, connect_timeout=REQUEST_TIMEOUT_SECONDS,
                       read_timeout=REQUEST_TIMEOUT_SECONDS)


def _info(state: _State) -> bool:
    try:
        response = _get(API_BASE + "info")
        if response.status != 200:
            state.fail(f"SSL Labs info API returned HTTP {response.status}")
            _log(f"SSL Lab is not working getSSLLabInfo(). Response Code->{response.status}")
            return False
        _read_limits(state, response)
        while state.current_assessments >= state.max_assessments:
            seconds = random.randint(10, 20)
            _log(f"Max assessments limit reached, sleeping {seconds}s")
            sleep(seconds)
            _refresh_limits(state)
        return True
    except Exception as exc:
        state.fail(f"SSL Labs info API exception: {exc}")
        _log(f"Exception->{exc}")
        return False


def _read_limits(state: _State, response: jdk.JdkResponse) -> None:
    info = json.loads(response.input_text())
    state.max_assessments = int(info["maxAssessments"])
    state.current_assessments = int(info["currentAssessments"])
    _log(f"SSL Labs Max Assessments limit-> {state.max_assessments} Current Assessments scheduled-> "
         f"{state.current_assessments}")


def _refresh_limits(state: _State) -> None:
    """Java re-enters ``a()`` recursively; a failed re-check leaves the limits unchanged and the wait continues."""
    try:
        response = _get(API_BASE + "info")
        if response.status != 200:
            state.fail(f"SSL Labs info API returned HTTP {response.status}")
            _log(f"SSL Lab is not working getSSLLabInfo(). Response Code->{response.status}")
            return
        _read_limits(state, response)
    except Exception as exc:
        state.fail(f"SSL Labs info API exception: {exc}")
        _log(f"Exception->{exc}")


def _analyze(state: _State, host: str, clear_cache: bool) -> str | None:
    """``GET analyze``; HTTP 429/529 wait 5 minutes and retry (10 attempts). ``None`` on failure."""
    attempts = 0
    try:
        while True:
            response = _get(f"{API_BASE}analyze?host={host}{'&clearCache=on' if clear_cache else ''}")
            if response.status == 200:
                return response.input_text()
            if response.status not in (429, 529) or attempts >= MAX_THROTTLE_ATTEMPTS:
                state.fail(f"SSL Labs analyze API returned HTTP {response.status} for host {host}")
                _log(f"SSL Lab not working. Response Code->{response.status}")
                return None
            attempts += 1
            _log(f"Received {response.status} from SSL Labs. Waiting 5 min. Attempt {attempts}/{MAX_THROTTLE_ATTEMPTS}")
            sleep(THROTTLE_SECONDS)
    except JavaIOError as exc:
        state.fail(f"SSL Labs analyze API exception for host {host}: {exc}")
        _log(f"Exception->{exc}")
        return None


def _assess(state: _State, host: str) -> bool:
    state.status_message = ""
    try:
        if _analyze(state, host, True) is None:
            _log("SSL Lab is not working as response is null")
            return False
        for _ in range(MAX_ANALYZE_POLLS):
            body = _analyze(state, host, False)
            if body is None:
                if _s(state.status_message) == "":
                    state.fail(f"SSL Labs analysis polling returned no response for host {host}")
                return False
            try:
                result = json.loads(body)
            except json.JSONDecodeError as exc:
                print(_parse_error_text(body, exc.pos), file=sys.stderr)
                state.fail(f"Unable to parse SSL Labs analysis response for host {host}")
                return False
            status = result.get("status")
            if status is None:
                state.fail(f"SSL Labs analysis response did not contain a status for host {host}")
                return False
            if status.upper() == "READY":
                state.status = status
                state.status_message = _last(result, "endpoints", "statusMessage")
            elif status.upper() == "ERROR":
                state.status = status
            else:
                _log(f"Waiting for SSL Labs analysis on url->{host}")
                sleep(POLL_SECONDS)
                continue
            if _ready(state):
                state.ip = _last(result, "endpoints", "ipAddress")
                return True
            if state.status.upper() == "ERROR":
                state.status_message = result.get("statusMessage")
            return False
        state.fail(f"SSL Labs analysis did not finish within {MAX_ANALYZE_POLLS * POLL_SECONDS // 60} minutes "
                   f"for host {host}")
        return False
    except Exception as exc:
        state.fail(f"SSL Labs analysis exception for host {host}: {exc}")
        _log(f"Exception->{exc}")
        return False


def _parse_error_text(body: str, position: int) -> str:
    """What json-simple's ``ParseException.printStackTrace()`` starts with."""
    if position < len(body):
        return f"Unexpected character ({body[position]}) at position {position}."
    return f"Unexpected token END OF FILE at position {position}."


def _ready(state: _State) -> bool:
    if _s(state.status).upper() != "READY":
        return False
    message = state.status_message.lower()
    return all(message != failure.lower() for failure in _ENDPOINT_FAILURES)


def _last(result: dict, array: str, key: str) -> str:
    """Last non-null ``key`` across ``result[array]``."""
    value = ""
    for item in result[array]:
        if item.get(key) is not None:
            value = item[key]
    return value


def _endpoint_data(state: _State, host: str) -> None:
    """Grade, TLS versions and weak ciphers. A status other than Ready / "Failed to communicate with the secure
    server" is polled every 5 s (Java re-checked the same response forever; here it re-fetches, with a limit)."""
    try:
        for _ in range(MAX_ENDPOINT_POLLS):
            response = _get(f"{API_BASE}getEndpointData?host={host}&s={_s(state.ip)}")
            if response.status != 200:
                _log("SSL Lab is not working.")
                return
            data = json.loads(response.input_text())
            message = data.get("statusMessage")
            _log(f"Got status from SSL Labs ->{_null(message)} URL->{host}")
            if message.lower() in ("ready", "failed to communicate with the secure server"):
                state.status = message
                if message.lower() == "ready":
                    state.grade = data.get("grade")
                    _protocols(state, data)
                    _weak_ciphers(state, data)
                else:
                    state.grade = state.tls_versions = state.weak_ciphers = ""
                return
            _log(f"Waiting & Getting data from SSL Labs for URL->{host}")
            sleep(POLL_SECONDS)
        _log(f"Gave up waiting for SSL Labs endpoint data for URL->{host}")
    except Exception as exc:
        _log(f"Exception->{exc}")


def _protocols(state: _State, data: dict) -> None:
    found: list[str] = []
    has_tls13 = False
    for protocol in data["details"]["protocols"]:
        version = protocol.get("version")
        if version in ("1.0", "1.1"):
            found.append(version)
        if version == "1.3":
            has_tls13 = True
    if not has_tls13:
        found.append("1.3 not enabled")
    state.tls_versions = ",".join(found)


def _weak_ciphers(state: _State, data: dict) -> None:
    """Cipher names whose entry has ``q=1`` (SSL Labs marks weak suites with ``"q": 1``)."""
    suites = data["details"].get("suites")
    names: list[str] = []
    try:
        for suite in suites:
            for cipher in suite.get("list") or []:
                weak = any(key == "q" and _java_text(value) == "1" for key, value in cipher.items())
                if weak and cipher.get("name") is not None:
                    names.append(cipher["name"])
    except Exception as exc:
        _log(f"Exception->{exc}")
    state.weak_ciphers = ",".join(names)


def _java_text(value: object) -> str:
    """``String.valueOf`` for a json-simple value (``Long``/``Double``/``Boolean``/``String``)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(value)
    return str(value)


def _scrape(state: _State, host: str) -> None:
    response = jdk.request(jdk.https_url(f"{ANALYZE_PAGE}?d={host}&s={_s(state.ip)}&hideResults=on"), "GET",
                           [("User-Agent", config.USER_AGENT)])
    sleep(SETTLE_SECONDS)
    if response.status != 200:
        _log(f"SSL Lab is not working to generate HTML, Response Code->{response.status}")
        return
    page = response.input_text()
    _log(f"Going to write in html file for URL->{host}")
    save_report(host, page)
    state.scraped = scrape(page)


def save_report(host: str, page: str) -> str:
    """``./results/SSL-Lab-Reports/<host> [dd-MM-yyyy HH-mm-ss].html`` (overwritten)."""
    try:
        os.mkdir(config.SSL_LAB_REPORTS_DIR)
    except OSError:
        pass
    path = f"{config.SSL_LAB_REPORTS_DIR}{host} [{datetime.now().strftime('%d-%m-%Y %H-%M-%S')}].html"
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(page)
    return path


def scrape(page: str) -> dict[str, str]:
    """Label -> ``Vulnerable`` (or the label's alternative text) for every flagged cell of the report page."""
    page = page.replace('"#F88017"', "#F88017")
    result = {}
    for label in SCRAPED_LABELS:
        if label in _EXACT_TEXT:
            result[label] = "Vulnerable" if _cell_text(page, label).lower() == _EXACT_TEXT[label].lower() else ""
        elif _cell_starts_with(page, label, ORANGE):
            result[label] = "Vulnerable"
        elif label in _RED_ALSO and _cell_starts_with(page, label, RED):
            result[label] = _RED_ALSO[label]
        else:
            result[label] = ""
    return result


def _cell(page: str, label: str) -> str | None:
    """Text after ``<td class="tableLabel">LABEL</td>`` and the following ``<td class="tableCell">``."""
    marker = _LABEL.format(label)
    start = page.find(marker)
    if start == -1:
        return None
    rest = _strip_leading(page[start + len(marker):])
    return rest[len(_CELL):] if rest.startswith(_CELL) else None


def _cell_starts_with(page: str, label: str, prefix: str) -> bool:
    cell = _cell(page, label)
    return cell is not None and _strip_leading(cell).startswith(prefix)


def _cell_text(page: str, label: str) -> str:
    cell = _cell(page, label)
    if cell is None or "</td>" not in cell:
        return ""
    return java_trim(cell[:cell.find("</td>")])


def _strip_leading(text: str) -> str:
    """``String.stripLeading()`` (``Character.isWhitespace``: no-break spaces and U+0085 are not whitespace)."""
    index = 0
    while index < len(text) and text[index].isspace() and text[index] not in "   \u0085":
        index += 1
    return text[index:]
