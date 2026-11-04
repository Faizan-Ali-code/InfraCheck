"""OpenAI version lookup for banner assessment (Java ``n.b`` / ``o``), with a process-wide memory cache and an
append-only disk cache.

Deviations from Java: the ``OPENAI_API_KEY`` environment variable overrides the key in openai-config.txt, and the
disk cache is actually loaded (the Java loader split lines on the wrong regex and never loaded anything).
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from ... import config
from ...javacompat.java_utf8 import java_utf8_decode
from ...javacompat.strings import is_blank, java_trim
from ...log import log

API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TTL_DAYS = 30
API_KEY_ENV = "OPENAI_API_KEY"
_TIMEOUT_SECONDS = 15
_SYSTEM_PROMPT = "You are a security version classifier. Reply strictly as JSON only."
_CONTENT = re.compile(r'"content"\s*:\s*"((?:\\.|[^\\"])*)"', re.S)
_LONG = re.compile(r"[+-]?[0-9]+")


@dataclass(frozen=True)
class Assessment:
    """Java ``o``: a successful answer (``ok``) or a failure whose ``reason`` explains why."""

    ok: bool
    vulnerable: bool
    latest: str
    reason: str | None
    timestamp_ms: int


@dataclass(frozen=True)
class OpenAIConfig:
    api_key: str
    model: str
    ttl_days: int


def _failure(reason: str | None) -> Assessment:
    return Assessment(False, False, "", reason, _now_ms())


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _parse_ttl(raw: str | None) -> int:
    if is_blank(raw):
        return DEFAULT_TTL_DAYS
    try:
        value = int(java_trim(raw))
    except ValueError:
        log.warning(f"Invalid cache TTL value -> '{raw}'; falling back to default {DEFAULT_TTL_DAYS} days")
        return DEFAULT_TTL_DAYS
    return DEFAULT_TTL_DAYS if value < 0 else value


def load_config(path: str | None = None) -> OpenAIConfig:
    """Read openai-config.txt (``key=value`` lines; a bare line is the API key) and apply the env override."""
    values = {"model": DEFAULT_MODEL}
    try:
        with open(path or config.OPENAI_CONFIG_FILE, encoding="utf-8", errors="strict") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []
    except (OSError, UnicodeDecodeError) as exc:
        log.warning(f"Failed to read OpenAI config file -> {path or config.OPENAI_CONFIG_FILE} : {exc}")
        lines = []
    for line in lines:
        line = java_trim(line)
        if not line or line.startswith("#"):
            continue
        equals = line.find("=")
        if equals <= 0:
            values.setdefault("api_key", line)
            continue
        key, value = java_trim(line[:equals]).lower(), java_trim(line[equals + 1:])
        if not value:
            continue
        if key in ("api_key", "apikey", "key"):
            values["api_key"] = value
        elif key in ("model", "openai_model"):
            values["model"] = value
        elif key in ("cache_ttl_days", "openai_cache_ttl_days"):
            values["cache_ttl_days"] = value
    env_key = os.environ.get(API_KEY_ENV)
    api_key = java_trim(env_key) if not is_blank(env_key) else values.get("api_key", "")
    return OpenAIConfig(api_key, values["model"], _parse_ttl(values.get("cache_ttl_days")))


_memory: dict[str, Assessment] = {}
_lock = threading.Lock()
_disk_loaded = False


def _expired(timestamp_ms: int, ttl_days: int) -> bool:
    return ttl_days != 0 and _now_ms() - timestamp_ms > ttl_days * 24 * 60 * 60 * 1000


def _b64_decode(text: str) -> str:
    try:
        return java_utf8_decode(base64.b64decode(text, validate=True))
    except (binascii.Error, ValueError):
        return ""


def _b64_encode(text: str | None) -> str:
    return base64.b64encode((text or "").encode("utf-8")).decode("ascii")


def ensure_disk_cache_loaded(ttl_days: int) -> None:
    """Load ``key|epochMillis|ok|vulnerable|b64(latest)|b64(reason)`` lines once per process."""
    global _disk_loaded
    with _lock:
        if _disk_loaded:
            return
        _disk_loaded = True
        try:
            if not os.path.exists(config.OPENAI_CACHE_FILE):
                return
            with open(config.OPENAI_CACHE_FILE, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            for line in lines:
                if is_blank(line) or line.startswith("#"):
                    continue
                parts = line.split("|", 5)
                if len(parts) < 5:
                    continue
                timestamp, offset = _now_ms(), 0
                if len(parts) >= 6 and _LONG.fullmatch(parts[1]):
                    timestamp, offset = int(parts[1]), 1
                if _expired(timestamp, ttl_days):
                    continue
                _memory[parts[0]] = Assessment(parts[1 + offset] == "1", parts[2 + offset] == "1",
                                               _b64_decode(parts[3 + offset]), _b64_decode(parts[4 + offset]),
                                               timestamp)
        except (OSError, UnicodeDecodeError) as exc:
            log.info(f"Unable to load OpenAI cache file: {exc}")


def _persist(key: str, assessment: Assessment) -> None:
    line = (f"{key}|{assessment.timestamp_ms}|{'1' if assessment.ok else '0'}|{'1' if assessment.vulnerable else '0'}"
            f"|{_b64_encode(assessment.latest)}|{_b64_encode(assessment.reason)}{os.linesep}")
    try:
        directory = os.path.dirname(config.OPENAI_CACHE_FILE)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(config.OPENAI_CACHE_FILE, "ab") as handle:
            handle.write(line.encode("utf-8"))
    except OSError as exc:
        log.info(f"Unable to persist OpenAI cache entry: {exc}")


def _remember(key: str, assessment: Assessment, persist: bool) -> Assessment:
    """``putIfAbsent``: the first stored answer wins; only a newly stored success is written to disk."""
    with _lock:
        existing = _memory.setdefault(key, assessment)
        if existing is assessment and persist:
            _persist(key, assessment)
    return existing


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _unescape(text: str) -> str:
    return (text.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t").replace('\\"', '"')
            .replace("\\/", "/").replace("\\\\", "\\"))


def _truncate(text: str | None, limit: int) -> str:
    if text is None:
        return ""
    return text[:limit] + "..." if len(text) > limit else text


def _one_line(text: str) -> str:
    return text.replace("\r", " ").replace("\n", " ")


def request_body(technology: str, version: str, model: str) -> str:
    """The hand-built JSON request (byte-compatible with the Java string concatenation)."""
    user = (f"Assess whether technology '{technology}' version '{version}' is vulnerable. Return strict JSON with "
            "keys: status, latest_secure_version, reason. status must be either VULNERABLE or NOT_VULNERABLE.")
    return ('{"model":"' + _escape(model) + '","temperature":0,"response_format":{"type":"json_object"},'
            '"messages":[{"role":"system","content":"' + _escape(_SYSTEM_PROMPT) + '"},'
            '{"role":"user","content":"' + _escape(user) + '"}]}')


def _string_field(text: str, name: str) -> str:
    match = re.search('"' + re.escape(name) + r'"\s*:\s*"((?:\\.|[^\\"])*)"', text, re.S)
    return java_trim(_unescape(match.group(1))) if match else ""


def _first_present(*values: str) -> str:
    return next((value for value in values if not is_blank(value)), "")


def _normalized_status(status: str) -> str:
    lowered = status.lower().replace("-", "_").replace(" ", "_")
    if lowered in ("vulnerable", "true", "yes"):
        return "VULNERABLE"
    if lowered in ("not_vulnerable", "safe", "false", "no"):
        return "NOT_VULNERABLE"
    return java_trim(status).upper()


def parse_answer(content: str) -> Assessment:
    """Parse the assistant message (string-valued JSON fields only, matched by regex like Java)."""
    if is_blank(content):
        return _failure("Empty response content.")
    text = java_trim(content)
    if text.startswith("```"):
        text = java_trim(text.replace("```json", "").replace("```", ""))
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        text = text[start:end + 1]
    status = _first_present(_string_field(text, "status"), _string_field(text, "result"),
                            _string_field(text, "vulnerability_status"))
    latest = _first_present(_string_field(text, "latest_secure_version"), _string_field(text, "latestSecureVersion"),
                            _string_field(text, "secure_version"), _string_field(text, "latest_version"))
    reason = _first_present(_string_field(text, "reason"), _string_field(text, "details"),
                            _string_field(text, "explanation"))
    if is_blank(status) or is_blank(latest):
        return _failure("Response does not contain required fields: status/latest_secure_version.")
    normalized = _normalized_status(status)
    if normalized not in ("VULNERABLE", "NOT_VULNERABLE"):
        return _failure("Response status is invalid: " + status)
    return Assessment(True, normalized == "VULNERABLE", latest, reason or "No reason provided.", _now_ms())


def _assistant_content(raw: str) -> str:
    matches = _CONTENT.findall(raw) if not is_blank(raw) else []
    return _unescape(matches[-1]) if matches else ""


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post(body: str, api_key: str) -> tuple[int, str]:
    request = urllib.request.Request(API_URL, data=body.encode("utf-8"), method="POST", headers={
        "Authorization": "Bearer " + api_key, "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with _opener.open(request, timeout=_TIMEOUT_SECONDS) as response:
            return response.status, java_utf8_decode(response.read())
    except urllib.error.HTTPError as error:
        return error.code, java_utf8_decode(error.read())


def lookup(technology: str, version: str, settings: OpenAIConfig) -> Assessment:
    """Assessment of ``technology@version`` from the cache or the OpenAI API; failures are cached too."""
    ensure_disk_cache_loaded(settings.ttl_days)
    key = technology.lower() + "@" + version
    with _lock:
        cached = _memory.get(key)
        if cached is not None:
            if not _expired(cached.timestamp_ms, settings.ttl_days):
                return cached
            if _memory.get(key) is cached:
                del _memory[key]
    if is_blank(settings.api_key):
        return _remember(key, _failure("OpenAI API key file is missing or empty."), persist=False)
    try:
        status, raw = _post(request_body(technology, version, settings.model), settings.api_key)
    except Exception as exc:
        return _remember(key, _failure(str(exc) or None), persist=False)
    if status != 200:
        return _remember(key, _failure(f"OpenAI HTTP status: {status} body: {_truncate(raw, 200)}"), persist=False)
    content = _assistant_content(raw)
    assessment = parse_answer(content)
    if not assessment.ok:
        log.info(f"OpenAI parse failure for tech='{technology}' version='{version}' reason='{assessment.reason}' "
                 f"assistant='{_truncate(_one_line(content), 400)}' raw='{_truncate(_one_line(raw), 400)}'")
    return _remember(key, assessment, persist=assessment.ok)

