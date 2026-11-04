"""Application version check (Java package ``b``): fetch the version JSON and compare it with this build.

The source URL comes from ``input data/update-config.txt`` (``version_url=``). A GitHub ``.../blob/<ref>/<path>``
page URL is turned into a contents-API URL like the Java tool did; any other URL is fetched as-is. A bearer token
is sent only when ``INFRACHECKER_UPDATE_TOKEN`` is set; no credential is embedded.
"""
from __future__ import annotations

import enum
import json
import os
from dataclasses import dataclass
from itertools import zip_longest

import requests

from . import VERSION, config
from .javacompat.strings import java_trim
from .log import log

URL_KEY = "version_url"
TOKEN_ENV = "INFRACHECKER_UPDATE_TOKEN"
TIMEOUT_SECONDS = 10
NOT_CONFIGURED = "Version check is not configured. Set version_url in input data/update-config.txt."

_GITHUB_PREFIX = "https://github.com/"
_REQUEST_HEADERS = {"Accept": "application/vnd.github.raw+json", "X-GitHub-Api-Version": "2022-11-28",
                    "Cache-Control": "no-cache", "User-Agent": "InfraChecker-VersionCheck"}
_INT_MAX = 2**31 - 1


class UpdateStatus(enum.Enum):
    UPDATE_AVAILABLE = "update available"
    UP_TO_DATE = "up to date"
    FAILED = "failed"


@dataclass(frozen=True)
class VersionInfo:
    """Content of the version file (Java ``b.d``)."""

    application: str = ""
    latest_version: str = ""
    release_date: str = ""
    release_notes: tuple[str, ...] = ()
    download_url: str = ""
    mandatory: bool = False


@dataclass(frozen=True)
class UpdateCheckResult:
    """Outcome of a check (Java ``b.c``): ``info`` is set unless it failed, ``message`` only when it failed."""

    status: UpdateStatus
    current_version: str
    info: VersionInfo | None = None
    message: str | None = None


class VersionCheckError(Exception):
    pass


def read_version_url(path: str = config.UPDATE_CONFIG_FILE) -> str:
    """``version_url`` from the update config (``key=value`` lines, ``#`` comments); empty when not set."""
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            entry = line.strip()
            if not entry or entry.startswith("#") or "=" not in entry:
                continue
            key, value = entry.split("=", 1)
            if key.strip().lower() == URL_KEY:
                return value.strip()
    return ""


def check_for_update(current_version: str = VERSION, config_path: str = config.UPDATE_CONFIG_FILE
                     ) -> UpdateCheckResult:
    """Fetch the version file and compare it with ``current_version`` (Java ``b.a.b``). Never raises."""
    try:
        source = read_version_url(config_path)
    except OSError as exc:
        log.warning(f"Unable to read {config_path}: {exc}")
        source = ""
    if not source:
        return UpdateCheckResult(UpdateStatus.FAILED, current_version, message=NOT_CONFIGURED)
    try:
        info = fetch_version_info(source)
    except Exception as exc:
        log.warning(f"Unable to complete version check: {exc}", exc_info=True)
        return UpdateCheckResult(UpdateStatus.FAILED, current_version,
                                 message=f"Unable to read version information from GitHub: {source}. {exc}")
    newer = compare_versions(current_version, info.latest_version) < 0
    return UpdateCheckResult(UpdateStatus.UPDATE_AVAILABLE if newer else UpdateStatus.UP_TO_DATE,
                             current_version, info)


def resolve_url(url: str) -> str:
    """GitHub ``https://github.com/<owner>/<repo>/blob/<ref>/<path>`` -> contents API; other URLs unchanged."""
    if "api.github.com" in url or not url.startswith(_GITHUB_PREFIX):
        return url
    parts = url[len(_GITHUB_PREFIX):].split("/", 4)
    if len(parts) < 5 or parts[2] != "blob":
        raise VersionCheckError(f"Unrecognized GitHub URL format (expected .../blob/<ref>/<path>): {url}")
    owner, repo, _, ref, path = parts
    return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"


def fetch_version_info(url: str) -> VersionInfo:
    target = resolve_url(url)
    headers = dict(_REQUEST_HEADERS)
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(target, headers=headers, timeout=TIMEOUT_SECONDS, allow_redirects=False)
    if response.status_code != 200:
        log.warning(f"GitHub API non-200 response - Status: {response.status_code}, "
                    f"RateLimit-Remaining: {response.headers.get('X-RateLimit-Remaining', 'n/a')}, "
                    f"RateLimit-Reset: {response.headers.get('X-RateLimit-Reset', 'n/a')}, "
                    f"Retry-After: {response.headers.get('Retry-After', 'n/a')}")
        raise VersionCheckError(f"GitHub API fetch failed with HTTP status {response.status_code} for {target}")
    body = response.content.decode("utf-8", errors="replace")
    if not body.strip():
        raise VersionCheckError(f"GitHub source returned an empty response for {target}")
    return parse_version_info(body)


def parse_version_info(text: str) -> VersionInfo:
    """Parse the version JSON: ``application``, ``latestVersion`` (required), ``releaseDate``, ``downloadUrl``,
    ``mandatoryUpdate`` (only JSON ``true`` counts) and ``releaseNotes`` (array)."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise VersionCheckError(str(exc)) from exc
    if not isinstance(data, dict):
        raise VersionCheckError("Version file does not contain a valid JSON object.")
    latest = _text(data.get("latestVersion"))
    if not latest:
        raise VersionCheckError("latestVersion is missing in version file.")
    notes = data.get("releaseNotes")
    return VersionInfo(
        application=_text(data.get("application")),
        latest_version=latest,
        release_date=_text(data.get("releaseDate")),
        release_notes=tuple(note for note in map(_text, notes) if note) if isinstance(notes, list) else (),
        download_url=_text(data.get("downloadUrl")),
        mandatory=data.get("mandatoryUpdate") is True,
    )


def compare_versions(current: str, latest: str) -> int:
    """-1/0/1 comparing dot-separated parts by their leading digits; missing or non-numeric parts count as 0."""
    for mine, theirs in zip_longest(java_trim(current).split("."), java_trim(latest).split("."), fillvalue=""):
        left, right = _version_part(mine), _version_part(theirs)
        if left != right:
            return -1 if left < right else 1
    return 0


def _version_part(text: str) -> int:
    digits = ""
    for char in java_trim(text):
        if not char.isdecimal():
            break
        digits += char
    value = int(digits) if digits else 0
    return value if value <= _INT_MAX else 0


def _text(value: object) -> str:
    """Java ``String.valueOf(value).trim()`` for a json-simple value; ``None`` -> empty."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return java_trim(str(value))
