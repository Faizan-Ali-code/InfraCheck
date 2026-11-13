"""Settings: defaults, optionally a TOML file (infracheck.example.toml lists every key), then CLI options."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, fields

DEFAULT_CHECKS = ["transport", "headers", "csp", "cookies", "cors", "versions", "methods", "errors", "spoofing"]
OPT_IN_CHECKS = ["exposure"]  # a port check reaches beyond the web service: only when asked for
ALL_CHECKS = DEFAULT_CHECKS + OPT_IN_CHECKS
DEFAULT_SPOOF_IPS = ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1"]
# Services that should not be reachable from outside, with the severity of finding them open.
DEFAULT_EXPOSURE_PORTS = {
    21: "low", 22: "info", 23: "high", 445: "high", 1433: "medium", 1521: "medium", 2375: "high", 3306: "medium",
    3389: "medium", 5432: "medium", 5900: "medium", 6379: "high", 9200: "high", 11211: "high", 27017: "high",
}
REPORT_FORMATS = ("csv", "json", "xlsx")

_SECTIONS = {
    "scan": {"checks": "checks", "timeout": "timeout", "concurrency": "concurrency", "proxy": "proxy",
             "ca_file": "ca_file", "offline": "offline"},
    "methods": {"allow_write_probes": "allow_write_probes"},
    "errors": {"expected_marker": "expected_error_marker"},
    "spoofing": {"client_ips": "spoof_ips"},
    "exposure": {"ports": "exposure_ports"},
    "report": {"formats": "formats", "output_dir": "output_dir", "save_evidence": "save_evidence"},
}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    checks: list[str] = field(default_factory=lambda: list(DEFAULT_CHECKS))
    timeout: float = 10.0
    concurrency: int = 8
    proxy: str = ""
    ca_file: str = ""
    offline: bool = False  # no end-of-life lookups (endoflife.date)
    allow_write_probes: bool = False
    expected_error_marker: str = ""
    spoof_ips: list[str] = field(default_factory=lambda: list(DEFAULT_SPOOF_IPS))
    exposure_ports: list[int] = field(default_factory=lambda: sorted(DEFAULT_EXPOSURE_PORTS))
    formats: list[str] = field(default_factory=lambda: ["csv", "json", "xlsx"])
    output_dir: str = ""
    save_evidence: bool = True

    def validate(self) -> Config:
        unknown = [c for c in self.checks if c not in ALL_CHECKS]
        if unknown:
            raise ConfigError(f"unknown check(s): {', '.join(unknown)} (available: {', '.join(ALL_CHECKS)})")
        bad = [f for f in self.formats if f not in REPORT_FORMATS]
        if bad:
            raise ConfigError(f"unknown report format(s): {', '.join(bad)}")
        if self.timeout <= 0 or self.concurrency < 1:
            raise ConfigError("timeout must be positive and concurrency at least 1")
        for ip in self.spoof_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ConfigError(f"spoofing client_ips: '{ip}' is not an IP address") from exc
        if any(not 0 < p < 65536 for p in self.exposure_ports):
            raise ConfigError("exposure ports must be between 1 and 65535")
        if self.proxy and ":" not in self.proxy:
            raise ConfigError("proxy must be host:port")
        return self


def load_config(path: str | None) -> Config:
    cfg = Config()
    if not path:
        return cfg
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    types = {f.name: f.type for f in fields(Config)}
    checks = {"str": lambda v: isinstance(v, str), "bool": lambda v: isinstance(v, bool),
              "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
              "float": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
              "list[str]": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
              "list[int]": lambda v: isinstance(v, list) and all(isinstance(x, int) for x in v)}
    for section, values in data.items():
        if section not in _SECTIONS or not isinstance(values, dict):
            raise ConfigError(f"{path}: unknown section [{section}]")
        for key, value in values.items():
            attr = _SECTIONS[section].get(key)
            if attr is None:
                raise ConfigError(f"{path}: unknown key '{key}' in [{section}]")
            if not checks[types[attr]](value):
                raise ConfigError(f"{path}: [{section}] {key} must be of type {types[attr]}")
            setattr(cfg, attr, float(value) if types[attr] == "float" else value)
    return cfg.validate()


def load_ip_list(path: str) -> list[str]:
    """IP addresses from a file, one per line, '#' comments allowed."""
    out = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            text = line.split("#", 1)[0].strip()
            if text:
                try:
                    out.append(str(ipaddress.ip_address(text)))
                except ValueError as exc:
                    raise ConfigError(f"{path}: '{text}' is not an IP address") from exc
    return list(dict.fromkeys(out))
