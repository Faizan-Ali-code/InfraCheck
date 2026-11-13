"""Exposed services: TCP ports on the target host that should not be reachable from where the scan runs.

Opt-in (--checks exposure), because it goes beyond the web service. It only opens and closes a TCP
connection per port; no data is sent. Run it from outside the network to see what the internet sees.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from infracheck.config import DEFAULT_EXPOSURE_PORTS
from infracheck.context import TargetContext
from infracheck.http import tcp_open
from infracheck.model import Rule

REF = "CIS Controls v8 4.4 / 12.2; OWASP WSTG-CONF-01; NIST SP 800-41"
SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 1521: "Oracle DB", 2375: "Docker API",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
            11211: "Memcached", 27017: "MongoDB"}
RULES = {sev: Rule(f"exposed-service-{sev}", "exposure", sev, f"Service port reachable ({sev} risk)", REF)
         for sev in ("high", "medium", "low", "info")}


def run(ctx: TargetContext) -> None:
    host = urlsplit(ctx.url).hostname or ""
    ports = ctx.cfg.exposure_ports
    with ThreadPoolExecutor(max_workers=min(16, len(ports) or 1)) as pool:
        states = dict(zip(ports, pool.map(lambda p: tcp_open(host, p, min(3.0, ctx.client.timeout)), ports)))
    for port in ports:
        if states[port]:
            severity = DEFAULT_EXPOSURE_PORTS.get(port, "medium")
            name = SERVICES.get(port, "unknown service")
            ctx.add(RULES[severity], f"{host}:{port} ({name}) accepts connections. Restrict it to the networks that "
                    "need it, or close it.", f"tcp/{port} open")
