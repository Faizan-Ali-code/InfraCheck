"""Paths, output names, column sets and per-analysis settings.

All paths are relative to the working directory, like the Java tool (run.bat starts the app from its own folder).
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from datetime import datetime

from . import VERSION

RESULTS_DIR = "./results/"
HTML_DIR = "./results/html/"
ACCESSIBLE_DIR = "./results/html/Accessible-HTMLs/"
NON_ACCESSIBLE_DIR = "./results/html/Non-Accessible-HTMLs/"
STANDARD_ERROR_DIR = "./results/html/Standard-Error-Pages-HTMLs/"
NON_STANDARD_ERROR_DIR = "./results/html/Non-Standard-Error-Pages-HTMLs/"
SSL_LAB_REPORTS_DIR = ".//results//SSL-Lab-Reports//"
CACHE_DIR = "./cache/"
LOGS_DIR = "logs"

INPUT_DIR = "./input data/"
URLS_FILE = "./input data/urls.txt"
IPS_FILE = "./input data/ips list-spoofing-errorpage-exposure.txt"
BANNER_BASELINES_FILE = "./input data/banner-version-baselines.txt"
OPENAI_CONFIG_FILE = "./input data/openai-config.txt"
OPENAI_CACHE_FILE = "./cache/openai-version-cache.txt"
IP_OWNERSHIP_FILE = "./input data/IP-Ownership.xls"
CSP_OWNERSHIP_FILE = "./input data/CSP-Ownership.xls"
IGNORED_DOMAINS_FILE = "./input data/ignored-domains.txt"
IGNORED_BANNER_FILE = "./input data/ignored-banner-grabbing.txt"
UPDATE_CONFIG_FILE = "./input data/update-config.txt"
ORGANIZATION_CONFIG_FILE = "./input data/organization-config.txt"

RESULT_SHEET = f"Result ver {VERSION}"
USER_AGENT = "Mozilla/5.0"

# WAF block pages recognised in responses (used by WAF and HTTP-method analysis).
WAF_BLOCK_PAGE_1 = ("Request Rejected</title></head><body>Your request can not be completed at this moment. "
                    "<br>Please consult with support team and provide support ID given below.<br> Thanks.<br><br>"
                    "Your support ID is:")
WAF_BLOCK_PAGE_2 = ("Request Rejected</title></head><body>The requested URL was rejected. "
                    "Please consult with your administrator.<br><br>Your support ID is:")

# Output column sets (Java class `aq`).
HEADER_COLUMNS = ["URL", "Host", "IP", "IP Type", "Ownership", "Header", "Value", "Status Code",
                  "Vulnerability Status", "Recommendation", "Severity", "Details", "Justification", "Response Body"]
HTTP_METHOD_COLUMNS = ["URL", "HTTP Method", "Status Code", "WAF Detected", "Vulnerability Status", "Details",
                       "Response Body"]
WAF_COLUMNS = ["URL", "Payload Category", "Payload", "HTTP Method", "Status Code", "WAF Status", "Details",
               "Response Body"]
IP_SPOOFING_COLUMNS = ["URL", "Spoofed IP", "Spoofed Header", "Status Code", "Vulnerability Status", "Details"]
ERROR_PAGE_COLUMNS = ["URL", "IP", "Status Code", "Vulnerability Status", "Details"]
EXPOSURE_COLUMNS = ["URL", "IP", "Status Code", "Vulnerability Status", "Details"]
HEADER_STATS_COLUMNS = ["Header Name", "Count", "Coverage % (Distinct Vulnerable Domains)", "Risk Signal"]
OWNERSHIP_STATS_COLUMNS = ["Ownership", "Count", "Coverage % (Distinct Vulnerable Domains)", "Concentration Signal"]
SSL_LABS_COLUMNS = [
    "Host", "Vulnerability Status", "Node IP", "Grade", "Vulnerable TLS Versions", "Weak Ciphers", "Comments",
    "Chain issues", "Subject", "Common names", "Alternative names", "Serial Number", "Valid from", "Valid until",
    "Key", "Weak key (Debian)", "Issuer", "Signature algorithm", "Extended Validation", "Certificate Transparency",
    "OCSP Must Staple", "Revocation information", "Revocation status", "DNS CAA", "Trusted", "DROWN",
    "Secure Renegotiation", "Secure Client-Initiated Renegotiation", "Insecure Client-Initiated Renegotiation",
    "BEAST attack", "POODLE (SSLv3)", "POODLE (TLS)", "Zombie POODLE", "GOLDENDOODLE", "OpenSSL 0-Length",
    "Sleeping POODLE", "Downgrade attack prevention", "SSL/TLS compression", "RC4", "Heartbeat (extension)",
    "Heartbleed (vulnerability)", "Ticketbleed (vulnerability)", "OpenSSL CCS vuln. (CVE-2014-0224)",
    "OpenSSL Padding Oracle vuln. (CVE-2016-2107)", "ROBOT (vulnerability)", "Forward Secrecy", "ALPN", "NPN",
    "Session resumption (caching)", "Session resumption (tickets)", "OCSP stapling",
    "Strict Transport Security (HSTS)", "HSTS Preloading", "Public Key Pinning (HPKP)",
    "Public Key Pinning Report-Only", "Public Key Pinning (Static)", "Long handshake intolerance",
    "TLS extension intolerance", "TLS version intolerance", "Incorrect SNI alerts", "Uses common DH primes",
    "DH public server param (Ys) reuse", "ECDH public server param reuse", "Supported Named Groups",
    "SSL 2 handshake compatibility", "PQC Key Exchange"]


class Analysis(enum.IntEnum):
    HEADERS = 1
    WAF = 2
    HTTP_METHODS = 3
    IP_SPOOFING = 4
    ERROR_PAGES = 5
    SSL_LABS = 6
    EXPOSURE = 7

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def pool_size(self) -> int:
        return {Analysis.HEADERS: 100, Analysis.SSL_LABS: 25, Analysis.EXPOSURE: 5}.get(self, 20)

    @property
    def uses_ip_list(self) -> bool:
        return self in (Analysis.IP_SPOOFING, Analysis.ERROR_PAGES, Analysis.EXPOSURE)


_LABELS = {
    Analysis.HEADERS: "Header Analysis",
    Analysis.WAF: "WAF Analysis",
    Analysis.HTTP_METHODS: "HTTP Method Analysis",
    Analysis.IP_SPOOFING: "IP Spoofing Analysis",
    Analysis.ERROR_PAGES: "Error Page Analysis",
    Analysis.SSL_LABS: "SSL Labs Analysis",
    Analysis.EXPOSURE: "Exposure Check",
}

# Child-thread pool per URL for the IP fan-out analyses (Java `ac.i` / `ac.j`).
CHILD_POOL_SIZE = 50


@dataclass(frozen=True)
class OutputPaths:
    waf_html: str
    waf: str
    headers: str
    http_methods: str
    ssl_labs: str
    exposure: str
    error_pages: str
    ip_spoofing: str

    def for_analysis(self, analysis: Analysis) -> str:
        return {
            Analysis.HEADERS: self.headers,
            Analysis.WAF: self.waf,
            Analysis.HTTP_METHODS: self.http_methods,
            Analysis.IP_SPOOFING: self.ip_spoofing,
            Analysis.ERROR_PAGES: self.error_pages,
            Analysis.SSL_LABS: self.ssl_labs,
            Analysis.EXPOSURE: self.exposure,
        }[analysis]

    def all_paths(self) -> list[str]:
        return [self.headers, self.waf, self.http_methods, self.ip_spoofing, self.error_pages, self.exposure,
                self.ssl_labs]


def run_timestamp(now: datetime | None = None) -> str:
    """Java SimpleDateFormat("dd-MM-yyyy-HHmmss-SSS")."""
    now = now or datetime.now()
    return now.strftime("%d-%m-%Y-%H%M%S-") + f"{now.microsecond // 1000:03d}"


def new_output_paths(now: datetime | None = None) -> OutputPaths:
    ts = run_timestamp(now)
    return OutputPaths(
        waf_html=f"./results/WAF-Status-{ts}.html",
        waf=f"./results/WAF-Status-{ts}.xlsx",
        headers=f"./results/Headers-Status-{ts}.xlsx",
        http_methods=f"./results/HTTP-Methods-Status-{ts}.xlsx",
        ssl_labs=f"./results/SSL-Lab-Status-{ts}.xlsx",
        exposure=f"./results/URL-Exposure-Status-{ts}.xlsx",
        error_pages=f"./results/Error-Pages-Status-{ts}.xlsx",
        ip_spoofing=f"./results/IP-Spoofing-Status-{ts}.xlsx",
    )


def columns_for(analysis: Analysis) -> list[str]:
    return {
        Analysis.HEADERS: HEADER_COLUMNS,
        Analysis.WAF: WAF_COLUMNS,
        Analysis.HTTP_METHODS: HTTP_METHOD_COLUMNS,
        Analysis.IP_SPOOFING: IP_SPOOFING_COLUMNS,
        Analysis.ERROR_PAGES: ERROR_PAGE_COLUMNS,
        Analysis.SSL_LABS: SSL_LABS_COLUMNS,
        Analysis.EXPOSURE: EXPOSURE_COLUMNS,
    }[analysis]


def sqlite_path_for(path: str) -> str:
    """Java `path.replaceAll("\\.[^.]+$", ".sqlite")`."""
    return re.sub(r"\.[^.]+$", ".sqlite", path)
