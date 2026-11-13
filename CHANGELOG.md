# Changelog

## 2.0.0 (2026-11-13)

A new implementation that replaces version 1.x completely. The input files, the Excel layout and the
desktop GUI of 1.x are gone.

- **Command line and dependencies.** A command-line tool on the Python standard library with a TOML settings
  file, CI exit codes and CSV/JSON/Excel reports with evidence files. No Qt, no emulation layer, no
  organisation-specific settings.
- **Spoofing.** Each request is compared with a baseline without the header, using its own list of
  addresses to claim.
- **Headers.** Every rule cites a standard. `Expires` is parsed as an HTTP date, HSTS `preload` is not
  required, caching is only checked on responses that set cookies, Referrer-Policy fallback lists are
  read as browsers read them, and hardening-only headers are *info*.
- **CSP and cookies.** CSP rules follow CSP Level 3 and strict-CSP guidance, written for this tool (the
  csp-evaluator port and its copied allowlists are removed). Cookie attributes are parsed, not
  substring-matched.
- **Methods.** Any verb is sent, with a control verb to detect servers that answer everything. TRACE is
  confirmed by an echoed marker, and PUT/DELETE by an opt-in upload, read-back and delete.
- **Error pages.** Template and stack-trace signatures replace a single organisation's error sentence, with
  an optional configurable marker.
- **Versions.** End-of-life data from endoflife.date replaces the LLM verdict and the "latest release"
  baseline file. Disclosure, end-of-life and patch level are reported separately.
- **Certificates.** Verified by default; an invalid certificate is a finding, and the scan continues
  unverified. A local TLS 1.0/1.1 probe replaces the scraped SSL Labs v3 integration.
- **New checks.** CORS origin trust, and an opt-in exposed-services port check.
- **Tests.** Local HTTP/HTTPS validation servers with generated certificates, golden-file tests, and GitHub
  Actions on Windows and Linux.
