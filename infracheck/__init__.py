"""InfraCheck: checks web-facing hosts for common security weaknesses (TLS, headers, CSP, cookies, CORS,
HTTP methods, error pages, version disclosure, client-IP spoofing, exposed services).

Every rule names the standard it comes from (docs/CHECKS.md), and active probes are non-destructive
unless write probes are explicitly allowed.
"""

__version__ = "2.0.0"
USER_AGENT = f"InfraCheck/{__version__} (authorised security assessment)"
