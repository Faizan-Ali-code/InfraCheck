# Validation

How the checks were validated, and how to validate them yourself.

## Automated: local servers with known behaviour

`tests/` starts local HTTP and HTTPS servers (`tests/server.py`) whose responses each test controls, and
scans them with the real client. There is no mocking of the network layer. Certificates are generated at
test time (`tests/certs.py`): a test CA, a valid certificate for 127.0.0.1 that expires in 20 days, an
expired one, a self-signed one and one for the wrong host name.

| Check | Validated behaviour |
|---|---|
| transport | Expired, self-signed and wrong-host certificates are reported with their reason, and the scan continues unverified. A valid certificate from a trusted CA passes, with an "expires within 30 days" note. A server limited to TLS 1.1 is detected and a modern server is not. HTTP without a redirect is reported; a 301 to HTTPS is not. |
| headers, csp, cookies, versions | Golden files: whole responses in `tests/fixtures/*.http` and the exact rule ids each must produce in `tests/fixtures/expected.json`. One of them is a hardened page that must produce no finding. Unit tests cover HTTP-date parsing of `Expires`, Referrer-Policy fallback lists, HSTS edge cases, cookie attribute parsing, CSP rules and end-of-life matching. |
| methods | A WebDAV-like server: TRACE echo, PROPFIND 207 and advertised PUT/DELETE are found. The write probe stores a file, reads it back and leaves the server's storage empty afterwards. A server that answers every method with 200 produces only the "any method accepted" note, not false TRACE or PUT findings. |
| errors | An Apache 404 template and a Java stack trace are recognised and the Apache version is extracted. A custom page that mentions "Apache 2.0" in its footer produces nothing. The expected-page marker works both ways, and a soft 404 is reported. |
| spoofing | A page that returns 403 unless `X-Forwarded-For: 10.0.0.1` is reported. A public page is "not applicable", a page that always refuses produces nothing, and a status change without access is low. |
| cors | Reflected origin with credentials, `null` origin and prefix matching are each reported. `*` and no CORS produce nothing. |
| exposure | An open local port is reported and a closed one is not. |
| scanner, reports, CLI | Unreachable targets are marked and their checks skipped. A failing check does not stop the others. Reports neutralise formula cells, evidence files are written, and exit codes are tested. |

Run them with `python -m pytest`. GitHub Actions runs them on Windows and Linux with Python 3.11 and 3.13.

## Manual: public and self-hosted targets

These were **not** run from the development machine for this release: its network blocks or intercepts
outside TLS connections. Use them to check a release on an open network.

| Target | Expected result |
|---|---|
| `https://expired.badssl.com/` | `tls-certificate-invalid` (expired) |
| `https://wrong.host.badssl.com/` | `tls-certificate-invalid` (hostname mismatch) |
| `https://self-signed.badssl.com/` | `tls-certificate-invalid` (self-signed) |
| `https://tls-v1-0.badssl.com:1010/` | `tls-legacy-protocol` |
| `https://badssl.com/` | no certificate finding |
| OWASP Juice Shop (`docker run -p 3000:3000 bkimminich/juice-shop`), target `http://localhost:3000/` | header, CSP and CORS findings; compare with the Juice Shop documentation |

A self-hosted nginx reproduces the server-side cases:

```nginx
server {
    listen 8443 ssl;
    ssl_certificate     /etc/nginx/test.pem;           # any test certificate
    ssl_certificate_key /etc/nginx/test.key;
    ssl_protocols TLSv1.1 TLSv1.2;                     # tls-legacy-protocol (needs an OpenSSL that allows 1.1)
    server_tokens on;                                  # version-disclosed, error-default-page
    add_header Set-Cookie "sessionid=abc123456789abcdef; Path=/";   # cookie-no-secure, cookie-no-httponly
    location /admin {
        set_real_ip_from 0.0.0.0/0;                    # the classic mistake: trust X-Forwarded-For from anyone
        real_ip_header X-Forwarded-For;
        allow 10.0.0.0/8;
        deny all;                                      # spoofing-access-granted
    }
}
```

## What is not covered

- **TLS depth:** cipher suites, key exchange, certificate chain details, OCSP stapling and TLS
  vulnerabilities. Use testssl.sh or sslyze.
- **CVEs from versions:** banners do not show distribution patches.
- **CSP bypasses on specific allowlisted hosts.** Google's csp-evaluator checks those.
- **Pages behind authentication:** no login is performed.
- **Web application firewall detection.**
