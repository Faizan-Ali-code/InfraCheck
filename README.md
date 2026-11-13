# InfraCheck

InfraCheck checks web-facing hosts for common security weaknesses:

- TLS certificates and protocol versions, and HTTP to HTTPS redirection;
- security headers, Content-Security-Policy and cookie attributes;
- CORS trust, accepted HTTP methods and error pages;
- disclosed and end-of-life software versions;
- client-IP spoofing of access controls;
- optionally, exposed service ports.

Every rule names the standard it comes from, and every active test is harmless by default.

```
C:\work> python -m infracheck scan http://127.0.0.1:62267/ http://127.0.0.1:62267/admin -o ic-demo-report
          --formats csv,json --checks headers,csp,cookies,cors,errors,versions,methods,spoofing
Scanning 2 target(s) with: headers, csp, cookies, cors, errors, versions, methods, spoofing. Only scan systems you are authorised to test.
[1/2] http://127.0.0.1:62267/: 12 finding(s)
[2/2] http://127.0.0.1:62267/admin: 10 finding(s)

InfraCheck 2.0.0: 2 target(s), 2 reachable, 1.3 s
Findings: 22 (1 high, 9 medium, 7 low, 5 info)
  http://127.0.0.1:62267/: 5 medium, 4 low, 3 info
  http://127.0.0.1:62267/admin: 1 high, 4 medium, 3 low, 2 info
Report: C:\work\ic-demo-report\findings.csv
Report: C:\work\ic-demo-report\findings.json
```

That run was against a local demo server with planted weaknesses. The high finding is the `/admin` page:
it answers 403, but 200 when the request carries `X-Forwarded-For: 10.0.0.1`.

## How it decides

- **Effects, not assumptions.**
  - **Spoofing:** a client-IP header is only reported when a page refused without it is served with it.
  - **TRACE:** reported only when a marker header comes back in the response.
  - **PUT and DELETE:** confirmed only by uploading a probe file and reading it back, which is opt-in.
  - **Control request:** a made-up HTTP method is sent first, so a server that answers *everything* with
    200 does not produce false "PUT enabled" findings.
- **Parsed, not substring-matched.**
  - Cookies are split into name, value and attributes, so a cookie *named* `secure_id` is not a Secure
    cookie.
  - `Expires` is parsed as an HTTP date, CSP as directives, and `Referrer-Policy` fallback lists as the
    browser reads them.
  - Error pages are matched against server templates and stack-trace patterns, not single words.
- **Severity follows impact.** A missing control that leaves a real attack open (HSTS, frame protection,
  CSP) is rated higher than hardening headers. `Permissions-Policy` and an explicit `Referrer-Policy` are
  *info*, and HSTS `preload` is not required.
- **Versions: facts, not guesses.**
  - Disclosed versions are compared with vendor support schedules from endoflife.date.
  - The report keeps three things apart: "version disclosed", "release line end-of-life" and "newer patch
    exists" (info only, because distributions backport fixes).
  - Nothing is declared vulnerable to a CVE from a banner.
- **Certificates are verified.** An invalid certificate is a finding with the reason (expired,
  self-signed, wrong host). The rest of that target is then still checked, unverified.

All rules, their severities and sources are listed in [docs/CHECKS.md](docs/CHECKS.md).

## Checks

| Check | What it does | Requests |
|---|---|---|
| `transport` | Certificate validity and expiry, TLS 1.0/1.1 accepted, TLS 1.3 offered, HTTP to HTTPS redirect, HTTP/2 | TLS handshakes, one HTTP request |
| `headers` | HSTS, nosniff, frame protection, Referrer-Policy, Permissions-Policy, X-XSS-Protection, caching of responses that set cookies | none extra |
| `csp` | Content-Security-Policy on HTML pages: unsafe-inline, unsafe-eval, wildcards, allowlists, object-src, base-uri, report-only | none extra |
| `cookies` | Secure, HttpOnly (session cookies), SameSite, `__Host-` / `__Secure-` prefix rules | none extra |
| `cors` | Arbitrary origin, `null` origin and prefix-matching origins trusted, with or without credentials | 3 GET |
| `errors` | Stack traces, debug pages, file paths and default server templates on a 404 and a 400 page; optional expected-page marker | 2 GET |
| `versions` | Versions in headers, generator tags and error pages; end-of-life and patch level from endoflife.date | endoflife.date (skip with `--offline`) |
| `methods` | Control verb, OPTIONS, TRACE (echo confirmed), PROPFIND; PUT/DELETE confirmed with `--allow-write-probes` | 4 (+4) |
| `spoofing` | 9 client-IP headers × the spoof address list, compared with a baseline | up to 37 |
| `exposure` | Opt-in: TCP connect to database, admin and remote-access ports | 1 connect per port |

## Quick start

Needs Python 3.11 or newer. The scanner uses the standard library only; `openpyxl` adds Excel reports.

```bat
git clone https://github.com/Faizan-Ali-code/InfraCheck.git
cd InfraCheck
pip install -r requirements.txt
python -m infracheck scan www.example.com
python -m infracheck scan -f urls.txt --out reports\today
```

On Windows, `run.bat scan -f urls.txt` does the same and creates a virtual environment on the first run.
Targets are host names or URLs (`https://` is assumed). Test restricted pages for spoofing by listing
their URLs, for example `https://intranet.example.com/admin`.

| Option | Meaning |
|---|---|
| `-f FILE` | Targets, one per line (`#` comments allowed) |
| `--checks a,b` | Run only these checks; `all` adds `exposure` |
| `--allow-write-probes` | Confirm PUT/DELETE by uploading and deleting one uniquely named text file (only where you may write) |
| `--spoof-ips FILE` | Addresses the spoofing check claims to be: your trusted office, VPN or internal ranges |
| `--expected-error-marker TEXT` | A sentence from your standard error page; pages without it are reported |
| `--ca-file PEM` | Trust an internal CA |
| `--proxy host:port` | Use an HTTP proxy |
| `--offline` | No end-of-life lookups |
| `--ports 22,3306` | Ports for the `exposure` check |
| `--fail-on SEVERITY` | Exit code 1 when a finding of this severity or higher exists (default `low`; `never` to always exit 0). Exit code 2 means nothing was reachable or the options were invalid. |
| `--config FILE` | Settings file; [infracheck.example.toml](infracheck.example.toml) lists every setting with its default |

## Reports

`findings.csv`, `findings.json` and `findings.xlsx` (Summary, Findings and Targets sheets).

- **Each finding** has:
  - target, check, rule and severity;
  - a detail line saying why;
  - the evidence (header line, policy, status codes);
  - the source standard;
  - for active tests, an evidence file with the full request and response under `evidence/`.
- **The Targets sheet** shows reachability, final URL, TLS version, certificate status, HTTP/2 and the
  state of every check. That includes "not applicable" and "partial", for example when a proxy
  prevents the TLS version probes.
- **Formula injection:** response text from servers is written as text, never as spreadsheet formulas.

## Validation

[docs/VALIDATION.md](docs/VALIDATION.md) describes how the checks were validated:

- local HTTP and HTTPS servers with known behaviour, run by the test suite, with generated certificates
  (valid, expired, self-signed, wrong host) and a TLS 1.1-only server;
- golden-file tests of whole responses;
- public test targets you can use yourself.

What the checks do not cover is listed there too.

## Development

```
pip install -r requirements-dev.txt
python -m pytest
```

> Only scan systems you are authorised to test. Reports describe weaknesses of the scanned systems:
> keep them private.
