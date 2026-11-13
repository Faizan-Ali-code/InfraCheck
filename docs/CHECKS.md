# Checks and rules

Every finding comes from one rule. A rule has an id, a severity and the standard it is based on.
`python -m infracheck checks` prints the same list.

**Severity**

| Severity | Meaning |
|---|---|
| high | Directly exploitable, or exposes credentials or sessions (invalid certificate, CORS with credentials for any origin, stack traces, working PUT, spoofing bypass) |
| medium | A missing control that leaves a known attack open (no HSTS, framing allowed, no CSP, TRACE, end-of-life software) |
| low | Weakens defence in depth or leaks information (version banners, default error pages, nosniff) |
| info | Good-practice notes that are not weaknesses on their own (Permissions-Policy, explicit SameSite, newer patch available) |

## transport

Certificates are verified against the system trust store (plus `--ca-file`). If verification fails, the
reason is reported and the target is fetched again without verification, so the other checks still run.

The legacy-protocol test completes a handshake capped at TLS 1.0, then TLS 1.1. If the local OpenSSL build
cannot offer those versions, the check is marked *partial* rather than passed. This is a quick check, not
a TLS audit: use testssl.sh or sslyze for cipher suites, key exchange and protocol vulnerabilities.

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `tls-certificate-invalid` | high | TLS certificate does not verify | OWASP Transport Layer Security Cheat Sheet; OWASP ASVS 4.0.3 V9.1 |
| `tls-certificate-expiring` | low | TLS certificate expires within 30 days | OWASP Transport Layer Security Cheat Sheet; OWASP ASVS 4.0.3 V9.1 |
| `tls-legacy-protocol` | medium | Server accepts TLS 1.0 or TLS 1.1 | RFC 8996; NIST SP 800-52 Rev. 2; OWASP Transport Layer Security Cheat Sheet |
| `tls13-unsupported` | info | Server does not offer TLS 1.3 | RFC 8996; NIST SP 800-52 Rev. 2 |
| `http-no-redirect` | medium | Plain HTTP is served without a redirect to HTTPS | OWASP Transport Layer Security Cheat Sheet; OWASP ASVS 4.0.3 V9.1.1 |
| `http-only` | high | Target is served over plain HTTP | OWASP ASVS 4.0.3 V9.1.1 |

## headers

Rules that protect documents (framing, Referrer-Policy, Permissions-Policy) apply to HTML responses only.
HSTS is evaluated on HTTPS responses only, as RFC 6797 requires.

- **HSTS** needs a parsable `max-age`. One year is recommended; `includeSubDomains` is advised (info).
  `preload` is not required: it is an opt-in to browser preload lists with lasting consequences.
- **Referrer-Policy** may be a comma-separated list. Browsers use the last value they recognise, so a
  fallback list is evaluated as the browser reads it.
- **Caching** is only checked on responses that set cookies, because static assets are meant to be
  cached. `Cache-Control` decides. Without it, `Expires` is parsed as an HTTP date: a past date, `0`,
  `-1` or any invalid date means "already expired" (RFC 9111 section 5.3).

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `hsts-missing` | medium | HSTS header missing | OWASP HSTS Cheat Sheet; RFC 6797 |
| `hsts-disabled` | medium | HSTS max-age is 0 (HSTS switched off) | OWASP HSTS Cheat Sheet; RFC 6797 |
| `hsts-short` | low | HSTS max-age shorter than one year | OWASP HSTS Cheat Sheet; RFC 6797 |
| `hsts-invalid` | medium | HSTS header cannot be parsed | OWASP HSTS Cheat Sheet; RFC 6797 |
| `hsts-no-subdomains` | info | HSTS does not include subdomains | OWASP HSTS Cheat Sheet; RFC 6797 |
| `nosniff-missing` | low | X-Content-Type-Options: nosniff missing | OWASP Secure Headers Project; OWASP ASVS 4.0.3 V14.4 |
| `clickjacking` | medium | Page can be framed by other sites (no frame-ancestors or X-Frame-Options) | OWASP Clickjacking Defense Cheat Sheet; CSP Level 3 |
| `xfo-allow-from` | low | X-Frame-Options ALLOW-FROM is obsolete and ignored by browsers | OWASP Clickjacking Defense Cheat Sheet |
| `referrer-unsafe` | low | Referrer-Policy sends full URLs to other sites | W3C Referrer Policy; OWASP Secure Headers Project |
| `referrer-missing` | info | Referrer-Policy not set (browser default applies) | W3C Referrer Policy; OWASP Secure Headers Project |
| `permissions-policy-missing` | info | Permissions-Policy not set | OWASP Secure Headers Project; OWASP ASVS 4.0.3 V14.4 |
| `xss-protection-deprecated` | info | X-XSS-Protection enabled (deprecated; set 0 or remove) | OWASP Secure Headers Project |
| `cacheable-with-cookies` | low | Response that sets cookies may be stored by caches | OWASP ASVS 4.0.3 V8.2.1; RFC 9111 |

`X-Permitted-Cross-Domain-Policies` (Flash and Acrobat cross-domain policies) is not checked: it only
matters for sites that serve `crossdomain.xml` to those plug-ins.

## csp

HTML responses only. The script policy is `script-src`, or `default-src` when `script-src` is absent.

- **Nonces and hashes.** When a nonce or hash is present, `'unsafe-inline'` is ignored by browsers and not
  reported.
- **`'strict-dynamic'`.** With it, host and scheme sources are ignored and not reported.
- **Allowlists.** Host allowlists are reported as *low*, because allowed hosts that serve JSONP or script
  gadgets bypass them. See Weichselbaum, Spagnuolo, Lekies and Janc, "CSP Is Dead, Long Live CSP!", ACM
  CCS 2016.
- **Not checked:** allowlist bypasses for specific hosts. Google's csp-evaluator checks those.

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `csp-missing` | medium | No Content-Security-Policy on an HTML page | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-report-only` | low | Content-Security-Policy is only in report-only mode | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-no-script-control` | high | CSP does not restrict scripts (no script-src or default-src) | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-unsafe-inline` | high | CSP allows inline scripts ('unsafe-inline' without nonce or hash) | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-unsafe-eval` | medium | CSP allows eval() ('unsafe-eval') | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-wildcard-script` | high | CSP allows scripts from any host or scheme (*, https:, data:...) | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-insecure-source` | medium | CSP allows scripts over plain HTTP | W3C CSP Level 3; OWASP CSP Cheat Sheet |
| `csp-host-allowlist` | low | CSP relies on a host allowlist for scripts | W3C CSP Level 3; Weichselbaum et al., CCS 2016 |
| `csp-object-src` | low | CSP does not set object-src 'none' | W3C CSP Level 3; Weichselbaum et al., CCS 2016 |
| `csp-base-uri` | medium | CSP uses nonces or hashes but not base-uri | W3C CSP Level 3; Weichselbaum et al., CCS 2016 |
| `csp-unknown-directive` | info | CSP contains unknown or deprecated directives | W3C CSP Level 3 |

## cookies

`Set-Cookie` is split into name, value and attributes before anything is tested; attribute names are
matched case-insensitively. HttpOnly is only required for cookies that look like sessions: a name
containing sess, sid, auth, token, jwt, login, remember or identity, or a long value with no expiry. Many
non-session cookies are meant to be read by scripts.

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `cookie-no-secure` | medium | Cookie sent over HTTPS without the Secure attribute | RFC 6265bis; OWASP Session Management Cheat Sheet; ASVS V3.4 |
| `cookie-no-httponly` | medium | Session cookie readable by JavaScript (no HttpOnly) | RFC 6265bis; OWASP Session Management Cheat Sheet; ASVS V3.4 |
| `cookie-samesite-none-insecure` | medium | SameSite=None without Secure (browsers reject it) | RFC 6265bis |
| `cookie-no-samesite` | info | Cookie without an explicit SameSite attribute | RFC 6265bis |
| `cookie-prefix-violation` | medium | __Host- / __Secure- cookie breaks its prefix rules | RFC 6265bis |

## cors

Three requests carry an `Origin` that no deployment should trust. `.invalid` is a reserved top-level
domain (RFC 2606). The probes are:

- an arbitrary origin;
- `null`;
- an origin that only *starts* with the target's host name.

If any origin is trusted, the narrower probes are not reported again.

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `cors-reflects-origin-credentials` | high | CORS trusts any origin and allows credentials | WHATWG Fetch; OWASP WSTG-CLNT-07 |
| `cors-reflects-origin` | medium | CORS reflects any origin (without credentials) | WHATWG Fetch; OWASP WSTG-CLNT-07 |
| `cors-null-origin` | high | CORS trusts the 'null' origin with credentials | WHATWG Fetch; OWASP WSTG-CLNT-07 |
| `cors-prefix-match` | high | CORS trusts origins that only start with the site's host name | WHATWG Fetch; OWASP WSTG-CLNT-07 |

## errors

Two error responses are provoked: a random missing path (404) and a malformed percent-encoding (400).
Their bodies are matched against:

- stack traces (Java, Python, .NET, Node.js);
- debug pages (Django, Laravel or Whoops, Rails);
- PHP and ASP.NET error pages that show file paths;
- the default error templates of Apache httpd, nginx, IIS, Tomcat, Jetty, Spring Boot, Express and
  HTTP.sys.

Signatures are template patterns, such as `<address>Apache/2.4.41 … Server at … Port 443</address>`, not
words: "Apache License" in a footer matches nothing. Versions are only read from pages already recognised
as templates. Organisations with a standard error page can set `expected_marker`.

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `error-stack-trace` | high | Error page shows a stack trace or debug output | OWASP WSTG-ERRH-01; ASVS V7.4.1, V14.3.2 |
| `error-path-disclosure` | medium | Error page discloses server file paths | OWASP WSTG-ERRH-01; ASVS V7.4.1 |
| `error-default-page` | low | Default server error page (product identifiable) | OWASP WSTG-ERRH-01; ASVS V14.3.2 |
| `error-unexpected-page` | info | Error page is not the expected standard page | OWASP WSTG-ERRH-01 |
| `error-soft-404` | info | Missing pages are answered with 200 (soft 404) | OWASP WSTG-ERRH-01 |

## versions

Versions come from `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `Via`,
`<meta name="generator">` and recognised error templates.

For products that endoflife.date covers (nginx, Apache httpd, PHP, Tomcat, Jetty, Node.js, OpenSSL,
Python, WordPress, Drupal, Joomla, HAProxy, Varnish, Caddy, Envoy, Traefik), the version is matched to
its release line:

- **End-of-life line** (no more vendor security fixes): *medium*.
- **Older than the newest patch of a supported line:** *info*, because distribution packages often carry
  backported fixes under an old version number.

The data is fetched once per product per run. `--offline` turns it off. No CVE is inferred from a banner.

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `version-disclosed` | low | Software version disclosed | OWASP WSTG-INFO-02; ASVS V14.3.3 |
| `version-end-of-life` | medium | Software release line is end-of-life | endoflife.date; OWASP Top 10 2021 A06 |
| `version-not-latest-patch` | info | Newer patch release exists in this release line | endoflife.date |

## methods

1. **Control.** A made-up method is sent first. A 2xx answer means the server treats every method like
   GET, so status codes say nothing about methods there (`method-any-accepted`) and no write method is
   reported.
2. **Read-only probes.**
   - OPTIONS: reads the Allow header.
   - TRACE: sends a random marker header; reported only if the marker is echoed.
   - PROPFIND with `Depth: 0`: a 207 answer means WebDAV.
3. **Write probes, only with `--allow-write-probes`.**
   - PUT `infracheck-probe-<random>.txt`, read it back with GET, then DELETE it and confirm it is gone.
   - If the file cannot be removed, the Targets sheet says so, so it can be deleted by hand.
   - Without the option, advertised write methods are *low*: "verify manually".

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `method-trace-enabled` | medium | TRACE echoes requests (Cross-Site Tracing) | RFC 9110 §9; OWASP WSTG-CONF-06 |
| `method-put-writes-files` | high | PUT stores files on the server | RFC 9110 §9; OWASP WSTG-CONF-06 |
| `method-delete-removes-files` | high | DELETE removes files on the server | RFC 9110 §9; OWASP WSTG-CONF-06 |
| `method-webdav-enabled` | medium | WebDAV is enabled (PROPFIND answered 207) | RFC 9110 §9; OWASP WSTG-CONF-06 |
| `method-write-advertised` | low | Write methods advertised or accepted; verify manually | OWASP WSTG-CONF-06 |
| `method-any-accepted` | info | Server answers any method like GET; method results are unreliable | OWASP WSTG-CONF-06 |

## spoofing

A baseline request has no client-IP header. Then each of 9 headers is sent:

- `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`,
  `True-Client-IP` and `X-Cluster-Client-IP`;
- `Forwarded`, in RFC 7239 syntax.

Each header claims, in turn, every address in the spoof list. The default list is 127.0.0.1, 10.0.0.1,
172.16.0.1 and 192.168.1.1; set your trusted ranges with `--spoof-ips`. Redirects are not followed.

| Baseline | With a header | Result |
|---|---|---|
| served (2xx) | any | not applicable: nothing to unlock |
| refused, redirected or error | served | `spoofing-access-granted` |
| refused, redirected or error | other status, not served | `spoofing-behaviour-changed` |
| refused, redirected or error | same status | header ignored |

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `spoofing-access-granted` | high | Client-IP header grants access to a restricted page | OWASP WSTG-ATHZ-02; RFC 7239; CWE-290 |
| `spoofing-behaviour-changed` | low | Client-IP header changes the response; review manually | OWASP WSTG-ATHZ-02; CWE-290 |

## exposure (opt-in)

A TCP connect to each configured port of the target host; no data is sent. Severity depends on the
service:

| Severity | Ports |
|---|---|
| high | Services often run without authentication or with full remote control: Telnet 23, SMB 445, Docker API 2375, Redis 6379, Elasticsearch 9200, Memcached 11211, MongoDB 27017 |
| medium | Databases, RDP and VNC |
| low | FTP |
| info | SSH |

| Rule | Severity | Finding | Source |
|---|---|---|---|
| `exposed-service-<severity>` | per port | Service port reachable | CIS Controls v8 4.4 and 12.2; OWASP WSTG-CONF-01; NIST SP 800-41 |
