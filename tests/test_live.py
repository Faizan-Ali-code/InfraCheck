"""Checks against local HTTP(S) servers with known behaviour: the validation targets (review item I11)."""

import socket
import ssl
from urllib.parse import urlsplit

import pytest

from infracheck.checks import cors, errors, exposure, methods, spoofing, transport
from infracheck.config import Config
from infracheck.context import TargetContext
from infracheck.http import CertificateError, Client
from infracheck.scanner import scan_target
from server import TestServer, page

HTML = [("Content-Type", "text/html")]


def ctx_for(url, **cfg) -> TargetContext:
    ca = cfg.pop("ca_file", None)
    return TargetContext(url, Client(timeout=5, ca_file=ca), Config(**cfg))


def rules(ctx):
    return sorted(f.rule for f in ctx.result.findings)


# ------------------------------------------------------------------------------------------ http client

def test_client_keeps_repeated_headers_and_does_not_follow_redirects():
    def app(method, path, h, body):
        if path == "/start":
            return 302, [("Location", "/next"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2; Expires=Thu, 01 Jan 2099")], ""
        return 200, HTML, "final"
    with TestServer(app) as srv:
        client = Client(timeout=5)
        first = client.request(srv.url + "start")
        assert first.status == 302 and first.header_all("Set-Cookie") == ["a=1", "b=2; Expires=Thu, 01 Jan 2099"]
        chain = client.follow(srv.url + "start")
        assert [r.status for r in chain] == [302, 200] and chain[-1].text == "final"
        assert client.request(srv.url, "PROPFIND").status == 200  # any method can be sent


# ------------------------------------------------------------------------------------------ I8: certificates

@pytest.mark.parametrize("cert,reason", [("expired", "expired"), ("selfsigned", "self-signed"),
                                         ("wronghost", "mismatch")])
def test_invalid_certificates_are_reported_and_the_scan_continues(certs, tls_context, cert, reason):
    with TestServer(page(), tls_context(cert)) as srv:
        with pytest.raises(CertificateError):
            Client(timeout=5, ca_file=certs["ca"][0]).request(srv.url)
        result = scan_target(srv.url, Config(checks=["transport", "headers"], ca_file=certs["ca"][0]),
                             Client(timeout=5, ca_file=certs["ca"][0]))
    assert result.reachable and reason in result.certificate.lower()
    found = [f.rule for f in result.findings]
    assert "tls-certificate-invalid" in found and "hsts-missing" in found  # headers were still checked (unverified)


def test_valid_certificate_from_a_trusted_ca(certs, tls_context):
    with TestServer(page(), tls_context("valid")) as srv:
        ctx = ctx_for(srv.url, ca_file=certs["ca"][0])
        transport.run(ctx)
    assert ctx.result.certificate == "valid"
    assert "tls-certificate-invalid" not in rules(ctx)
    assert "tls-certificate-expiring" in rules(ctx)  # the test certificate is valid for 20 more days


def test_legacy_tls_is_detected(certs, tls_context):
    try:
        server_ctx = tls_context("valid", maximum=ssl.TLSVersion.TLSv1_1)
    except (ssl.SSLError, ValueError):
        pytest.skip("this OpenSSL build cannot serve TLS 1.1")
    with TestServer(page(), server_ctx) as srv:
        port = urlsplit(srv.url).port
        try:
            found = transport.legacy_tls("127.0.0.1", port, 5)
        except RuntimeError:
            pytest.skip("this OpenSSL build cannot offer TLS 1.0/1.1")
    assert found in ("TLSv1", "TLSv1.1")
    with TestServer(page(), tls_context("valid")) as srv:
        assert transport.legacy_tls("127.0.0.1", urlsplit(srv.url).port, 5) is None


def test_http_to_https_redirect():
    with TestServer(page()) as srv:
        ctx = ctx_for("https://127.0.0.1:1/")
        transport.check_http_redirect(ctx, srv.url)
    assert rules(ctx) == ["http-no-redirect"]
    with TestServer(lambda m, p, h, b: (301, [("Location", "https://127.0.0.1/")], "")) as srv:
        ctx = ctx_for("https://127.0.0.1:1/")
        transport.check_http_redirect(ctx, srv.url)
    assert rules(ctx) == []


def test_plain_http_target():
    with TestServer(page()) as srv:
        ctx = ctx_for(srv.url)
        transport.run(ctx)
    assert rules(ctx) == ["http-only"]


# ------------------------------------------------------------------------------------------ I3: methods

def webdav_server(store=None, echo_trace=True):
    store = {} if store is None else store

    def app(method, path, headers, body):
        if method == "OPTIONS":
            return 200, [("Allow", "GET, HEAD, OPTIONS, PUT, DELETE, TRACE, PROPFIND")], ""
        if method == "TRACE" and echo_trace:
            echoed = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            return 200, [("Content-Type", "message/http")], f"TRACE {path} HTTP/1.1\r\n{echoed}"
        if method == "PROPFIND":
            return 207, [("Content-Type", "application/xml")], "<multistatus/>"
        if method == "PUT":
            store[path] = body
            return 201, [], ""
        if method == "DELETE":
            return (204, [], "") if store.pop(path, None) is not None else (404, [], "")
        if method == "GET":
            return (200, [], store[path]) if path in store else (200, HTML, "<html>home</html>") if path == "/" else (404, HTML, "no")
        return 405, [], ""
    return app


def test_methods_read_only_probes():
    with TestServer(webdav_server()) as srv:
        ctx = ctx_for(srv.url)
        methods.run(ctx)
    assert rules(ctx) == ["method-trace-enabled", "method-webdav-enabled", "method-write-advertised"]


def test_methods_write_probe_confirms_and_cleans_up():
    store = {}
    with TestServer(webdav_server(store)) as srv:
        ctx = ctx_for(srv.url, allow_write_probes=True)
        methods.run(ctx)
    assert "method-put-writes-files" in rules(ctx) and "method-delete-removes-files" in rules(ctx)
    assert store == {}  # the probe file was removed


def test_server_that_answers_every_method_like_get():
    with TestServer(page()) as srv:  # 200 for PUT, DELETE, TRACE, INFRACHECK ...
        ctx = ctx_for(srv.url, allow_write_probes=True)
        methods.run(ctx)
    assert rules(ctx) == ["method-any-accepted"]  # no false 'PUT works' or 'TRACE enabled'


# ------------------------------------------------------------------------------------------ I5, I6: error pages

APACHE_404 = ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head><body>'
              '<h1>Not Found</h1><hr><address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1 Port 443</address></body></html>')
JAVA_TRACE = ("<pre>java.lang.IllegalArgumentException: Invalid URL\n\tat com.shop.web.Router.route(Router.java:88)\n"
              "\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:193)</pre>")


def test_error_pages_with_template_and_stack_trace():
    def app(method, path, h, body):
        return (400, HTML, JAVA_TRACE) if "%" in path else (404, HTML, APACHE_404)
    with TestServer(app) as srv:
        ctx = ctx_for(srv.url)
        errors.run(ctx)
    assert rules(ctx) == ["error-default-page", "error-stack-trace"]
    assert ("Apache", "2.4.41", "missing page error page") in ctx.version_hints


def test_words_in_a_custom_error_page_are_not_a_server_signature():
    custom = "<html><body><h1>Sorry, page not found</h1><footer>Built with Apache 2.0 licensed software</footer></body></html>"
    with TestServer(page(custom, 404)) as srv:
        ctx = ctx_for(srv.url)
        errors.run(ctx)
        assert rules(ctx) == [] and ctx.version_hints == []
        marked = ctx_for(srv.url, expected_error_marker="We are sorry")
        errors.run(marked)
        assert rules(marked) == ["error-unexpected-page"]
        ok = ctx_for(srv.url, expected_error_marker="Sorry, page not found")
        errors.run(ok)
        assert rules(ok) == []


def test_soft_404():
    with TestServer(page("<html>home</html>")) as srv:
        ctx = ctx_for(srv.url)
        errors.run(ctx)
    assert "error-soft-404" in rules(ctx)


# ------------------------------------------------------------------------------------------ I1: spoofing (kept)

def restricted(trusted_header="X-Forwarded-For", trusted="10.0.0.1"):
    def app(method, path, headers, body):
        return (200, HTML, "admin") if headers.get(trusted_header) == trusted else (403, HTML, "forbidden")
    return app


def test_spoofing_detects_a_header_that_unlocks_a_page():
    with TestServer(restricted()) as srv:
        ctx = ctx_for(srv.url)
        spoofing.run(ctx)
    [finding] = ctx.result.findings
    assert finding.rule == "spoofing-access-granted" and "X-Forwarded-For: 10.0.0.1" in finding.evidence


def test_spoofing_on_public_and_strict_pages():
    with TestServer(page()) as srv:
        ctx = ctx_for(srv.url)
        spoofing.run(ctx)
    assert rules(ctx) == [] and ctx.result.checks["spoofing"].startswith("not applicable")
    with TestServer(page("no", 403)) as srv:
        ctx = ctx_for(srv.url)
        spoofing.run(ctx)
    assert rules(ctx) == []


def test_spoofing_behaviour_change_is_low():
    def app(method, path, headers, body):
        return (302, [("Location", "/login")], "") if headers.get("X-Real-IP") else (401, HTML, "login")
    with TestServer(app) as srv:
        ctx = ctx_for(srv.url)
        spoofing.run(ctx)
    assert rules(ctx) == ["spoofing-behaviour-changed"]


# ------------------------------------------------------------------------------------------ CORS

def cors_server(mode):
    def app(method, path, headers, body):
        origin = headers.get("Origin", "")
        out = []
        if mode == "reflect" and origin:
            out = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
        elif mode == "null" and origin == "null":
            out = [("Access-Control-Allow-Origin", "null"), ("Access-Control-Allow-Credentials", "true")]
        elif mode == "prefix" and origin.startswith("https://127.0.0.1"):
            out = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
        elif mode == "public":
            out = [("Access-Control-Allow-Origin", "*")]
        return 200, HTML + out, "data"
    return app


@pytest.mark.parametrize("mode,expected", [("reflect", ["cors-reflects-origin-credentials"]),
                                           ("null", ["cors-null-origin"]), ("prefix", ["cors-prefix-match"]),
                                           ("public", []), ("none", [])])
def test_cors(mode, expected):
    with TestServer(cors_server(mode)) as srv:
        ctx = ctx_for(srv.url)
        cors.run(ctx)
    assert rules(ctx) == expected


# ------------------------------------------------------------------------------------------ exposure

def test_exposure_reports_open_ports():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    open_port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        ctx = ctx_for("https://127.0.0.1/", exposure_ports=[open_port, closed_port])
        exposure.run(ctx)
    finally:
        listener.close()
    [finding] = ctx.result.findings
    assert f":{open_port}" in finding.detail and finding.severity == "medium"
