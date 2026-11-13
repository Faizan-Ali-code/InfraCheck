"""Local HTTP(S) servers with fully controlled responses: the validation targets for the tests.

    with TestServer(app) as srv:        # app(method, path, headers) -> (status, [(name, value)], body)
        scan(srv.url)
"""

from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    app = None  # set per server

    def log_message(self, *args):  # keep test output quiet
        pass

    def send_response(self, code, message=None):  # no automatic 'Server: BaseHTTP/... Python/...' header
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _dispatch(self):
        length = int(self.headers.get("Content-Length") or 0)
        body_in = self.rfile.read(length) if length else b""
        status, headers, body = self.server.app(self.command, self.path, self.headers, body_in)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def __getattr__(self, name):
        if name.startswith("do_"):  # every method, including made-up ones, goes to the app
            return self._dispatch
        raise AttributeError(name)


class TestServer:
    __test__ = False  # not a pytest test class

    def __init__(self, app, tls: ssl.SSLContext | None = None) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.app = app
        self.httpd.daemon_threads = True
        self.scheme = "http"
        if tls is not None:
            self.httpd.socket = tls.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}/"

    def __enter__(self) -> TestServer:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def page(body: str = "<html><body>ok</body></html>", status: int = 200, headers=None):
    """An app that answers every request with the same response."""
    def app(method, path, req_headers, body_in):
        return status, [("Content-Type", "text/html; charset=utf-8"), *(headers or [])], body
    return app
