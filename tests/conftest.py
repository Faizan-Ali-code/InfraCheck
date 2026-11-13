import os
import ssl
import warnings

import pytest

from infracheck.config import Config
from infracheck.context import TargetContext
from infracheck.http import Client, RequestError, Response

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def response_from(raw: str, url: str = "https://www.example.test/") -> Response:
    """A Response from a raw HTTP response text (status line, headers, blank line, body)."""
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    status_line, *header_lines = head.strip("\n").split("\n")
    _version, status, *reason = status_line.split(" ", 2)
    headers = [tuple(part.strip() for part in line.split(":", 1)) for line in header_lines if ":" in line]
    return Response(url, "GET", int(status), reason[0] if reason else "", headers, body.encode())


class StubClient(Client):
    """Serves one canned page as the target and refuses every other request."""

    def __init__(self, page: Response) -> None:
        super().__init__()
        self.page = page

    def follow(self, url, max_hops=5, verify=True):
        return [self.page]

    def request(self, *args, **kwargs):
        raise RequestError("offline test client")


def stub_context(page: Response, **cfg) -> TargetContext:
    return TargetContext(page.url, StubClient(page), Config(**cfg))


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    from certs import make_certs
    return make_certs(str(tmp_path_factory.mktemp("certs")))


@pytest.fixture
def tls_context(certs):
    def make(name: str, maximum: ssl.TLSVersion | None = None) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*certs[name])
        if maximum is not None:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                ctx.maximum_version = maximum
        return ctx
    return make
