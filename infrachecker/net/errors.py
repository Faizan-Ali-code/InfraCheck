"""Java exceptions as the Java tool saw them, and the mapping from Python socket/TLS failures.

Messages are those of JDK 25 on Windows (checked against a local server), e.g. ``Connection refused: getsockopt``.
"""
from __future__ import annotations

import re
import socket
import ssl

_ALERT = re.compile(r"(?:SSLV3|TLSV1|TLSV13)_(?:ALERT_)?(\w+)")
_PLAINTEXT_REASONS = {"WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "HTTP_REQUEST", "HTTPS_PROXY_REQUEST",
                      "PACKET_LENGTH_TOO_LONG", "UNKNOWN_PROTOCOL"}
_PKIX_BUILD = ("(certificate_unknown) PKIX path building failed: sun.security.provider.certpath."
               "SunCertPathBuilderException: unable to find valid certification path to requested target")
_PKIX_VALIDITY = ("(certificate_unknown) PKIX path validation failed: java.security.cert.CertPathValidatorException: "
                  "validity check failed")
_X509_EXPIRED = (9, 10)
_X509_HOSTNAME_MISMATCH = 62
_X509_IP_MISMATCH = 64


class JavaIOError(Exception):
    """A Java ``IOException`` (or subclass). ``str()`` gives Java's ``toString()``."""

    def __init__(self, java_class: str, message: str | None):
        super().__init__(message)
        self.java_class = java_class
        self.message = message

    @property
    def simple_name(self) -> str:
        return self.java_class.rsplit(".", 1)[-1]

    def __str__(self) -> str:
        return self.java_class if self.message is None else f"{self.java_class}: {self.message}"


class ClientProtocolError(JavaIOError):
    """Apache ``ClientProtocolException``; wraps an ``HttpException`` via ``initCause``, so its message is null."""

    def __init__(self) -> None:
        super().__init__("org.apache.http.client.ClientProtocolException", None)


class JavaClassCastError(Exception):
    """``(HttpsURLConnection) url.openConnection()`` on a non-HTTPS URL."""

    simple_name = "ClassCastException"

    def __init__(self) -> None:
        super().__init__("class sun.net.www.protocol.http.HttpURLConnection cannot be cast to class "
                         "javax.net.ssl.HttpsURLConnection")


class ExchangeError(Exception):
    """A Python-level failure of one HTTP exchange, tagged with the phase it happened in.

    Phases: ``connect`` (TCP), ``tunnel`` (proxy CONNECT), ``handshake`` (TLS), ``send``, ``headers``, ``body``.
    """

    def __init__(self, phase: str, cause: BaseException):
        super().__init__(f"{phase}: {cause!r}")
        self.phase = phase
        self.cause = cause


def java_message(exc: BaseException) -> str:
    """``e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()`` (Java ``d``/``h`` helper)."""
    if isinstance(exc, JavaIOError):
        return exc.simple_name if exc.message is None else exc.message
    text = str(exc)
    return text if text else type(exc).__name__


def socket_error(error: ExchangeError, host: str) -> JavaIOError:
    """Java's exception for a socket/TLS-level failure. Protocol-level failures are mapped by each client flavour."""
    exc, phase = error.cause, error.phase
    if isinstance(exc, ssl.SSLCertVerificationError):
        return JavaIOError("javax.net.ssl.SSLHandshakeException", _certificate_message(exc, host))
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return JavaIOError("javax.net.ssl.SSLHandshakeException", "Remote host terminated the handshake")
    if isinstance(exc, ssl.SSLError):
        return _tls_error(exc, phase)
    if isinstance(exc, TimeoutError):
        return JavaIOError("java.net.SocketTimeoutException",
                           "Connect timed out" if phase == "connect" else "Read timed out")
    if isinstance(exc, ConnectionRefusedError):
        return JavaIOError("java.net.ConnectException", "Connection refused: getsockopt")
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return JavaIOError("java.net.SocketException", "Connection reset")
    if isinstance(exc, socket.gaierror):
        return JavaIOError("java.net.UnknownHostException", host)
    if isinstance(exc, OSError):
        return JavaIOError("java.net.SocketException", exc.strerror or str(exc))
    return JavaIOError("java.io.IOException", str(exc) or None)


def _certificate_message(exc: ssl.SSLCertVerificationError, host: str) -> str:
    if exc.verify_code == _X509_HOSTNAME_MISMATCH:
        return f"(certificate_unknown) No subject alternative DNS name matching {host} found."
    if exc.verify_code == _X509_IP_MISMATCH:
        return f"(certificate_unknown) No subject alternative names matching IP address {host} found"
    if exc.verify_code in _X509_EXPIRED:
        return _PKIX_VALIDITY
    return _PKIX_BUILD


def _tls_error(exc: ssl.SSLError, phase: str) -> JavaIOError:
    reason = exc.reason or ""
    if reason in _PLAINTEXT_REASONS:
        return JavaIOError("javax.net.ssl.SSLException", "Unsupported or unrecognized SSL message")
    alert = _ALERT.fullmatch(reason)
    java_class = "javax.net.ssl.SSLHandshakeException" if phase == "handshake" else "javax.net.ssl.SSLException"
    if alert:
        name = alert.group(1).lower()
        return JavaIOError(java_class, f"({name}) Received fatal alert: {name}")
    return JavaIOError(java_class, reason or str(exc))
