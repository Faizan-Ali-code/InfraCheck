"""Test certificates made at run time (no private keys are stored in the repository)."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os

import pytest

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(folder: str, name: str, cert, key) -> tuple[str, str]:
    cert_path, key_path = os.path.join(folder, f"{name}.pem"), os.path.join(folder, f"{name}.key")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


def make_certs(folder: str) -> dict[str, tuple[str, str]]:
    """{'ca', 'valid', 'expired', 'wronghost', 'selfsigned'} -> (cert.pem, key.pem)."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("InfraCheck Test CA")).issuer_name(_name("InfraCheck Test CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    out = {"ca": _write(folder, "ca", ca, ca_key)}

    def leaf(name, sans, start, end, issuer=ca, issuer_key=ca_key, self_signed=False):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(_name(name))
                   .issuer_name(_name(name) if self_signed else issuer.subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
                   .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        if not self_signed:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        cert = builder.sign(key if self_signed else issuer_key, hashes.SHA256())
        out[name] = _write(folder, name, cert, key)

    local = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    leaf("valid", local, now - dt.timedelta(days=1), now + dt.timedelta(days=20))  # also "expires within 30 days"
    leaf("expired", local, now - dt.timedelta(days=60), now - dt.timedelta(days=1))
    leaf("wronghost", [x509.DNSName("other.example")], now - dt.timedelta(days=1), now + dt.timedelta(days=200))
    leaf("selfsigned", local, now - dt.timedelta(days=1), now + dt.timedelta(days=200), self_signed=True)
    return out
