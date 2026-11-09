import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from cfms_pki.ca_gen import build_ca_certificate
from cfms_pki.shared import write_atomic


def issuer(*, ca=True, expired=False, path_length=1, allow_signing=True):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 10))
        .add_extension(x509.BasicConstraints(ca, path_length if ca else None), True)
        .add_extension(
            x509.KeyUsage(
                True, False, False, False, False, allow_signing, True, False, False
            ),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


@pytest.mark.parametrize(
    "options,match",
    [
        ({"ca": False}, "not a CA"),
        ({"expired": True}, "not currently valid"),
        ({"path_length": 0}, "path length"),
        ({"allow_signing": False}, "forbids"),
    ],
)
def test_reject_invalid_ca_issuer(options, match):
    cert, key = issuer(**options)
    child_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match=match):
        build_ca_certificate(cert.subject, child_key, issuer_cert=cert, issuer_key=key)


def test_ca_key_match_and_validity_cap():
    cert, key = issuer()
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="does not match"):
        build_ca_certificate(cert.subject, other, issuer_cert=cert, issuer_key=other)
    child = build_ca_certificate(
        cert.subject, other, valid_days=90, issuer_cert=cert, issuer_key=key
    )
    assert child.not_valid_after_utc == cert.not_valid_after_utc


def test_weak_rsa_ca_key_is_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak CA")])
    with pytest.raises(ValueError, match="2048"):
        build_ca_certificate(name, key)


def test_atomic_permissions_before_publish(tmp_path, monkeypatch):
    target = tmp_path / "secret.key"
    original_replace = os.replace
    observed = []

    def inspect_replace(source, destination):
        if os.name != "nt":
            observed.append(stat.S_IMODE(Path(source).stat().st_mode))
        else:
            acl = subprocess.check_output(["icacls", str(source)], text=True)
            assert "(F)" in acl
            observed.append(0o600)
        original_replace(source, destination)

    monkeypatch.setattr(os, "replace", inspect_replace)
    write_atomic(target, b"private material")
    assert observed == [0o600]
    if os.name == "nt":
        before = subprocess.check_output(["icacls", str(target)], text=True)
        write_atomic(target, b"replacement")
        assert subprocess.check_output(["icacls", str(target)], text=True) == before
    else:
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_public_atomic_permissions(tmp_path):
    target = tmp_path / "public.pem"
    write_atomic(target, b"public material", mode=0o644)
    assert target.read_bytes() == b"public material"
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
