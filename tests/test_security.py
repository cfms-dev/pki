import json
import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from cfms_pki import acme_export
from cfms_pki.ca_gen import build_ca_certificate, generate_ca
from cfms_pki.crl.issuing import issue_crl_for_ca
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


@pytest.fixture
def export_fixture(tmp_path):
    registry = tmp_path / "registry"
    registry.mkdir()
    cert_path = tmp_path / "ca.pem"
    ca, key = generate_ca("Export CA", algorithm="ecdsa", out_cert_path=cert_path)
    info = {"location": str(cert_path), "pk_env": "TEST_EXPORT_CA"}
    (registry / "ca.json").write_text(
        json.dumps({"cas": {"test-ca": info}}), encoding="utf-8"
    )
    now = datetime.now(UTC).replace(microsecond=0)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.com")])
        )
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(123)
        .not_valid_before(now - timedelta(seconds=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
        )
        .sign(key, hashes.SHA256())
    )
    row = {
        "id": "leaf",
        "pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "ca_id": None,
        "serial_number": "7b",
        "revoked_at": int(now.timestamp()) - 1,
        "revocation_reason": "keyCompromise",
    }
    return registry, info, ca, key, leaf, row


def test_acme_revocation_reaches_signed_crl(export_fixture, monkeypatch):
    registry, info, ca, key, leaf, row = export_fixture
    merged, backfills = acme_export.merge_revocations(
        registry, [row], {"revocations": {}}
    )
    assert backfills == {"leaf": "test-ca"}
    monkeypatch.setenv(
        "TEST_EXPORT_CA",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    output = issue_crl_for_ca(
        "test-ca",
        info,
        merged["revocations"]["test-ca"],
        registry,
        datetime.now(UTC),
        7,
    )
    crl = x509.load_pem_x509_crl(output.read_bytes())
    assert crl.is_signature_valid(ca.public_key())
    revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    assert revoked is not None
    assert (
        revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason
        == x509.ReasonFlags.key_compromise
    )


@pytest.mark.parametrize(
    "changes",
    [{"ca_id": "wrong-ca"}, {"serial_number": "ff"}, {"revocation_reason": "unknown"}],
)
def test_export_rejects_inconsistent_metadata(export_fixture, changes):
    registry, _, _, _, _, row = export_fixture
    with pytest.raises(ValueError):
        acme_export.merge_revocations(registry, [row | changes], {"revocations": {}})


def test_export_failure_preserves_previous_output(export_fixture, monkeypatch):
    registry, _, _, _, _, _ = export_fixture
    output = registry.parent / "merged.json"
    output.write_bytes(b"previous verified input")

    def fail(*_):
        raise ValueError("D1 unavailable")

    monkeypatch.setattr(acme_export, "query_d1", fail)
    with pytest.raises(ValueError, match="unavailable"):
        acme_export.export_revocations(registry, output)
    assert output.read_bytes() == b"previous verified input"


def test_export_keyset_pagination_and_idempotence(export_fixture, monkeypatch):
    registry, _, _, _, _, row = export_fixture
    output = registry.parent / "merged.json"
    calls = []

    def query(sql, params):
        calls.append(params[0])
        return [row] if params[0] == "" else []

    monkeypatch.setattr(acme_export, "query_d1", query)
    acme_export.export_revocations(registry, output)
    first = output.read_bytes()
    acme_export.export_revocations(registry, output)
    assert output.read_bytes() == first
    assert calls == ["", "leaf", "", "leaf"]
