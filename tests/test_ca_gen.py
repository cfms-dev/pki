import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from cfms_pki.ca_gen import generate_ca


def test_gen_ca_self_signed_mldsa65(tmp_path: Path):
    """Test generating a self-signed Root CA with default ML-DSA-65."""
    cert_path = tmp_path / "root.pem"
    key_path = tmp_path / "root.key"

    cert, key = generate_ca(
        common_name="Test Root CA",
        out_cert_path=cert_path,
        out_key_path=key_path,
    )

    assert cert_path.exists()
    assert key_path.exists()
    assert isinstance(key, mldsa.MLDSA65PrivateKey)
    assert (
        cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        == "Test Root CA"
    )
    assert cert.issuer == cert.subject
    assert (
        cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    )


def test_gen_ca_intermediate_mldsa65(tmp_path: Path):
    """Test generating an intermediate CA signed by root."""
    root_cert_path = tmp_path / "root.pem"
    root_key_path = tmp_path / "root.key"
    int_cert_path = tmp_path / "int.pem"
    int_key_path = tmp_path / "int.key"

    root_cert, _ = generate_ca(
        common_name="Test Root CA",
        algorithm="mldsa65",
        out_cert_path=root_cert_path,
        out_key_path=root_key_path,
    )

    int_cert, int_key = generate_ca(
        common_name="Test Intermediate CA",
        algorithm="mldsa65",
        issuer_cert_path=root_cert_path,
        issuer_key_path=root_key_path,
        out_cert_path=int_cert_path,
        out_key_path=int_key_path,
    )

    assert int_cert.issuer == root_cert.subject
    assert (
        int_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        == "Test Intermediate CA"
    )
    assert (
        int_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length
        == 0
    )
    assert isinstance(int_key, mldsa.MLDSA65PrivateKey)


def test_gen_ca_mldsa87(tmp_path: Path):
    """Test generating CA with ML-DSA-87."""
    cert_path = tmp_path / "ca87.pem"
    key_path = tmp_path / "ca87.key"

    cert, key = generate_ca(
        common_name="Test ML-DSA-87 CA",
        algorithm="mldsa87",
        out_cert_path=cert_path,
        out_key_path=key_path,
    )

    assert isinstance(key, mldsa.MLDSA87PrivateKey)
    assert cert.signature_algorithm_oid.dotted_string == "2.16.840.1.101.3.4.3.19"


def test_gen_ca_ed25519(tmp_path: Path):
    """Test generating CA with Ed25519."""
    cert_path = tmp_path / "ca_ed.pem"
    key_path = tmp_path / "ca_ed.key"

    cert, key = generate_ca(
        common_name="Test Ed25519 CA",
        algorithm="ed25519",
        out_cert_path=cert_path,
        out_key_path=key_path,
    )

    assert isinstance(key, ed25519.Ed25519PrivateKey)
    assert cert.signature_algorithm_oid.dotted_string == "1.3.101.112"


def test_gen_ca_with_password(tmp_path: Path):
    """Test generating CA with password-encrypted private key."""
    cert_path = tmp_path / "ca_enc.pem"
    key_path = tmp_path / "ca_enc.key"

    generate_ca(
        common_name="Encrypted CA",
        algorithm="mldsa65",
        key_password="secure_password_123",
        out_cert_path=cert_path,
        out_key_path=key_path,
    )

    raw_key = key_path.read_bytes()
    assert b"ENCRYPTED" in raw_key
    loaded = serialization.load_pem_private_key(
        raw_key, password=b"secure_password_123"
    )
    assert isinstance(loaded, mldsa.MLDSA65PrivateKey)


def test_gen_ca_cli_runner(tmp_path: Path):
    """Test executing gen-ca CLI command."""
    cert_path = tmp_path / "cli_cert.pem"
    key_path = tmp_path / "cli_key.pem"

    res = subprocess.run(
        [
            "uv",
            "run",
            "cfms-pki",
            "gen-ca",
            "--cn",
            "CLI CA Test",
            "--out-cert",
            str(cert_path),
            "--out-key",
            str(key_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "Generated CA (mldsa65)" in res.stdout
    assert cert_path.exists()
    assert key_path.exists()
