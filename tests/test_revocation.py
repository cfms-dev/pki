import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.x509.oid import NameOID

from cfms_pki.cli import main
from cfms_pki.revocation import (
    match_ca,
    parse_serial_string,
)


@pytest.fixture
def ca_environment(tmp_path: Path):
    """Create a temporary PKI environment with CAs and certificates."""
    reg_dir = tmp_path / "registry"
    certs_dir = tmp_path / "certs"
    reg_dir.mkdir()
    certs_dir.mkdir()

    # Create Intermediate CA 1
    ca1_key = ec.generate_private_key(ec.SECP256R1())
    ca1_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA 1"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )
    ca1_cert = (
        x509.CertificateBuilder()
        .subject_name(ca1_name)
        .issuer_name(ca1_name)
        .public_key(ca1_key.public_key())
        .serial_number(0x1001)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca1_key.public_key()),
            critical=False,
        )
        .sign(ca1_key, hashes.SHA256())
    )
    ca1_pem = certs_dir / "ca1.pem"
    ca1_pem.write_bytes(ca1_cert.public_bytes(serialization.Encoding.PEM))

    # Create Intermediate CA 2
    ca2_key = ec.generate_private_key(ec.SECP256R1())
    ca2_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA 2"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )
    ca2_cert = (
        x509.CertificateBuilder()
        .subject_name(ca2_name)
        .issuer_name(ca2_name)
        .public_key(ca2_key.public_key())
        .serial_number(0x2001)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca2_key.public_key()),
            critical=False,
        )
        .sign(ca2_key, hashes.SHA256())
    )
    ca2_pem = certs_dir / "ca2.pem"
    ca2_pem.write_bytes(ca2_cert.public_bytes(serialization.Encoding.PEM))

    # Leaf cert signed by CA 1
    leaf1_key = ec.generate_private_key(ec.SECP256R1())
    leaf1_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf1.example.com")])
        )
        .issuer_name(ca1_name)
        .public_key(leaf1_key.public_key())
        .serial_number(0x30E24C)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca1_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )
        .sign(ca1_key, hashes.SHA256())
    )
    leaf1_pem = certs_dir / "leaf1.pem"
    leaf1_pem.write_bytes(leaf1_cert.public_bytes(serialization.Encoding.PEM))

    # ca.json
    ca_json_path = reg_dir / "ca.json"
    ca_json_data = {
        "$schema": "../schemas/ca-registry.schema.json",
        "cas": {
            "ca-one": {
                "location": str(ca1_pem),
                "pk_env": "PK_CA_ONE",
            },
            "ca-two": {
                "location": str(ca2_pem),
                "pk_env": "PK_CA_TWO",
            },
        },
    }
    ca_json_path.write_text(json.dumps(ca_json_data, indent=4), encoding="utf-8")

    return {
        "reg_dir": reg_dir,
        "ca1_cert": ca1_cert,
        "ca2_cert": ca2_cert,
        "leaf1_cert": leaf1_cert,
        "leaf1_pem": leaf1_pem,
        "ca1_key": ca1_key,
        "ca2_key": ca2_key,
        "certs_dir": certs_dir,
    }


def test_parse_serial_string():
    s_int, s_hex = parse_serial_string("12345")
    assert s_int == 12345
    assert s_hex == "3039"

    s_int, s_hex = parse_serial_string("0x1A2B")
    assert s_int == 0x1A2B
    assert s_hex == "1A2B"

    s_int, s_hex = parse_serial_string("30E24CEFA")
    assert s_int == 0x30E24CEFA
    assert s_hex == "30E24CEFA"

    with pytest.raises(ValueError, match="positive integer"):
        parse_serial_string("0")

    with pytest.raises(ValueError, match="positive integer"):
        parse_serial_string("invalid_serial")


def test_match_ca(ca_environment):
    env = ca_environment
    assert match_ca(env["leaf1_cert"], env["ca1_cert"]) is True
    assert match_ca(env["leaf1_cert"], env["ca2_cert"]) is False


def test_revoke_cli_pem_auto_inference(ca_environment, monkeypatch):
    env = ca_environment
    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(env["leaf1_pem"]),
        "--registry-dir",
        str(env["reg_dir"]),
        "--reason",
        "key_compromise",
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    # Verify revocations.json
    rev_path = env["reg_dir"] / "revocations.json"
    assert rev_path.exists()
    data = json.loads(rev_path.read_text(encoding="utf-8"))
    assert "ca-one" in data["revocations"]
    assert "30E24C" in data["revocations"]["ca-one"]
    entry = data["revocations"]["ca-one"]["30E24C"]
    assert entry["serial"] == "30E24C"
    assert entry["reason"] == "key_compromise"
    assert "date" in entry
    assert "not_after" in entry


def test_revoke_cli_pem_custom_name(ca_environment, monkeypatch):
    env = ca_environment
    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(env["leaf1_pem"]),
        "--name",
        "custom_leaf_cert",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    rev_path = env["reg_dir"] / "revocations.json"
    data = json.loads(rev_path.read_text(encoding="utf-8"))
    assert "custom_leaf_cert" in data["revocations"]["ca-one"]
    entry = data["revocations"]["ca-one"]["custom_leaf_cert"]
    assert entry["serial"] == "30E24C"


def test_revoke_cli_manual_mode(ca_environment, monkeypatch):
    env = ca_environment
    args = [
        "cfms-pki",
        "revoke",
        "--serial",
        "0xAABB11",
        "--ca",
        "ca-two",
        "--name",
        "manual-cert-1",
        "--registry-dir",
        str(env["reg_dir"]),
        "--reason",
        "superseded",
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    rev_path = env["reg_dir"] / "revocations.json"
    data = json.loads(rev_path.read_text(encoding="utf-8"))
    assert "ca-two" in data["revocations"]
    assert "manual-cert-1" in data["revocations"]["ca-two"]
    entry = data["revocations"]["ca-two"]["manual-cert-1"]
    assert entry["serial"] == "AABB11"
    assert entry["reason"] == "superseded"


def test_revoke_multiple_matching_cas(ca_environment, monkeypatch):
    """When a cert matches multiple CAs (e.g. cross-signed/reissued with same key and subject),

    CLI must list candidate CAs and require user to specify with --ca.
    """
    env = ca_environment
    # Add a duplicate CA in registry with same subject and key as ca-one
    ca_json_path = env["reg_dir"] / "ca.json"
    ca_data = json.loads(ca_json_path.read_text(encoding="utf-8"))
    ca_data["cas"]["ca-one-dup"] = {
        "location": ca_data["cas"]["ca-one"]["location"],
        "pk_env": "PK_CA_ONE_DUP",
    }
    ca_json_path.write_text(json.dumps(ca_data), encoding="utf-8")

    # Attempt to revoke without --ca should fail and list candidate CAs
    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(env["leaf1_pem"]),
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1

    # But specifying --ca ca-one succeeds
    args_with_ca = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(env["leaf1_pem"]),
        "--ca",
        "ca-one",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args_with_ca)
    main()

    rev_path = env["reg_dir"] / "revocations.json"
    data = json.loads(rev_path.read_text(encoding="utf-8"))
    assert "ca-one" in data["revocations"]
    assert "30E24C" in data["revocations"]["ca-one"]


def test_revoke_unmatched_ca(ca_environment, monkeypatch):
    env = ca_environment
    # Generate cert signed by another key
    unknown_key = ec.generate_private_key(ec.SECP256R1())
    unknown_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unknown Root")])
    unknown_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.example.com")])
        )
        .issuer_name(unknown_name)
        .public_key(unknown_key.public_key())
        .serial_number(999)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(unknown_key, hashes.SHA256())
    )
    unknown_pem = env["certs_dir"] / "unknown.pem"
    unknown_pem.write_bytes(unknown_cert.public_bytes(serialization.Encoding.PEM))

    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(unknown_pem),
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_invalid_key_name(ca_environment, monkeypatch):
    env = ca_environment
    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(env["leaf1_pem"]),
        "--name",
        "invalid name with spaces!",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_invalid_date(ca_environment, monkeypatch):
    env = ca_environment
    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(env["leaf1_pem"]),
        "--date",
        "not-a-date",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_missing_args_manual_mode(ca_environment, monkeypatch):
    env = ca_environment
    # Neither pem nor serial
    args1 = [
        "cfms-pki",
        "revoke",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args1)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1

    # Serial provided but no ca
    args2 = [
        "cfms-pki",
        "revoke",
        "--serial",
        "0x123",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args2)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1

    # Ca not in registry
    args3 = [
        "cfms-pki",
        "revoke",
        "--serial",
        "0x123",
        "--ca",
        "non-existent-ca",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args3)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_update_existing_entry(ca_environment, monkeypatch):
    env = ca_environment
    # First revocation
    args1 = [
        "cfms-pki",
        "revoke",
        "--serial",
        "0x12345",
        "--ca",
        "ca-one",
        "--name",
        "cert-to-update",
        "--reason",
        "key_compromise",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args1)
    main()

    # Update with new reason
    args2 = [
        "cfms-pki",
        "revoke",
        "--serial",
        "0x12345",
        "--ca",
        "ca-one",
        "--name",
        "cert-to-update",
        "--reason",
        "superseded",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args2)
    main()

    rev_path = env["reg_dir"] / "revocations.json"
    data = json.loads(rev_path.read_text(encoding="utf-8"))
    entry = data["revocations"]["ca-one"]["cert-to-update"]
    assert entry["reason"] == "superseded"


@pytest.mark.parametrize(
    "algo,key_factory",
    [
        ("mldsa65", mldsa.MLDSA65PrivateKey.generate),
        ("mldsa87", mldsa.MLDSA87PrivateKey.generate),
        ("ed25519", ed25519.Ed25519PrivateKey.generate),
    ],
)
def test_revoke_pqc_and_ed25519(tmp_path: Path, monkeypatch, algo, key_factory):
    """Test revoking a certificate signed by ML-DSA-65, ML-DSA-87, or Ed25519 CA."""
    reg_dir = tmp_path / "registry"
    certs_dir = tmp_path / "certs"
    reg_dir.mkdir()
    certs_dir.mkdir()

    ca_key = key_factory()
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"{algo.upper()} CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test PKI"),
        ]
    )
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0x5555)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )

    ca_pem_path = certs_dir / f"{algo}-ca.pem"
    ca_pem_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Issue a leaf certificate signed by this CA
    leaf_key = key_factory()
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"Leaf for {algo}"),
        ]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0xABCDEF)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )

    leaf_pem_path = tmp_path / f"{algo}-leaf.pem"
    leaf_pem_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))

    ca_registry = {
        "cas": {
            f"{algo}-ca": {
                "location": f"certs/{algo}-ca.pem",
                "pk_env": f"PK_{algo.upper()}_CA",
            }
        }
    }
    (reg_dir / "ca.json").write_text(json.dumps(ca_registry))
    (reg_dir / "revocations.json").write_text(json.dumps({"revocations": {}}))

    args = [
        "cfms-pki",
        "revoke",
        "--pem",
        str(leaf_pem_path),
        "--reason",
        "key_compromise",
        "--registry-dir",
        str(reg_dir),
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    rev_data = json.loads((reg_dir / "revocations.json").read_text())
    assert f"{algo}-ca" in rev_data["revocations"]
    assert "ABCDEF" in rev_data["revocations"][f"{algo}-ca"]
    assert rev_data["revocations"][f"{algo}-ca"]["ABCDEF"]["reason"] == "key_compromise"
