import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.x509.oid import NameOID

from cfms_pki.cli import main
from cfms_pki.crl.issuing import (
    generate_crl_number,
    resolve_crl_output_path,
)


@pytest.fixture
def crl_pki_env(tmp_path: Path, monkeypatch):
    """Set up a complete temporary PKI environment with CAs, keys, and registry."""
    reg_dir = tmp_path / "registry"
    certs_dir = tmp_path / "certs"
    crl_dir = tmp_path / "crl"
    reg_dir.mkdir()
    certs_dir.mkdir()
    crl_dir.mkdir()

    # Generate CA 1
    ca1_key = ec.generate_private_key(ec.SECP256R1())
    ca1_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA 1"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test PKI"),
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
            x509.KeyUsage(
                digital_signature=False,
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
            x509.SubjectKeyIdentifier.from_public_key(ca1_key.public_key()),
            critical=False,
        )
        .sign(ca1_key, hashes.SHA256())
    )
    ca1_pem = certs_dir / "ca1.pem"
    ca1_pem.write_bytes(ca1_cert.public_bytes(serialization.Encoding.PEM))

    # Generate CA 2
    ca2_key = ec.generate_private_key(ec.SECP256R1())
    ca2_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA 2"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test PKI"),
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
            x509.KeyUsage(
                digital_signature=False,
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
            x509.SubjectKeyIdentifier.from_public_key(ca2_key.public_key()),
            critical=False,
        )
        .sign(ca2_key, hashes.SHA256())
    )
    ca2_pem = certs_dir / "ca2.pem"
    ca2_pem.write_bytes(ca2_cert.public_bytes(serialization.Encoding.PEM))

    # Set up environment variables with PEM keys
    ca1_key_pem = ca1_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    ca2_key_pem = ca2_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    monkeypatch.setenv("PK_TEST_CA_ONE", ca1_key_pem)
    monkeypatch.setenv("PK_TEST_CA_TWO", ca2_key_pem)

    # ca.json
    ca_json_data = {
        "$schema": "../schemas/ca-registry.schema.json",
        "cas": {
            "ca-one": {
                "location": str(ca1_pem),
                "pk_env": "PK_TEST_CA_ONE",
            },
            "ca-two": {
                "location": str(ca2_pem),
                "pk_env": "PK_TEST_CA_TWO",
            },
        },
    }
    (reg_dir / "ca.json").write_text(
        json.dumps(ca_json_data, indent=4), encoding="utf-8"
    )

    # revocations.json
    rev_json_data = {
        "$schema": "../schemas/revocations.schema.json",
        "revocations": {
            "ca-one": {
                "revoked-leaf-1": {
                    "serial": "1A2B3C",
                    "date": "2026-11-04T10:00:00Z",
                    "reason": "key_compromise",
                },
                "revoked-leaf-2": {
                    "serial": "4D5E6F",
                    "date": "2026-11-04T11:00:00Z",
                    "reason": "superseded",
                },
            },
            "ca-two": {
                "revoked-leaf-3": {
                    "serial": "7A8B9C",
                    "date": "2026-11-04T12:00:00Z",
                    "reason": "cessation_of_operation",
                }
            },
        },
    }
    (reg_dir / "revocations.json").write_text(
        json.dumps(rev_json_data, indent=4), encoding="utf-8"
    )

    return {
        "reg_dir": reg_dir,
        "certs_dir": certs_dir,
        "crl_dir": crl_dir,
        "ca1_cert": ca1_cert,
        "ca2_cert": ca2_cert,
        "ca1_key": ca1_key,
        "ca2_key": ca2_key,
    }


def test_generate_crl_number():
    """Verify CRLNumber generation algorithm, bit length, MSB=0, and DER constraints."""
    for _ in range(50):
        crl_num = generate_crl_number()
        assert isinstance(crl_num, int)
        assert crl_num >= 0

        # Must fit within 160 bits and have MSB (bit 159) cleared (<= 159 bits)
        assert crl_num < (1 << 159)
        assert crl_num.bit_length() <= 159

        # ASN.1 DER encoding length of CRLNumber must be <= 20 bytes (RFC 5280)
        crl_ext = x509.CRLNumber(crl_num)
        assert crl_ext.crl_number == crl_num

        raw_bytes = crl_num.to_bytes(20, "big")
        assert len(raw_bytes) == 20
        # High bit of first byte is guaranteed to be 0
        assert (raw_bytes[0] & 0x80) == 0


def test_resolve_crl_output_path(tmp_path: Path):
    reg_dir = tmp_path / "registry"

    # Default without crl_path
    ca_info_default = {"location": "certs/ca.pem", "pk_env": "PK_CA"}
    p_def = resolve_crl_output_path("my-ca", ca_info_default, reg_dir)
    assert p_def == tmp_path / "crl" / "my-ca.crl"

    # Custom relative crl_path
    ca_info_custom = {
        "location": "certs/ca.pem",
        "pk_env": "PK_CA",
        "crl_path": "custom-output/test.crl",
    }
    p_custom = resolve_crl_output_path("my-ca", ca_info_custom, reg_dir)
    assert p_custom == tmp_path / "custom-output" / "test.crl"

    # Custom absolute crl_path
    abs_path = tmp_path / "abs" / "out.crl"
    ca_info_abs = {
        "location": "certs/ca.pem",
        "pk_env": "PK_CA",
        "crl_path": str(abs_path),
    }
    p_abs = resolve_crl_output_path("my-ca", ca_info_abs, reg_dir)
    assert p_abs == abs_path


def test_issue_crl_default_all_cas(crl_pki_env, monkeypatch):
    """Running issue-crl without positional arguments issues CRLs for all registered CAs."""
    env = crl_pki_env
    args = ["cfms-pki", "issue-crl", "--registry-dir", str(env["reg_dir"])]
    monkeypatch.setattr("sys.argv", args)
    main()

    # Check ca-one CRL
    ca1_crl_path = env["reg_dir"].parent / "crl" / "ca-one.crl"
    assert ca1_crl_path.exists()
    ca1_crl = x509.load_pem_x509_crl(ca1_crl_path.read_bytes())
    assert ca1_crl.is_signature_valid(env["ca1_cert"].public_key())
    assert ca1_crl.issuer == env["ca1_cert"].subject

    # Check CRL Number
    crl_num_ext = ca1_crl.extensions.get_extension_for_class(x509.CRLNumber)
    assert not crl_num_ext.critical
    assert crl_num_ext.value.crl_number < (1 << 159)

    # Check AuthorityKeyIdentifier
    aki_ext = ca1_crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not aki_ext.critical

    # Check revoked entries for ca-one (2 certs)
    revoked_map = {entry.serial_number: entry for entry in ca1_crl}
    assert 0x1A2B3C in revoked_map
    assert 0x4D5E6F in revoked_map
    assert len(revoked_map) == 2

    # Check CRLReason extension on revoked entry
    entry1 = revoked_map[0x1A2B3C]
    reason_ext1 = entry1.extensions.get_extension_for_class(x509.CRLReason)
    assert reason_ext1.value.reason == x509.ReasonFlags.key_compromise

    entry2 = revoked_map[0x4D5E6F]
    reason_ext2 = entry2.extensions.get_extension_for_class(x509.CRLReason)
    assert reason_ext2.value.reason == x509.ReasonFlags.superseded

    # Check ca-two CRL
    ca2_crl_path = env["reg_dir"].parent / "crl" / "ca-two.crl"
    assert ca2_crl_path.exists()
    ca2_crl = x509.load_pem_x509_crl(ca2_crl_path.read_bytes())
    assert ca2_crl.is_signature_valid(env["ca2_cert"].public_key())
    assert len(ca2_crl) == 1
    assert ca2_crl[0].serial_number == 0x7A8B9C


def test_issue_crl_selective_positional_cas(crl_pki_env, monkeypatch):
    """Specifying CA names as positional arguments only issues CRLs for those CAs."""
    env = crl_pki_env
    args = [
        "cfms-pki",
        "issue-crl",
        "ca-one",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    ca1_crl_path = env["reg_dir"].parent / "crl" / "ca-one.crl"
    ca2_crl_path = env["reg_dir"].parent / "crl" / "ca-two.crl"
    assert ca1_crl_path.exists()
    assert not ca2_crl_path.exists()


def test_issue_crl_custom_crl_path(crl_pki_env, monkeypatch):
    """When crl_path is specified in ca.json, CRL is output to that custom path."""
    env = crl_pki_env
    ca_json_path = env["reg_dir"] / "ca.json"
    data = json.loads(ca_json_path.read_text(encoding="utf-8"))
    data["cas"]["ca-one"]["crl_path"] = "custom-dist/my-custom-name.crl"
    ca_json_path.write_text(json.dumps(data, indent=4), encoding="utf-8")

    args = [
        "cfms-pki",
        "issue-crl",
        "ca-one",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    custom_path = env["reg_dir"].parent / "custom-dist" / "my-custom-name.crl"
    assert custom_path.exists()
    crl = x509.load_pem_x509_crl(custom_path.read_bytes())
    assert crl.is_signature_valid(env["ca1_cert"].public_key())


def test_orphaned_revocations_warning_and_isolation(crl_pki_env, monkeypatch, capsys):
    """Orphaned revocation records emit a warning to stderr, but do not block valid CAs."""
    env = crl_pki_env
    rev_path = env["reg_dir"] / "revocations.json"
    rev_data = json.loads(rev_path.read_text(encoding="utf-8"))
    # Add an orphaned CA that does not exist in ca.json
    rev_data["revocations"]["orphaned-ca-unknown"] = {
        "ghost-cert": {
            "serial": "DEADBEEF",
            "date": "2026-11-04T12:00:00Z",
        }
    }
    rev_path.write_text(json.dumps(rev_data, indent=4), encoding="utf-8")

    args = ["cfms-pki", "issue-crl", "--registry-dir", str(env["reg_dir"])]
    monkeypatch.setattr("sys.argv", args)
    main()

    captured = capsys.readouterr()
    assert (
        "Warning: Revocation registry contains 1 record(s) under CA 'orphaned-ca-unknown'"
        in captured.err
    )
    assert "DEADBEEF" in captured.err

    # Both valid CAs must still have their CRLs issued successfully
    assert (env["reg_dir"].parent / "crl" / "ca-one.crl").exists()
    assert (env["reg_dir"].parent / "crl" / "ca-two.crl").exists()


def test_orphaned_revocations_fail_on_orphaned(crl_pki_env, monkeypatch):
    """When --fail-on-orphaned is given, orphaned records cause the command to fail with code 1."""
    env = crl_pki_env
    rev_path = env["reg_dir"] / "revocations.json"
    rev_data = json.loads(rev_path.read_text(encoding="utf-8"))
    rev_data["revocations"]["unregistered-ca"] = {
        "ghost-cert": {
            "serial": "AABBCC",
            "date": "2026-11-04T12:00:00Z",
        }
    }
    rev_path.write_text(json.dumps(rev_data, indent=4), encoding="utf-8")

    args = [
        "cfms-pki",
        "issue-crl",
        "--fail-on-orphaned",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_issue_crl_unknown_ca_positional_error(crl_pki_env, monkeypatch):
    """Requesting an unregistered CA via positional argument results in exit code 1."""
    env = crl_pki_env

    # 1. Unknown CA not in revocations either
    args1 = [
        "cfms-pki",
        "issue-crl",
        "completely-unknown-ca",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args1)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1

    # 2. Unknown CA that exists in revocations (orphaned)
    rev_path = env["reg_dir"] / "revocations.json"
    rev_data = json.loads(rev_path.read_text(encoding="utf-8"))
    rev_data["revocations"]["orphaned-ca"] = {
        "leaf": {"serial": "123", "date": "2026-11-04T12:00:00Z"}
    }
    rev_path.write_text(json.dumps(rev_data, indent=4), encoding="utf-8")

    args2 = [
        "cfms-pki",
        "issue-crl",
        "orphaned-ca",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args2)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_missing_private_key_env_fails(crl_pki_env, monkeypatch):
    """Missing private key environment variable raises an error and exits with code 1."""
    env = crl_pki_env
    monkeypatch.delenv("PK_TEST_CA_ONE", raising=False)

    args = [
        "cfms-pki",
        "issue-crl",
        "ca-one",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_invalid_valid_days_fails(crl_pki_env, monkeypatch):
    """Invalid valid_days values (<= 0 or > 365) are rejected."""
    env = crl_pki_env
    args = [
        "cfms-pki",
        "issue-crl",
        "--valid-days",
        "0",
        "--registry-dir",
        str(env["reg_dir"]),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


@pytest.mark.parametrize(
    "algo,key_factory",
    [
        ("mldsa65", mldsa.MLDSA65PrivateKey.generate),
        ("mldsa87", mldsa.MLDSA87PrivateKey.generate),
        ("ed25519", ed25519.Ed25519PrivateKey.generate),
    ],
)
def test_issue_crl_pqc_and_ed25519(tmp_path: Path, monkeypatch, algo, key_factory):
    """Test issuing a CRL for ML-DSA-65, ML-DSA-87, and Ed25519 intermediate CAs."""
    reg_dir = tmp_path / "registry"
    certs_dir = tmp_path / "certs"
    crl_dir = tmp_path / "crl"
    reg_dir.mkdir()
    certs_dir.mkdir()
    crl_dir.mkdir()

    ca_key = key_factory()
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"Test {algo.upper()} CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test PKI"),
        ]
    )
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0x9999)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
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

    cert_path = certs_dir / f"{algo}-ca.pem"
    cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    env_var = f"PK_{algo.upper()}_CA"
    monkeypatch.setenv(env_var, key_pem)

    ca_registry = {
        "cas": {
            f"{algo}-ca": {
                "location": f"certs/{algo}-ca.pem",
                "pk_env": env_var,
            }
        }
    }
    (reg_dir / "ca.json").write_text(json.dumps(ca_registry))
    (reg_dir / "revocations.json").write_text(json.dumps({"revocations": {}}))

    args = [
        "cfms-pki",
        "issue-crl",
        "--registry-dir",
        str(reg_dir),
    ]
    monkeypatch.setattr("sys.argv", args)
    main()

    output_crl = crl_dir / f"{algo}-ca.crl"
    assert output_crl.exists()
    crl_data = output_crl.read_bytes()
    crl = x509.load_pem_x509_crl(crl_data)
    assert crl.is_signature_valid(ca_cert.public_key())
