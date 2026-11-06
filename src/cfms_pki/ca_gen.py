"""Generate Root and Intermediate CA keys and certificates."""

import argparse
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, rsa
from cryptography.x509.oid import NameOID

from cfms_pki.revocation import verify_cert_signature
from cfms_pki.shared import (
    SUPPORTED_PRIVATE_KEY_TYPES,
    authority_key_identifier,
    signing_hash_algorithm,
    write_atomic,
)

ALGORITHM_MAP = {
    "mldsa65": mldsa.MLDSA65PrivateKey.generate,
    "mldsa87": mldsa.MLDSA87PrivateKey.generate,
    "mldsa44": mldsa.MLDSA44PrivateKey.generate,
    "ed25519": ed25519.Ed25519PrivateKey.generate,
    "ecdsa": lambda: ec.generate_private_key(ec.SECP256R1()),
    "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
}


def generate_ca_key(algorithm: str):
    """Generate a private key for the given algorithm name."""
    algo_lower = algorithm.lower()
    generator = ALGORITHM_MAP.get(algo_lower)
    if not generator:
        valid_algos = ", ".join(ALGORITHM_MAP.keys())
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Choose from: {valid_algos}"
        )
    return generator()


def load_issuer_key(
    issuer_key_path: Path | None = None,
    issuer_key_env: str | None = None,
    issuer_key_password: str | None = None,
):
    """Load issuer private key from file or environment variable."""
    if issuer_key_path is not None:
        pem_bytes = issuer_key_path.read_bytes()
    elif issuer_key_env:
        secret = os.environ.get(issuer_key_env)
        if not secret:
            raise ValueError(
                f"Issuer private key environment variable ${issuer_key_env} is not set or empty"
            )
        pem_bytes = secret.encode("utf-8")
    else:
        raise ValueError("Must provide either --issuer-key or --issuer-key-env")

    password_bytes = (
        issuer_key_password.encode("utf-8") if issuer_key_password else None
    )
    key = serialization.load_pem_private_key(pem_bytes, password=password_bytes)
    if not isinstance(key, SUPPORTED_PRIVATE_KEY_TYPES):
        raise TypeError(
            f"Unsupported issuer key type: {type(key).__name__}. "
            "Supported types: ML-DSA, Ed25519, Ed448, ECDSA, RSA"
        )
    return key


def build_ca_certificate(
    subject_dn: x509.Name,
    key: Any,
    valid_days: int = 1095,
    path_length: int | None = 0,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: Any | None = None,
) -> x509.Certificate:
    """Build and sign an X.509 CA certificate (Self-Signed Root or Intermediate)."""
    now = datetime.now(UTC)
    not_after = now + timedelta(days=valid_days)

    is_self_signed = issuer_cert is None
    signing_key = key if is_self_signed else issuer_key
    if signing_key is None:
        raise ValueError("Missing signing key for CA certificate")

    issuer_name = subject_dn if is_self_signed else issuer_cert.subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_dn)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
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
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )

    if is_self_signed:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            authority_key_identifier(issuer_cert),
            critical=False,
        )

    hash_algorithm = signing_hash_algorithm(signing_key)
    cert = builder.sign(private_key=signing_key, algorithm=hash_algorithm)

    # Self-validation
    verification_cert = cert if is_self_signed else issuer_cert
    if not verify_cert_signature(cert, verification_cert):
        raise ValueError("Generated CA certificate failed signature verification")

    return cert


def generate_ca(
    common_name: str,
    algorithm: str = "mldsa65",
    organization: str = "CFMS Intermediate CA Management Organization",
    country: str = "CN",
    state: str = "Beijing",
    locality: str = "Beijing",
    valid_days: int | None = None,
    path_length: int | None = None,
    issuer_cert_path: Path | None = None,
    issuer_key_path: Path | None = None,
    issuer_key_env: str | None = None,
    issuer_key_password: str | None = None,
    out_cert_path: Path | None = None,
    out_key_path: Path | None = None,
    key_password: str | None = None,
) -> tuple[x509.Certificate, Any]:
    """Generate CA key and certificate, then optionally save them to disk."""
    is_intermediate = issuer_cert_path is not None

    if valid_days is None:
        valid_days = 1095 if is_intermediate else 3650

    if path_length is None and is_intermediate:
        path_length = 0

    key = generate_ca_key(algorithm)

    subject_dn = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    issuer_cert = None
    issuer_key = None
    if is_intermediate:
        if not issuer_cert_path.exists():
            raise FileNotFoundError(f"Issuer certificate not found: {issuer_cert_path}")
        issuer_cert = x509.load_pem_x509_certificate(issuer_cert_path.read_bytes())
        issuer_key = load_issuer_key(
            issuer_key_path=issuer_key_path,
            issuer_key_env=issuer_key_env,
            issuer_key_password=issuer_key_password,
        )

    cert = build_ca_certificate(
        subject_dn=subject_dn,
        key=key,
        valid_days=valid_days,
        path_length=path_length,
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
    )

    # Export private key PEM (PKCS#8 for universal support across EC, RSA, Ed25519, ML-DSA)
    enc_algo = (
        serialization.BestAvailableEncryption(key_password.encode("utf-8"))
        if key_password
        else serialization.NoEncryption()
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    if out_key_path:
        out_key_path.parent.mkdir(parents=True, exist_ok=True)
        # Write private key with restrictive permissions
        write_atomic(out_key_path, key_pem)
        try:
            os.chmod(out_key_path, 0o600)
        except OSError:
            pass

    if out_cert_path:
        out_cert_path.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(out_cert_path, cert_pem)

    return cert, key


def register_gen_ca_cli(subparsers: argparse._SubParsersAction) -> None:
    """Register 'gen-ca' subcommand to the main CLI parser."""
    parser = subparsers.add_parser(
        "gen-ca",
        help="generate CA private key and certificate (defaults to ML-DSA-65)",
    )
    parser.add_argument(
        "--algorithm",
        "-a",
        choices=["mldsa65", "mldsa87", "mldsa44", "ed25519", "ecdsa", "rsa"],
        default="mldsa65",
        help="signature algorithm for the CA key (default: mldsa65)",
    )
    parser.add_argument(
        "--common-name",
        "--cn",
        required=True,
        help="Common Name (CN) for the CA certificate",
    )
    parser.add_argument(
        "--organization",
        "--org",
        default="CFMS Intermediate CA Management Organization",
        help="Organization (O) for the CA certificate",
    )
    parser.add_argument(
        "--country",
        "-c",
        default="CN",
        help="Country (C) code (default: CN)",
    )
    parser.add_argument(
        "--state",
        "-s",
        default="Beijing",
        help="State or province (ST) (default: Beijing)",
    )
    parser.add_argument(
        "--locality",
        "-l",
        default="Beijing",
        help="Locality (L) (default: Beijing)",
    )
    parser.add_argument(
        "--valid-days",
        type=int,
        default=None,
        help="validity period in days (defaults: 1095 for intermediate, 3650 for root)",
    )
    parser.add_argument(
        "--path-length",
        type=int,
        default=None,
        help="BasicConstraints path_length (default: 0 for intermediate, None for root)",
    )
    parser.add_argument(
        "--issuer-cert",
        type=Path,
        default=None,
        help="path to issuer CA certificate (creates intermediate CA; if omitted, creates self-signed Root CA)",
    )
    parser.add_argument(
        "--issuer-key",
        type=Path,
        default=None,
        help="path to issuer CA private key file (PEM)",
    )
    parser.add_argument(
        "--issuer-key-env",
        type=str,
        default=None,
        help="environment variable containing issuer CA private key",
    )
    parser.add_argument(
        "--issuer-key-password",
        type=str,
        default=None,
        help="password for encrypted issuer private key",
    )
    parser.add_argument(
        "--out-cert",
        type=Path,
        required=True,
        help="output destination path for CA certificate PEM",
    )
    parser.add_argument(
        "--out-key",
        type=Path,
        required=True,
        help="output destination path for CA private key PEM (PKCS#8)",
    )
    parser.add_argument(
        "--key-password",
        type=str,
        default=None,
        help="password to encrypt generated private key (optional)",
    )
