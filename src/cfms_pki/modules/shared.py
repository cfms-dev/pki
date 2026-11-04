import argparse
import os
import tempfile
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa


def load_signing_key(args: argparse.Namespace):
    if args.key_file is not None:
        pem = args.key_file.read_bytes()
    else:
        variable = args.key_env or "CFMS_PKI_PRIVATE_KEY"
        secret = os.environ.get(variable)
        if not secret:
            raise ValueError(f"private key missing: provide --key-file or ${variable}")
        pem = secret.encode("utf-8")

    password = os.environ.get("CFMS_PKI_KEY_PASSWORD")
    key = serialization.load_pem_private_key(
        pem, password=password.encode("utf-8") if password else None
    )
    if not isinstance(
        key,
        (
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
        ),
    ):
        raise TypeError("unsupported key type: use RSA, ECDSA, Ed25519 or Ed448")
    return key


def check_signer(ca: x509.Certificate, key, now: datetime) -> None:
    key_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_der = ca.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if key_der != cert_der:
        raise ValueError("private key does not match issuer certificate")

    if not (ca.not_valid_before_utc <= now < ca.not_valid_after_utc):
        raise ValueError("issuer certificate is not currently valid")

    try:
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ValueError("issuer certificate lacks BasicConstraints") from None
    if not constraints.ca:
        raise ValueError("issuer certificate is not a CA")

    try:
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.crl_sign:
        raise ValueError("issuer certificate forbids CRL signing")


def authority_key_identifier(ca: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    public_key = ca.public_key()
    if not isinstance(
        public_key,
        (
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ),
    ):
        raise TypeError("unsupported issuer key type: use RSA, ECDSA, Ed25519 or Ed448")

    try:
        ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def parse_serial(value: str) -> int:
    """Accept decimal serials or hexadecimal serials prefixed with 0x."""
    try:
        serial = int(value, 0) if value.startswith(("0x", "0X")) else int(value, 10)
        if serial <= 0:
            raise ValueError
        return serial
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "serial must be a positive decimal integer or 0x-prefixed hex"
        ) from exc


def write_atomic(path: Path, content: bytes) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)  # CRLs are public, unlike CA private keys.
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)