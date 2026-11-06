import argparse
import os
import tempfile
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, rsa

SIGNATURE_ONLY_PRIVATE_KEY_TYPES = (
    mldsa.MLDSA65PrivateKey,
    mldsa.MLDSA87PrivateKey,
    mldsa.MLDSA44PrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)

SUPPORTED_PRIVATE_KEY_TYPES = (
    *SIGNATURE_ONLY_PRIVATE_KEY_TYPES,
    ec.EllipticCurvePrivateKey,
    rsa.RSAPrivateKey,
)

SIGNATURE_ONLY_PUBLIC_KEY_TYPES = (
    mldsa.MLDSA65PublicKey,
    mldsa.MLDSA87PublicKey,
    mldsa.MLDSA44PublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
)

SUPPORTED_PUBLIC_KEY_TYPES = (
    *SIGNATURE_ONLY_PUBLIC_KEY_TYPES,
    ec.EllipticCurvePublicKey,
    rsa.RSAPublicKey,
)

REVOCATION_REASONS = (
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "privilege_withdrawn",
    "aa_compromise",
)

VALID_REASONS = frozenset(REVOCATION_REASONS)


def signing_hash_algorithm(key: object) -> hashes.HashAlgorithm | None:
    """Return None for schemes that embed the digest (EdDSA/ML-DSA)."""
    if isinstance(key, SIGNATURE_ONLY_PRIVATE_KEY_TYPES):
        return None
    return hashes.SHA256()


def format_rfc3339(value: datetime) -> str:
    """Format an aware UTC datetime as RFC 3339 with a 'Z' suffix."""
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_ca_key(ca_id: str, pk_env: str):
    """Load CA private key from the designated environment variable."""
    secret = os.environ.get(pk_env)
    if not secret:
        raise ValueError(
            f"private key missing for CA '{ca_id}': environment variable ${pk_env} is not set or empty"
        )

    password = os.environ.get("CFMS_PKI_KEY_PASSWORD")
    try:
        key = serialization.load_pem_private_key(
            secret.encode("utf-8"),
            password=password.encode("utf-8") if password else None,
        )
    except Exception as exc:
        raise ValueError(
            f"failed to load private key for CA '{ca_id}' from ${pk_env}: {exc}"
        ) from exc

    if not isinstance(key, SUPPORTED_PRIVATE_KEY_TYPES):
        raise TypeError(
            f"unsupported key type for CA '{ca_id}': use ML-DSA, Ed25519, Ed448, ECDSA, or RSA"
        )
    return key


def resolve_ca_path(location: str, registry_dir: Path) -> Path:
    """Resolve the location of a CA certificate file."""
    loc = Path(location)
    if loc.exists():
        return loc

    for candidate in (registry_dir.parent / loc, registry_dir / loc):
        if candidate.exists():
            return candidate

    raise FileNotFoundError(f"CA certificate file not found: {location}")


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
    if not isinstance(key, SUPPORTED_PRIVATE_KEY_TYPES):
        raise TypeError(
            "unsupported key type: use ML-DSA, Ed25519, Ed448, ECDSA, or RSA"
        )
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
    if not isinstance(public_key, SUPPORTED_PUBLIC_KEY_TYPES):
        raise TypeError(
            "unsupported issuer key type: use ML-DSA, Ed25519, Ed448, ECDSA, or RSA"
        )

    try:
        ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


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
