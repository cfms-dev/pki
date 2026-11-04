import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
)
from cryptography.x509.oid import ExtensionOID

from cfms_pki.shared import (
    authority_key_identifier,
    check_signer,
    load_signing_key,
    write_atomic,
)


def load_previous(path: Path, ca: x509.Certificate, now: datetime):
    previous = x509.load_pem_x509_crl(path.read_bytes())
    public_key = ca.public_key()

    if not isinstance(public_key, CertificateIssuerPublicKeyTypes):
        raise TypeError(f"Unsupported CA public key type: {type(public_key).__name__}")

    if previous.issuer != ca.subject or not previous.is_signature_valid(public_key):
        raise ValueError(
            f"previous CRL has a different issuer or invalid signature: {path}"
        )
    if previous.last_update_utc > now:
        raise ValueError("previous CRL has a future thisUpdate")

    # This CLI supports full, direct CRLs only; don't silently discard scope extensions.
    supported = {ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    if any(ext.oid not in supported for ext in previous.extensions):
        raise ValueError("previous CRL has extensions this CLI cannot preserve")

    try:
        number = previous.extensions.get_extension_for_class(
            x509.CRLNumber
        ).value.crl_number
    except x509.ExtensionNotFound:
        raise ValueError("previous CRL lacks CRLNumber") from None
    return previous, number


def issue_crl(args: argparse.Namespace) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    ca = x509.load_pem_x509_certificate(args.issuer.read_bytes())
    key = load_signing_key(args)
    check_signer(ca, key, now)

    previous_path = args.previous if args.previous is not None else args.output
    if previous_path.exists():
        previous, old_number = load_previous(previous_path, ca, now)
        revoked = {entry.serial_number: entry for entry in previous}
        crl_number = old_number + 1
    else:
        if args.require_previous or args.previous is not None:
            raise ValueError(f"required previous CRL not found: {previous_path}")
        revoked = {}
        crl_number = 1

    for serial in args.revoke:
        if serial not in revoked:
            revoked[serial] = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(now)
                .build()
            )

    end = min(now + timedelta(days=args.valid_days), ca.not_valid_after_utc)
    if end <= now:
        raise ValueError("CRL validity would be empty")

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now)
        .next_update(end)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(authority_key_identifier(ca), critical=False)
    )
    for entry in sorted(revoked.values(), key=lambda e: e.serial_number):
        builder = builder.add_revoked_certificate(entry)

    hash_algorithm = (
        None
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
        else hashes.SHA256()
    )
    crl = builder.sign(private_key=key, algorithm=hash_algorithm)

    public_key = ca.public_key()
    if not isinstance(public_key, CertificateIssuerPublicKeyTypes):
        raise TypeError(f"Unsupported CA public key type: {type(public_key).__name__}")

    if not crl.is_signature_valid(public_key):
        raise ValueError("generated CRL failed signature verification")
    write_atomic(args.output, crl.public_bytes(serialization.Encoding.PEM))
    print(f"Issued {args.output} (CRLNumber={crl_number}, revoked={len(revoked)})")
