"""Manage certificate revocations in the registry."""

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from cfms_pki.shared import VALID_REASONS, resolve_ca_path, write_atomic

KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def parse_serial_string(value: str) -> tuple[int, str]:
    """Parse a serial number string (hex or decimal) and return (serial_int, serial_hex)."""
    raw = value.strip()
    if not raw:
        raise ValueError("Serial number cannot be empty.")

    try:
        if raw.startswith(("0x", "0X")) or any(c in "abcdefABCDEF" for c in raw):
            serial_int = int(raw, 16)
        else:
            serial_int = int(raw, 10)

        if serial_int <= 0:
            raise ValueError
    except ValueError as exc:
        raise ValueError(
            f"Invalid serial number '{value}': must be a positive integer or hex string."
        ) from exc

    return serial_int, f"{serial_int:X}"


def verify_cert_signature(
    cert: x509.Certificate, issuer_cert: x509.Certificate
) -> bool:
    """Verify that cert was signed by issuer_cert using public key cryptography."""
    pubkey = issuer_cert.public_key()
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            params = cert.signature_algorithm_parameters
            pad = params if isinstance(params, padding.PSS) else padding.PKCS1v15()
            hash_algo = cert.signature_hash_algorithm
            if hash_algo is None:
                return False
            pubkey.verify(cert.signature, cert.tbs_certificate_bytes, pad, hash_algo)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            hash_algo = cert.signature_hash_algorithm
            if hash_algo is None:
                return False
            pubkey.verify(
                cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hash_algo)
            )
        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pubkey.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
        return True
    except InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm:
        return False


def match_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Check if ca_cert issued cert using Subject/Issuer DN, AKI/SKI, and signature verification."""
    # 1. Subject DN of CA must match Issuer DN of certificate
    if ca_cert.subject != cert.issuer:
        return False

    # 2. Utilize AKI and SKI for efficient filtering if AKI is present
    try:
        cert_aki = cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        cert_aki = None

    if cert_aki is not None:
        if cert_aki.key_identifier is not None:
            try:
                ca_ski = ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
                ca_key_id = ca_ski.digest
            except x509.ExtensionNotFound:
                ca_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_cert.public_key()
                ).key_identifier
            if ca_key_id != cert_aki.key_identifier:
                return False

        if (
            cert_aki.authority_cert_serial_number is not None
            and ca_cert.serial_number != cert_aki.authority_cert_serial_number
        ):
            return False

    # 3. Cryptographic signature verification
    return verify_cert_signature(cert, ca_cert)


def find_matching_cas(
    cert: x509.Certificate, cas_data: dict[str, Any], registry_dir: Path
) -> list[str]:
    """Traverse all intermediate CAs in registry and return matching CA IDs."""
    matched: list[str] = []
    for ca_id, ca_info in cas_data.items():
        if not isinstance(ca_info, dict) or "location" not in ca_info:
            continue
        ca_path = resolve_ca_path(ca_info["location"], registry_dir)
        ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
        if match_ca(cert, ca_cert):
            matched.append(ca_id)
    return matched


def revoke_certificate(args: argparse.Namespace) -> None:
    """CLI handler for revoking a certificate and recording it in the registry."""
    registry_dir: Path = args.registry_dir
    ca_registry_path = registry_dir / "ca.json"
    if not ca_registry_path.exists():
        raise FileNotFoundError(f"CA registry not found: {ca_registry_path}")

    ca_data = json.loads(ca_registry_path.read_text(encoding="utf-8"))
    cas: dict[str, Any] = ca_data.get("cas", {})

    serial_hex: str
    default_not_after: str | None = None
    ca_id: str

    if args.pem is not None:
        if not args.pem.exists():
            raise FileNotFoundError(f"Certificate file not found: {args.pem}")
        cert = x509.load_pem_x509_certificate(args.pem.read_bytes())
        serial_int = cert.serial_number
        serial_hex = f"{serial_int:X}"
        default_not_after = (
            cert.not_valid_after_utc.replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

        matched_cas = find_matching_cas(cert, cas, registry_dir)
        if len(matched_cas) == 0:
            raise ValueError(
                f"No intermediate CA in registry signed certificate {args.pem} "
                f"(issuer: '{cert.issuer.rfc4514_string()}')."
            )
        if len(matched_cas) > 1:
            if args.ca and args.ca in matched_cas:
                ca_id = args.ca
            else:
                candidates = ", ".join(repr(c) for c in sorted(matched_cas))
                raise ValueError(
                    f"Certificate matches multiple intermediate CAs: [{candidates}]. "
                    "Please specify which intermediate CA to use with --ca."
                )
        else:
            inferred_ca = matched_cas[0]
            if args.ca and args.ca != inferred_ca:
                raise ValueError(
                    f"Specified CA '{args.ca}' does not match inferred signing CA '{inferred_ca}'."
                )
            ca_id = inferred_ca

        if args.serial:
            _, user_serial_hex = parse_serial_string(args.serial)
            if user_serial_hex != serial_hex:
                raise ValueError(
                    f"Provided --serial ({user_serial_hex}) does not match PEM certificate serial ({serial_hex})."
                )
    else:
        if not args.serial:
            raise ValueError(
                "Either --pem (certificate file) or both --serial and --ca must be provided."
            )
        if not args.ca:
            raise ValueError(
                "When --pem is not provided, intermediate CA id (--ca) is required."
            )
        if args.ca not in cas:
            raise ValueError(f"CA '{args.ca}' not found in registry.")

        ca_id = args.ca
        _, serial_hex = parse_serial_string(args.serial)

    # Determine key name in registry
    if args.name:
        key_name = args.name.strip()
        if not KEY_NAME_RE.match(key_name):
            raise ValueError(
                f"Invalid key name '{key_name}': must match '^[A-Za-z0-9][A-Za-z0-9_-]*$'."
            )
    else:
        key_name = serial_hex

    # Determine revocation date
    if args.date:
        try:
            dt = datetime.fromisoformat(args.date)
            revocation_date = (
                dt.astimezone(UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid --date '{args.date}': must be valid ISO 8601 date-time."
            ) from exc
    else:
        revocation_date = (
            datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )

    # Determine not_after
    not_after_str: str | None = None
    if args.not_after:
        try:
            dt = datetime.fromisoformat(args.not_after)
            not_after_str = (
                dt.astimezone(UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid --not-after '{args.not_after}': must be valid ISO 8601 date-time."
            ) from exc
    elif default_not_after:
        not_after_str = default_not_after

    # Build entry
    entry: dict[str, Any] = {
        "serial": serial_hex,
        "date": revocation_date,
    }
    if args.reason:
        if args.reason not in VALID_REASONS:
            raise ValueError(
                f"Invalid reason '{args.reason}'. Must be one of {sorted(VALID_REASONS)}."
            )
        entry["reason"] = args.reason
    if not_after_str is not None:
        entry["not_after"] = not_after_str

    # Update registry/revocations.json
    revocations_path = registry_dir / "revocations.json"
    if revocations_path.exists():
        raw_text = revocations_path.read_text(encoding="utf-8").strip()
        if raw_text:
            rev_data = json.loads(raw_text)
        else:
            rev_data = {
                "$schema": "../schemas/revocations.schema.json",
                "revocations": {},
            }
    else:
        rev_data = {
            "$schema": "../schemas/revocations.schema.json",
            "revocations": {},
        }

    revocations_dict = rev_data.setdefault("revocations", {})
    ca_revocations = revocations_dict.setdefault(ca_id, {})
    existed = key_name in ca_revocations
    ca_revocations[key_name] = entry

    # Save atomically
    json_bytes = (json.dumps(rev_data, indent=4) + "\n").encode("utf-8")
    write_atomic(revocations_path, json_bytes)

    action = "Updated" if existed else "Added"
    print(
        f"{action} revocation in registry for CA '{ca_id}': key='{key_name}' (serial={serial_hex})"
    )
