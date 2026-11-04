"""Issue and renew X.509 certificate revocation lists based on registry contents."""

import argparse
import json
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, mldsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
)

from cfms_pki.crl.inference import (
    calculate_retention_boundary,
    parse_duration,
    resolve_cutoff,
    resolve_last_success,
    should_exclude_revocation,
)
from cfms_pki.shared import (
    VALID_REASONS,
    authority_key_identifier,
    check_signer,
    load_ca_key,
    resolve_ca_path,
    write_atomic,
)


def generate_crl_number() -> int:
    """Generate a 160-bit stateless CRL number according to the algorithm.

    Formula: CRLNumber = ((S mod 2^39) * 2^32 + N) * 2^88 + R
    where S is UTC Unix seconds, N is nanoseconds in current second (0 <= N < 10^9),
    and R is an 88-bit CSPRNG random integer (0 <= R < 2^88).

    The most significant bit (bit 159) is cleared (0) by (S mod 2^39), guaranteeing
    that the DER-encoded INTEGER is non-negative and does not exceed 20 octets (RFC 5280 compliant).
    """
    now_ns = time.time_ns()
    s = now_ns // 1_000_000_000
    n = now_ns % 1_000_000_000
    r = secrets.randbits(88)
    return (((s % (1 << 39)) << 32) + n) << 88 | r


def resolve_crl_output_path(
    ca_id: str,
    ca_info: dict[str, Any],
    registry_dir: Path,
) -> Path:
    """Resolve destination path for the intermediate CA's CRL file.

    If crl_path is specified in ca.json, use it (resolved relative to registry_dir.parent if relative).
    Otherwise, default to 'crl/{ca_id}.crl' under registry_dir.parent.
    """
    crl_path_str = ca_info.get("crl_path")
    if crl_path_str:
        loc = Path(crl_path_str)
        if loc.is_absolute():
            return loc
        return registry_dir.parent / loc

    return registry_dir.parent / "crl" / f"{ca_id}.crl"


def check_orphaned_revocations(
    revocations: dict[str, Any],
    cas: dict[str, Any],
    fail_on_orphaned: bool = False,
) -> list[str]:
    """Identify revocation entries belonging to CAs not present in the CA registry.

    Prints diagnostic warnings for each orphaned CA and raises ValueError if fail_on_orphaned is True.
    """
    registered_cas = set(cas.keys())
    revocation_cas = set(revocations.keys())
    orphaned_cas = sorted(revocation_cas - registered_cas)

    if orphaned_cas:
        for orphaned_ca in orphaned_cas:
            ca_entries = revocations.get(orphaned_ca, {})
            serials = [
                entry.get("serial", key)
                for key, entry in ca_entries.items()
                if isinstance(entry, dict)
            ]
            serial_list_str = ", ".join(serials) if serials else "none"
            print(
                f"Warning: Revocation registry contains {len(ca_entries)} record(s) under CA '{orphaned_ca}', "
                f"which is not registered in ca.json (serials: [{serial_list_str}]). "
                "These revocations cannot be included in any CRL.",
                file=sys.stderr,
            )
        if fail_on_orphaned:
            raise ValueError(
                f"Orphaned revocation records detected for unregistered CAs: {', '.join(orphaned_cas)}"
            )
    return orphaned_cas


def issue_crl_for_ca(
    ca_id: str,
    ca_info: dict[str, Any],
    ca_revocations: dict[str, Any],
    registry_dir: Path,
    now: datetime,
    valid_days: int,
    retention_boundary: datetime | None = None,
) -> Path:
    """Issue a CRL for a single intermediate CA based on registry records."""
    if not isinstance(ca_info, dict):
        raise TypeError(f"Invalid CA configuration for '{ca_id}': expected dict")
    if "location" not in ca_info:
        raise ValueError(f"CA '{ca_id}' is missing required 'location' in ca.json")
    if "pk_env" not in ca_info:
        raise ValueError(f"CA '{ca_id}' is missing required 'pk_env' in ca.json")

    ca_path = resolve_ca_path(ca_info["location"], registry_dir)
    ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    key = load_ca_key(ca_id, ca_info["pk_env"])
    check_signer(ca_cert, key, now)

    revoked: dict[int, x509.RevokedCertificate] = {}
    excluded_expired = 0
    for entry_key, entry in ca_revocations.items():
        if not isinstance(entry, dict) or "serial" not in entry or "date" not in entry:
            continue

        if should_exclude_revocation(entry, retention_boundary):
            excluded_expired += 1
            continue

        try:
            serial_int = int(entry["serial"], 16)
        except ValueError as exc:
            raise ValueError(
                f"Invalid hex serial '{entry['serial']}' in revocation entry '{entry_key}' for CA '{ca_id}'"
            ) from exc

        try:
            rev_date = datetime.fromisoformat(entry["date"]).astimezone(UTC)
        except ValueError as exc:
            raise ValueError(
                f"Invalid date format '{entry['date']}' in revocation entry '{entry_key}' for CA '{ca_id}'"
            ) from exc

        rev_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(rev_date)
        )
        reason = entry.get("reason")
        if reason:
            if reason not in VALID_REASONS:
                raise ValueError(
                    f"Invalid revocation reason '{reason}' in revocation entry '{entry_key}' for CA '{ca_id}'"
                )
            reason_flag = getattr(x509.ReasonFlags, reason)
            rev_builder = rev_builder.add_extension(
                x509.CRLReason(reason_flag),
                critical=False,
            )
        revoked[serial_int] = rev_builder.build()

    end = min(now + timedelta(days=valid_days), ca_cert.not_valid_after_utc)
    if end <= now:
        raise ValueError(
            f"CRL validity for CA '{ca_id}' would be empty (CA expired or invalid valid_days)"
        )

    crl_number = generate_crl_number()

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(end)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(authority_key_identifier(ca_cert), critical=False)
    )

    for entry in sorted(revoked.values(), key=lambda e: e.serial_number):
        builder = builder.add_revoked_certificate(entry)

    hash_algorithm = (
        None
        if isinstance(
            key,
            (
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
                mldsa.MLDSA65PrivateKey,
                mldsa.MLDSA87PrivateKey,
                mldsa.MLDSA44PrivateKey,
            ),
        )
        else hashes.SHA256()
    )
    crl = builder.sign(private_key=key, algorithm=hash_algorithm)

    public_key = ca_cert.public_key()
    if not isinstance(public_key, CertificateIssuerPublicKeyTypes):
        raise TypeError(f"Unsupported CA public key type: {type(public_key).__name__}")

    if not crl.is_signature_valid(public_key):
        raise ValueError(
            f"Generated CRL for CA '{ca_id}' failed signature verification"
        )

    output_path = resolve_crl_output_path(ca_id, ca_info, registry_dir)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(output_path, crl.public_bytes(serialization.Encoding.PEM))

    print(
        f"Issued CRL for CA '{ca_id}': {output_path} (CRLNumber={crl_number}, revoked={len(revoked)}, excluded_expired={excluded_expired})"
    )
    return output_path


def issue_crl(args: argparse.Namespace) -> None:
    """Issue CRLs for intermediate CAs based on registry contents."""
    registry_dir: Path = args.registry_dir
    ca_registry_path = registry_dir / "ca.json"
    if not ca_registry_path.exists():
        raise FileNotFoundError(f"CA registry not found: {ca_registry_path}")

    ca_data = json.loads(ca_registry_path.read_text(encoding="utf-8"))
    cas: dict[str, Any] = ca_data.get("cas", {})

    revocations_path = registry_dir / "revocations.json"
    if revocations_path.exists():
        raw_text = revocations_path.read_text(encoding="utf-8").strip()
        rev_data = json.loads(raw_text) if raw_text else {}
    else:
        rev_data = {}
    all_revocations: dict[str, Any] = rev_data.get("revocations", {})

    # Check for orphaned revocations
    check_orphaned_revocations(
        all_revocations,
        cas,
        fail_on_orphaned=getattr(args, "fail_on_orphaned", False),
    )

    # Determine target CAs
    if args.cas:
        target_cas: list[str] = []
        for requested_ca in args.cas:
            if requested_ca not in cas:
                if requested_ca in all_revocations:
                    raise ValueError(
                        f"Cannot issue CRL for CA '{requested_ca}': CA is not registered in ca.json, "
                        f"though {len(all_revocations[requested_ca])} revocation record(s) exist in revocations.json."
                    )
                raise ValueError(
                    f"CA '{requested_ca}' not found in registry (ca.json)."
                )
            if requested_ca not in target_cas:
                target_cas.append(requested_ca)
    else:
        target_cas = list(cas.keys())

    if not target_cas:
        print("No intermediate CAs found in registry to issue CRL for.")
        return

    now = datetime.now(UTC).replace(microsecond=0)

    # Resolve retention model boundary H = min(C, T, S - G - epsilon)
    no_filter = getattr(args, "no_filter_expired", False)
    if no_filter:
        boundary = None
        print(
            "Retention Model: Filter disabled (--no-filter-expired). Retaining all records."
        )
    else:
        expired_before_raw = getattr(args, "expired_before", "now")
        cutoff = resolve_cutoff(expired_before_raw, now)

        last_success_raw = getattr(args, "last_success", None)
        last_success = resolve_last_success(last_success_raw)

        grace_period_raw = getattr(args, "grace_period", "0s")
        grace_period = parse_duration(grace_period_raw)

        clock_tolerance_raw = getattr(args, "clock_tolerance", "5m")
        clock_tolerance = parse_duration(clock_tolerance_raw)

        boundary = calculate_retention_boundary(
            now=now,
            last_success=last_success,
            cutoff=cutoff,
            grace_period=grace_period,
            clock_tolerance=clock_tolerance,
        )

        if boundary is not None:
            s_str = last_success.isoformat() if last_success else "None"
            c_str = cutoff.isoformat() if cutoff else "None"
            print(
                f"Retention Model: T={now.isoformat()}, S={s_str}, C={c_str}, "
                f"G={grace_period_raw}, epsilon={clock_tolerance_raw} -> "
                f"Effective Boundary H={boundary.isoformat()}"
            )
        else:
            print(
                "Retention Model: S is None or inactive (retaining all revocations per RFC 5280 §3.3)"
            )

    for ca_id in target_cas:
        issue_crl_for_ca(
            ca_id=ca_id,
            ca_info=cas[ca_id],
            ca_revocations=all_revocations.get(ca_id, {}),
            registry_dir=registry_dir,
            now=now,
            valid_days=args.valid_days,
            retention_boundary=boundary,
        )
