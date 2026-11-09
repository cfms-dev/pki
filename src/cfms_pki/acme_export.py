"""Export verified ACME revocations into a temporary CRL registry input."""

import argparse
import copy
import json
import os
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

from cfms_pki.revocation import find_matching_cas
from cfms_pki.shared import format_rfc3339, write_atomic

REASONS = {
    "unspecified": None,
    "keyCompromise": "key_compromise",
    "cACompromise": "ca_compromise",
    "affiliationChanged": "affiliation_changed",
    "superseded": "superseded",
    "cessationOfOperation": "cessation_of_operation",
    "certificateHold": "certificate_hold",
    "privilegeWithdrawn": "privilege_withdrawn",
    "aACompromise": "aa_compromise",
}


def query_d1(sql: str, params: list) -> list[dict]:
    account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
    database = os.environ["CLOUDFLARE_D1_DATABASE_ID"]
    token = os.environ["CLOUDFLARE_API_TOKEN"]
    if not account.isalnum() or not all(c.isalnum() or c == "-" for c in database):
        raise ValueError("Invalid Cloudflare account/database identifier")
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}/query",
        data=json.dumps({"sql": sql, "params": params}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(16 * 1024 * 1024 + 1)
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError("D1 response exceeds limit")
    body = json.loads(payload)
    if not body.get("success") or len(body.get("result", [])) != 1:
        raise ValueError("D1 query failed")
    result = body["result"][0]
    if not result.get("success") or not isinstance(result.get("results"), list):
        raise ValueError("D1 query failed")
    return result["results"]


def merge_revocations(
    registry_dir: Path, rows: list[dict], existing: dict
) -> tuple[dict, dict[str, str]]:
    """Verify issuer signatures and metadata before trusting a D1 revocation."""
    cas = json.loads((registry_dir / "ca.json").read_text(encoding="utf-8"))["cas"]
    output = copy.deepcopy(existing)
    revocations = output.setdefault("revocations", {})
    backfills: dict[str, str] = {}
    for row in rows:
        cert = x509.load_pem_x509_certificate(row["pem"].encode())
        matches = find_matching_cas(cert, cas, registry_dir)
        if len(matches) != 1 or (
            row.get("ca_id") is not None and row["ca_id"] != matches[0]
        ):
            raise ValueError(
                f"Unresolved or inconsistent issuer for certificate {row['id']}"
            )
        ca_id = matches[0]
        if row.get("ca_id") is None:
            backfills[row["id"]] = ca_id
        if int(row["serial_number"], 16) != cert.serial_number:
            raise ValueError("Certificate serial metadata mismatch")
        if row.get("revoked_at") is None:
            continue
        reason = row.get("revocation_reason")
        if reason not in REASONS:
            raise ValueError(f"Unknown revocation reason for certificate {row['id']}")
        entry = {
            "serial": format(cert.serial_number, "x"),
            "date": format_rfc3339(datetime.fromtimestamp(row["revoked_at"], UTC)),
            "not_after": format_rfc3339(cert.not_valid_after_utc),
        }
        if REASONS[reason] is not None:
            entry["reason"] = REASONS[reason]
        bucket = revocations.setdefault(ca_id, {})
        same_serial = [
            key
            for key, value in bucket.items()
            if int(value["serial"], 16) == cert.serial_number
        ]
        for key in same_serial:
            prior = bucket.pop(key)
            if datetime.fromisoformat(prior["date"]) < datetime.fromisoformat(
                entry["date"]
            ):
                entry["date"] = prior["date"]
            if prior.get("reason") in {"key_compromise", "ca_compromise"}:
                entry["reason"] = prior["reason"]
        bucket[f"acme-{row['id']}"] = entry
    return output, backfills


def export_revocations(
    registry_dir: Path, output: Path, *, backfill_ca_ids: bool = False
) -> None:
    existing_path = registry_dir / "revocations.json"
    merged = (
        json.loads(existing_path.read_text(encoding="utf-8"))
        if existing_path.exists()
        else {"revocations": {}}
    )
    cursor = ""
    cutoff = int(datetime.now(UTC).timestamp())
    while True:
        rows = query_d1(
            "SELECT id, pem, ca_id, serial_number, revoked_at, revocation_reason FROM certificates "
            "WHERE id > ? AND (revoked_at < ? OR (? = 1 AND ca_id IS NULL)) ORDER BY id LIMIT 100",
            [cursor, cutoff, int(backfill_ca_ids)],
        )
        if not rows:
            break
        merged, backfills = merge_revocations(registry_dir, rows, merged)
        if backfill_ca_ids:
            for cert_id, ca_id in backfills.items():
                query_d1(
                    "UPDATE certificates SET ca_id = ? WHERE id = ? AND ca_id IS NULL RETURNING id",
                    [ca_id, cert_id],
                )
        next_cursor = rows[-1]["id"]
        if next_cursor <= cursor:
            raise ValueError("D1 pagination did not advance")
        cursor = next_cursor
    output.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(output, (json.dumps(merged, indent=2) + "\n").encode(), mode=0o644)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-dir", type=Path, default=Path("registry"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--backfill-ca-ids",
        action="store_true",
        help="also persist verified legacy CA identities; requires a write token",
    )
    args = parser.parse_args()
    export_revocations(
        args.registry_dir, args.output, backfill_ca_ids=args.backfill_ca_ids
    )


if __name__ == "__main__":
    main()
