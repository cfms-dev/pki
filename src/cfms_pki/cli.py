"""Issue and renew complete X.509 certificate revocation lists."""

import argparse
from pathlib import Path

from cfms_pki.crl.issuing import issue_crl
from cfms_pki.revocation import revoke_certificate
from cfms_pki.shared import (
    parse_serial,
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="cfms-pki")
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue = subparsers.add_parser("issue-crl", help="issue or renew a full CRL")
    issue.add_argument(
        "--issuer", required=True, type=Path, help="issuer CA certificate (PEM)"
    )

    # key sources
    source = issue.add_mutually_exclusive_group()
    source.add_argument("--key-file", type=Path, help="path to CA private key (PEM)")
    source.add_argument(
        "--key-env", metavar="NAME", help="environment variable holding PEM key"
    )

    issue.add_argument("--output", required=True, type=Path)
    issue.add_argument(
        "--previous", type=Path, help="previous CRL (defaults to output if it exists)"
    )
    issue.add_argument(
        "--require-previous",
        action="store_true",
        help="fail if there is no previous CRL",
    )
    issue.add_argument("--valid-days", type=int, default=7)
    issue.add_argument(
        "--revoke", action="append", type=parse_serial, default=[], metavar="SERIAL"
    )

    revoke = subparsers.add_parser(
        "revoke", help="add a certificate to the revocation registry"
    )
    revoke.add_argument(
        "--pem",
        "--cert",
        dest="pem",
        type=Path,
        help="path to target certificate (PEM)",
    )
    revoke.add_argument(
        "--serial",
        type=str,
        help="serial number of target certificate",
    )
    revoke.add_argument(
        "--ca",
        type=str,
        help="intermediate CA id in registry",
    )
    revoke.add_argument(
        "--name",
        "--key",
        dest="name",
        type=str,
        help="key name in registry (defaults to serial)",
    )
    revoke.add_argument(
        "--reason",
        choices=[
            "key_compromise",
            "ca_compromise",
            "affiliation_changed",
            "superseded",
            "cessation_of_operation",
            "certificate_hold",
            "privilege_withdrawn",
            "aa_compromise",
        ],
        help="revocation reason",
    )
    revoke.add_argument(
        "--date",
        type=str,
        help="revocation timestamp in ISO 8601 format (defaults to current UTC time)",
    )
    revoke.add_argument(
        "--not-after",
        type=str,
        help="certificate expiration time in ISO 8601 format",
    )
    revoke.add_argument(
        "--registry-dir",
        type=Path,
        default=Path("registry"),
        help="path to registry directory (defaults to registry)",
    )

    args = parser.parse_args()

    try:
        if args.command == "issue-crl":
            if not (1 <= args.valid_days <= 365):
                raise ValueError("--valid-days must be between 1 and 365")
            issue_crl(args)
        elif args.command == "revoke":
            revoke_certificate(args)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"cfms-pki: {exc}\n")


if __name__ == "__main__":
    main()
