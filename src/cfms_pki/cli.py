"""Issue and renew complete X.509 certificate revocation lists."""

import argparse
from pathlib import Path

from cfms_pki.modules.crl.issuing import issue_crl
from cfms_pki.modules.shared import (
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

    args = parser.parse_args()

    try:
        if args.command == "issue-crl":
            if not (1 <= args.valid_days <= 365):
                raise ValueError("--valid-days must be between 1 and 365")
            issue_crl(args)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"cfms-pki: {exc}\n")


if __name__ == "__main__":
    main()
