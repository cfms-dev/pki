"""Issue and renew complete X.509 certificate revocation lists."""

import argparse
from pathlib import Path

from cfms_pki.ca_gen import generate_ca, register_gen_ca_cli
from cfms_pki.crl.issuing import issue_crl
from cfms_pki.revocation import revoke_certificate
from cfms_pki.shared import REVOCATION_REASONS


def main() -> None:
    parser = argparse.ArgumentParser(prog="cfms-pki")
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue = subparsers.add_parser(
        "issue-crl", help="issue or renew full CRLs from registry"
    )
    issue.add_argument(
        "cas",
        nargs="*",
        metavar="CA",
        help="intermediate CA(s) to issue CRL for (defaults to all CAs in registry)",
    )
    issue.add_argument(
        "--registry-dir",
        type=Path,
        default=Path("registry"),
        help="path to registry directory (defaults to registry)",
    )
    issue.add_argument(
        "--revocations-file",
        type=Path,
        default=None,
        help="merged revocation input (defaults to registry/revocations.json)",
    )
    issue.add_argument(
        "--valid-days",
        type=int,
        default=7,
        help="validity period in days (defaults to 7)",
    )
    issue.add_argument(
        "--fail-on-orphaned",
        action="store_true",
        help="fail if revocation registry contains records for unregistered CAs",
    )
    issue.add_argument(
        "--expired-before",
        "-c",
        type=str,
        default="now",
        help="cutoff timestamp C in ISO 8601 (defaults to current time 'now'; pass 'none' to disable)",
    )
    issue.add_argument(
        "--last-success",
        "-s",
        type=str,
        default=None,
        help="start time S of the last successful regular CRL issuing run (exact ISO 8601 timestamp)",
    )
    issue.add_argument(
        "--grace-period",
        "-g",
        type=str,
        default="0s",
        help="extra retention grace period G (e.g. '0s', '1d', '12h'; defaults to 0s)",
    )
    issue.add_argument(
        "--clock-tolerance",
        type=str,
        default="5m",
        help="clock skew safety margin epsilon (e.g. '5m', '300s'; defaults to 5m)",
    )
    issue.add_argument(
        "--no-filter-expired",
        action="store_true",
        help="disable expiration filtering entirely and retain all revoked certificates",
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
        choices=REVOCATION_REASONS,
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

    pages = subparsers.add_parser(
        "build-pages", help="build static GitHub Pages distribution site for CRLs"
    )
    pages.add_argument(
        "--crl-dir",
        type=Path,
        default=Path("crl"),
        help="path to source CRL directory (defaults to crl)",
    )
    pages.add_argument(
        "--output-dir",
        type=Path,
        default=Path("_site"),
        help="path to output distribution directory (defaults to _site)",
    )
    pages.add_argument(
        "--template-dir",
        type=Path,
        default=None,
        help="custom template directory to override built-in templates",
    )
    pages.add_argument(
        "--no-copy",
        action="store_true",
        help="do not copy CRL files to output directory",
    )

    register_gen_ca_cli(subparsers)

    args = parser.parse_args()

    try:
        if args.command == "issue-crl":
            if not (1 <= args.valid_days <= 365):
                raise ValueError("--valid-days must be between 1 and 365")
            issue_crl(args)
        elif args.command == "revoke":
            revoke_certificate(args)
        elif args.command == "build-pages":
            from cfms_pki.crl.pages import build_crl_pages

            build_crl_pages(
                crl_dir=args.crl_dir,
                output_dir=args.output_dir,
                template_dir=args.template_dir,
                copy_crls=not args.no_copy,
            )
        elif args.command == "gen-ca":
            cert, _key = generate_ca(
                common_name=args.common_name,
                algorithm=args.algorithm,
                organization=args.organization,
                country=args.country,
                state=args.state,
                locality=args.locality,
                valid_days=args.valid_days,
                path_length=args.path_length,
                issuer_cert_path=args.issuer_cert,
                issuer_key_path=args.issuer_key,
                issuer_key_env=args.issuer_key_env,
                issuer_key_password=args.issuer_key_password,
                out_cert_path=args.out_cert,
                out_key_path=args.out_key,
                key_password=args.key_password,
            )
            print(
                f"Generated CA ({args.algorithm}): {args.out_cert} and {args.out_key} "
                f"(Serial={cert.serial_number:#X})"
            )
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"cfms-pki: {exc}\n")


if __name__ == "__main__":
    main()
