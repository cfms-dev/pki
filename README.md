# CFMS Public Key Infrastructure (PKI)

> [!NOTE]
> To obtain a certificate for a domain you control, you can use any ACME-compatible client with the following directory URL:
>
> https://acme.cfms-pki.crpteam.club/directory

A lightweight, GitOps-driven PKI toolkit and stateless CRL distribution system for the CFMS ecosystem.

Security updates, database migration, ACME revocation export, and production
verification are documented in the [security rollout runbook](docs/security-rollout.md).

CFMS-PKI provides automated X.509 CA management and certificate revocation list (CRL) distribution without the overhead of heavy database infrastructure. It pairs declarative GitOps workflows with modern cryptography to ensure reliable, zero-maintenance PKI operations.

### Key Features

- **Post-Quantum & Modern Cryptography**: Native support for NIST FIPS 204 ML-DSA (ML-DSA-44/65/87), Ed25519, ECDSA, and RSA-4096 for Root and Intermediate CAs.
- **Stateless CRL Issuance**: Generates RFC 5280-compliant CRLs using a deterministic 160-bit timestamp/entropy algorithm, eliminating the need for stateful serial counters.
- **Declarative GitOps Registry**: Track and audit CA mappings and revoked certificates via version-controlled, JSON-Schema-validated registries.
- **Automated Distribution**: Built-in GitHub Actions pipeline to automatically renew expiring CRLs and deploy a static download site to GitHub Pages with SHA-256 integrity checksums.
