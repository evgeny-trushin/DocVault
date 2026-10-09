# Security

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/evgeny-trushin/DocVault/security/advisories/new)
when it is enabled. If it is unavailable, contact
[the maintainer](https://github.com/evgeny-trushin) privately using a contact method
listed on their profile. A public issue may request a private reporting channel;
do not include exploit details, documents, passwords or key files there.

Include the affected version, macOS and 7-Zip versions, a minimal reproduction
with synthetic files, and the observed impact. The current development version is
the target for fixes; no response time or support for older versions is promised.

## Scope and limitations

DocVault 0.1.0 is alpha software and has not undergone an independent security
audit. Retain independent backups and test recovery before relying on it.
Encryption removes verified plaintext by default; `--keep` retains it. Deletion
does not guarantee secure erasure from SSDs, snapshots, cloud sync or backups.

Keep the two bundle passwords independently. Public filename hints reveal their
contents. Bundles made with the same local key share an archive secret; compromise
of that secret affects those bundles. Use separate keys for independent secrets.
DocVault does not protect documents while they are decrypted or against malware
running as you. Supported metadata and unsupported-file restrictions are described
in [docs/7z.md](docs/7z.md); format and recovery limitations are in
[docs/archive-recovery.md](docs/archive-recovery.md).
