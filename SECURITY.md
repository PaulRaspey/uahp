# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/PaulRaspey/uahp/security/advisories/new). Do not open a public issue for anything you believe is exploitable.

You can expect an acknowledgment within a few days. This is a solo-maintained project, so please allow reasonable time for a fix before public disclosure. There is currently no bug bounty.

## Scope

The interesting surface is the protocol implementation in the `uahp` package:

- Identity and signatures (`uahp/core.py`)
- The 3-message handshake and session derivation (`uahp/core.py`)
- The AEAD record layer (`uahp/record.py`)
- Receipts, chain hashing, and post-death rejection (`uahp/core.py`)
- The compliance verifier (`uahp/verifier.py`)
- The registry service (`uahp/registry/`)

## Known limitations, stated up front

These are documented in the README and SPEC.md and are not new findings:

- Python cannot guarantee memory zeroization. Revocation drops the only key reference and relies on protocol-level enforcement.
- The classical path (Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305) makes no quantum resistance claim. Hybrid PQC is behind a feature flag requiring liboqs.
- No external security audit has been performed yet. One is planned.

Reports that sharpen or refute any of the above are welcome too.
