# TODO-270: Cargo Dependency Security Vulnerabilities

## Severity: CRITICAL

## Source
Cross-model forensic audit (2026-03-22). Confirmed by all 5 audit models.

## Problem
Transitive dependencies have known CVEs:

| Crate | Version | Vulnerability | Fix |
|-------|---------|---------------|-----|
| aws-lc-sys | 0.37.1 | RUSTSEC-2026-0048 - CRL Distribution Point Scope Check Logic Error | >= 0.39.0 |
| aws-lc-sys | 0.37.1 | RUSTSEC-2026-0047 - PKCS7_verify Signature Validation Bypass | >= 0.38.0 |
| aws-lc-sys | 0.37.1 | RUSTSEC-2026-0046 - PKCS7_verify Certificate Chain Validation Bypass | >= 0.38.0 |
| aws-lc-sys | 0.37.1 | RUSTSEC-2026-0045 - Timing Side-Channel in AES-CCM Tag Verification | >= 0.38.0 |
| quinn-proto | 0.11.13 | RUSTSEC-2026-0037 - Denial of Service in Quinn endpoints | >= 0.11.14 |

All come through the rustls/quinn dependency chain.

## Fix
```bash
cargo update -p aws-lc-sys
cargo update -p quinn-proto
cargo audit --deny warnings
```

## Verification
- `cargo audit` returns 0 warnings
- All tests pass after update

## Notes
- Also multiple duplicate crate versions in Cargo.lock (base64 x2, getrandom x3, rand_core x3, hashbrown x2) - these are transitive and may resolve with the above updates.
