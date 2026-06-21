# TODO-288: ChaCha TLS Cover vs TLS Policy DPI Inconsistency

## Problem
When TLS Cover mode uses ChaCha20-Poly1305 but the actual QUIC policy selects AES-GCM (or vice versa), DPI can observe the cipher suite mismatch between the outer TLS wrapper and inner QUIC traffic - creating a distinguisher that defeats stealth.

## Source
AI Model Review (GLM-5) - verified correct conceptually, needs code-level verification of actual impact.

## Location
- `src/stealth/tls_cover.rs` - TLS Cover cipher selection
- `src/stealth/mod.rs` - stealth policy cipher configuration

## Fix
Ensure TLS Cover cipher selection is consistent with the QUIC transport cipher, or document why the mismatch is acceptable (e.g., if cover traffic is opaque enough).

## Acceptance Criteria
- Cipher consistency between TLS Cover and QUIC transport, OR documented justification for current approach
- No new DPI distinguisher introduced
