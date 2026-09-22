# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | Yes                |
| < 0.4   | No                 |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in QuicFuscate, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send details to [christopher.schulze.github@proton.me](mailto:christopher.schulze.github@proton.me)
2. **Subject line**: `[SECURITY] QuicFuscate - <brief description>`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Impact assessment
   - Any suggested fix (optional)

### What to Expect

- Acknowledgment within 48 hours
- Status update within 7 days
- Coordinated disclosure timeline agreed upon

### Scope

The following areas are in scope:
- QUIC transport layer (packet handling, frame parsing, crypto)
- AEAD cipher implementations and key management
- Stealth subsystem (TLS Cover, fingerprinting, Reality cover targets)
- FEC encoder/decoder
- Admin HTTP/Unix socket server
- Kill-switch and DNS leak prevention
- QKey authentication and token handling
- Configuration parsing (especially security-relevant fields)

### Out of Scope

- Denial of service via resource exhaustion (documented limitation)
- Issues in third-party dependencies (report upstream, notify us)
- Browser profile accuracy (not a security issue)

## Security Design

QuicFuscate is a VPN/obfuscation tool. Security-critical design decisions are documented in `docs/DOCUMENTATION.md`. The codebase uses:

- Packet protection: rustls AES-128-GCM for the handshake, Initial, header protection, and every stealth mode. Performance mode uses libaegis AEGIS-128L for the authenticated 1-RTT payload only. There is no MORUS owner and no CPU selector among AEGIS widths.
- Argon2id for admin password hashing
- SHA-256 for QKey token verification
- 0-RTT anti-replay via strike register (RFC 8446 Section 8)
- Atomic kill-switch rule application (iptables-restore)
