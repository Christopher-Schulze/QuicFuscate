# TODO-297: Shallow Stealth Test Coverage

## Problem
Stealth subsystem tests are shallow - missing coverage for:
- XOR obfuscation edge cases
- Padding byte generation/validation
- Header protection round-trip
- 0-RTT replay protection under stealth modes
- TLS Cover cipher consistency

These are security-critical paths that need adversarial test coverage.

## Source
AI Model Review (GLM-5, Mimo v2 Pro) - verified correct at high level.

## Location
- `src/stealth/mod.rs` - stealth subsystem
- `src/stealth/tls_cover.rs` - TLS Cover
- `scripts/tests/rust/` - existing tests

## Fix
Add targeted tests for the identified gaps. Priority: 0-RTT replay under stealth, header protection, TLS Cover cipher consistency.

## Acceptance Criteria
- New tests covering identified gaps
- All tests pass
- Adversarial inputs tested (malformed headers, replay attacks)
