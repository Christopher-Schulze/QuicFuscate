# TODO-136: Token SHA256 Hashes Hex String Instead of Binary Bytes

## Status
**COMPLETED**

## Severity
**MEDIUM**

## Context
In `src/implementations/server/qkey_registry.rs:382-397`, the token hashing function hashes the hex-encoded STRING representation of the token instead of the decoded binary bytes:

- Input: 64-character hex string (e.g., "a1b2c3d4...") = 64 ASCII bytes
- Expected: decode hex to 32 binary bytes, then SHA256 hash those 32 bytes
- Actual: SHA256 hashes the 64 ASCII bytes of the hex string directly

This is not insecure per se - SHA256 of the hex string is still pre-image resistant and collision resistant. However:
- It hashes 64 bytes instead of 32 (2x work, minor)
- It means token comparison is case-sensitive on hex encoding
- It diverges from standard practice (hash the actual secret, not its encoding)
- If the hex encoding format ever changes (e.g., uppercase vs lowercase), stored hashes break

## Root Cause
The hex string is passed directly to the hash function without decoding to binary first.

## Fix Plan
1. Before hashing, decode the hex string to binary bytes using `hex::decode()` or equivalent
2. Hash the decoded 32-byte binary value
3. Add input validation: reject non-hex input before hashing
4. **Migration path for existing hashes:**
   - Support both old (hex-string) and new (binary) hash formats during transition
   - On successful authentication with old format, re-hash in new format and update storage
   - Add a config flag or version marker to distinguish hash formats
   - After migration period, remove old format support
5. Add unit test comparing hash of hex string vs hash of decoded bytes to prove they differ

## Acceptance Criteria
- Token hashing uses decoded binary bytes, not hex string
- Existing tokens continue to work during migration period
- Migration path re-hashes tokens on next successful auth
- Input validation rejects malformed hex strings
- Unit test verifies correct behavior

## Dependencies
- `hex` crate (likely already a dependency)
- Storage format for hash version marker

## Affected Files
- `src/implementations/server/qkey_registry.rs`
- Token storage/persistence layer (if any)
