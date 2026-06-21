# TODO-120: QKey Tokens on Disk - Plaintext Removal

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
In `src/implementations/server/qkey_registry.rs:69-77`, the `QKeyEntry` struct contains legacy plaintext `qkey` and `token` fields alongside the secure `token_sha256` field. These plaintext fields are serialized and persisted to `qkeys.json` on disk, exposing raw authentication tokens in a readable file.

Only `token_sha256` should be persisted. The plaintext fields are a direct credential exposure risk - anyone with filesystem read access obtains valid authentication tokens.

## Root Cause
Legacy fields (`qkey`, `token`) were kept in the struct for backward compatibility but were never removed from the serialization path. The `#[serde(Serialize, Deserialize)]` derive on `QKeyEntry` includes all fields, writing plaintext tokens to disk.

## Fix Plan
1. Add `#[serde(skip_serializing)]` to the `qkey` and `token` fields in `QKeyEntry` so they are never written to disk.
2. Keep `#[serde(default)]` on these fields for deserialization so existing `qkeys.json` files with legacy plaintext fields can still be loaded during migration.
3. Add a startup migration step: on load, if any `QKeyEntry` contains plaintext `qkey`/`token` fields, strip them and re-save `qkeys.json` immediately with only `token_sha256`.
4. After migration, the plaintext fields should be `Option<String>` set to `None` in memory (or removed entirely if no code path reads them).
5. Add a unit test that serializes a `QKeyEntry` and asserts no `qkey` or `token` key appears in the JSON output.
6. Add a migration test that loads a legacy `qkeys.json` with plaintext fields and confirms they are stripped on re-save.

## Acceptance Criteria
- No plaintext `qkey` or `token` values appear in `qkeys.json` after startup.
- Existing `qkeys.json` files with legacy plaintext fields are migrated automatically on first load.
- Only `token_sha256` is persisted for authentication verification.
- Unit tests confirm serialization excludes plaintext fields.

## Dependencies
- None (self-contained within qkey_registry.rs and the qkeys.json persistence layer).

## Affected Files
- `src/implementations/server/qkey_registry.rs` (lines 69-77, serialization/deserialization logic)
- `qkeys.json` (runtime data file - format change)
