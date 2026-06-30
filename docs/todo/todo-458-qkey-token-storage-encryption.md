---
id: TODO-458
title: "Encryption at rest for QKey token storage (qkeys.json)"
severity: HIGH
phase: "H"
priority: P1
status: DONE
created: 2026-06-30
depends_on: ["TODO-440"]
---

# TODO-458: Encryption at rest for QKey token storage (qkeys.json)

## Problem

QKey tokens are stored as SHA-256 hashes in a **plaintext JSON file**
(`qkeys.json`) with no encryption at rest. The `QKeyRegistry::persist`
and `load` methods serialize entries (including `token_sha256`) to disk
as plain JSON. If the file is compromised — via a backup leak, disk
theft, container escape, or filesystem snapshot — all QKey hashes are
exposed. Because the QKey token is typically a short hex string (64 hex
chars = 32 bytes), SHA-256 of such a token is brute-forceable with
modern GPU hardware (billions of hashes/sec).

### Evidence

1. `QKeyRegistry::insert_with_ttl`
   (`src/implementations/server/qkey_registry.rs:154-179`) computes
   `token_sha256` via `token_sha256_hex_from_token_hex` (line 176) and
   stores it in the `QKeyEntry` / `QKeyRecord` struct.
2. `QKeyRegistry::persist` serializes the registry to JSON and writes
   it to `qkeys.json` (the path is configurable but the content is
   plaintext). `QKeyRegistry::load` reads the JSON back. There is no
   encryption, no MAC, no key derivation, and no integrity check.
3. The stored hash is `SHA-256(token_hex)`. A 32-byte token has
   ~2^256 entropy, but if tokens are generated from a weaker source
   (e.g. a human-chosen passphrase, a truncated UUID, or a predictable
   PRNG), the hash is offline-brute-forceable. Even with full entropy,
   exposing hashes violates defense-in-depth: the attacker does not
   need to interact with the server to attempt cracking.
4. There is no master key, no key derivation function, and no
   authenticated encryption. A corrupted or tampered `qkeys.json` is
   silently loaded (or causes a parse error with no integrity
   verification).

## Goal

- `qkeys.json` is encrypted at rest using **AES-256-GCM**
  (authenticated encryption: confidentiality + integrity).
- The encryption key is derived from a master passphrase via
  **Argon2id** (memory-hard KDF, resistant to GPU/ASIC brute-force).
- The master key is sourced from the `QUICFUSCATE_MASTER_KEY`
  environment variable or a key file at a configurable path
  (`QUICFUSCATE_MASTER_KEY_FILE`).
- An **HMAC-SHA-256** integrity tag is computed over the encrypted
  blob to detect tampering before decryption.
- Existing plaintext `qkeys.json` files are **automatically migrated**
  to encrypted format on first load when a master key is present.
- Key rotation is supported: changing the master key re-encrypts the
  file on next `persist`.
- Tests prove: the file is encrypted at rest (no plaintext hashes
  visible), decryption with the wrong key fails, migration from
  plaintext works, and tampering is detected.

## Implementation Plan

### Step 1: Add crypto dependencies

**File:** `Cargo.toml`

- Add (if not already present):
  - `aes-gcm = "0.10"` (AES-256-GCM)
  - `argon2 = "0.5"` (Argon2id KDF)
  - `hmac = "0.12"` (HMAC-SHA-256 for integrity tag)
  - `sha2 = "0.10"` (already present for SHA-256 hashing)
  - `rand = "0.8"` (already present, for salt and nonce generation)
  - `zeroize = "1"` (already present, for key zeroization — TODO-440)
  - `base64 = "0.22"` (for encoding the encrypted blob)

### Step 2: Define the encrypted file format

**File:** `src/implementations/server/qkey_registry.rs` (or a new
`src/implementations/server/qkey_storage.rs`)

- Define a versioned binary format for the encrypted `qkeys.json`:
  ```
  Magic:   "QFENC1\0"   (7 bytes)
  Version: u8            (1 byte, = 1)
  Salt:    [u8; 16]      (Argon2id salt)
  Nonce:   [u8; 12]      (AES-256-GCM nonce)
  HMAC:    [u8; 32]      (HMAC-SHA-256 over ciphertext)
  Ciphertext: Vec<u8>    (AES-256-GCM ciphertext of JSON payload)
  ```
- The HMAC is computed as `HMAC-SHA-256(hmac_key, ciphertext)` where
  `hmac_key` is derived separately from the master key (see Step 3).
- AES-256-GCM already provides authentication (the GCM tag), but the
  additional HMAC layer protects against nonce-reuse-related forgery
  and provides a fast tamper check before the slower AEAD decryption.

### Step 3: Implement key derivation (Argon2id)

**File:** `src/implementations/server/qkey_storage.rs` (new) or
`qkey_registry.rs`

- Derive two subkeys from the master passphrase + salt:
  ```rust
  fn derive_keys(passphrase: &[u8], salt: &[u8; 16]) -> ( [u8; 32], [u8; 32] ) {
      // encryption_key = Argon2id(passphrase, salt, "enc")
      // hmac_key       = Argon2id(passphrase, salt, "hmac")
      let params = argon2::Params::new(64 * 1024, 3, 4, Some(32)).unwrap();
      let enc_key = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
          .hash_password(passphrase, &salt_for("enc"))
          .map(|h| h.hash.unwrap().as_bytes().try_into().unwrap());
      // ... similarly for hmac_key
      (enc_key, hmac_key)
  }
  ```
- Use Argon2id parameters: 64 MiB memory, 3 iterations, 4 lanes,
  32-byte output. These are OWASP-recommended minimums.
- Zeroize both keys on drop (wrap in `zeroize::Zeroizing<[u8; 32]>`).

### Step 4: Implement encrypt and decrypt functions

**File:** `src/implementations/server/qkey_storage.rs`

- `fn encrypt_json(json: &[u8], master_key: &[u8]) -> Vec<u8>`:
  1. Generate random 16-byte `salt` and 12-byte `nonce`.
  2. Derive `(enc_key, hmac_key)` via `derive_keys(master_key, &salt)`.
  3. `ciphertext = AES_256_GCM(enc_key, nonce).encrypt(nonce, json)`.
  4. `hmac_tag = HMAC-SHA-256(hmac_key, &ciphertext)`.
  5. Serialize: `magic || version || salt || nonce || hmac_tag ||
     ciphertext`.
- `fn decrypt_blob(blob: &[u8], master_key: &[u8]) -> Result<Vec<u8>, StorageError>`:
  1. Parse and validate `magic` and `version`.
  2. Extract `salt`, `nonce`, `hmac_tag`, `ciphertext`.
  3. Derive `(enc_key, hmac_key)` via `derive_keys(master_key, &salt)`.
  4. Verify `HMAC-SHA-256(hmac_key, &ciphertext) == hmac_tag` in
     constant time. If mismatch → `StorageError::IntegrityFailed`.
  5. `plaintext = AES_256_GCM(enc_key, nonce).decrypt(nonce,
     ciphertext)`. If AEAD fails →
     `StorageError::DecryptionFailed` (wrong key or corrupted).
  6. Return `plaintext` (the JSON bytes).

### Step 5: Load the master key from env or file

**File:** `src/implementations/server/qkey_storage.rs`

- `fn load_master_key() -> Result<Zeroizing<Vec<u8>>, StorageError>`:
  1. Check `QUICFUSCATE_MASTER_KEY` env var. If set, use its value as
     the passphrase.
  2. Else check `QUICFUSCATE_MASTER_KEY_FILE` env var (or config field
     `master_key_file`). Read the file content (trim trailing
     whitespace) as the passphrase.
  3. If neither is set:
     - If the existing `qkeys.json` is plaintext (no `QFENC1` magic),
       log a warning and operate in **plaintext fallback mode** (for
       backward compatibility), but emit a deprecation warning.
     - If the file is encrypted and no key is available →
       `StorageError::NoMasterKey`.
- The master key is wrapped in `Zeroizing<Vec<u8>>` so it is erased
  from memory when dropped (depends on TODO-440's zeroize work).

### Step 6: Modify `QKeyRegistry::persist` and `load`

**File:** `src/implementations/server/qkey_registry.rs`

- **`persist`:** If a master key is available, serialize entries to
  JSON as before, then call `encrypt_json(&json_bytes, &master_key)`
  and write the encrypted blob to `qkeys.json`. If no master key,
  write plaintext JSON (fallback mode) with a log warning.
- **`load`:** Read the file. Check for the `QFENC1` magic:
  - If encrypted: call `decrypt_blob(&file_bytes, &master_key)`,
    parse the resulting JSON.
  - If plaintext (no magic): parse JSON directly. **If a master key
    is available**, set a `needs_migration = true` flag so the next
    `persist` writes an encrypted file (automatic migration).
- After a successful plaintext load with a master key, immediately
  call `persist` to write the encrypted version (migration on first
  load). Log: `"Migrated qkeys.json from plaintext to encrypted
  format"`.

### Step 7: Key rotation

**File:** `src/implementations/server/qkey_registry.rs`

- When the master key changes (e.g. env var updated and server
  restarted), `load` decrypts with the old key (if the file was
  encrypted with it) or reads plaintext, and `persist` re-encrypts
  with the new key. No explicit rotation command is needed — the
  next write after a key change re-encrypts.
- Add a `rotate_master_key(new_key: &[u8])` method that re-derives
  keys and re-encrypts in place, for runtime rotation without restart.

### Step 8: Tests

**File:** `tests/qkey_storage_encryption_test.rs` (new),
`src/implementations/server/qkey_storage.rs` (inline tests)

- Test: `encrypt_json` then `decrypt_blob` with the correct key
  returns the original JSON.
- Test: `decrypt_blob` with the wrong key returns
  `StorageError::DecryptionFailed`.
- Test: tamper with one byte of the ciphertext → `decrypt_blob`
  returns `StorageError::IntegrityFailed` (HMAC mismatch) or
  `DecryptionFailed` (GCM tag mismatch).
- Test: the encrypted file does not contain the plaintext hash string
  (grep the bytes for a known hash → not found).
- Test: migration — write a plaintext `qkeys.json`, set
  `QUICFUSCATE_MASTER_KEY`, call `load` → file is rewritten in
  encrypted format; verify the file starts with `QFENC1`.
- Test: key rotation — encrypt with key A, load + persist with key B,
  decrypt with key B succeeds, decrypt with key A fails.
- Test: no master key + encrypted file → `StorageError::NoMasterKey`.
- Test: no master key + plaintext file → loads in fallback mode with
  a warning.
- Test: Argon2id derivation is deterministic for the same
  passphrase + salt.

## Files to Modify/Create

- `Cargo.toml` — add `aes-gcm`, `argon2`, `hmac`, `base64` deps
- `src/implementations/server/qkey_storage.rs` — **new**: encrypted
  file format, `derive_keys`, `encrypt_json`, `decrypt_blob`,
  `load_master_key`
- `src/implementations/server/qkey_registry.rs` — modify `persist`
  and `load` to encrypt/decrypt; add migration and key rotation
- `src/engine/config.rs` — add `master_key_file` config field
- `tests/qkey_storage_encryption_test.rs` — **new**: tests for
  encryption, decryption, tampering, migration, rotation

## Acceptance Criteria

- [ ] `qkeys.json` is encrypted with AES-256-GCM when a master key is
      present.
- [ ] Encryption key is derived via Argon2id (64 MiB, 3 iterations, 4
      lanes, 32-byte output).
- [ ] Master key is sourced from `QUICFUSCATE_MASTER_KEY` env var or
      `QUICFUSCATE_MASTER_KEY_FILE` path.
- [ ] HMAC-SHA-256 integrity tag detects tampering before decryption.
- [ ] Decryption with the wrong key fails with a clear error.
- [ ] Existing plaintext `qkeys.json` is automatically migrated to
      encrypted format on first load with a master key.
- [ ] Key rotation: changing the master key re-encrypts on next
      `persist`.
- [ ] Fallback mode: no master key + plaintext file loads with a
      deprecation warning.
- [ ] No master key + encrypted file returns `NoMasterKey` error.
- [ ] Master key and derived keys are zeroized on drop.
- [ ] Test: encrypted file contains no plaintext hashes.
- [ ] Test: tampering is detected (HMAC or GCM tag mismatch).
- [ ] Test: migration from plaintext works.
- [ ] Test: key rotation works.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Argon2id key derivation (load/persist) | ~100-300 ms | 64 MiB, 3 iterations; one-time per load/persist |
| AES-256-GCM encrypt (1 KB JSON) | < 10 µs | AEAD over small payload |
| AES-256-GCM decrypt (1 KB JSON) | < 10 µs | AEAD + HMAC verify |
| HMAC-SHA-256 (1 KB) | < 1 µs | Integrity check |
| File I/O (read + write) | < 1 ms | Dominated by fsync; same as plaintext |
| Memory during derivation | ~64 MiB | Argon2id memory parameter; freed after derivation |
| Encrypted file size overhead | ~58 bytes | Magic(7) + version(1) + salt(16) + nonce(12) + HMAC(32) |
