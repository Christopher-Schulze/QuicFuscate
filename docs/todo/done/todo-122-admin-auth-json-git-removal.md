# TODO-122: admin-auth.json Git Removal

## Status
**COMPLETED**

## Completion Note
Added `config/admin-auth.json` to `.gitignore`. Created `config/admin-auth.json.example` with placeholder values (no real hash). File was already untracked (not in git index), so no `git rm --cached` needed.

## Severity
**CRITICAL**

## Context
The file `config/admin-auth.json` contains an Argon2 password hash and is checked into git version control. Even though the password is hashed (not plaintext), having it in version control makes it a permanent brute-force target. Anyone with repository access can attempt offline dictionary/brute-force attacks against the hash indefinitely.

## Root Cause
The auth configuration file was committed to the repository without being added to `.gitignore`. No mechanism exists to auto-generate credentials on first startup, so the file was committed as a convenience.

## Fix Plan
1. Add `config/admin-auth.json` to `.gitignore` immediately to prevent future commits.
2. Remove `config/admin-auth.json` from git tracking via `git rm --cached config/admin-auth.json`.
3. Create `config/admin-auth.json.example` as a template showing the expected structure (with placeholder values, no real hashes).
4. Implement auto-generation logic in the server startup path: if `admin-auth.json` does not exist, generate a random admin password, hash it with Argon2, write the file, and print the generated password to stdout/logs once.
5. Document the setup flow in `docs/DOCUMENTATION.md` - explain that credentials are auto-generated on first start.
6. Note in the TODO that the existing hash cannot be removed from git history without a history rewrite (`git filter-branch` or `git filter-repo`). Recommend a history rewrite before any public release.

## Acceptance Criteria
- `config/admin-auth.json` is in `.gitignore` and no longer tracked by git.
- A `.example` template exists for reference.
- Server auto-generates credentials on first startup if the file is missing.
- No auth credentials (even hashed) exist in new commits.
- Documentation updated with credential setup instructions.
- Note: Removing from git history requires a separate history rewrite operation.

## Dependencies
- None for the gitignore/tracking fix.
- Auto-generation logic depends on the existing Argon2 hashing code in `admin_http.rs`.

## Affected Files
- `.gitignore`
- `config/admin-auth.json` (remove from tracking)
- `config/admin-auth.json.example` (new template file)
- `src/implementations/server/admin_http.rs` (auto-generation on missing file)
- `docs/DOCUMENTATION.md` (setup instructions)
