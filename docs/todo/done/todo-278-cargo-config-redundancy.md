# TODO-278: .cargo/config.toml Profile Redundancy and German Comments

## Severity: MEDIUM

## Source
Cross-model forensic audit (2026-03-22). Found by Mimo V2 Pro, verified.

## Problem
`.cargo/config.toml` contains:
1. `[profile.dev]`, `[profile.release]`, `[profile.test]`, `[profile.bench]` - all identical to Cargo.toml definitions. If they diverge, unexpected behavior results.
2. German comments: `# Einheitlicher Target-Ordner im Root` (line 2), `# Workspace-Einstellungen` (line 31)
3. `[workspace]` section duplicates Cargo.toml workspace settings

## Fix
1. Remove all `[profile.*]` sections from `.cargo/config.toml` (keep only in Cargo.toml)
2. Translate German comments to English
3. Remove duplicate `[workspace]` section
4. Keep only `.cargo/config.toml`-specific settings (target-dir, build flags, linker config)

## Verification
- `cargo build` still works after cleanup
- No profile conflicts between config.toml and Cargo.toml
