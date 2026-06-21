---
id: TODO-375
title: "Replace unwrap() in quicfuscate-ctl with proper error handling"
severity: "LOW"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-375: Replace unwrap() in quicfuscate-ctl with proper error handling


## Problem
`src/bin/quicfuscate-ctl.rs` lines 122-163 use heavy `unwrap()` for JSON field access.
A malformed server response will crash the CLI tool instead of showing a useful error.

## Fix Plan
1. Replace unwrap() chains with proper error handling (? operator or match)
2. Print user-friendly error message on malformed responses
3. Return non-zero exit code on failure

## Files to Modify
- src/bin/quicfuscate-ctl.rs