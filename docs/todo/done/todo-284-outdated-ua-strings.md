# TODO-284: Update Outdated User-Agent Strings

## Problem
Hardcoded UA strings reference outdated browser versions:
- `UA_CHROME_WIN` = Chrome/130 (Q4 2024, current is ~135+)
- Firefox 133 references similarly outdated

Outdated UAs are a DPI fingerprinting vector - the whole point of stealth mode is to look like current browser traffic.

## Source
AI Model Review (Mimo v2 Pro, GLM-5) - verified correct.

## Location
- `src/stealth/mod.rs` - UA_CHROME_WIN and related constants

## Fix
Update all UA strings to current stable browser versions (Chrome 136+, Firefox 138+, Safari 18+).

## Acceptance Criteria
- All UA strings reflect current browser versions
- Tests pass
- No stale version references remain
