# TODO-280: Config stealth.mode = "performance" Non-Canonical Value

## Severity: MEDIUM

## Source
Cross-model forensic audit (2026-03-22). Found by MiniMax M2.7 (Kilocode), verified.

## Problem
`config/server-linux.default.toml` line 52: `mode = "performance"`

Canonical StealthMode values are: "off", "auto", "max", "manual".
"performance" is a runtime alias (mapped to the same baseline as "base") but is not a canonical config value. The parser silently falls back to the default mode without warning.

## Fix
Change line 52 to a canonical value:
```toml
mode = "auto"
```

Or if "performance" should be canonical, add it to the parser's match arms with a comment.

## Verification
- Config validation: no silent fallback on default template values
- Server starts with expected stealth mode
