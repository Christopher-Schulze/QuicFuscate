# TODO-172: Troubleshooting Guide

## Status
**COMPLETED** - Created `docs/troubleshooting.md` covering connection failures, DNS leak detection/prevention, kill-switch issues per platform, performance tuning, log interpretation, platform-specific issues (Linux/macOS/Windows), and admin interface troubleshooting.

## Severity
**LOW**

## Context
No troubleshooting documentation exists. Users encountering issues have no reference for diagnosing common problems, leading to repeated support requests for the same issues.

- No `docs/troubleshooting.md` or equivalent exists
- Common issues (connection failures, DNS leaks, performance problems) undocumented

## Root Cause
Operational knowledge exists only in developer heads. No structured effort to document common failure modes and their resolutions.

## Fix Plan
1. Create `docs/troubleshooting.md` covering:
   - **Connection failures**: TLS handshake errors, timeout tuning, firewall issues, NAT traversal
   - **DNS leaks**: Detection methods, platform-specific DNS configuration, kill-switch verification
   - **Performance tuning**: MTU optimization, buffer sizing, FEC configuration, CPU affinity
   - **Kill-switch issues**: Platform-specific behavior (Linux/macOS/Windows), recovery procedures
   - **Platform-specific problems**:
     - Linux: io_uring compatibility, XDP requirements, kernel version issues
     - macOS: utun interface issues, network extension permissions
     - Windows: WinTun driver installation, service permissions
   - **Admin interface**: Connection refused, authentication issues
   - **Logging**: How to enable debug logging, interpreting log output
   - **Stealth mode**: Mode selection guidance, detection avoidance tips
2. Include diagnostic commands for each issue category
3. Link from README.md

## Acceptance Criteria
- Common issues have documented symptoms, causes, and solutions
- Diagnostic commands provided for each issue category
- Platform-specific sections cover Linux, macOS, and Windows
- Guide is searchable by error message or symptom

## Dependencies
- None

## Affected Files
- `docs/troubleshooting.md` (new)
- `README.md` (add link)
