# Release Threat Model Plan

## Goal
Create a formal threat model for v1 with actionable controls, tests, and monitoring hooks.

## Model Structure
- Assets
- Actors
- Trust boundaries
- Entry points
- Threat scenarios
- Mitigations
- Residual risks

## Asset Inventory
- [x] Server private keys and runtime secrets.
- [x] Admin credentials and sessions.
- [x] QKey material and policy fields.
- [x] Client runtime state and stored profiles.
- [x] Update channel metadata and binaries.

## Threat Scenarios
- [x] Credential stuffing and brute-force on admin login.
- [x] Session theft and fixation.
- [x] QKey misuse, replay, unauthorized issuance.
- [x] Config tampering through admin paths.
- [x] Malicious update payload and signature bypass.
- [x] Probe/detection evasion failures under censorship.
- [x] Local privilege abuse through desktop IPC commands.

## Mitigation Mapping
- [x] Map each threat to current controls.
- [x] Identify missing controls and classify severity.
- [x] Add detection/alerting signals and test hooks.

## Acceptance Criteria
- [x] Threat model is documented in `docs/DOCUMENTATION.md`.
- [x] Each threat has control owner and verification method.
- [x] Residual risks are explicit and accepted or planned.

## Completion Note (2026-02-12)
- Threat model is now documented in `docs/DOCUMENTATION.md` under "Threat Model (v1)" with assets, trust boundaries, threat scenarios, controls, verification hooks, and residual risks.
