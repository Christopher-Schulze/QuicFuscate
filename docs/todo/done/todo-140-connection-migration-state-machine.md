# TODO-140: Connection Migration State Machine Missing

## Status
**PARTIAL** - PathEvent documented with RFC 9000 gaps, pending_path_challenges field added as skeleton

## Severity
**MEDIUM**

## Context
In `src/transport/connection.rs:56-74`, the `PathEvent` enum defines variants for path validation events (`PathChallenge`, `PathResponse`, `PathAbandoned`, etc.), and `src/transport/frames.rs` includes `PathChallenge` and `PathResponse` frame types. However, no state machine drives the path validation lifecycle.

Current state:
- `PathEvent` enum exists but is never constructed or matched on in a state machine
- `PathChallenge` frames can be parsed from wire but no challenge is ever initiated
- `PathResponse` frames can be parsed but responses are never validated against pending challenges
- No tracking of validated vs unvalidated paths
- No migration cooldown to prevent abuse

Per RFC 9000 Section 9, connection migration requires:
- Initiating path validation with PATH_CHALLENGE containing random data
- Matching PATH_RESPONSE to pending challenges
- Tracking path validation state (pending, validated, failed)
- Limiting migration frequency to prevent amplification attacks

## Root Cause
Path validation frames were implemented at the parsing layer but the control logic was never built. The `PathEvent` enum appears to be a design sketch that was never connected to a state machine.

## Fix Plan
1. Create a `PathValidator` struct tracking:
   - `pending_challenges: HashMap<SocketAddr, (ChallengeData, Instant)>` - outstanding challenges
   - `validated_paths: HashSet<SocketAddr>` - paths that have been validated
   - `last_migration: Instant` - cooldown tracking
   - `challenge_timeout: Duration` - configurable timeout for path validation
2. Implement path validation state machine:
   - `initiate_validation(new_path)` - send PATH_CHALLENGE with 8 random bytes
   - `on_challenge_received(data)` - respond with PATH_RESPONSE echoing data
   - `on_response_received(data)` - match against pending, mark path validated
   - `check_timeouts()` - expire stale challenges
3. Integrate with connection migration logic:
   - On packet from new address: initiate validation before migrating
   - Only migrate after path is validated
   - Enforce migration cooldown
4. Add anti-amplification: limit data sent on unvalidated path to 3x received
5. Unit tests for full validation lifecycle

## Acceptance Criteria
- Connection migration works with proper path validation per RFC 9000 Section 9
- Pending challenges tracked and matched against responses
- Validated paths recorded, unvalidated paths rate-limited
- Migration cooldown prevents rapid path switching
- Anti-amplification limit enforced on unvalidated paths
- Unit and integration tests cover the full lifecycle

## Dependencies
- `src/transport/frames.rs` - PATH_CHALLENGE/PATH_RESPONSE frame handling
- `src/transport/connection.rs` - connection state integration
- Cryptographically random challenge data generation

## Affected Files
- `src/transport/connection.rs` (state machine, integration)
- `src/transport/frames.rs` (frame construction for outgoing challenges/responses)
- `src/transport/packet.rs` (sending challenge/response frames)
