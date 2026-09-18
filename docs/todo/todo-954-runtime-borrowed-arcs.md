# TODO-954 - `LiveClientRuntime`: borrowed `&'a Arc` fields instead of 3 clones per datagram

## Status
DONE

## Problem
`LiveClientRuntime` (built per inbound datagram in the `Occupied` acquire
arm) carried owned `forwarding_policy`, `sessions`, and `fanout_queue` -
three `Arc::clone`s (atomic increments) per packet. The only place needing
owned Arcs is the `'static` MASQUE datagram callback, and `Arc::clone`
itself only needs `&Arc` - the runtime never had to own them.

## Solution
- `LiveClientRuntime.forwarding_policy` / `sessions` / `fanout_queue` are
  now `&'a Arc<...>` / `&'a ClientFanoutQueue` - the struct already has the
  `'a` lifetime from `connection`.
- Acquire locals bind `&self.domain.shared.*` / `&self.fanout_queue` instead
  of `Arc::clone`s.
- `live_auth.rs`: `Arc::clone(&x)` -> `Arc::clone(x)` for the 'static
  callback; `&x` -> `x` at the borrow-taking callsites
  (`admit_session_bandwidth`, `allow_client_uplink`, `enqueue_client_fanout`).

Net: -3 atomic refcount ops per inbound server datagram.

## Verification
- `cargo check --all-targets` clean locally and on Omega.
- `cargo clippy --lib --all-targets` clean.
- qkey 129/129 on both platforms.

## Files
- `src/implementations/server/live_state.rs` - field types + acquire locals.
- `src/implementations/server/live_auth.rs` - clone/callsite adjustments.
