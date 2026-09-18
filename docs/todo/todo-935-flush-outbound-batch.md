---
id: TODO-935
title: "flush_outbound: one send syscall per ACK/PTO datagram → sendmmsg burst"
severity: MEDIUM
phase: "P"
priority: P2
status: DONE
created: 2026-09-17
depends_on: []
---

# TODO-935: flush_outbound batches ACK/PTO bursts via sendmmsg

Implemented in the same change that documented it — see the resolution in
`docs/todo.md` for the merged entry.
