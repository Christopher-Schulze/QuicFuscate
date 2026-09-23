---
id: TODO-937
title: "TUN downlink flush: one sendto per packet -> flat staging + sendmmsg/GSO burst"
severity: MEDIUM
phase: "P"
priority: P2
status: DONE
created: 2026-09-17
depends_on: [TODO-923]
---

# TODO-937: TUN downlink flush batches via sendmmsg + GSO

Implemented in the same change that documented it - see the resolution in
`docs/todo.md` for the merged entry.
