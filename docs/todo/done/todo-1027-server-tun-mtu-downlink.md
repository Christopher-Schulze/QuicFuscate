---
id: TODO-1027
title: Server TUN MTU 1500 vs client effective 1413 blackholes TCP downlink
severity: HIGH
phase: L
priority: P1
status: DONE
created: 2026-09-21
depends_on: []
---

# TODO-1027: Server TUN MTU does not follow the inner tunnel MTU

## Context

Omega e2e 2026-09-21: TCP uplink through the tunnel is 87.167 Mbit/s
/ 0 retransmits / `qtun0 TX dropped=0`. TCP downlink (`iperf3 -R`,
15 s) delivers 0.023 Mbit/s (43 KB). ICMP ping both ways is 0% loss.
Client `qtun0` MTU is 1413 (`negotiated.min(effective_tunnel_mtu())`
after DPLPMTUD 1500 minus QUIC/MASQUE overhead). Server `qtun0` stays
1500. The server kernel therefore sources ~1460-byte TCP segments;
`deliver_tun_downlink_target` rejects `frame_len > effective_mtu`
(1413) and should emit ICMP PTB. Downlink TCP never recovers. Client
`-M 1200` does not clamp the server sender under `-R`.

## Objective

Inner TUN MTU on the server must not exceed the per-client
`effective_tunnel_mtu()` (or the min across live clients). Either set
the server TUN MTU after path-MTU confirmation, or advertise the
inner MTU in the client assignment so both stacks open at 1413.

## Acceptance

- [x] Omega `iperf3 -R` same order as uplink, `qtun0 TX dropped=0`
- [x] Assignment/open MTU 1413; admit uses opened TUN
- [x] UDP 60 M 0% loss path did not regress

## Implementation (2026-09-21)

MTU alignment landed and is still correct: server open/assignment uses
`inner_tun_mtu(1500)=1413`; downlink admit uses the opened TUN MTU, not
the pre-PMTU 1280 floor. Housekeeping `follow_live_inner_mtu` was tried
and removed after it sticky-floored live TUN at 1280.

That did not clear the 0.02 Mbit `-R` stall. The remaining blackhole was
server `PacketNormalizer` rewriting inner-VPN TCP SYNs to the Windows
persona (`window_scale=2`) while both Linux stacks use scale 10. The
server send window collapsed on client-initiated flows (`iperf3 -R`).
Uplink stayed fast because the client is the sender and sees the
unrewritten server SYN-ACK.

`normalize_tcp` now skips SYN-ACK and RFC1918 destinations. Public-dest
pure SYNs still rewrite.

Omega `/home/ubuntu/TESTING/QuicFuscate` (one release bin):
- TCP up: 93.847 Mbit/s, 0 retrans
- TCP SWAP downlink: 131.614 Mbit/s, 0 retrans
- TCP `-R` after RFC1918 SYN skip (`tcp-1027-r3`): 90.171 Mbit/s,
  135 MB recv, 0 retrans, 3085x1361 payloads, both `qtun0` MTU 1413,
  `qtun0 TX dropped=0`, `tun_drops=0`
- UDP 60 M reorder-off: 59.987 Mbit/s, 0% loss (prior 1027e/f)
