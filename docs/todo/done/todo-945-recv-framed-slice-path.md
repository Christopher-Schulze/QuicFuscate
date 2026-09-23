---
id: TODO-945
title: `recv_on_path`: Pool-Checkout + Copy + Free pro framed Datagramm -> Slice-Pfad
status: DONE
created: 2026-09-18
---

# TODO-945 - `recv_on_path`: Pool-Checkout + Copy + Free pro framed Datagramm -> Slice-Pfad

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`recv_on_path` (Slice-Eingang - der Standard-Einlieferpfad fuer Server- und
Client-Ingress) allozierte pro Datagramm einen Pool-Block, kopierte das Payload
hinein und rief `recv_pooled_block_on_path`. Der **framed** (FEC-Wire)-Pfad
las den Block aber nur als `&block[..len]`-Slice und gab ihn sofort wieder frei
- Checkout + Memcpy + Free waren reine Verschwendung auf dem haeufigsten Pfad
(FEC aktiviert -> alles ist geframed).

## Fix
- `recv_on_path` prueft `wire::is_framed(data)` vorab: geframete Datagramme
  laufen direkt auf dem Eingangs-Slice - kein Pool-Roundtrip.
- `framed_wire_report(&mut self, data, recovered)` extrahiert den
  Seed-Lazy-Init + `receive`/`receive_source_only`-Dispatch (shared mit dem
  Pooled-Block-Einlieferpfad, der weiterhin existiert: io_uring/GRO liefern
  echte Bloecke ohne Copy).
- `finish_wire_receive(report, recovered, len, from, to)` extrahiert den
  gemeinsamen Tail: Telemetry-Observe, Drain-Loop (Stealth `process_incoming`,
  `conn.recv`, Fallback), `do_tls_handshake`.
- Malformed-Semantik identisch: Parse-Fehler -> debug-log + `Ok(len)`
  (consumed), Scratch wird zurueckgelegt.

## Effekt
- Pro framed Ingress-Datagramm: 1 Pool-Checkout, 1 Payload-Memcpy, 1 Pool-Free
  eliminiert - Server-`recv_datagram_batch`-Drain und Client-Standard-RX
  profitieren beide.
- Der ungeframete Pfad (rohe QUIC-Datagramme) behaelt den Block - Ownership wird
  dort tatsaechlich gebraucht (`FecPacket::from_pooled_blocks`).

## Verifikation
- Lokal: `cargo check` + `clippy --lib` sauber; `cargo test --lib connection`
  326/326, `--lib fec` gruen.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` sauber;
  `cargo test --lib connection` 326/326 gruen.
