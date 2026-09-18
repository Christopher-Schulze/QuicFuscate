# TODO-939 — Client-RX Standardpfad: Per-Datagram-Kopie in Batch-Slots → Flat+Spans

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`run_inbound_standard` kopierte jedes empfangene Datagramm per
`emit_wire_record` in einen `Vec<Vec<u8>>`-Slot (`clear` + `extend_from_slice`),
weil der 64-KiB-`recv_buf` vom nächsten `try_recv` überschrieben wurde.
`process_inbound_batch` las jedes Payload danach genau einmal
(`conn_guard.recv(&payload)`) — die Kopie war reine Verschwendung:
1 Memcpy + 2 Atomics (Copy-Telemetrie) pro Datagramm.

## Fix
- Persistenter `recv_flat: Vec<u8>` mit `batch_cap` Slots à 64 KiB
  (fester Stride, Default-Batch 64 → 4 MiB; identische Größenordnung wie das
  Server-Downlink-Staging aus TODO-937).
- `emit_wire_spans(base, len, gso, spans)` ersetzt `emit_wire_record`:
  reine Span-Arithmetik, kein Byte wird bewegt. GRO-Superbuffer erzeugen
  weiterhin mehrere Spans pro Slot.
- Jeder Recv schreibt in einen eigenen Slot (`slots_used * 65535`); die
  Span-Tabelle `(offset, len)` zeichnet die Datagramm-Grenzen in Wire-Order auf.
- `process_inbound_batch` iteriert Spans und übergibt Slices direkt an
  `conn.recv` — `conn` sieht unverändert `&[u8]`.
- Plattformneutral: kein `cfg`-Split nötig (gilt für Linux `recv_msg_gro`
  und non-Linux `recv`/`try_recv` gleichermaßen).
- `IO_DRIVER_COPY_OPS/BYTES`-Telemetrie fällt auf diesem Pfad weg (keine
  Kopien mehr); `IO_DRIVER_BATCH_DRAIN_PACKETS` bleibt.
- Bounded: Recvs ≤ `batch_cap` (jeder Recv erzeugt ≥1 Span →
  `slots_used ≤ spans.len() < batch_cap` garantiert freien Slot).

## Verifikation
- Lokal: `cargo check`, `cargo clippy -p quicfuscate --lib` sauber;
  `cargo test --lib io_driver` 17/17.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` + `clippy`
  sauber, `cargo test --lib io_driver` 22/22 grün.

## Grenzen
- Der io_uring-Inbound-Pfad (`run_inbound_uring`/`UringRecvBatch`) war bereits
  zero-copy über Pool-Blöcke/GRO-cmsg — unverändert.
- Worst-Case-Speicher: `batch_cap × 65535` (max. 256 → 16 MiB bei
  `wide_batch_cpu` + max. konfiguriertem Batch). Fest verdrahtet, kein
  Laufzeit-Wachstum.
