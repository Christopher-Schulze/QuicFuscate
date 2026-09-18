# TODO-940 — Server-TUN-Uplink: `to_vec` pro Frame im Reader-Thread → Pool-Channel

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
Der dedizierte `tun-reader`-Thread las jedes Frame über
`reader_loop_with_shutdown` (Callback mit `&[u8]` in einen Pool-Block) und kopierte
es sofort per `packet.to_vec()` in einen frischen Heap-Vec, der dann durch den
`sync_channel` an den Run-Loop ging — pro TUN-Paket: 1 Pool-Block-Checkout,
1 Heap-Alloc, 1 Memcpy, 1 Free. Der Pool-Block wurde am Callback-Ende sofort
zurückgegeben, die kopierten Bytes lebten als `Vec<u8>` weiter.

## Fix
- Channel-Typ `Vec<u8>` → `crate::interface::TunPacket` (bereits vorhanden:
  `PooledBlock` + `len`, `Send`-fähig über `AlignedBox`/`Arc`-Felder).
- Reader nutzt `reader_loop_with_shutdown_owned` (`interface.rs:720`), das den
  Pool-Block als `TunPacket` in die Callback gibt — `tx.send(packet)` schiebt
  den Block unverändert über den Channel.
- Consumer-Seite (`drain_server_tun_packets`, `tun_path.rs`) liest
  `packet.as_slice()`; beim Drop des `TunPacket` fließt der Block in den
  TUN-Pool zurück — der Reader findet ihn dort wieder.
- `tun_rx`-Feldtyp in `ServerLiveRuntime` entsprechend migriert.

## Effekt
- 0 Heap-Allocs, 0 Payload-Kopien auf dem TUN-Uplink-Hotpath (vorher: 1×
  `to_vec` pro Frame).
- Bounded: `sync_channel`-Kapazität `TUN_PACKET_QUEUE_CAPACITY` = 1024 deckelt
  in-flight Pool-Blöcke; Pool wächst bei Bedarf (`alloc_cold` allokiert frisch —
  kein Deadlock-Risiko durch Erschöpfung).
- Send-Fehlerpfad unverändert: Drop des Pakets gibt den Block zurück, Fault-
  Reporting und Shutdown-Semantik identisch.

## Verifikation
- Lokal: `cargo check`, `cargo clippy --lib` sauber; `cargo test --lib tun_path`
  grün.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` sauber;
  `cargo test --lib tun` 58/58 grün.

## Grenzen
- Channel bleibt `std::sync::mpsc::sync_channel` (ein Mutex-Handoff pro Paket) —
  ein evtl. späterer Umstieg auf `SegQueue`/crossbeam wäre ein eigenes Finding.
