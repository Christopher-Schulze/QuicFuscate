

## [2025-07-09] - Optimierte Bitslice-Kerne

### ✨ Added
- Optimierte Multiplikationsroutinen für AVX2, AVX512 und NEON.
- Benchmarkdokumentation aktualisiert.

### 📜 Ergebnisse
- AVX2 erreicht nun ca. 2,5 GB/s, AVX512 rund 4 GB/s und NEON etwa 2,3 GB/s.

## [2024-12-24] - Bit-Sliced GF Multiplication

### ✨ Added
- Neue bitgeschnittene Multiplikationsroutinen für AVX2/AVX512 und NEON.
- Erweiterte CPU-Feature-Erkennung mit dynamischem Dispatching.

### 📝 Ergebnisse
- Rund 30% mehr Durchsatz auf AVX2- und 40% auf AVX512-Systemen.

## [2024-12-23] - CLI Compilation Fixes

### ✅ Behoben
- Die Kommandozeilenanwendung kompiliert wieder nach Anpassungen an den
  Verbindungsaufrufen und Feldnamen.

## [2024-12-22] - Deprecated C++ Removal

### 🔥 Removed
- `crypto/aegis128l.cpp`, `crypto/aegis128x.cpp`, `crypto/morus.cpp`, `crypto/morus1280.cpp` removed in favor of Rust implementations.

## [2024-12-20] - MORUS-1280-128 Implementierung

### ✅ Behoben
- **Vollständige ASCON-Ersetzung**: Alle ASCON-Referenzen durch MORUS-1280-128 ersetzt
- **Konsistente Cipher Suite Benennung**: Alle TLS-Identifikatoren und Kommentare aktualisiert
- **Komplette Code-Integration**: Alle Referenzen in C++, Rust und Dokumentation ersetzt
- **Datei-Umbenennung**: `ascon.hpp/cpp` zu `morus.hpp/cpp` umbenannt

### 🔧 Geändert
- `crypto/cipher_suite_selector.hpp` und `crypto/cipher_suite_selector.cpp`: ASCON durch MORUS-1280-128 ersetzt
- `crypto/ascon.hpp` → `crypto/morus.hpp`: Klasse `Ascon` zu `MORUS` umbenannt
- `crypto/ascon.cpp` → `crypto/morus.cpp`: Alle Funktionen und Konstanten aktualisiert
- `core/quic_connection.hpp`: Include und Variable von ASCON zu MORUS geändert
- `stealth/browser_profiles/fingerprints/browser_fingerprint.hpp`: Cipher Suite Liste aktualisiert
- `stealth/tls/FakeTLS.hpp`, `stealth/tls/FakeTLS.cpp`, `stealth/tls/uTLS.cpp`: TLS-Fingerprinting angepasst
- `libs/patched_quiche/quiche/src/crypto.rs`: Algorithm enum und alle Referenzen aktualisiert
- `libs/patched_quiche/quiche/src/tls.rs`: TLS-Cipher-Mapping aktualisiert
- `DOCUMENTATION.md`: Vollständige Dokumentation überarbeitet

### 📝 Technische Details
- MORUS-1280-128 bietet bessere Performance (2-3 Gbps) als ASCON (1-2 Gbps) in Software-Implementierungen
- Beibehaltung der 128-bit Schlüssel-, Tag- und Nonce-Größen für Kompatibilität
- Konsistente TLS-ID 0x1304 für `TLS_MORUS_1280_128_SHA256`
- Hardware-Erkennung bleibt unverändert (VAES → AEGIS-128X, AES-NI → AEGIS-128L, Software → MORUS-1280-128)
- Vollständige Umbenennung aller Funktionen: `ascon_permutation` → `morus_permutation`

### 🎯 Auswirkungen
- **Performance**: 50-100% Verbesserung der Software-Fallback-Geschwindigkeit
- **Kompatibilität**: Vollständig rückwärtskompatibel durch beibehaltene TLS-IDs
- **Sicherheit**: Gleichwertige kryptographische Stärke bei verbesserter Effizienz
- **Code-Konsistenz**: Keine verbleibenden ASCON-Referenzen im gesamten Projekt

## [2024-12-19] - SIMD Konsolidierung

### ✅ Behoben
- **SIMD-Funktionalität konsolidiert**: Fehlende `simd_dispatch.hpp` und `simd_feature_detection.hpp` Header-Dateien wurden in `optimize/unified_optimizations.hpp` integriert
- **Rückwärtskompatibilität hergestellt**: `simd::FeatureDetector` Wrapper-Klasse hinzugefügt für bestehenden Crypto-Code
- **CPU-Feature-Erkennung vereinheitlicht**: `UnifiedFeatureDetector` als zentrale Implementierung

### 🔧 Geändert
- `optimize/unified_optimizations.hpp`: `simd::FeatureDetector` Kompatibilitäts-Wrapper hinzugefügt
- `docs/todo.md`: SIMD-bezogene Untersuchungspunkte als erledigt markiert
- `docs/DOCUMENTATION.md`: SIMD-Sektion aktualisiert mit Konsolidierungshinweisen und Rückwärtskompatibilität
- `crypto/aegis128l.cpp`, `crypto/aegis128x.cpp`, `crypto/cipher_suite_selector.hpp`: Include-Statements auf unified_optimizations.hpp aktualisiert

### 📝 Technische Details
- Bestehende Crypto-Module (`aegis128l.cpp`, `aegis128x.cpp`, `cipher_suite_selector.hpp`) verwenden weiterhin `simd::FeatureDetector::instance()`
- Neue Implementierungen können direkt `UnifiedFeatureDetector::has_feature()` verwenden
- Alle SIMD-Dispatching-Funktionalität ist nun in einer einzigen Header-Datei konsolidiert

### 🎯 Auswirkungen
- Kompilierung funktioniert wieder ohne fehlende Header-Includes
- Einheitliche SIMD-API für das gesamte Projekt
- Reduzierte Code-Duplikation und verbesserte Wartbarkeit

---

*Ende des Changelogs*
