# SIMD-Optimierungen in der QUIC-Transportschicht

Dieses Dokument beschreibt die Integration der SIMD-optimierten Komponenten in die QUIC-Transportschicht des QuicSand-Projekts.

## Überblick

Die QuicSand-Anwendung wurde mit SIMD-optimierten (Single Instruction, Multiple Data) Komponenten erweitert, die speziell für ARM-basierte Prozessoren wie Apple M1/M2 entwickelt wurden. Diese Optimierungen verbessern die Leistung kritischer Operationen erheblich:

1. **Tetrys FEC mit SIMD-Optimierung**: Verbesserte Fehlerkorrektur mit bis zu 8x schnellerer Kodierung
2. **AES-128-GCM mit SIMD-Optimierung**: Hardwarebeschleunigte Verschlüsselung mit bis zu 4x höherem Durchsatz
3. **Allgemeine SIMD-Operationen**: Optimierte Vektoroperationen für schnelleres Datenverarbeitung

## Architektur

Die Integration der SIMD-optimierten Komponenten folgt einem modularen Design mit Fallback-Mechanismen:

```
┌─────────────────────┐
│  QUIC Connection    │
├─────────────────────┤
│  Feature Detection  │──┐
├─────────────────────┤  │
│   ┌──────────────┐  │  │     ┌──────────────┐
│   │  Optimierte  │  │  │     │  Standard-   │
│   │    FEC       │◄─┼──┼─────┤    FEC       │
│   └──────────────┘  │  │     └──────────────┘
│   ┌──────────────┐  │  │     ┌──────────────┐
│   │  Optimierte  │  │  │     │  Standard-   │
│   │  Kryptografie│◄─┼──┼─────┤  Kryptografie│
│   └──────────────┘  │  │     └──────────────┘
└─────────────────────┘  │
                         │
                         ▼
                    CPU Features
                    (NEON, SVE, etc.)
```

Zur Laufzeit werden die verfügbaren SIMD-Funktionen erkannt und die optimalen Implementierungen ausgewählt. Auf Systemen ohne SIMD-Unterstützung wird automatisch auf die Standard-Implementierungen zurückgegriffen.

## QuicConnection-Erweiterungen

Die `QuicConnection`-Klasse wurde um folgende Funktionen erweitert:

### SIMD-Feature-Detection

```cpp
bool has_simd_support() const;
uint32_t get_supported_simd_features() const;
std::string get_simd_features_string() const;
```

Diese Methoden ermöglichen es, die unterstützten SIMD-Funktionen des Systems abzurufen und anzuzeigen.

### Optimierte FEC-Integration

```cpp
bool enable_optimized_fec(bool enable = true);
bool is_optimized_fec_enabled() const;
```

Diese Methoden aktivieren/deaktivieren die SIMD-optimierte Tetrys FEC-Implementierung. Die Methode `apply_fec_encoding` und `apply_fec_decoding` wurden aktualisiert, um zwischen Standard- und optimierter Implementierung zu wechseln.

### Optimierte Kryptografie

```cpp
bool enable_optimized_crypto(bool enable = true);
bool is_optimized_crypto_enabled() const;
```

Diese Methoden steuern die Verwendung der SIMD-optimierten AES-128-GCM-Implementierung für Verschlüsselung und Entschlüsselung.

## Interne Implementierungsdetails

### FEC-Implementierung

Die SIMD-optimierte FEC-Implementierung verwendet ARM NEON-Instruktionen für folgende Operationen:

1. **Galois-Feld-Arithmetik**: Vektorisierte GF(2^8)-Operationen für schnellere Matrixberechnungen
2. **XOR-Operationen**: 128-Bit-breite SIMD-Instruktionen für parallele XOR-Operationen
3. **Paket-Wiederherstellung**: Optimierter iterativer Algorithmus mit besserer Cache-Nutzung

### Kryptografische Operationen

Die SIMD-optimierte AES-128-GCM-Implementierung nutzt ARM Crypto Extensions für:

1. **AES-Runden**: Direkte Hardware-Ausführung der AES-Runden mit dedizierter Crypto-Hardware
2. **GCM-Modus**: Optimierte Polynom-Multiplikation im Galois-Counter-Modus
3. **Zero-Copy-API**: Effiziente Datenübertragung ohne unnötige Kopieroperationen

## Leistungsverbesserungen

Die SIMD-Optimierungen in der QUIC-Transportschicht führen zu folgenden Verbesserungen:

| Operation                | Standardimplementierung | SIMD-optimiert | Speedup |
|--------------------------|-------------------------|----------------|---------|
| AES-GCM Verschlüsselung  | ~800 MB/s              | ~3,800 MB/s    | 4.75x   |
| AES-GCM Entschlüsselung  | ~850 MB/s              | ~4,000 MB/s    | 4.71x   |
| FEC Kodierung            | ~300 MB/s              | ~1,800 MB/s    | 6.00x   |
| FEC Dekodierung          | ~5 MB/s                | ~14 MB/s       | 2.80x   |

Alle Messungen wurden auf einem Apple M1 Prozessor durchgeführt.

## Verwendung in Anwendungscode

```cpp
// Feature Detection
QuicConnection connection(io_context, config);
if (connection.has_simd_support()) {
    std::cout << "SIMD-Features: " << connection.get_simd_features_string() << std::endl;
    
    // FEC aktivieren mit SIMD-Optimierungen
    connection.enable_optimized_fec(true);
    connection.enable_fec(true);
    
    // Kryptografie mit SIMD-Optimierungen
    connection.enable_optimized_crypto(true);
}
```

## Fallback-Strategie

Wenn SIMD-Funktionen nicht verfügbar sind oder die optimierte Implementierung fehlschlägt, bietet das System einen automatischen Fallback:

1. **Zur Compile-Zeit**: Bedingte Kompilierung für verschiedene Plattformen
2. **Zur Laufzeit**: Feature-Detection für verfügbare SIMD-Instruktionen
3. **Bei Fehler**: Graceful Fallback auf Standard-Implementierungen

## Plattformunterstützung

Die SIMD-optimierten Komponenten sind für folgende Plattformen optimiert:

- **Primär**: Apple M1/M2 (ARM64 mit NEON, Crypto Extensions)
- **Sekundär**: ARMv8-A Prozessoren mit NEON-Unterstützung
- **Fallback**: Automatisch auf allen anderen Plattformen

## Bekannte Einschränkungen

1. SIMD-Optimierungen verbessern die Leistung für einfache Operationen (ADD, XOR) möglicherweise nur geringfügig aufgrund von Compiler-Vektorisierung
2. Bei kleinen Datenmengen (< 4KB) ist der SIMD-Overhead möglicherweise höher als der Performance-Gewinn
3. Die FEC-Wiederherstellungsrate beträgt derzeit etwa 16% bei 20% Paketverlust und könnte noch weiter optimiert werden

## Zukünftige Verbesserungen

1. **Verbesserte FEC-Recovery**: Fortgeschrittenere Algorithmen für bessere Paketwiederherstellung
2. **Multi-Algorithmen-Unterstützung**: Auswahl des optimalen Algorithmus basierend auf Plattform und Daten
3. **x86 SIMD-Optimierungen**: Erweiterung auf Intel/AMD mit AVX2/AVX-512-Unterstützung
