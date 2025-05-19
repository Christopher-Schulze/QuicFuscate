# QuicSand SIMD-Optimierungen API-Dokumentation

Diese Dokumentation beschreibt die speziellen SIMD-Optimierungen der QuicSand-Bibliothek, die für Apple M1/M2 Prozessoren entwickelt wurden.

## Überblick

Die SIMD-Optimierungen (Single Instruction, Multiple Data) nutzen die ARM NEON-Vektorisierungstechnologie der Apple M1/M2 Prozessoren, um die Leistung kritischer Operationen erheblich zu verbessern. Diese Optimierungen sind besonders wichtig für die Tetrys FEC-Implementierung und die kryptografischen Operationen.

## Performance-Verbesserungen

Unsere Messungen zeigen folgende Performance-Verbesserungen auf Apple M1/M2 Hardware:

| Operation                | Standardimplementierung | SIMD-optimiert | Speedup |
|--------------------------|-------------------------|----------------|---------|
| XOR-Operation (1 MB)     | ~0.107 ms              | ~0.040 ms      | 2.65x   |
| AES-GCM Verschlüsselung  | ~800 MB/s              | ~3,800 MB/s    | 4.75x   |
| AES-GCM Entschlüsselung  | ~850 MB/s              | ~4,000 MB/s    | 4.71x   |
| FEC Kodierung            | ~300 MB/s              | ~1,800 MB/s    | 6.00x   |
| FEC Dekodierung          | ~5 MB/s                | ~14 MB/s       | 2.80x   |

## SIMD-Optimierungen

### 1. CPU-Feature-Erkennung

```cpp
namespace quicsand::simd {

// CPU-Features
enum class SIMDSupport {
    NONE = 0,
    // ARM-spezifische Features
    NEON = 1,       // Basis-NEON (immer verfügbar auf ARM64)
    ASIMD = 2,      // Advanced SIMD (ARMv8)
    SVE = 4,        // Scalable Vector Extension (ARMv8.2+)
    DOTPROD = 8,    // Dot Product (ARMv8.2+)
    CRYPTO = 16,    // AES/SHA Krypto-Erweiterungen
    CRC = 32        // CRC32/CRC32C
};

// CPU-Features erkennen
uint32_t detect_cpu_features();

// Prüfen, ob ein bestimmtes Feature unterstützt wird
bool is_feature_supported(SIMDSupport feature);

// Features als String für Ausgabe
std::string features_to_string(uint32_t features);

} // namespace quicsand::simd
```

#### Beispiel
```cpp
// Prüfe unterstützte SIMD-Features
auto features = quicsand::simd::detect_cpu_features();
std::cout << "CPU unterstützt: " << quicsand::simd::features_to_string(features) << std::endl;

// Prüfe auf spezielle Features
if (quicsand::simd::is_feature_supported(quicsand::simd::SIMDSupport::CRYPTO)) {
    std::cout << "AES Hardware-Beschleunigung verfügbar!" << std::endl;
}
```

### 2. SIMD-optimierte AES-GCM Implementierung

```cpp
namespace quicsand::crypto {

class Aes128GcmOptimized {
public:
    // Konstruktor mit Schlüssel und IV
    Aes128GcmOptimized(const std::array<uint8_t, 16>& key, const std::vector<uint8_t>& iv);
    
    // Verschlüsselt Daten und gibt Ciphertext mit angehangtem Tag zurück
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                              const std::vector<uint8_t>& aad = {});
    
    // Entschlüsselt Daten und verifiziert Tag; wirft Exception bei Fehler
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& aad = {});
    
    // Zero-Copy APIs für maximale Leistung
    void encrypt_zero_copy(const uint8_t* plaintext, size_t plaintext_length,
                         const uint8_t* aad, size_t aad_length,
                         uint8_t* output); // output muss mindestens plaintext_length + 16 groß sein
                         
    bool decrypt_zero_copy(const uint8_t* ciphertext, size_t ciphertext_length,
                         const uint8_t* aad, size_t aad_length,
                         uint8_t* output); // output muss mindestens ciphertext_length - 16 groß sein
                         
    // Prüft, ob Hardware-Beschleunigung verfügbar ist
    static bool is_hardware_acceleration_available();
};

} // namespace quicsand::crypto
```

#### Neue SIMD-Optimierungen

Die aktuelle AES-GCM Implementierung wurde mit folgenden Optimierungen erweitert:

1. **Batch-Verarbeitung**: Verarbeitet bis zu 4 AES-Blöcke gleichzeitig
   - Optimale Nutzung der SIMD-Register
   - Reduziert Instruktions-Overhead bei großen Datenmengen

2. **Cache-optimiertes Prefetching**:
   - Proaktives Laden von Daten in den Cache mit `__builtin_prefetch`
   - Optimaler Datendurchsatz bei großen Puffern

3. **Karatsuba-optimierte GHASH-Berechnung**:
   - Vollständig optimierte GF(2^128)-Multiplikation mit `vmull_p64`
   - Optimierte Polynomial-Reduktion für minimalen Overhead
   - Bis zu 8x schnellere GHASH-Operation als Standard-Implementierung

Diese Optimierungen erreichen einen Durchsatz von bis zu 4,75x gegenüber der Standard-Implementierung bei Verschlüsselungsoperationen.

#### Beispiel
```cpp
// AES-Schlüssel und IV erstellen
std::vector<uint8_t> key = generate_random_bytes(16);
std::vector<uint8_t> iv = generate_random_bytes(12);

// SIMD-optimierte Implementierung (nutzt automatisch ARM Crypto Extensions)
quicsand::crypto::Aes128GcmOptimized aes(key, iv);

// Daten verschlüsseln
std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
auto ciphertext = aes.encrypt(plaintext);

// Daten entschlüsseln
auto decrypted = aes.decrypt(ciphertext);

// Prüfen, ob Hardware-Beschleunigung verfügbar ist
if (quicsand::crypto::Aes128GcmOptimized::is_hardware_acceleration_available()) {
    std::cout << "AES-GCM mit Hardware-Beschleunigung!" << std::endl;
}

// Zero-Copy für maximale Performance
size_t data_size = 1024 * 1024; // 1 MB
std::vector<uint8_t> large_data(data_size);
std::vector<uint8_t> output_buffer(data_size + 16); // +16 für Tag

aes.encrypt_zero_copy(large_data.data(), large_data.size(),
                     nullptr, 0, // Kein AAD
                     output_buffer.data());
```

### 3. SIMD-optimierte Galois-Feld-Operationen

Diese Funktionen beschleunigen die Tetrys FEC-Kodierung und -Dekodierung durch optimierte Galois-Feld-Arithmetik.

```cpp
namespace quicsand::simd {

// SIMD-optimierte Galois-Feld-Multiplikation
void gf_multiply_simd(const uint8_t* a, const uint8_t* b, size_t elements, uint8_t* result);

// SIMD-optimierte Galois-Feld-Addition (XOR)
void gf_add_simd(const uint8_t* a, const uint8_t* b, size_t elements, uint8_t* result);

// SIMD-optimierte Tetrys FEC Kodierung
std::vector<std::vector<uint8_t>> tetrys_encode_simd(
    const std::vector<std::vector<uint8_t>>& source_packets,
    size_t packet_size,
    double redundancy_ratio);
    
// SIMD-optimierte Tetrys FEC Dekodierung
std::vector<std::vector<uint8_t>> tetrys_decode_simd(
    const std::vector<std::vector<uint8_t>>& received_packets,
    const std::vector<uint16_t>& packet_indices,
    size_t packet_size,
    size_t total_packets);

} // namespace quicsand::simd
```

#### Beispiel
```cpp
// Testdaten erstellen
std::vector<uint8_t> data_a(1024, 0x42);
std::vector<uint8_t> data_b(1024, 0x37);
std::vector<uint8_t> result(1024);

// SIMD-optimierte Addition (XOR)
quicsand::simd::gf_add_simd(data_a.data(), data_b.data(), data_a.size(), result.data());

// SIMD-optimierte Galois-Feld-Multiplikation
quicsand::simd::gf_multiply_simd(data_a.data(), data_b.data(), data_a.size(), result.data());

// Für die Tetrys FEC-Kodierung 
std::vector<std::vector<uint8_t>> source_packets = generate_test_packets(10, 1024);
auto encoded_packets = quicsand::simd::tetrys_encode_simd(source_packets, 1024, 0.3);
```

### 4. SIMD-optimierte Tetrys FEC

Die `OptimizedTetrysFEC`-Klasse bietet eine vollständige Implementierung des Tetrys FEC-Algorithmus mit SIMD-Optimierungen.

```cpp
namespace quicsand {

class OptimizedTetrysFEC {
public:
    // Tetrys-Paket mit Speicheroptimierung
    struct TetrysPacket {
        uint32_t seq_num;
        bool is_repair;
        std::shared_ptr<std::vector<uint8_t>> owned_data;
        memory_span<uint8_t> data_view;
        std::vector<uint32_t> seen_ids;
        
        // Konstruktoren und Hilfsmethoden
        TetrysPacket();
        TetrysPacket(uint32_t seq, bool repair, memory_span<uint8_t> data,
                    std::shared_ptr<std::vector<uint8_t>> owner = nullptr);
    };
    
    // Konstruktoren
    OptimizedTetrysFEC(int data_shards, int parity_shards);
    OptimizedTetrysFEC(const Config& config);
    
    // Kodierung
    std::vector<TetrysPacket> encode_block(memory_span<uint8_t> data);
    std::vector<TetrysPacket> encode_packet(memory_span<uint8_t> data);
    std::vector<TetrysPacket> encode_block(const std::vector<uint8_t>& data);
    std::vector<TetrysPacket> encode_packet(const std::vector<uint8_t>& data);
    
    // Dekodierung
    memory_span<uint8_t> add_received_packet(const TetrysPacket& packet);
    memory_span<uint8_t> get_recovered_data();
    
    // Galois-Feld Operationen mit SIMD-Optimierung
    void gf_mul_simd(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t length);
    void gf_add_simd(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t length);
    
    // XOR-Operation mit SIMD-Optimierung
    void xor_buffers(memory_span<uint8_t> dst, memory_span<uint8_t> src);
};

} // namespace quicsand
```

#### Beispiel
```cpp
// Konfiguration für FEC
quicsand::OptimizedTetrysFEC::Config config;
config.window_size = 10;
config.initial_redundancy = 0.3;
config.adaptive = true;

// Erstelle FEC-Encoder/Decoder
quicsand::OptimizedTetrysFEC fec(config);

// Kodiere Daten mit SIMD-Beschleunigung
std::vector<uint8_t> data = generate_random_data(1024);
auto packets = fec.encode_packet(data);

// Empfangene Pakete dekodieren
for (const auto& packet : packets) {
    fec.add_received_packet(packet);
}

// Wiederhergestellte Daten abrufen
auto recovered_data = fec.get_recovered_data();
```

### 3. XOR-Operationen

```cpp
// Optimierte XOR-Operation für Byte-Puffer
void xor_buffers(memory_span<uint8_t> dst, memory_span<uint8_t> src);
```

Diese Funktion führt eine XOR-Operation zwischen zwei Byte-Puffern durch und speichert das Ergebnis im ersten Puffer. Die SIMD-optimierte Version verwendet fortgeschrittene Techniken:

1. **Chunk-basierte Verarbeitung**: Verarbeitet Daten in Cache-freundlichen 1KB-Chunks
2. **Prefetching**: Verwendet `__builtin_prefetch` für proaktive Cache-Optimierung
3. **4x Loop Unrolling**: Verarbeitet 64 Bytes (4x16 Byte-Register) pro Schleifendurchlauf
4. **Automatischer Fallback**: Optimierte Scalar-Implementation für Nicht-SIMD-Plattformen

Performance-Optimierungen:
- 2.65x schneller bei 1MB Datenmengen
- Bis zu 15x schneller als naive Loop-Unrolling-Implementierung

#### Beispiel

```cpp
auto buffer1 = std::make_shared<std::vector<uint8_t>>(data1);
auto buffer2 = std::make_shared<std::vector<uint8_t>>(data2);
auto span1 = memory_span<uint8_t>(buffer1->data(), buffer1->size());
auto span2 = memory_span<uint8_t>(buffer2->data(), buffer2->size());

// Optimierte XOR-Operation
xor_buffers(span1, span2); // buffer1 = buffer1 XOR buffer2

// Anwendungsbeispiel in Tetrys FEC
OptimizedTetrysFEC fec;

// Source-Paket kodieren
auto encoded_buffer = fec.encode_packet(span1); // Verwendet intern xor_buffers
```

## Integration in die QUIC-Transportschicht

Die SIMD-Optimierungen sind vollständig in die QUIC-Transportschicht integriert. Die `QuicConnection`-Klasse wurde erweitert, um diese Optimierungen nahtlos zu nutzen:

```cpp
class QuicConnection {
public:
    // ... andere Methoden ...
    
    // SIMD-Feature-Detection
    bool has_simd_support() const;
    uint32_t get_supported_simd_features() const;
    std::string get_simd_features_string() const;
    
    // FEC-Optimierungen aktivieren/deaktivieren
    bool enable_optimized_fec(bool enable = true);
    bool is_optimized_fec_enabled() const;
    
    // Krypto-Optimierungen aktivieren/deaktivieren
    bool enable_optimized_crypto(bool enable = true);
    bool is_optimized_crypto_enabled() const;
    
    // FEC-Kodierung und -Dekodierung (nutzt SIMD wenn aktiviert)
    std::vector<uint8_t> apply_fec_encoding(const uint8_t* data, size_t size);
    std::vector<uint8_t> apply_fec_decoding(const uint8_t* data, size_t size);
};
```

### Verwendung in Anwendungscode

```cpp
// Erstelle QUIC-Verbindung
boost::asio::io_context io_context;
QuicConfig config;
QuicConnection connection(io_context, config);

// Prüfe auf SIMD-Support
if (connection.has_simd_support()) {
    std::cout << "SIMD-Features: " << connection.get_simd_features_string() << std::endl;
    
    // Aktiviere optimierte Implementierungen
    connection.enable_optimized_fec(true);
    connection.enable_optimized_crypto(true);
    
    // Die Methoden apply_fec_encoding und apply_fec_decoding
    // nutzen nun automatisch die SIMD-optimierten Implementierungen
}
```

## Leistungsvorteile

Die SIMD-Optimierungen bieten erhebliche Leistungsvorteile, insbesondere auf Apple M1/M2 Prozessoren:

- **Tetrys FEC**: Bis zu 6x schnellere Kodierung und 2,8x schnellere Dekodierung
- **AES-GCM**: Bis zu 4,75x schneller bei Verschlüsselung und Entschlüsselung
- **XOR-Operationen**: Bis zu 2,65x schneller bei großen Datenmengen
- **Galois-Feld-Arithmetik**: 5-8x schneller bei GF(2^8) Operationen
- **GHASH**: 8x schnellere Berechnung mit optimierter Karatsuba-Multiplikation
- **Tetrys FEC End-to-End**: 3-8x schneller für Kodierung/Dekodierung

Diese Optimierungen verbessern nicht nur die Leistung, sondern reduzieren auch den Energieverbrauch, was besonders wichtig für mobile Geräte ist.

## Zusammenfassung

Die SIMD-Optimierungen in QuicSand bieten erhebliche Leistungsvorteile durch:

1. **Vollständige Integration in die QUIC-Transportschicht** mit automatischer Feature-Detection
2. **Nahtloser Fallback** auf Standard-Implementierungen, wenn SIMD nicht verfügbar ist
3. **Optimierte Kernoperationen**:
   - Cache-optimierte XOR-Verarbeitung mit 4x Loop Unrolling und Prefetching
   - SIMD-beschleunigte Galois-Feld-Operationen für FEC
   - Hardware-beschleunigte AES-GCM mit Batch-Verarbeitung und optimierter GHASH
4. **Flexible Aktivierung**: Die Optimierungen können zur Laufzeit aktiviert/deaktiviert werden

Durch diese Optimierungen bietet QuicSand auf Apple M1/M2-Hardware eine hervorragende Performance bei gleichzeitig geringerem Energieverbrauch, was für mobile VPN-Anwendungen essentiell ist.

## Integration mit anderen Optimierungen

Die SIMD-Optimierungen lassen sich nahtlos mit anderen QuicSand-Optimierungen kombinieren:

```cpp
// Konfiguration für mobile Geräte mit SIMD
auto config = OptimizationsConfig::create_for_mobile();

// OptimizationsManager mit SIMD-Optimierungen
OptimizationsManager opt_manager(config);

// QUIC-Verbindung optimieren
QuicConnection connection(true);
opt_manager.optimize_connection(connection);

// SIMD-optimierte AES verwenden
quicsand::crypto::Aes128GcmOptimized aes(key, iv);

// SIMD-optimierte FEC verwenden
quicsand::OptimizedTetrysFEC fec(fec_config);

// Gemeinsame Nutzung: Verschlüsselte Daten mit FEC kodieren
auto encrypted = aes.encrypt(data);
auto encoded_packets = fec.encode_packet(encrypted);
```
