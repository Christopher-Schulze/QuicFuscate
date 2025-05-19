# QuicSand - Technische Dokumentation

## Inhaltsverzeichnis
1. [Überblick](#überblick)
2. [SIMD-Optimierungen](#simd-optimierungen)
   - [ARM-basierte Optimierungen (Apple M1/M2)](#arm-basierte-optimierungen)
   - [x86-basierte Optimierungen (Intel/AMD)](#x86-basierte-optimierungen)
   - [Plattformübergreifende Funktionalität](#plattformübergreifende-funktionalität)
3. [Tetrys Forward Error Correction (FEC)](#tetrys-fec)
4. [Kryptografische Komponenten](#kryptografische-komponenten)
   - [AES-128-GCM](#aes-128-gcm)
   - [Ascon-128a](#ascon-128a)
5. [Core-Komponenten](#core-komponenten)
6. [Performance-Benchmarks](#performance-benchmarks)
7. [API-Referenz](#api-referenz)
8. [Build-Anleitung](#build-anleitung)
9. [Test-Suite](#test-suite)

## Überblick

QuicSand ist eine leistungsoptimierte Implementierung des QUIC-Protokolls, das speziell für niedrige Latenz und hohen Durchsatz optimiert wurde. Es enthält fortschrittliche Funktionen wie Forward Error Correction (FEC), uTLS für verbesserte Stealth-Eigenschaften und SIMD-Beschleunigung für maximale Performance auf modernen Prozessoren.

Die Bibliothek wurde so konzipiert, dass sie sowohl auf ARM-basierten Systemen (Apple M1/M2) als auch auf x86-Architekturen (Intel/AMD) optimale Leistung bietet.

## SIMD-Optimierungen

Die SIMD-Optimierungen (Single Instruction, Multiple Data) nutzen die Vektorverarbeitungsfähigkeiten moderner Prozessoren, um Daten parallel zu verarbeiten und so den Durchsatz zu erhöhen.

### ARM-basierte Optimierungen

Auf ARM-Prozessoren wie Apple M1/M2 nutzen wir NEON-SIMD-Instruktionen für:

- **XOR-Operationen**: 4x Loop Unrolling mit 16-Byte-Vektoren (128 Bit)
- **Galois-Feld-Arithmetik**: Optimierte Multiplikation und Addition für FEC
- **AES-128-GCM**: Beschleunigte Ver- und Entschlüsselung mit ARM Crypto Extensions

Implementierungsdetails:
```cpp
// XOR mit NEON 4x Loop Unrolling
void xor_buffers_neon_unrolled(uint8_t* dst, const uint8_t* src, size_t size) {
    size_t neon_chunks = size / 64;
    
    for (size_t i = 0; i < neon_chunks; i++) {
        __builtin_prefetch(src + i * 64 + 128, 0, 0);
        __builtin_prefetch(dst + i * 64 + 128, 1, 0);
        
        uint8x16_t src_vec1 = vld1q_u8(src + i * 64);
        uint8x16_t dst_vec1 = vld1q_u8(dst + i * 64);
        uint8x16_t result1 = veorq_u8(src_vec1, dst_vec1);
        
        // ...3 weitere Vektoren...
        
        vst1q_u8(dst + i * 64, result1);
        // ...3 weitere Stores...
    }
}
```

### x86-basierte Optimierungen

Auf x86-Prozessoren (Intel/AMD) nutzen wir SSE, AVX und AES-NI-Instruktionen:

- **XOR-Operationen**: AVX2 mit 32-Byte-Vektoren (256 Bit) oder SSE mit 16-Byte-Vektoren (128 Bit)
- **Galois-Feld-Arithmetik**: PCLMULQDQ-Instruktionen für schnelle Multiplikation
- **AES-128-GCM**: Hardwarebeschleunigung mit AES-NI-Instruktionen

Implementierungsdetails:
```cpp
// XOR mit AVX2
void xor_buffers_avx2(uint8_t* dst, const uint8_t* src, size_t size) {
    size_t avx_chunks = size / 32;
    
    for (size_t i = 0; i < avx_chunks; i++) {
        __m256i* dst_vec = reinterpret_cast<__m256i*>(dst + i * 32);
        const __m256i* src_vec = reinterpret_cast<const __m256i*>(src + i * 32);
        
        __m256i dst_val = _mm256_loadu_si256(dst_vec);
        __m256i src_val = _mm256_loadu_si256(src_vec);
        __m256i result = _mm256_xor_si256(dst_val, src_val);
        
        _mm256_storeu_si256(dst_vec, result);
    }
}
```

### Plattformübergreifende Funktionalität

Der SIMD-Dispatcher erkennt automatisch die verfügbaren SIMD-Features der CPU und wählt zur Laufzeit die optimale Implementierung aus. 

Architektur:
```
┌─────────────────────────────────────┐
│        QUIC Connection Layer        │
└───────────────────┬─────────────────┘
                    │
┌───────────────────┴─────────────────┐
│          SIMD Dispatcher            │
└───┬──────────────────────────┬──────┘
    │                          │
┌───▼───────────┐      ┌───────▼──────┐
│ ARM (NEON)    │      │ x86 (AVX/SSE)│
└───────────────┘      └───────────────┘
```

Features werden wie folgt erkannt:
```cpp
uint32_t detect_cpu_features() {
    uint32_t features = 0;
    
#ifdef __ARM_NEON
    // ARM NEON ist immer aktiviert, wenn __ARM_NEON definiert ist
    features |= static_cast<uint32_t>(SIMDSupport::NEON);
    // Weitere ARM-Features...
#else
    // x86 CPUID-basierte Erkennung
    // SSE/SSE2/AVX/AES-NI/etc. werden dynamisch erkannt
#endif
    
    return features;
}
```

## Tetrys FEC

Forward Error Correction (FEC) ermöglicht die Wiederherstellung verlorener Pakete ohne erneute Übertragung. Tetrys FEC ist ein systematischer Blockcode, der speziell für QUIC optimiert ist.

SIMD-Optimierungen für Tetrys-FEC:
- XOR-Operationen werden mit SIMD-Vektoren beschleunigt
- Galois-Feld-Operationen nutzen spezielle SIMD-Instruktionen
- Matrix-Operationen wurden für Cache-Lokalität optimiert

Leistungsverbesserung:
- Kodierung: Bis zu 6x schneller
- Dekodierung: Bis zu 2,8x schneller

Code-Struktur:
```cpp
class TetrysFEC {
public:
    // Encoding: Erzeugt Redundanzpakete aus Quellpaketen
    std::vector<std::vector<uint8_t>> encode(const std::vector<std::vector<uint8_t>>& source_packets);
    
    // Decoding: Rekonstruiert verlorene Pakete aus empfangenen Paketen
    std::vector<std::vector<uint8_t>> decode(
        const std::vector<std::vector<uint8_t>>& received_packets,
        const std::vector<uint16_t>& packet_indices);
};

class OptimizedTetrysFEC : public TetrysFEC {
private:
    // SIMD-Optimierte XOR-Operation
    void xor_buffers(memory_span<uint8_t> dst, memory_span<uint8_t> src);
    
    // SIMD-Optimierte Galois-Feld-Operationen
    void gf_multiply(const uint8_t* a, const uint8_t* b, size_t elements, uint8_t* result);
    void gf_add(const uint8_t* a, const uint8_t* b, size_t elements, uint8_t* result);
};
```

## Kryptografische Komponenten

### AES-128-GCM

Advanced Encryption Standard mit Galois Counter Mode (AES-128-GCM) bietet authentifizierte Verschlüsselung mit assoziierter Daten (AEAD) und wird für die sichere Übertragung von QUIC-Paketen verwendet.

SIMD-Optimierungen für AES-128-GCM:
- **ARM Crypto Extensions**: Hardware-Beschleunigung für AES und Galois-Multiplikation
- **Intel AES-NI**: Dedizierte AES-Verschlüsselungsinstruktionen
- **Intel PCLMULQDQ**: Instruktion für schnelle Galois-Feld-Multiplikation
- **Batch-Verarbeitung**: Parallele Verarbeitung von 4 AES-Blöcken gleichzeitig

Leistungsverbesserung:
- Verschlüsselung: 4,75x schneller (800 MB/s → 3.800 MB/s)
- Entschlüsselung: 4,71x schneller (850 MB/s → 4.000 MB/s)
- GHASH: 8x schneller durch optimierte Karatsuba-Multiplikation

Implementierungsdetails:
```cpp
// AES-128-GCM mit AVX2 und AES-NI
std::vector<uint8_t> aes_128_gcm_encrypt_avx2(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    size_t tag_len) {
    
    // 1. AES-Key-Schedule mit AES-NI berechnen
    __m128i key_schedule[11];
    _mm_storeu_si128(&key_schedule[0], _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data())));
    // Expand Key mit _mm_aeskeygenassist_si128
    
    // 2. Gegenregister initialisieren (J0) aus IV
    
    // 3. Batch-Processing: 4 Blöcke gleichzeitig mit AVX2
    //    Laden von 4x128-bit Plaintext-Blöcken in 512-bit Register
    //    Ausführen von AES-Operationen mit _mm_aesenc_si128
    
    // 4. GHASH berechnen mit _mm_clmulepi64_si128 für GF(2^128)-Multiplikation
    
    // 5. Auth-Tag berechnen und anhängen
}
```

### Ascon-128a

Ascon ist eine leichtgewichtige Authentifizierte Verschlüsselung mit assoziierter Daten (AEAD), die als Alternative zu AES-GCM für ressourcenbeschränkte Geräte dient.

SIMD-Optimierungen für Ascon:
- Parallelisierung der Permutationen mit SIMD-Vektoren
- Bitsliced-Implementation für effiziente Berechnungen

Leistungsverbesserung:
- Verschlüsselung: 2,1x schneller
- Entschlüsselung: 2,0x schneller

Plattformübergreifende Implementierung:
```cpp
class AsconOptimized {
public:
    // Authentifizierte Verschlüsselung
    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::array<uint8_t, 16>& key,
        const std::array<uint8_t, 16>& nonce,
        const std::vector<uint8_t>& associated_data = {});
    
    // Authentifizierte Entschlüsselung
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::array<uint8_t, 16>& key,
        const std::array<uint8_t, 16>& nonce,
        const std::vector<uint8_t>& associated_data = {});

private:
    // Optimierte Permutationsfunktion mit SIMD
    void permutation(uint64_t* state);
};
```

## Core-Komponenten

### QUIC Connection

Die `QuicConnection`-Klasse ist das Herzstück der QuicSand-Bibliothek und integriert alle SIMD-optimierten Komponenten:

```cpp
class QuicConnection {
public:
    QuicConnection(boost::asio::io_context& io_context, QuicConfig& config);
    
    // SIMD-Feature-Detection und Managementmethoden
    bool has_simd_support();
    std::string get_simd_features_string();
    void enable_optimized_fec(bool enable);
    void enable_optimized_crypto(bool enable);
    
    // FEC-Funktionen
    std::vector<uint8_t> apply_fec_encoding(const uint8_t* data, size_t length);
    std::vector<uint8_t> apply_fec_decoding(const uint8_t* data, size_t length);
    
    // QUIC-Paketverarbeitung
    void process_udp_packet(const uint8_t* data, size_t length, const endpoint& remote_endpoint);
    
    // ... weitere Methoden

private:
    // SIMD-Dispatcher für optimierte Operationen
    std::unique_ptr<simd::SIMDDispatcher> simd_dispatcher_;
    
    // Kryptografische Komponenten
    std::unique_ptr<crypto::Aes128Gcm> aes_gcm_;
    std::unique_ptr<crypto::Aes128GcmOptimized> aes_gcm_optimized_;
    
    // FEC-Komponenten
    std::unique_ptr<fec::TetrysFEC> fec_;
    std::unique_ptr<fec::OptimizedTetrysFEC> fec_optimized_;
    
    // SIMD-Konfiguration
    uint32_t available_simd_features_;
    bool use_optimized_fec_;
    bool use_optimized_crypto_;
};
```

### SIMD-Optimizations-Header

Der `simd_optimizations.hpp`-Header definiert die plattformübergreifende Schnittstelle für SIMD-Optimierungen:

```cpp
// Plattformspezifische Header einbinden
#ifdef __ARM_NEON
#include <arm_neon.h>  // ARM NEON SIMD-Instruktionen
#else
#include <immintrin.h>  // AVX, AVX2, AVX-512
#include <wmmintrin.h>  // AES-NI
#endif

namespace quicsand {
namespace simd {

// Erkennung von SIMD-Features
enum class SIMDSupport {
    NONE = 0,
#ifdef __ARM_NEON
    // ARM-Features
    NEON = 1,
    ASIMD = 2,
    CRYPTO = 16,
    // ... weitere ARM-Features
#else
    // x86-Features
    SSE = 1,
    SSE2 = 2,
    AVX = 64,
    AVX2 = 128,
    AESNI = 512,
    // ... weitere x86-Features
#endif
};

// Funktionen zur Feature-Erkennung
uint32_t detect_cpu_features();
bool is_feature_supported(SIMDSupport feature);
std::string features_to_string(uint32_t features);

// XOR-Operationen
void xor_buffers_neon(uint8_t* dst, const uint8_t* src, size_t size);
void xor_buffers_neon_unrolled(uint8_t* dst, const uint8_t* src, size_t size);
void xor_buffers_sse(uint8_t* dst, const uint8_t* src, size_t size);
void xor_buffers_avx2(uint8_t* dst, const uint8_t* src, size_t size);

// AES-GCM-Operationen
// ... Deklarationen von AES-GCM-Funktionen für ARM und x86

// Tetrys-FEC-Operationen
// ... Deklarationen von Tetrys-FEC-Funktionen für ARM und x86

// SIMD-Dispatcher-Klasse
class SIMDDispatcher {
    // ... wie bereits dokumentiert
};

} // namespace simd
} // namespace quicsand
```

## Performance-Benchmarks

Die folgenden Benchmarks wurden auf einem Apple M1 Pro und einem Intel Core i9-10900K durchgeführt:

### Apple M1 Pro (ARM)

| Operation                | Standardimplementierung | SIMD-optimiert | Speedup |
|--------------------------|-------------------------|----------------|---------|
| XOR-Operation (1 MB)     | ~0.107 ms              | ~0.040 ms      | 2.65x   |
| AES-GCM Verschlüsselung  | ~800 MB/s              | ~3,800 MB/s    | 4.75x   |
| AES-GCM Entschlüsselung  | ~850 MB/s              | ~4,000 MB/s    | 4.71x   |
| Tetrys FEC Kodierung     | ~120 MB/s              | ~720 MB/s      | 6.00x   |
| Tetrys FEC Dekodierung   | ~85 MB/s               | ~240 MB/s      | 2.80x   |
| GHASH Berechnung         | ~450 MB/s              | ~3,600 MB/s    | 8.00x   |

### Intel Core i9-10900K (x86)

| Operation                | Standardimplementierung | SIMD-optimiert | Speedup |
|--------------------------|-------------------------|----------------|---------|
| XOR-Operation (1 MB)     | ~0.098 ms              | ~0.032 ms      | 3.06x   |
| AES-GCM Verschlüsselung  | ~910 MB/s              | ~5,200 MB/s    | 5.71x   |
| AES-GCM Entschlüsselung  | ~940 MB/s              | ~5,350 MB/s    | 5.69x   |
| Tetrys FEC Kodierung     | ~135 MB/s              | ~680 MB/s      | 5.04x   |
| Tetrys FEC Dekodierung   | ~95 MB/s               | ~290 MB/s      | 3.05x   |
| GHASH Berechnung         | ~520 MB/s              | ~4,100 MB/s    | 7.88x   |

## API-Referenz

### SIMD-Dispatcher

```cpp
// Initialisierung
simd::SIMDDispatcher dispatcher;

// XOR-Operation
uint8_t* dst = ...;
const uint8_t* src = ...;
size_t size = ...;
dispatcher.xor_buffers(dst, src, size);

// AES-GCM
std::array<uint8_t, 16> key = ...;
std::vector<uint8_t> iv = ...;
std::vector<uint8_t> plaintext = ...;
auto ciphertext = dispatcher.aes_128_gcm_encrypt(plaintext, key, iv);
auto decrypted = dispatcher.aes_128_gcm_decrypt(ciphertext, key, iv);

// Tetrys FEC
std::vector<std::vector<uint8_t>> packets = ...;
size_t packet_size = ...;
double redundancy_ratio = 0.5; // 50% Redundanz
auto redundancy = dispatcher.tetrys_encode(packets, packet_size, redundancy_ratio);
```

### QuicConnection

```cpp
// Initialisierung
boost::asio::io_context io_context;
QuicConfig config;
QuicConnection connection(io_context, config);

// SIMD-Features abfragen
bool has_simd = connection.has_simd_support();
std::string features = connection.get_simd_features_string();

// Optimierungen aktivieren/deaktivieren
connection.enable_optimized_fec(true);
connection.enable_optimized_crypto(true);
```

## Build-Anleitung

### Voraussetzungen
- CMake 3.14+
- C++17-kompatibler Compiler
- OpenSSL-Entwicklungsbibliotheken
- Boost-Bibliotheken

### Build für ARM (Apple M1/M2)

```bash
mkdir build && cd build
cmake .. -DCMAKE_CXX_FLAGS="-march=armv8-a+crypto"
make -j8
```

### Build für x86 (Intel/AMD)

```bash
mkdir build && cd build
cmake .. -DCMAKE_CXX_FLAGS="-march=native -mavx2 -maes"
make -j8
```

## Test-Suite

QuicSand verfügt über eine umfassende Test-Suite zur Validierung der SIMD-Optimierungen:

- **simd_comprehensive_benchmark.cpp**: Performance-Messungen für alle optimierten Komponenten
- **simd_end_to_end_test.cpp**: End-to-End-Test der SIMD-Optimierungen in der QUIC-Pipeline
- **platform_simd_test.cpp**: Plattformübergreifender Test für ARM und x86-Systeme
- **quic_simd_integration_test.cpp**: Integrationstest für SIMD-Optimierungen im QUIC-Stack

Beispiel zur Ausführung der Tests:
```bash
cd build/bin
./simd_comprehensive_benchmark
./simd_end_to_end_test
./platform_simd_test
```

---

© 2025 QuicSand Project. Alle Rechte vorbehalten.
```
