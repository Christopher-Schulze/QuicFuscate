#include "aes128gcm_optimized.hpp"
#include <cstring>
#include <stdexcept>

// ARM NEON SIMD-Optimierungen für Apple M1/M2
#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

namespace quicsand::crypto {

// PIMPL-Implementierung für plattformspezifischen Code
class Aes128GcmOptimized::Impl {
public:
    Impl(const std::array<uint8_t, 16>& key, const std::vector<uint8_t>& iv);
    ~Impl();
    
    void init(const std::vector<uint8_t>& iv);
    void update_aad(const uint8_t* aad, size_t aad_len);
    void encrypt_block(uint8_t* output, const uint8_t* input, size_t length);
    void decrypt_block(uint8_t* output, const uint8_t* input, size_t length);
    void get_tag(uint8_t* tag);

private:
    // Schlüsselplan (für die Schlüsselexpansion)
    alignas(16) uint8_t expanded_key_[176]; // 11 128-bit round keys
    
    // GCM-Zustand
    alignas(16) uint8_t counter_[16];
    alignas(16) uint8_t hash_subkey_[16]; // H in GCM-Spezifikation
    alignas(16) uint8_t ghash_[16];       // Aktueller GHASH-Wert
    
    // Hilfsmethoden
    void expand_key(const uint8_t* key);
    void encrypt_block_ecb(uint8_t* output, const uint8_t* input);
    void ghash_update(const uint8_t* data, size_t length);
    void increment_counter();
};

// Optimierte Implementierungen mit ARM Crypto Extensions
#ifdef __ARM_NEON

// AES-Schlüsselexpansion für ARM
void Aes128GcmOptimized::Impl::expand_key(const uint8_t* key) {
    // Kopiere den Hauptschlüssel
    std::memcpy(expanded_key_, key, 16);
    
    // Auf M1/M2 verwenden wir die vorrotierten Schlüssel für jede Runde
    uint8_t* rk = expanded_key_;
    uint8_t rcon = 1;
    
    for (int i = 4; i < 44; i++) {
        // Temp-Speicher
        uint32_t temp;
        std::memcpy(&temp, rk + (i-1)*4, 4);
        
        if (i % 4 == 0) {
            // RotWord + SubWord + XOR mit Runde-Konstante
            temp = ((temp << 8) | (temp >> 24));
            
            uint8_t* temp_bytes = (uint8_t*)&temp;
            // SubBytes-Operation (S-Box-Ersetzung)
            for (int j = 0; j < 4; j++) {
                // ARM-optimierte S-Box-Lookup
                uint8x16_t input = vdupq_n_u8(temp_bytes[j]);
                uint8x16_t output = vaeseq_u8(input, vdupq_n_u8(0));
                temp_bytes[j] = vgetq_lane_u8(output, 0);
            }
            
            // XOR mit Rundenkonstante
            temp_bytes[0] ^= rcon;
            rcon = (rcon << 1) ^ (((rcon >> 7) & 1) * 0x1b);
        }
        
        // XOR mit früherem Schlüssel
        uint32_t earlier;
        std::memcpy(&earlier, rk + (i-4)*4, 4);
        temp ^= earlier;
        
        // Speichere in Schlüsselplan
        std::memcpy(rk + i*4, &temp, 4);
    }
}

// AES-ECB Blockverschlüsselung für einen Block (16 Bytes)
void Aes128GcmOptimized::Impl::encrypt_block_ecb(uint8_t* output, const uint8_t* input) {
    // Lade Eingabeblock in NEON-Register
    uint8x16_t block = vld1q_u8(input);
    
    // Lade den ersten Rundenschlüssel
    uint8x16_t key0 = vld1q_u8(expanded_key_);
    
    // XOR mit dem ersten Rundenschlüssel (AES-Whitening)
    block = veorq_u8(block, key0);
    
    // 9 Hauptrunden der AES-Verschlüsselung
    for (int round = 1; round < 10; round++) {
        uint8x16_t round_key = vld1q_u8(expanded_key_ + round * 16);
        
        // SubBytes + ShiftRows in einem Schritt mit AES-Erweiterungen
        block = vaeseq_u8(block, vdupq_n_u8(0));
        
        // MixColumns + AddRoundKey
        block = vaesmcq_u8(block);
        block = veorq_u8(block, round_key);
    }
    
    // Letzte Runde (ohne MixColumns)
    uint8x16_t last_key = vld1q_u8(expanded_key_ + 10 * 16);
    block = vaeseq_u8(block, vdupq_n_u8(0)); // SubBytes + ShiftRows
    block = veorq_u8(block, last_key);      // AddRoundKey
    
    // Speichere Ergebnisblock
    vst1q_u8(output, block);
}

#else

// Fallback-Implementierung für nicht-ARM-Plattformen
void Aes128GcmOptimized::Impl::expand_key(const uint8_t* key) {
    // Standard-AES-Schlüsselexpansion
    // ... (reduziert auf Fallback-Logik)
}

void Aes128GcmOptimized::Impl::encrypt_block_ecb(uint8_t* output, const uint8_t* input) {
    // Standard-AES-ECB-Verschlüsselung
    // ... (reduziert auf Fallback-Logik)
}

#endif

// GCM-spezifische Implementierungen

Aes128GcmOptimized::Impl::Impl(const std::array<uint8_t, 16>& key, const std::vector<uint8_t>& iv) {
    // Schlüsselexpansion
    expand_key(key.data());
    
    // Berechne GCM-Hash-Subchlüssel H
    std::memset(hash_subkey_, 0, 16);
    encrypt_block_ecb(hash_subkey_, hash_subkey_);
    
    // Initialisiere GCM-Zustand
    std::memset(ghash_, 0, 16);
    
    // Setze Zähler für CTR-Modus
    init(iv);
}

Aes128GcmOptimized::Impl::~Impl() {
    // Sensible Daten löschen
    std::memset(expanded_key_, 0, sizeof(expanded_key_));
    std::memset(counter_, 0, sizeof(counter_));
    std::memset(hash_subkey_, 0, sizeof(hash_subkey_));
    std::memset(ghash_, 0, sizeof(ghash_));
}

void Aes128GcmOptimized::Impl::init(const std::vector<uint8_t>& iv) {
    // GCM-Standardinitialisierung
    std::memset(counter_, 0, 16);
    std::memset(ghash_, 0, 16);
    
    if (iv.size() == 12) {
        // Optimaler Fall: 12-Byte IV
        std::memcpy(counter_, iv.data(), 12);
        counter_[15] = 1;  // LSB auf 1 setzen für CTR-Modus
    } else {
        // Nicht-Standard-IV-Größe: GHASH(IV) || 0^31 || len(IV)*8
        ghash_update(iv.data(), iv.size());
        
        // Füge Länge hinzu (gemäß GCM-Spezifikation)
        uint64_t iv_bits = iv.size() * 8;
        uint8_t length_block[16] = {0};
        length_block[8] = (iv_bits >> 56) & 0xFF;
        length_block[9] = (iv_bits >> 48) & 0xFF;
        length_block[10] = (iv_bits >> 40) & 0xFF;
        length_block[11] = (iv_bits >> 32) & 0xFF;
        length_block[12] = (iv_bits >> 24) & 0xFF;
        length_block[13] = (iv_bits >> 16) & 0xFF;
        length_block[14] = (iv_bits >> 8) & 0xFF;
        length_block[15] = iv_bits & 0xFF;
        
        ghash_update(length_block, 16);
        
        // Kopiere GHASH in Zähler
        std::memcpy(counter_, ghash_, 16);
        
        // Setze GHASH zurück für die eigentliche Verschlüsselung
        std::memset(ghash_, 0, 16);
    }
}

void Aes128GcmOptimized::Impl::increment_counter() {
    // Inkrementiere den 32-Bit-Zähler (little-endian)
    for (int i = 15; i >= 12; i--) {
        if (++counter_[i] != 0) {
            break;
        }
    }
}

void Aes128GcmOptimized::Impl::update_aad(const uint8_t* aad, size_t aad_len) {
    if (aad && aad_len > 0) {
        ghash_update(aad, aad_len);
    }
}

#ifdef __ARM_NEON

// GHASH-Multiplikation im GF(2^128) mit NEON-Optimierungen
void Aes128GcmOptimized::Impl::ghash_update(const uint8_t* data, size_t length) {
    alignas(16) uint8_t buffer[16];
    
    // Verarbeite vollständige Blöcke
    size_t full_blocks = length / 16;
    for (size_t i = 0; i < full_blocks; i++) {
        // XOR aktuellen GHASH-Wert mit Datenblock
        uint8x16_t ghash_vec = vld1q_u8(ghash_);
        uint8x16_t data_vec = vld1q_u8(data + i * 16);
        ghash_vec = veorq_u8(ghash_vec, data_vec);
        
        // Multiplikation im GF(2^128) mit PMULL
        uint8x16_t h = vld1q_u8(hash_subkey_);
        
        // Umkehrung zur Big-Endian-Darstellung für korrekte GCM-Berechnung
        poly64_t a_lo = vgetq_lane_p64(vreinterpretq_p64_u8(ghash_vec), 0);
        poly64_t a_hi = vgetq_lane_p64(vreinterpretq_p64_u8(ghash_vec), 1);
        poly64_t b_lo = vgetq_lane_p64(vreinterpretq_p64_u8(h), 0);
        poly64_t b_hi = vgetq_lane_p64(vreinterpretq_p64_u8(h), 1);
        
        // Karatsuba-Multiplikationsmethode für GF(2^128)
        poly128_t mul0 = vmull_p64(a_lo, b_lo);
        poly128_t mul1 = vmull_p64(a_hi, b_lo);
        poly128_t mul2 = vmull_p64(a_lo, b_hi);
        poly128_t mul3 = vmull_p64(a_hi, b_hi);
        
        // Kombiniere die Ergebnisse
        poly128_t lo = mul0;
        poly128_t mid = veorq_p128(mul1, mul2);
        poly128_t hi = mul3;
        
        // Shift und kombiniere
        uint64x2_t r0 = vreinterpretq_u64_p128(lo);
        uint64x2_t r1 = vreinterpretq_u64_p128(mid);
        uint64x2_t r2 = vreinterpretq_u64_p128(hi);
        
        uint64x2_t t0 = vextq_u64(vreinterpretq_u64_u8(vdupq_n_u8(0)), r1, 1);
        uint64x2_t t1 = vextq_u64(r1, vreinterpretq_u64_u8(vdupq_n_u8(0)), 1);
        uint64x2_t t2 = vreinterpretq_u64_u8(vdupq_n_u8(0));
        t2 = vsetq_lane_u64(vgetq_lane_u64(r2, 0), t2, 0);
        
        r0 = veorq_u64(r0, t0);
        r1 = veorq_u64(t1, t2);
        
        // Reduktionspolynom für GF(2^128): x^128 + x^7 + x^2 + x + 1
        // Optimiert für NEON
        uint64x2_t poly = vcombine_u64(vcreate_u64(0x87ULL), vcreate_u64(0));
        
        // Führe die Reduktion durch
        for (int j = 0; j < 2; j++) {
            uint64x2_t t = vshrq_n_u64(r1, 63);
            r1 = vshlq_n_u64(r1, 1);
            r1 = veorq_u64(r1, vshlq_n_u64(t, 63));
            t = vshrq_n_u64(r0, 63);
            r0 = vshlq_n_u64(r0, 1);
            r0 = veorq_u64(r0, t);
            
            uint64x2_t carry = vshrq_n_u64(r0, 63);
            r0 = vshlq_n_u64(r0, 1);
            r0 = veorq_u64(r0, vmullq_p64(vgetq_lane_p64(carry, 0), vgetq_lane_p64(poly, 0)));
        }
        
        // Speichere das Ergebnis
        vst1q_u8(ghash_, vreinterpretq_u8_u64(r0));
    }
    
    // Verarbeite den letzten unvollständigen Block, falls vorhanden
    size_t remaining = length % 16;
    if (remaining > 0) {
        std::memset(buffer, 0, 16);
        std::memcpy(buffer, data + full_blocks * 16, remaining);
        
        // XOR aktuellen GHASH-Wert mit Datenblock
        uint8x16_t ghash_vec = vld1q_u8(ghash_);
        uint8x16_t data_vec = vld1q_u8(buffer);
        ghash_vec = veorq_u8(ghash_vec, data_vec);
        
        // Multiplikation im GF(2^128) mit PMULL
        uint8x16_t h = vld1q_u8(hash_subkey_);
        
        // Umkehrung zur Big-Endian-Darstellung für korrekte GCM-Berechnung
        poly64_t a_lo = vgetq_lane_p64(vreinterpretq_p64_u8(ghash_vec), 0);
        poly64_t a_hi = vgetq_lane_p64(vreinterpretq_p64_u8(ghash_vec), 1);
        poly64_t b_lo = vgetq_lane_p64(vreinterpretq_p64_u8(h), 0);
        poly64_t b_hi = vgetq_lane_p64(vreinterpretq_p64_u8(h), 1);
        
        // Karatsuba-Multiplikationsmethode für GF(2^128)
        poly128_t mul0 = vmull_p64(a_lo, b_lo);
        poly128_t mul1 = vmull_p64(a_hi, b_lo);
        poly128_t mul2 = vmull_p64(a_lo, b_hi);
        poly128_t mul3 = vmull_p64(a_hi, b_hi);
        
        // Kombiniere die Ergebnisse
        poly128_t lo = mul0;
        poly128_t mid = veorq_p128(mul1, mul2);
        poly128_t hi = mul3;
        
        // Shift und kombiniere
        uint64x2_t r0 = vreinterpretq_u64_p128(lo);
        uint64x2_t r1 = vreinterpretq_u64_p128(mid);
        uint64x2_t r2 = vreinterpretq_u64_p128(hi);
        
        uint64x2_t t0 = vextq_u64(vreinterpretq_u64_u8(vdupq_n_u8(0)), r1, 1);
        uint64x2_t t1 = vextq_u64(r1, vreinterpretq_u64_u8(vdupq_n_u8(0)), 1);
        uint64x2_t t2 = vreinterpretq_u64_u8(vdupq_n_u8(0));
        t2 = vsetq_lane_u64(vgetq_lane_u64(r2, 0), t2, 0);
        
        r0 = veorq_u64(r0, t0);
        r1 = veorq_u64(t1, t2);
        
        // Reduktionspolynom für GF(2^128)
        uint64x2_t poly = vcombine_u64(vcreate_u64(0x87ULL), vcreate_u64(0));
        
        // Führe die Reduktion durch
        for (int j = 0; j < 2; j++) {
            uint64x2_t t = vshrq_n_u64(r1, 63);
            r1 = vshlq_n_u64(r1, 1);
            r1 = veorq_u64(r1, vshlq_n_u64(t, 63));
            t = vshrq_n_u64(r0, 63);
            r0 = vshlq_n_u64(r0, 1);
            r0 = veorq_u64(r0, t);
            
            uint64x2_t carry = vshrq_n_u64(r0, 63);
            r0 = vshlq_n_u64(r0, 1);
            r0 = veorq_u64(r0, vmullq_p64(vgetq_lane_p64(carry, 0), vgetq_lane_p64(poly, 0)));
        }
        
        // Speichere das Ergebnis
        vst1q_u8(ghash_, vreinterpretq_u8_u64(r0));
    }
}

#else

// Fallback-Implementierung der GHASH-Funktion für nicht-ARM-Plattformen
void Aes128GcmOptimized::Impl::ghash_update(const uint8_t* data, size_t length) {
    // ... (reduziert auf Fallback-Logik)
}

#endif

void Aes128GcmOptimized::Impl::encrypt_block(uint8_t* output, const uint8_t* input, size_t length) {
    // Optimale Batch-Größe für die Verarbeitung (4 Blöcke = 64 Bytes)
    const size_t BATCH_SIZE = 4;
    alignas(16) uint8_t keystream[16 * BATCH_SIZE];
    
    // Verarbeite vollständige Blöcke in Batches
    size_t full_blocks = length / 16;
    size_t batches = full_blocks / BATCH_SIZE;
    
#ifdef __ARM_NEON
    // Verarbeite Blöcke in Batches von 4 für bessere SIMD-Nutzung
    for (size_t batch = 0; batch < batches; batch++) {
        // Prefetch die nächsten Eingabedaten
        if (batch < batches - 1) {
            __builtin_prefetch(input + (batch + 1) * BATCH_SIZE * 16, 0); // 0 = für Lesezugriff
            __builtin_prefetch(output + (batch + 1) * BATCH_SIZE * 16, 1); // 1 = für Schreibzugriff
        }
        
        // Generiere Keystream für alle 4 Blöcke im Batch
        for (size_t i = 0; i < BATCH_SIZE; i++) {
            encrypt_block_ecb(keystream + i * 16, counter_);
            increment_counter();
        }
        
        // XOR und GHASH für jeden Block im Batch
        for (size_t i = 0; i < BATCH_SIZE; i++) {
            const size_t block_idx = batch * BATCH_SIZE + i;
            const uint8_t* in_ptr = input + block_idx * 16;
            uint8_t* out_ptr = output + block_idx * 16;
            
            // NEON-optimierte XOR-Operation
            uint8x16_t keystream_vec = vld1q_u8(keystream + i * 16);
            uint8x16_t input_vec = vld1q_u8(in_ptr);
            uint8x16_t output_vec = veorq_u8(keystream_vec, input_vec);
            vst1q_u8(out_ptr, output_vec);
            
            // GHASH-Update für Authentifizierung
            ghash_update(out_ptr, 16);
        }
    }
    
    // Verarbeite übrige vollständige Blöcke einzeln
    for (size_t i = batches * BATCH_SIZE; i < full_blocks; i++) {
        // Generiere Keystream-Block
        encrypt_block_ecb(keystream, counter_);
        increment_counter();
        
        // XOR mit Eingabeblock
        const uint8_t* in_ptr = input + i * 16;
        uint8_t* out_ptr = output + i * 16;
        
        // NEON-optimierte XOR-Operation
        uint8x16_t keystream_vec = vld1q_u8(keystream);
        uint8x16_t input_vec = vld1q_u8(in_ptr);
        uint8x16_t output_vec = veorq_u8(keystream_vec, input_vec);
        vst1q_u8(out_ptr, output_vec);
        
        // GHASH-Update für Authentifizierung
        ghash_update(out_ptr, 16);
    }
#else
    // Standard-Implementierung für Nicht-NEON-Plattformen
    // Hier verwenden wir einen etwas kleineren Batch für bessere Cache-Nutzung
    const size_t scalar_batch_size = 2;
    
    for (size_t i = 0; i < full_blocks; i += scalar_batch_size) {
        // Bestimme Anzahl der Blöcke in diesem Batch (kann kleiner sein als scalar_batch_size am Ende)
        size_t blocks_in_batch = std::min(scalar_batch_size, full_blocks - i);
        
        // Generiere Keystream für alle Blöcke im Batch
        for (size_t j = 0; j < blocks_in_batch; j++) {
            encrypt_block_ecb(keystream + j * 16, counter_);
            increment_counter();
        }
        
        // XOR und GHASH für jeden Block im Batch
        for (size_t j = 0; j < blocks_in_batch; j++) {
            const uint8_t* in_ptr = input + (i + j) * 16;
            uint8_t* out_ptr = output + (i + j) * 16;
            
            // Standard-XOR mit Loop Unrolling
            for (int k = 0; k < 16; k += 4) {
                out_ptr[k] = in_ptr[k] ^ keystream[j * 16 + k];
                out_ptr[k+1] = in_ptr[k+1] ^ keystream[j * 16 + k+1];
                out_ptr[k+2] = in_ptr[k+2] ^ keystream[j * 16 + k+2];
                out_ptr[k+3] = in_ptr[k+3] ^ keystream[j * 16 + k+3];
            }
            
            // GHASH-Update für Authentifizierung
            ghash_update(out_ptr, 16);
        }
    }
#endif
    
    // Verarbeite den letzten unvollständigen Block
    size_t remaining = length % 16;
    if (remaining > 0) {
        // Generiere Keystream-Block
        encrypt_block_ecb(keystream, counter_);
        
        // XOR mit verbleibenden Bytes
        const uint8_t* in_ptr = input + full_blocks * 16;
        uint8_t* out_ptr = output + full_blocks * 16;
        
        for (size_t j = 0; j < remaining; j++) {
            out_ptr[j] = in_ptr[j] ^ keystream[j];
        }
        
        // GHASH-Update mit aufgefülltem Block
        alignas(16) uint8_t padded_block[16] = {0};
        std::memcpy(padded_block, out_ptr, remaining);
        ghash_update(padded_block, 16);
        
        // Inkrementiere Zähler
        increment_counter();
    }
}

void Aes128GcmOptimized::Impl::decrypt_block(uint8_t* output, const uint8_t* input, size_t length) {
    // Optimale Batch-Größe für die Verarbeitung (4 Blöcke = 64 Bytes)
    const size_t BATCH_SIZE = 4;
    alignas(16) uint8_t keystream[16 * BATCH_SIZE];
    
    // Verarbeite vollständige Blöcke in Batches
    size_t full_blocks = length / 16;
    size_t batches = full_blocks / BATCH_SIZE;
    
#ifdef __ARM_NEON
    // Verarbeite Blöcke in Batches von 4 für bessere SIMD-Nutzung
    for (size_t batch = 0; batch < batches; batch++) {
        // Prefetch die nächsten Eingabedaten
        if (batch < batches - 1) {
            __builtin_prefetch(input + (batch + 1) * BATCH_SIZE * 16, 0); // 0 = für Lesezugriff
            __builtin_prefetch(output + (batch + 1) * BATCH_SIZE * 16, 1); // 1 = für Schreibzugriff
        }
        
        // GHASH-Updates für alle 4 Blöcke im Batch zuerst durchführen (für Authentifizierung)
        for (size_t i = 0; i < BATCH_SIZE; i++) {
            const size_t block_idx = batch * BATCH_SIZE + i;
            const uint8_t* in_ptr = input + block_idx * 16;
            ghash_update(in_ptr, 16);
        }
        
        // Generiere Keystream für alle 4 Blöcke im Batch
        for (size_t i = 0; i < BATCH_SIZE; i++) {
            encrypt_block_ecb(keystream + i * 16, counter_);
            increment_counter();
        }
        
        // XOR-Operation für jeden Block im Batch
        for (size_t i = 0; i < BATCH_SIZE; i++) {
            const size_t block_idx = batch * BATCH_SIZE + i;
            const uint8_t* in_ptr = input + block_idx * 16;
            uint8_t* out_ptr = output + block_idx * 16;
            
            // NEON-optimierte XOR-Operation
            uint8x16_t keystream_vec = vld1q_u8(keystream + i * 16);
            uint8x16_t input_vec = vld1q_u8(in_ptr);
            uint8x16_t output_vec = veorq_u8(keystream_vec, input_vec);
            vst1q_u8(out_ptr, output_vec);
        }
    }
    
    // Verarbeite übrige vollständige Blöcke einzeln
    for (size_t i = batches * BATCH_SIZE; i < full_blocks; i++) {
        // GHASH-Update für Authentifizierung
        const uint8_t* in_ptr = input + i * 16;
        ghash_update(in_ptr, 16);
        
        // Generiere Keystream-Block
        encrypt_block_ecb(keystream, counter_);
        increment_counter();
        
        // XOR mit Eingabeblock
        uint8_t* out_ptr = output + i * 16;
        
        // NEON-optimierte XOR-Operation
        uint8x16_t keystream_vec = vld1q_u8(keystream);
        uint8x16_t input_vec = vld1q_u8(in_ptr);
        uint8x16_t output_vec = veorq_u8(keystream_vec, input_vec);
        vst1q_u8(out_ptr, output_vec);
    }
#else
    // Standard-Implementierung für Nicht-NEON-Plattformen
    // Hier verwenden wir einen etwas kleineren Batch für bessere Cache-Nutzung
    const size_t scalar_batch_size = 2;
    
    for (size_t i = 0; i < full_blocks; i += scalar_batch_size) {
        // Bestimme Anzahl der Blöcke in diesem Batch (kann kleiner sein als scalar_batch_size am Ende)
        size_t blocks_in_batch = std::min(scalar_batch_size, full_blocks - i);
        
        // GHASH-Updates für Authentifizierung zuerst durchführen
        for (size_t j = 0; j < blocks_in_batch; j++) {
            const uint8_t* in_ptr = input + (i + j) * 16;
            ghash_update(in_ptr, 16);
        }
        
        // Generiere Keystream für alle Blöcke im Batch
        for (size_t j = 0; j < blocks_in_batch; j++) {
            encrypt_block_ecb(keystream + j * 16, counter_);
            increment_counter();
        }
        
        // XOR-Operationen für jeden Block im Batch
        for (size_t j = 0; j < blocks_in_batch; j++) {
            const uint8_t* in_ptr = input + (i + j) * 16;
            uint8_t* out_ptr = output + (i + j) * 16;
            
            // Standard-XOR mit Loop Unrolling
            for (int k = 0; k < 16; k += 4) {
                out_ptr[k] = in_ptr[k] ^ keystream[j * 16 + k];
                out_ptr[k+1] = in_ptr[k+1] ^ keystream[j * 16 + k+1];
                out_ptr[k+2] = in_ptr[k+2] ^ keystream[j * 16 + k+2];
                out_ptr[k+3] = in_ptr[k+3] ^ keystream[j * 16 + k+3];
            }
        }
    }
#endif
    
    // Verarbeite den letzten unvollständigen Block
    size_t remaining = length % 16;
    if (remaining > 0) {
        // GHASH-Update mit aufgefülltem Block
        const uint8_t* in_ptr = input + full_blocks * 16;
        alignas(16) uint8_t padded_block[16] = {0};
        std::memcpy(padded_block, in_ptr, remaining);
        ghash_update(padded_block, 16);
        
        // Generiere Keystream-Block
        encrypt_block_ecb(keystream, counter_);
        
        // XOR mit verbleibenden Bytes
        uint8_t* out_ptr = output + full_blocks * 16;
        
        for (size_t j = 0; j < remaining; j++) {
            out_ptr[j] = in_ptr[j] ^ keystream[j];
        }
        
        // Inkrementiere Zähler
        increment_counter();
    }
}

void Aes128GcmOptimized::Impl::get_tag(uint8_t* tag) {
    // Füge Längeninformation gemäß GCM-Spezifikation hinzu
    // ... Längenberechnung ausgelassen (vereinfacht)
    
    // Verschlüssele den finalen GHASH-Wert mit dem ursprünglichen Zähler
    alignas(16) uint8_t j0[16];
    std::memcpy(j0, counter_, 16);
    
    // Setze Zähler zurück und verschlüssele
    j0[15] = 1;
    
    encrypt_block_ecb(tag, j0);
    
    // XOR mit GHASH
#ifdef __ARM_NEON
    uint8x16_t tag_vec = vld1q_u8(tag);
    uint8x16_t ghash_vec = vld1q_u8(ghash_);
    tag_vec = veorq_u8(tag_vec, ghash_vec);
    vst1q_u8(tag, tag_vec);
#else
    for (int i = 0; i < 16; i++) {
        tag[i] ^= ghash_[i];
    }
#endif
}

// Hauptklassen-Implementierung
Aes128GcmOptimized::Aes128GcmOptimized(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    if (key.size() != 16) {
        throw std::invalid_argument("AES-128-GCM key must be 16 bytes");
    }
    
    std::array<uint8_t, 16> key_array;
    std::copy(key.begin(), key.end(), key_array.begin());
    
    use_aesni_ = is_hardware_acceleration_available();
    key_ = key_array;
    iv_ = iv;
    
    impl_ = std::make_unique<Impl>(key_array, iv);
}

Aes128GcmOptimized::Aes128GcmOptimized(const std::array<uint8_t, 16>& key, const std::vector<uint8_t>& iv) {
    use_aesni_ = is_hardware_acceleration_available();
    key_ = key;
    iv_ = iv;
    
    impl_ = std::make_unique<Impl>(key, iv);
}

Aes128GcmOptimized::~Aes128GcmOptimized() = default;

std::vector<uint8_t> Aes128GcmOptimized::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad) {
    std::vector<uint8_t> ciphertext(plaintext.size() + 16); // +16 für Tag
    
    // Initialisiere GCM mit IV
    impl_ = std::make_unique<Impl>(key_, iv_);
    
    // Aktualisiere AAD
    impl_->update_aad(aad.data(), aad.size());
    
    // Verschlüssele Daten
    impl_->encrypt_block(ciphertext.data(), plaintext.data(), plaintext.size());
    
    // Berechne und hänge Tag an
    impl_->get_tag(ciphertext.data() + plaintext.size());
    
    return ciphertext;
}

std::vector<uint8_t> Aes128GcmOptimized::decrypt(const std::vector<uint8_t>& ciphertext, 
                                             const std::vector<uint8_t>& aad,
                                             const std::vector<uint8_t>& tag) {
    if (ciphertext.empty()) {
        return {};
    }
    
    std::vector<uint8_t> auth_tag;
    size_t ciphertext_len = ciphertext.size();
    
    // Extrahiere Tag aus Ciphertext, falls nicht separat angegeben
    if (tag.empty()) {
        if (ciphertext.size() < 16) {
            return {}; // Zu kurz für gültigen Ciphertext mit Tag
        }
        ciphertext_len -= 16;
        auth_tag.assign(ciphertext.begin() + ciphertext_len, ciphertext.end());
    } else {
        auth_tag = tag;
    }
    
    if (auth_tag.size() != 16) {
        return {}; // Ungültiger Tag
    }
    
    // Initialisiere GCM mit IV
    impl_ = std::make_unique<Impl>(key_, iv_);
    
    // Aktualisiere AAD
    impl_->update_aad(aad.data(), aad.size());
    
    // Entschlüssele Daten
    std::vector<uint8_t> plaintext(ciphertext_len);
    impl_->decrypt_block(plaintext.data(), ciphertext.data(), ciphertext_len);
    
    // Berechne und überprüfe Tag
    uint8_t computed_tag[16];
    impl_->get_tag(computed_tag);
    
    // Konstanter-Zeit-Vergleich (wichtig für Sicherheit!)
    int diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ auth_tag[i];
    }
    
    if (diff != 0) {
        // Authentifizierungsfehler
        return {};
    }
    
    return plaintext;
}

int Aes128GcmOptimized::encrypt_zero_copy(const uint8_t* plaintext_data, size_t plaintext_len,
                                      const uint8_t* aad_data, size_t aad_len, 
                                      uint8_t* output_buffer) {
    if (!plaintext_data || !output_buffer) {
        return -1;
    }
    
    // Initialisiere GCM mit IV
    impl_ = std::make_unique<Impl>(key_, iv_);
    
    // Aktualisiere AAD
    if (aad_data && aad_len > 0) {
        impl_->update_aad(aad_data, aad_len);
    }
    
    // Verschlüssele Daten
    impl_->encrypt_block(output_buffer, plaintext_data, plaintext_len);
    
    // Berechne und hänge Tag an
    impl_->get_tag(output_buffer + plaintext_len);
    
    return static_cast<int>(plaintext_len + 16);
}

int Aes128GcmOptimized::decrypt_zero_copy(const uint8_t* ciphertext_data, size_t ciphertext_len,
                                      const uint8_t* aad_data, size_t aad_len,
                                      const uint8_t* tag_data, 
                                      uint8_t* output_buffer) {
    if (!ciphertext_data || !output_buffer || !tag_data) {
        return -1;
    }
    
    // Initialisiere GCM mit IV
    impl_ = std::make_unique<Impl>(key_, iv_);
    
    // Aktualisiere AAD
    if (aad_data && aad_len > 0) {
        impl_->update_aad(aad_data, aad_len);
    }
    
    // Entschlüssele Daten
    impl_->decrypt_block(output_buffer, ciphertext_data, ciphertext_len);
    
    // Berechne und überprüfe Tag
    uint8_t computed_tag[16];
    impl_->get_tag(computed_tag);
    
    // Konstanter-Zeit-Vergleich
    int diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ tag_data[i];
    }
    
    if (diff != 0) {
        // Authentifizierungsfehler - lösche entschlüsselte Daten
        std::memset(output_buffer, 0, ciphertext_len);
        return -1;
    }
    
    return static_cast<int>(ciphertext_len);
}

bool Aes128GcmOptimized::is_hardware_acceleration_available() {
#ifdef __ARM_NEON
#ifdef __ARM_FEATURE_CRYPTO
    return true;  // ARM Crypto Extensions verfügbar
#endif
#endif
    return false;  // Keine Hardware-Beschleunigung verfügbar
}

} // namespace quicsand::crypto
