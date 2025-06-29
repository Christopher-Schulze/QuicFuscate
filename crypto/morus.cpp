#include "morus.hpp"
#include <cstring>
#include <stdexcept>

namespace quicfuscate {
namespace crypto {

// MORUS-1280-128 Konstanten
static const uint64_t MORUS_IV = 0x80400c0600000000ULL;
static const int MORUS_RATE = 16;  // 128-bit rate
static const int MORUS_PA_ROUNDS = 12;
static const int MORUS_PB_ROUNDS = 8;

// MORUS Permutation Konstanten
static const uint64_t ROUND_CONSTANTS[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

MORUS::MORUS() {
    // Konstruktor - keine spezielle Hardware-Erkennung nötig für Software-Implementierung
}

void MORUS::encrypt(const uint8_t* plaintext, size_t plaintext_len,
                   const uint8_t* key, const uint8_t* nonce,
                   const uint8_t* associated_data, size_t ad_len,
                   uint8_t* ciphertext, uint8_t* tag) {
    
    // MORUS-1280-128 State: 5 x 64-bit words
    uint64_t state[5];
    
    // Initialisierung
    state[0] = MORUS_IV;
    state[1] = bytes_to_u64(key);
    state[2] = bytes_to_u64(key + 8);
    state[3] = bytes_to_u64(nonce);
    state[4] = bytes_to_u64(nonce + 8);
    
    // Initiale Permutation
    morus_permutation(state, MORUS_PA_ROUNDS);
    
    // XOR mit Schlüssel
    state[3] ^= bytes_to_u64(key);
    state[4] ^= bytes_to_u64(key + 8);
    
    // Verarbeite Associated Data
    if (ad_len > 0) {
        size_t ad_blocks = ad_len / MORUS_RATE;
        for (size_t i = 0; i < ad_blocks; i++) {
            state[0] ^= bytes_to_u64(associated_data + i * MORUS_RATE);
            state[1] ^= bytes_to_u64(associated_data + i * MORUS_RATE + 8);
            morus_permutation(state, MORUS_PB_ROUNDS);
        }
        
        // Verarbeite letzten AD-Block
        if (ad_len % MORUS_RATE != 0) {
            uint8_t padded_ad[MORUS_RATE] = {0};
            memcpy(padded_ad, associated_data + ad_blocks * MORUS_RATE, ad_len % MORUS_RATE);
            padded_ad[ad_len % MORUS_RATE] = 0x80; // Padding
            
            state[0] ^= bytes_to_u64(padded_ad);
            state[1] ^= bytes_to_u64(padded_ad + 8);
            morus_permutation(state, MORUS_PB_ROUNDS);
        }
    }
    
    // Domain-Separation
    state[4] ^= 1;
    
    // Verschlüssele Plaintext
    size_t pt_blocks = plaintext_len / MORUS_RATE;
    for (size_t i = 0; i < pt_blocks; i++) {
        state[0] ^= bytes_to_u64(plaintext + i * MORUS_RATE);
        state[1] ^= bytes_to_u64(plaintext + i * MORUS_RATE + 8);
        
        u64_to_bytes(state[0], ciphertext + i * MORUS_RATE);
        u64_to_bytes(state[1], ciphertext + i * MORUS_RATE + 8);
        
        morus_permutation(state, MORUS_PB_ROUNDS);
    }
    
    // Verarbeite letzten Plaintext-Block
    if (plaintext_len % MORUS_RATE != 0) {
        uint8_t padded_pt[MORUS_RATE] = {0};
        memcpy(padded_pt, plaintext + pt_blocks * MORUS_RATE, plaintext_len % MORUS_RATE);
        padded_pt[plaintext_len % MORUS_RATE] = 0x80; // Padding
        
        uint64_t pt0 = bytes_to_u64(padded_pt);
        uint64_t pt1 = bytes_to_u64(padded_pt + 8);
        
        state[0] ^= pt0;
        state[1] ^= pt1;
        
        uint8_t ct_bytes[MORUS_RATE];
        u64_to_bytes(state[0], ct_bytes);
        u64_to_bytes(state[1], ct_bytes + 8);
        
        memcpy(ciphertext + pt_blocks * MORUS_RATE, ct_bytes, plaintext_len % MORUS_RATE);
    }
    
    // Finalisierung
    state[1] ^= bytes_to_u64(key);
    state[2] ^= bytes_to_u64(key + 8);
    
    morus_permutation(state, MORUS_PA_ROUNDS);
    
    state[3] ^= bytes_to_u64(key);
    state[4] ^= bytes_to_u64(key + 8);
    
    // Generiere Tag
    u64_to_bytes(state[3], tag);
    u64_to_bytes(state[4], tag + 8);
}

bool MORUS::decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                   const uint8_t* key, const uint8_t* nonce,
                   const uint8_t* associated_data, size_t ad_len,
                   const uint8_t* tag, uint8_t* plaintext) {
    
    // MORUS-1280-128 State: 5 x 64-bit words
    uint64_t state[5];
    
    // Initialisierung (gleich wie bei Verschlüsselung)
    state[0] = MORUS_IV;
    state[1] = bytes_to_u64(key);
    state[2] = bytes_to_u64(key + 8);
    state[3] = bytes_to_u64(nonce);
    state[4] = bytes_to_u64(nonce + 8);
    
    morus_permutation(state, MORUS_PA_ROUNDS);
    
    state[3] ^= bytes_to_u64(key);
    state[4] ^= bytes_to_u64(key + 8);
    
    // Verarbeite Associated Data (gleich wie bei Verschlüsselung)
    if (ad_len > 0) {
        size_t ad_blocks = ad_len / MORUS_RATE;
        for (size_t i = 0; i < ad_blocks; i++) {
            state[0] ^= bytes_to_u64(associated_data + i * MORUS_RATE);
            state[1] ^= bytes_to_u64(associated_data + i * MORUS_RATE + 8);
            morus_permutation(state, MORUS_PB_ROUNDS);
        }
        
        if (ad_len % MORUS_RATE != 0) {
            uint8_t padded_ad[MORUS_RATE] = {0};
            memcpy(padded_ad, associated_data + ad_blocks * MORUS_RATE, ad_len % MORUS_RATE);
            padded_ad[ad_len % MORUS_RATE] = 0x80;
            
            state[0] ^= bytes_to_u64(padded_ad);
            state[1] ^= bytes_to_u64(padded_ad + 8);
            morus_permutation(state, MORUS_PB_ROUNDS);
        }
    }
    
    state[4] ^= 1;
    
    // Entschlüssele Ciphertext
    size_t ct_blocks = ciphertext_len / MORUS_RATE;
    for (size_t i = 0; i < ct_blocks; i++) {
        uint64_t ct0 = bytes_to_u64(ciphertext + i * MORUS_RATE);
        uint64_t ct1 = bytes_to_u64(ciphertext + i * MORUS_RATE + 8);
        
        u64_to_bytes(state[0] ^ ct0, plaintext + i * MORUS_RATE);
        u64_to_bytes(state[1] ^ ct1, plaintext + i * MORUS_RATE + 8);
        
        state[0] = ct0;
        state[1] = ct1;
        
        morus_permutation(state, MORUS_PB_ROUNDS);
    }
    
    // Verarbeite letzten Ciphertext-Block
    if (ciphertext_len % MORUS_RATE != 0) {
        uint8_t ct_bytes[MORUS_RATE] = {0};
        memcpy(ct_bytes, ciphertext + ct_blocks * MORUS_RATE, ciphertext_len % MORUS_RATE);
        
        uint8_t state_bytes[MORUS_RATE];
        u64_to_bytes(state[0], state_bytes);
        u64_to_bytes(state[1], state_bytes + 8);
        
        for (size_t i = 0; i < ciphertext_len % MORUS_RATE; i++) {
            plaintext[ct_blocks * MORUS_RATE + i] = state_bytes[i] ^ ct_bytes[i];
            state_bytes[i] = ct_bytes[i];
        }
        state_bytes[ciphertext_len % MORUS_RATE] = 0x80;
        
        state[0] = bytes_to_u64(state_bytes);
        state[1] = bytes_to_u64(state_bytes + 8);
    }
    
    // Finalisierung
    state[1] ^= bytes_to_u64(key);
    state[2] ^= bytes_to_u64(key + 8);
    
    morus_permutation(state, MORUS_PA_ROUNDS);
    
    state[3] ^= bytes_to_u64(key);
    state[4] ^= bytes_to_u64(key + 8);
    
    // Verifiziere Tag
    uint8_t computed_tag[16];
    u64_to_bytes(state[3], computed_tag);
    u64_to_bytes(state[4], computed_tag + 8);
    
    return memcmp(tag, computed_tag, 16) == 0;
}

void MORUS::morus_permutation(uint64_t state[5], int rounds) {
    for (int i = 12 - rounds; i < 12; i++) {
        // Addition of Constants
        state[2] ^= ROUND_CONSTANTS[i];
        
        // Substitution Layer
        state[0] ^= state[4];
        state[4] ^= state[3];
        state[2] ^= state[1];
        
        uint64_t t0 = state[0];
        uint64_t t1 = state[1];
        uint64_t t2 = state[2];
        uint64_t t3 = state[3];
        uint64_t t4 = state[4];
        
        state[0] = t0 ^ ((~t1) & t2);
        state[1] = t1 ^ ((~t2) & t3);
        state[2] = t2 ^ ((~t3) & t4);
        state[3] = t3 ^ ((~t4) & t0);
        state[4] = t4 ^ ((~t0) & t1);
        
        state[1] ^= state[0];
        state[0] ^= state[4];
        state[3] ^= state[2];
        state[2] = ~state[2];
        
        // Linear Diffusion Layer
        state[0] ^= rotr64(state[0], 19) ^ rotr64(state[0], 28);
        state[1] ^= rotr64(state[1], 61) ^ rotr64(state[1], 39);
        state[2] ^= rotr64(state[2], 1) ^ rotr64(state[2], 6);
        state[3] ^= rotr64(state[3], 10) ^ rotr64(state[3], 17);
        state[4] ^= rotr64(state[4], 7) ^ rotr64(state[4], 41);
    }
}

uint64_t MORUS::bytes_to_u64(const uint8_t* bytes) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

void MORUS::u64_to_bytes(uint64_t value, uint8_t* bytes) {
    for (int i = 7; i >= 0; i--) {
        bytes[i] = value & 0xFF;
        value >>= 8;
    }
}

uint64_t MORUS::rotr64(uint64_t value, int shift) {
    return (value >> shift) | (value << (64 - shift));
}

} // namespace crypto
} // namespace quicfuscate
