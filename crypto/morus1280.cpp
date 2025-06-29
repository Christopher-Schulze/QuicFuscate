#include "morus1280.hpp"
#include <cstring>
#include <stdexcept>

namespace quicfuscate {
namespace crypto {

// MORUS-1280-128 Konstanten
static const int MORUS_RATE = 32;  // 256-bit rate
static const int MORUS_TAG_SIZE = 16;  // 128-bit tag
static const int MORUS_KEY_SIZE = 16;  // 128-bit key
static const int MORUS_NONCE_SIZE = 16;  // 128-bit nonce
static const int MORUS_ROUNDS = 5;  // Number of rounds per step

// MORUS-1280-128 Initialization Vector
static const uint64_t MORUS_IV[20] = {
    0x0d08050302010100ULL, 0x6279e99059372215ULL, 0xf12fc26d55183ddbULL, 0xdd28b57342311120ULL,
    0x5470917e43281e90ULL, 0x8d9b7abacc626ab9ULL, 0x142c3ba227d7cdcfULL, 0xf881e24d45a7ed8eULL,
    0x3c24ba1e0776a298ULL, 0x8427a4364c417daeULL, 0x4d84c3ce9a7a26b8ULL, 0x19dc8ce6c1356be5ULL,
    0x874761517311cf32ULL, 0x6d113b0f462f2c4aULL, 0xc2b4ac11f1c13289ULL, 0x915f2d99c2403f37ULL,
    0x6d9b4cf2a8b8e8e9ULL, 0x79607b532d176b19ULL, 0xb49ac2e85c91745fULL, 0x7bcd371c9a220496ULL
};

MORUS1280::MORUS1280() {
    // Konstruktor - keine spezielle Hardware-Erkennung nötig für Software-Implementierung
}

void MORUS1280::encrypt(const uint8_t* plaintext, size_t plaintext_len,
                       const uint8_t* key, const uint8_t* nonce,
                       const uint8_t* associated_data, size_t ad_len,
                       uint8_t* ciphertext, uint8_t* tag) {
    
    State state;
    
    // Initialisierung
    load_key_nonce(state, key, nonce);
    
    // Verarbeite Associated Data
    if (ad_len > 0) {
        process_associated_data(state, associated_data, ad_len);
    }
    
    // Verschlüssele Plaintext
    process_plaintext(state, plaintext, plaintext_len, ciphertext);
    
    // Finalisierung und Tag-Generierung
    finalize(state, ad_len, plaintext_len, tag);
}

bool MORUS1280::decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* key, const uint8_t* nonce,
                       const uint8_t* associated_data, size_t ad_len,
                       const uint8_t* tag, uint8_t* plaintext) {
    
    State state;
    
    // Initialisierung
    load_key_nonce(state, key, nonce);
    
    // Verarbeite Associated Data
    if (ad_len > 0) {
        process_associated_data(state, associated_data, ad_len);
    }
    
    // Entschlüssele Ciphertext
    size_t blocks = ciphertext_len / MORUS_RATE;
    for (size_t i = 0; i < blocks; i++) {
        uint64_t ct_block[4];
        bytes_to_words(ct_block, ciphertext + i * MORUS_RATE, MORUS_RATE);
        
        // Keystream generieren
        uint64_t keystream[4];
        xor_256(keystream, state.s, state.s + 4);
        xor_256(keystream, keystream, state.s + 8);
        
        // Entschlüsseln
        uint64_t pt_block[4];
        xor_256(pt_block, ct_block, keystream);
        words_to_bytes(plaintext + i * MORUS_RATE, pt_block, MORUS_RATE);
        
        // State update
        xor_256(state.s, state.s, ct_block);
        morus_permutation(state);
    }
    
    // Verarbeite letzten Block
    if (ciphertext_len % MORUS_RATE != 0) {
        size_t remaining = ciphertext_len % MORUS_RATE;
        uint8_t ct_block[MORUS_RATE] = {0};
        memcpy(ct_block, ciphertext + blocks * MORUS_RATE, remaining);
        
        uint64_t ct_words[4];
        bytes_to_words(ct_words, ct_block, MORUS_RATE);
        
        // Keystream generieren
        uint64_t keystream[4];
        xor_256(keystream, state.s, state.s + 4);
        xor_256(keystream, keystream, state.s + 8);
        
        // Entschlüsseln
        uint64_t pt_words[4];
        xor_256(pt_words, ct_words, keystream);
        
        uint8_t pt_block[MORUS_RATE];
        words_to_bytes(pt_block, pt_words, MORUS_RATE);
        memcpy(plaintext + blocks * MORUS_RATE, pt_block, remaining);
        
        // Padding für State update
        uint8_t padded_ct[MORUS_RATE] = {0};
        memcpy(padded_ct, ciphertext + blocks * MORUS_RATE, remaining);
        padded_ct[remaining] = 0x80;
        
        uint64_t padded_words[4];
        bytes_to_words(padded_words, padded_ct, MORUS_RATE);
        xor_256(state.s, state.s, padded_words);
        morus_permutation(state);
    }
    
    // Tag-Verifikation
    uint8_t computed_tag[MORUS_TAG_SIZE];
    finalize(state, ad_len, ciphertext_len, computed_tag);
    
    // Constant-time Vergleich
    uint8_t diff = 0;
    for (int i = 0; i < MORUS_TAG_SIZE; i++) {
        diff |= tag[i] ^ computed_tag[i];
    }
    
    return diff == 0;
}

void MORUS1280::load_key_nonce(State& state, const uint8_t* key, const uint8_t* nonce) {
    // Initialisiere State mit IV
    memcpy(state.s, MORUS_IV, sizeof(MORUS_IV));
    
    // XOR Key und Nonce in State
    uint64_t key_words[2], nonce_words[2];
    bytes_to_words(key_words, key, MORUS_KEY_SIZE);
    bytes_to_words(nonce_words, nonce, MORUS_NONCE_SIZE);
    
    // Key in S0 und S1
    state.s[0] ^= key_words[0];
    state.s[1] ^= key_words[1];
    state.s[4] ^= key_words[0];
    state.s[5] ^= key_words[1];
    
    // Nonce in S2 und S3
    state.s[8] ^= nonce_words[0];
    state.s[9] ^= nonce_words[1];
    state.s[12] ^= nonce_words[0];
    state.s[13] ^= nonce_words[1];
    
    // Initialization rounds
    for (int i = 0; i < 16; i++) {
        morus_permutation(state);
    }
}

void MORUS1280::process_associated_data(State& state, const uint8_t* ad, size_t ad_len) {
    size_t blocks = ad_len / MORUS_RATE;
    
    for (size_t i = 0; i < blocks; i++) {
        uint64_t ad_block[4];
        bytes_to_words(ad_block, ad + i * MORUS_RATE, MORUS_RATE);
        
        xor_256(state.s, state.s, ad_block);
        morus_permutation(state);
    }
    
    // Verarbeite letzten AD-Block
    if (ad_len % MORUS_RATE != 0) {
        uint8_t padded_ad[MORUS_RATE] = {0};
        memcpy(padded_ad, ad + blocks * MORUS_RATE, ad_len % MORUS_RATE);
        padded_ad[ad_len % MORUS_RATE] = 0x80; // Padding
        
        uint64_t ad_words[4];
        bytes_to_words(ad_words, padded_ad, MORUS_RATE);
        xor_256(state.s, state.s, ad_words);
        morus_permutation(state);
    }
}

void MORUS1280::process_plaintext(State& state, const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext) {
    size_t blocks = pt_len / MORUS_RATE;
    
    for (size_t i = 0; i < blocks; i++) {
        uint64_t pt_block[4];
        bytes_to_words(pt_block, plaintext + i * MORUS_RATE, MORUS_RATE);
        
        // Keystream generieren
        uint64_t keystream[4];
        xor_256(keystream, state.s, state.s + 4);
        xor_256(keystream, keystream, state.s + 8);
        
        // Verschlüsseln
        uint64_t ct_block[4];
        xor_256(ct_block, pt_block, keystream);
        words_to_bytes(ciphertext + i * MORUS_RATE, ct_block, MORUS_RATE);
        
        // State update
        xor_256(state.s, state.s, pt_block);
        morus_permutation(state);
    }
    
    // Verarbeite letzten Block
    if (pt_len % MORUS_RATE != 0) {
        size_t remaining = pt_len % MORUS_RATE;
        uint8_t pt_block[MORUS_RATE] = {0};
        memcpy(pt_block, plaintext + blocks * MORUS_RATE, remaining);
        
        uint64_t pt_words[4];
        bytes_to_words(pt_words, pt_block, MORUS_RATE);
        
        // Keystream generieren
        uint64_t keystream[4];
        xor_256(keystream, state.s, state.s + 4);
        xor_256(keystream, keystream, state.s + 8);
        
        // Verschlüsseln
        uint64_t ct_words[4];
        xor_256(ct_words, pt_words, keystream);
        
        uint8_t ct_block[MORUS_RATE];
        words_to_bytes(ct_block, ct_words, MORUS_RATE);
        memcpy(ciphertext + blocks * MORUS_RATE, ct_block, remaining);
        
        // Padding für State update
        uint8_t padded_pt[MORUS_RATE] = {0};
        memcpy(padded_pt, plaintext + blocks * MORUS_RATE, remaining);
        padded_pt[remaining] = 0x80;
        
        uint64_t padded_words[4];
        bytes_to_words(padded_words, padded_pt, MORUS_RATE);
        xor_256(state.s, state.s, padded_words);
        morus_permutation(state);
    }
}

void MORUS1280::finalize(State& state, size_t ad_len, size_t pt_len, uint8_t* tag) {
    // Encode lengths
    uint64_t lengths[4] = {0};
    lengths[0] = ad_len * 8;  // AD length in bits
    lengths[2] = pt_len * 8;  // PT length in bits
    
    xor_256(state.s + 16, state.s + 16, lengths);
    
    // Finalization rounds
    for (int i = 0; i < 10; i++) {
        morus_permutation(state);
    }
    
    // Generate tag
    uint64_t tag_words[2];
    tag_words[0] = state.s[0] ^ state.s[4] ^ state.s[8] ^ state.s[12] ^ state.s[16];
    tag_words[1] = state.s[1] ^ state.s[5] ^ state.s[9] ^ state.s[13] ^ state.s[17];
    
    words_to_bytes(tag, tag_words, MORUS_TAG_SIZE);
}

void MORUS1280::morus_permutation(State& state) {
    for (int round = 0; round < MORUS_ROUNDS; round++) {
        // S0 = S0 XOR (S1 AND S2) XOR S3 XOR (S1 << 13)
        uint64_t temp0[4], temp1[4], temp2[4];
        and_256(temp0, state.s + 4, state.s + 8);
        rotl_256(temp1, state.s + 4, 13);
        xor_256(temp2, state.s, temp0);
        xor_256(temp2, temp2, state.s + 12);
        xor_256(state.s, temp2, temp1);
        
        // Rotate state: S0 <- S1 <- S2 <- S3 <- S4 <- S0
        uint64_t temp_state[4];
        memcpy(temp_state, state.s, 32);
        memmove(state.s, state.s + 4, 64);
        memcpy(state.s + 16, temp_state, 32);
        
        // Rotate S0 by different amounts each round
        rotl_256(state.s, state.s, (round + 1) * 7);
    }
}

void MORUS1280::rotl_256(uint64_t* dst, const uint64_t* src, int bits) {
    if (bits == 0) {
        memcpy(dst, src, 32);
        return;
    }
    
    int word_shift = bits / 64;
    int bit_shift = bits % 64;
    
    for (int i = 0; i < 4; i++) {
        int src_idx = (i - word_shift + 4) % 4;
        if (bit_shift == 0) {
            dst[i] = src[src_idx];
        } else {
            int next_idx = (src_idx + 1) % 4;
            dst[i] = (src[src_idx] << bit_shift) | (src[next_idx] >> (64 - bit_shift));
        }
    }
}

void MORUS1280::xor_256(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
    for (int i = 0; i < 4; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

void MORUS1280::and_256(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
    for (int i = 0; i < 4; i++) {
        dst[i] = a[i] & b[i];
    }
}

void MORUS1280::bytes_to_words(uint64_t* words, const uint8_t* bytes, size_t len) {
    memset(words, 0, 32);
    for (size_t i = 0; i < len && i < 32; i++) {
        words[i / 8] |= ((uint64_t)bytes[i]) << ((i % 8) * 8);
    }
}

void MORUS1280::words_to_bytes(uint8_t* bytes, const uint64_t* words, size_t len) {
    for (size_t i = 0; i < len && i < 32; i++) {
        bytes[i] = (words[i / 8] >> ((i % 8) * 8)) & 0xFF;
    }
}

} // namespace crypto
} // namespace quicfuscate