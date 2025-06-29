#include "../../../crypto/morus.hpp"
using namespace quicfuscate::crypto;
extern "C" {
MORUS* morus_new() { return new MORUS(); }
void morus_free(MORUS* m) { delete m; }
void morus_encrypt(MORUS* m,
                   const uint8_t* plaintext,
                   size_t plaintext_len,
                   const uint8_t* key,
                   const uint8_t* nonce,
                   const uint8_t* ad,
                   size_t ad_len,
                   uint8_t* ciphertext,
                   uint8_t* tag) {
    m->encrypt(plaintext, plaintext_len, key, nonce, ad, ad_len, ciphertext, tag);
}
}
