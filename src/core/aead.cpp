#include "core/aead.hpp"
#include "core/errors.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <stdexcept>

namespace lgv {
std::vector<unsigned char> aead_encrypt(const SecureBuffer& key,
                                        std::span<const unsigned char> nonce,
                                        std::span<const unsigned char> plaintext,
                                        std::span<const unsigned char> aad) {
    ensure_sodium();
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw std::invalid_argument("key must be 32 bytes");
    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw std::invalid_argument("nonce must be 24 bytes");

    std::vector<unsigned char> ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr, nonce.data(), key.data()) != 0)
        throw std::runtime_error("aead encrypt failed");
    ct.resize(static_cast<std::size_t>(ct_len));
    return ct;
}

SecureBuffer aead_decrypt(const SecureBuffer& key,
                          std::span<const unsigned char> nonce,
                          std::span<const unsigned char> ciphertext,
                          std::span<const unsigned char> aad) {
    ensure_sodium();
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw std::invalid_argument("key must be 32 bytes");
    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw std::invalid_argument("nonce must be 24 bytes");
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) throw AuthError();

    SecureBuffer pt(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            aad.data(), aad.size(),
            nonce.data(), key.data()) != 0)
        throw AuthError();   // wrong key, tampered ct, or wrong aad — one generic failure
    // pt_len == pt.size() by construction; SecureBuffer keeps its allocated size.
    return pt;
}
}
