#pragma once
#include <span>
#include <vector>
#include "core/secure_buffer.hpp"
namespace lgv {
std::vector<unsigned char> aead_encrypt(const SecureBuffer& key,
                                        std::span<const unsigned char> nonce,
                                        std::span<const unsigned char> plaintext,
                                        std::span<const unsigned char> aad);
SecureBuffer aead_decrypt(const SecureBuffer& key,
                          std::span<const unsigned char> nonce,
                          std::span<const unsigned char> ciphertext,
                          std::span<const unsigned char> aad);
}
