#include "core/kdf.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace lgv {
namespace {
SecureBuffer blake2b256(std::span<const unsigned char> in) {
    SecureBuffer out(crypto_generichash_BYTES); // 32
    if (crypto_generichash(out.data(), out.size(), in.data(), in.size(), nullptr, 0) != 0)
        throw std::runtime_error("blake2b failed");
    return out;
}
} // namespace

SecureBuffer derive_master_key(std::span<const unsigned char> password,
                               std::optional<std::span<const unsigned char>> keyfile,
                               std::span<const unsigned char> salt,
                               const KdfParams& params) {
    ensure_sodium();
    if (salt.size() != crypto_pwhash_SALTBYTES) throw std::invalid_argument("salt must be 16 bytes");

    SecureBuffer hp = blake2b256(password);              // 32
    SecureBuffer composite;
    if (keyfile.has_value()) {
        if (keyfile->size() != 32) throw std::invalid_argument("keyfile must be 32 bytes");
        SecureBuffer cat(64);
        std::memcpy(cat.data(), hp.data(), 32);
        std::memcpy(cat.data() + 32, keyfile->data(), 32);
        composite = blake2b256(std::span<const unsigned char>(cat.data(), cat.size()));
    } else {
        composite = std::move(hp);
    }

    // Compute memlimit in 64-bit so a large m_kib cannot wrap on a 32-bit
    // size_t and silently run Argon2 with a tiny memory cost.
    const std::uint64_t memlimit = static_cast<std::uint64_t>(params.m_kib) * 1024u;
    if (memlimit > std::numeric_limits<std::size_t>::max())
        throw std::runtime_error("argon2id memlimit exceeds platform size_t");

    SecureBuffer mk(crypto_kdf_KEYBYTES);                 // 32
    const int rc = crypto_pwhash(
        mk.data(), mk.size(),
        reinterpret_cast<const char*>(composite.data()), composite.size(),
        salt.data(),
        static_cast<unsigned long long>(params.t),
        static_cast<std::size_t>(memlimit),
        crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) throw std::runtime_error("argon2id failed (out of memory?)");
    return mk;
}

Subkeys derive_subkeys(const SecureBuffer& master_key) {
    ensure_sodium();
    if (master_key.size() != crypto_kdf_KEYBYTES) throw std::invalid_argument("master key must be 32 bytes");
    Subkeys sk{ SecureBuffer(32), SecureBuffer(32) };
    // context is exactly crypto_kdf_CONTEXTBYTES (8) chars.
    if (crypto_kdf_derive_from_key(sk.enc_key.data(), 32, 1, "LGVKDF01", master_key.data()) != 0)
        throw std::runtime_error("kdf(enc) failed");
    if (crypto_kdf_derive_from_key(sk.commit_key.data(), 32, 2, "LGVKDF01", master_key.data()) != 0)
        throw std::runtime_error("kdf(commit) failed");
    return sk;
}
}
