#include "core/commit.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <stdexcept>

namespace lgv {
SecureBuffer compute_commit_tag(const SecureBuffer& commit_key,
                                std::span<const unsigned char> header_core) {
    ensure_sodium();
    if (commit_key.size() != 32) throw std::invalid_argument("commit key must be 32 bytes");
    SecureBuffer tag(crypto_generichash_BYTES); // 32
    if (crypto_generichash(tag.data(), tag.size(),
                           header_core.data(), header_core.size(),
                           commit_key.data(), commit_key.size()) != 0)
        throw std::runtime_error("commit tag hash failed");
    return tag;
}

bool verify_commit_tag(const SecureBuffer& commit_key,
                       std::span<const unsigned char> header_core,
                       std::span<const unsigned char> tag) {
    if (tag.size() != 32) return false;
    SecureBuffer expected = compute_commit_tag(commit_key, header_core);
    return sodium_memcmp(expected.data(), tag.data(), 32) == 0;
}
}
