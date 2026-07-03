#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <vector>
#include "core/commit.hpp"
#include "core/secure_buffer.hpp"
#include "core/sodium_init.hpp"

TEST_CASE("commit tag: deterministic, verifies, rejects tamper", "[commit]") {
    lgv::ensure_sodium();
    lgv::SecureBuffer key(32); std::memset(key.data(), 0x44, 32);
    std::vector<unsigned char> hdr(58); std::memset(hdr.data(), 0x55, hdr.size());

    auto tag = lgv::compute_commit_tag(key, hdr);
    REQUIRE(tag.size() == 32);
    REQUIRE(lgv::verify_commit_tag(key, hdr,
            std::span<const unsigned char>(tag.data(), tag.size())));

    std::vector<unsigned char> hdr2 = hdr; hdr2[0] ^= 0x01; // flip 1 bit of header
    REQUIRE_FALSE(lgv::verify_commit_tag(key, hdr2,
            std::span<const unsigned char>(tag.data(), tag.size())));

    lgv::SecureBuffer key2(32); std::memset(key2.data(), 0x66, 32);
    REQUIRE_FALSE(lgv::verify_commit_tag(key2, hdr,
            std::span<const unsigned char>(tag.data(), tag.size())));    // wrong key
}
