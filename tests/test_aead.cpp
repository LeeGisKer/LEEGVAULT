#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string>
#include <vector>
#include "core/aead.hpp"
#include "core/errors.hpp"
#include "core/secure_buffer.hpp"
#include "core/sodium_init.hpp"

TEST_CASE("aead: round-trip, tamper, wrong aad all fail closed", "[aead]") {
    lgv::ensure_sodium();
    lgv::SecureBuffer key(32); std::memset(key.data(), 0x77, 32);
    std::vector<unsigned char> nonce(24, 0x88);
    std::string msg = "top secret body";
    std::span<const unsigned char> pt(reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    std::vector<unsigned char> aad(90, 0x99);

    auto ct = lgv::aead_encrypt(key, nonce, pt, aad);
    REQUIRE(ct.size() == msg.size() + 16);

    auto out = lgv::aead_decrypt(key, nonce, ct, aad);
    REQUIRE(out.size() == msg.size());
    REQUIRE(std::memcmp(out.data(), msg.data(), msg.size()) == 0);

    auto ct2 = ct; ct2[0] ^= 0x01;
    REQUIRE_THROWS_AS(lgv::aead_decrypt(key, nonce, ct2, aad), lgv::AuthError);

    auto aad2 = aad; aad2[0] ^= 0x01;
    REQUIRE_THROWS_AS(lgv::aead_decrypt(key, nonce, ct, aad2), lgv::AuthError);

    lgv::SecureBuffer key2(32); std::memset(key2.data(), 0x00, 32);
    REQUIRE_THROWS_AS(lgv::aead_decrypt(key2, nonce, ct, aad), lgv::AuthError);
}
