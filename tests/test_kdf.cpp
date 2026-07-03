#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include "core/kdf.hpp"
#include "core/sodium_init.hpp"

using bytes = std::span<const unsigned char>;

static lgv::KdfParams fast() { return lgv::KdfParams{ 8192u, 3u, 1u }; } // 8 MiB for fast tests

TEST_CASE("master key: deterministic, distinct, keyfile-sensitive", "[kdf]") {
    lgv::ensure_sodium();
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, salt.size());
    std::string pw = "correct horse battery staple";
    bytes pwb(reinterpret_cast<const unsigned char*>(pw.data()), pw.size());

    auto k1 = lgv::derive_master_key(pwb, std::nullopt, salt, fast());
    auto k2 = lgv::derive_master_key(pwb, std::nullopt, salt, fast());
    REQUIRE(k1.size() == 32);
    REQUIRE(std::memcmp(k1.data(), k2.data(), 32) == 0);            // deterministic

    std::array<unsigned char, 16> salt2{}; std::memset(salt2.data(), 0x22, salt2.size());
    auto k3 = lgv::derive_master_key(pwb, std::nullopt, salt2, fast());
    REQUIRE(std::memcmp(k1.data(), k3.data(), 32) != 0);            // salt changes key

    std::array<unsigned char, 32> kf{}; std::memset(kf.data(), 0x33, kf.size());
    auto k4 = lgv::derive_master_key(pwb, bytes(kf), salt, fast());
    REQUIRE(std::memcmp(k1.data(), k4.data(), 32) != 0);            // keyfile changes key
}

TEST_CASE("subkeys: enc != commit, deterministic", "[kdf]") {
    lgv::ensure_sodium();
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, salt.size());
    std::string pw = "pw"; bytes pwb(reinterpret_cast<const unsigned char*>(pw.data()), pw.size());
    auto mk = lgv::derive_master_key(pwb, std::nullopt, salt, fast());

    auto a = lgv::derive_subkeys(mk);
    auto b = lgv::derive_subkeys(mk);
    REQUIRE(a.enc_key.size() == 32);
    REQUIRE(a.commit_key.size() == 32);
    REQUIRE(std::memcmp(a.enc_key.data(), a.commit_key.data(), 32) != 0);   // independent
    REQUIRE(std::memcmp(a.enc_key.data(), b.enc_key.data(), 32) == 0);      // deterministic
    REQUIRE(std::memcmp(a.commit_key.data(), b.commit_key.data(), 32) == 0);
}
