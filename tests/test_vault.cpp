#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include "core/vault.hpp"
#include "core/errors.hpp"
#include "core/header.hpp"
#include "core/sodium_init.hpp"

static lgv::KdfParams fast() { return lgv::KdfParams{ 8192u, 3u, 1u }; }

static lgv::VaultBody one_entry() {
    lgv::VaultBody b; lgv::Entry e; e.id = "1"; e.name = "GitHub";
    const char* s = "hunter2"; e.secret = lgv::SecureBuffer(7); std::memcpy(e.secret.data(), s, 7);
    b.entries.push_back(std::move(e)); return b;
}

static std::span<const unsigned char> as_bytes(const std::string& s) {
    return { reinterpret_cast<const unsigned char*>(s.data()), s.size() };
}

TEST_CASE("vault seal/open round-trip", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);

    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto bytes = lgv::seal_vault(km, fast(), salt, nonce, one_entry());
    REQUIRE(bytes.size() > lgv::kHeaderSize);

    auto body = lgv::open_vault(km, bytes);
    REQUIRE(body.entries.size() == 1);
    REQUIRE(body.entries[0].name == "GitHub");
    REQUIRE(std::memcmp(body.entries[0].secret.data(), "hunter2", 7) == 0);
}

TEST_CASE("wrong password, tampered header, tampered ciphertext all fail closed", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass", wrong = "master-Pass";
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);
    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto bytes = lgv::seal_vault(km, fast(), salt, nonce, one_entry());

    lgv::VaultKeyMaterial bad{ as_bytes(wrong), std::nullopt };
    REQUIRE_THROWS_AS(lgv::open_vault(bad, bytes), lgv::AuthError);

    auto th = bytes; th[16] ^= 0x01;   // flip a salt byte in the header
    REQUIRE_THROWS_AS(lgv::open_vault(km, th), lgv::AuthError);

    auto tc = bytes; tc.back() ^= 0x01; // flip last ciphertext/tag byte
    REQUIRE_THROWS_AS(lgv::open_vault(km, tc), lgv::AuthError);
}

TEST_CASE("keyfile is required to open a keyfile-protected vault", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    std::array<unsigned char, 32> kf{}; std::memset(kf.data(), 0x55, 32);
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);

    lgv::VaultKeyMaterial with_kf{ as_bytes(pw),
        std::span<const unsigned char>(kf.data(), kf.size()) };
    auto bytes = lgv::seal_vault(with_kf, fast(), salt, nonce, one_entry());

    lgv::VaultKeyMaterial no_kf{ as_bytes(pw), std::nullopt };
    REQUIRE_THROWS_AS(lgv::open_vault(no_kf, bytes), lgv::AuthError);
    REQUIRE_NOTHROW(lgv::open_vault(with_kf, bytes));
}

TEST_CASE("create_vault uses fresh randomness each call", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto a = lgv::create_vault(km, fast(), one_entry());
    auto b = lgv::create_vault(km, fast(), one_entry());
    REQUIRE(a != b);                                   // different salt+nonce
    REQUIRE_NOTHROW(lgv::open_vault(km, a));
    REQUIRE_NOTHROW(lgv::open_vault(km, b));
}

TEST_CASE("tampered KDF params fail closed as AuthError", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);
    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto bytes = lgv::seal_vault(km, fast(), salt, nonce, one_entry());

    auto tm = bytes; tm[7] = tm[8] = tm[9] = tm[10] = 0x00;   // m_kib -> 0 (below MEMLIMIT_MIN)
    REQUIRE_THROWS_AS(lgv::open_vault(km, tm), lgv::AuthError);

    auto tt = bytes; tt[11] = tt[12] = tt[13] = tt[14] = 0x00; // t -> 0 (below OPSLIMIT_MIN)
    REQUIRE_THROWS_AS(lgv::open_vault(km, tt), lgv::AuthError);

    // Above-ceiling params must fail closed BEFORE the KDF runs: if this
    // regresses, these cases hang for billions of passes / OOM instead of
    // throwing, and a tampered header becomes a pre-auth DoS + error oracle.
    auto hm = bytes; hm[7] = hm[8] = hm[9] = hm[10] = 0xFF;   // m_kib -> ~4 TiB (above policy ceiling)
    REQUIRE_THROWS_AS(lgv::open_vault(km, hm), lgv::AuthError);

    auto ht = bytes; ht[11] = ht[12] = ht[13] = ht[14] = 0xFF; // t -> ~4e9 passes (above policy ceiling)
    REQUIRE_THROWS_AS(lgv::open_vault(km, ht), lgv::AuthError);

    auto hp = bytes; hp[15] = 0x02;                            // p -> 2 (policy fixes p=1)
    REQUIRE_THROWS_AS(lgv::open_vault(km, hp), lgv::AuthError);
}

TEST_CASE("sealing with out-of-policy KDF params is refused", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);
    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };

    lgv::KdfParams too_big_m{ lgv::kMaxKdfMKib + 1u, 3u, 1u };
    REQUIRE_THROWS_AS(lgv::seal_vault(km, too_big_m, salt, nonce, one_entry()),
                      std::invalid_argument);

    lgv::KdfParams too_big_t{ 8192u, lgv::kMaxKdfT + 1u, 1u };
    REQUIRE_THROWS_AS(lgv::seal_vault(km, too_big_t, salt, nonce, one_entry()),
                      std::invalid_argument);

    lgv::KdfParams bad_p{ 8192u, 3u, 2u };
    REQUIRE_THROWS_AS(lgv::seal_vault(km, bad_p, salt, nonce, one_entry()),
                      std::invalid_argument);
}
