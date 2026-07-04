#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "core/vault.hpp"
#include "core/aead.hpp"
#include "core/sodium_init.hpp"

// Paste the exact value from tests/vectors/lgv1-kat.json (emit_vectors output) here, then freeze it.
static const std::string kGoldenVaultHex = "4c475631010001002000000300000001000102030405060708090a0b0c0d0e0f01404142434445464748494a4b4c4d4e4f50515253545556570081d0a81671deea496cca27163cabe5564be298371f19b7c1764a7bf2ac7abc1447efcd7849fd204f9d2010bc755f99634bc6d7a1f15bb4ce2f873bffa5a6d28e94dd6de491957d833e2b50ed7ef388cf435468744d146ca44efeccd5aebf3b4ccd40";

static std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> out; out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

TEST_CASE("LGV1 known-answer vector is stable and opens", "[kat]") {
    lgv::ensure_sodium();
    const std::string pw = "leegvault-kat-password";
    std::array<unsigned char, 16> salt{}; for (int i = 0; i < 16; ++i) salt[i] = static_cast<unsigned char>(i);
    std::array<unsigned char, 24> nonce{}; for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(0x40 + i);

    lgv::VaultBody body;
    lgv::Entry e; e.id = "kat-1"; e.name = "Example";
    e.secret = lgv::SecureBuffer(6); std::memcpy(e.secret.data(), "s3cr3t", 6);
    body.entries.push_back(std::move(e));

    lgv::VaultKeyMaterial km{
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pw.data()), pw.size()),
        std::nullopt };
    auto bytes = lgv::seal_vault(km, lgv::KdfParams{ 8192u, 3u, 1u }, salt, nonce, body);

    REQUIRE(bytes == unhex(kGoldenVaultHex));      // regression lock

    auto reopened = lgv::open_vault(km, bytes);    // and it actually opens
    REQUIRE(reopened.entries.size() == 1);
    REQUIRE(reopened.entries[0].name == "Example");
    REQUIRE(std::memcmp(reopened.entries[0].secret.data(), "s3cr3t", 6) == 0);
}

// Independent, PUBLISHED vector — anchors correctness against the standard, not just our
// own output. Canonical XChaCha20-Poly1305-IETF example from draft-irtf-cfrg-xchacha-03
// Appendix A.3 (cross-checked against golang.org/x/crypto). DO NOT regenerate from our code.
TEST_CASE("aead matches the published XChaCha20-Poly1305-IETF vector", "[aead-kat]") {
    lgv::ensure_sodium();
    lgv::SecureBuffer key(32);
    for (int i = 0; i < 32; ++i) key.data()[i] = static_cast<unsigned char>(0x80 + i);  // 80..9f
    std::vector<unsigned char> nonce(24);
    for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(0x40 + i);        // 40..57
    std::vector<unsigned char> aad =
        { 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };
    std::string msg =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    REQUIRE(msg.size() == 114);
    std::span<const unsigned char> pt(
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

    // 130 bytes = 114 ciphertext + 16 tag. Verified against draft-irtf-cfrg-xchacha-03 A.3
    // AND golang.org/x/crypto (byte-identical). DO NOT edit this constant.
    const std::string kPublishedCtHex =
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
        "c0875924c1c7987947deafd8780acf49";
    auto expected = unhex(kPublishedCtHex);
    REQUIRE(expected.size() == 130);

    auto ct = lgv::aead_encrypt(key, nonce, pt, aad);
    REQUIRE(ct == expected);                       // our AEAD output == the published standard
}
