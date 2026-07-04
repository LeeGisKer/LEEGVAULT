#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include "core/model.hpp"
#include "core/errors.hpp"
#include "core/sodium_init.hpp"

static lgv::Entry make_entry(const std::string& id, const std::string& name, const std::string& secret) {
    lgv::Entry e; e.id = id; e.name = name;
    e.secret = lgv::SecureBuffer(secret.size());
    std::memcpy(e.secret.data(), secret.data(), secret.size());
    return e;
}

TEST_CASE("vault body round-trips through CBOR, secrets preserved", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    body.entries.push_back(make_entry("id-1", "GitHub", "hunter2"));
    body.entries.push_back(make_entry("id-2", "Email",  "p@ssw0rd!"));

    auto blob = lgv::serialize_body(body);
    REQUIRE(blob.size() > 0);

    auto back = lgv::parse_body(std::span<const unsigned char>(blob.data(), blob.size()));
    REQUIRE(back.entries.size() == 2);
    REQUIRE(back.entries[0].id == "id-1");
    REQUIRE(back.entries[0].name == "GitHub");
    REQUIRE(back.entries[0].secret.size() == 7);
    REQUIRE(std::memcmp(back.entries[0].secret.data(), "hunter2", 7) == 0);
    REQUIRE(back.entries[1].secret.size() == 9);
    REQUIRE(std::memcmp(back.entries[1].secret.data(), "p@ssw0rd!", 9) == 0);
}

TEST_CASE("empty vault body round-trips", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    auto blob = lgv::serialize_body(body);
    auto back = lgv::parse_body(std::span<const unsigned char>(blob.data(), blob.size()));
    REQUIRE(back.entries.empty());
}

TEST_CASE("truncated body is rejected", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    body.entries.push_back(make_entry("id-1", "GitHub", "hunter2"));
    auto blob = lgv::serialize_body(body);
    std::vector<unsigned char> truncated(blob.data(), blob.data() + blob.size() / 2);
    REQUIRE_THROWS_AS(
        lgv::parse_body(std::span<const unsigned char>(truncated.data(), truncated.size())),
        lgv::FormatError);
}

TEST_CASE("trailing bytes after a valid body are rejected", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    body.entries.push_back(make_entry("id-1", "GitHub", "hunter2"));
    auto blob = lgv::serialize_body(body);
    std::vector<unsigned char> extra(blob.data(), blob.data() + blob.size());
    extra.push_back(0x00); // one stray byte
    REQUIRE_THROWS_AS(
        lgv::parse_body(std::span<const unsigned char>(extra.data(), extra.size())),
        lgv::FormatError);
}

TEST_CASE("oversized entry count is rejected without huge allocation", "[model]") {
    lgv::ensure_sodium();
    // map(2){ "v":1, "entries": array(2^64-1) }
    std::vector<unsigned char> blob = {
        0xA2,
        0x61, 'v', 0x01,
        0x67, 'e','n','t','r','i','e','s',
        0x9B, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };
    REQUIRE_THROWS_AS(
        lgv::parse_body(std::span<const unsigned char>(blob.data(), blob.size())),
        lgv::FormatError);
}

TEST_CASE("oversized secret byte-string length is rejected (no overflow bypass)", "[model]") {
    lgv::ensure_sodium();
    // map(2){ "v":1, "entries": array(1)[ map(3){"id":"","name":"","secret":bstr(2^64-1)} ] }
    std::vector<unsigned char> blob = {
        0xA2,
        0x61, 'v', 0x01,
        0x67, 'e','n','t','r','i','e','s',
        0x81,
        0xA3,
        0x62, 'i','d', 0x60,
        0x64, 'n','a','m','e', 0x60,
        0x66, 's','e','c','r','e','t', 0x5B, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };
    REQUIRE_THROWS_AS(
        lgv::parse_body(std::span<const unsigned char>(blob.data(), blob.size())),
        lgv::FormatError);
}
