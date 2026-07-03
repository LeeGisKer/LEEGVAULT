#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <vector>
#include "core/header.hpp"
#include "core/errors.hpp"

static lgv::Lgv1Header sample() {
    lgv::Lgv1Header h{};
    h.format_version = 1; h.kdf_id = 1; h.m_kib = 262144; h.t = 3; h.p = 1;
    std::memset(h.salt.data(), 0xA1, h.salt.size());
    h.aead_id = 1; std::memset(h.nonce.data(), 0xB2, h.nonce.size());
    h.keyfile_flag = 1; std::memset(h.commit_tag.data(), 0xC3, h.commit_tag.size());
    return h;
}

TEST_CASE("header round-trips and has the exact layout", "[header]") {
    auto h = sample();
    auto bytes = lgv::serialize_header(h);
    REQUIRE(bytes.size() == lgv::kHeaderSize);
    REQUIRE(bytes[0] == 'L'); REQUIRE(bytes[1] == 'G');
    REQUIRE(bytes[2] == 'V'); REQUIRE(bytes[3] == '1');
    REQUIRE(bytes[4] == 1); REQUIRE(bytes[5] == 0);      // version u16 LE
    REQUIRE(bytes[15] == 1);                             // p
    REQUIRE(bytes[57] == 1);                             // keyfile_flag

    auto core = lgv::serialize_header_core(h);
    REQUIRE(core.size() == lgv::kHeaderCoreSize);
    REQUIRE(std::memcmp(core.data(), bytes.data(), lgv::kHeaderCoreSize) == 0);

    auto h2 = lgv::parse_header(bytes);
    REQUIRE(h2.m_kib == 262144);
    REQUIRE(h2.t == 3);
    REQUIRE(h2.keyfile_flag == 1);
    REQUIRE(std::memcmp(h2.nonce.data(), h.nonce.data(), 24) == 0);
    REQUIRE(std::memcmp(h2.commit_tag.data(), h.commit_tag.data(), 32) == 0);
}

TEST_CASE("header rejects bad magic, version, truncation", "[header]") {
    auto bytes = lgv::serialize_header(sample());

    auto bad = bytes; bad[0] = 'X';
    REQUIRE_THROWS_AS(lgv::parse_header(bad), lgv::FormatError);

    auto ver = bytes; ver[4] = 2;                        // format_version = 2
    REQUIRE_THROWS_AS(lgv::parse_header(ver), lgv::FormatError);

    std::vector<unsigned char> shortb(bytes.begin(), bytes.begin() + 40);
    REQUIRE_THROWS_AS(lgv::parse_header(shortb), lgv::FormatError);
}
