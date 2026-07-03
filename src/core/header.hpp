#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace lgv {
inline constexpr std::size_t kHeaderSize = 90;
inline constexpr std::size_t kHeaderCoreSize = 58;
inline constexpr std::uint16_t kFormatVersion = 1;

struct Lgv1Header {
    std::uint16_t format_version;
    std::uint8_t  kdf_id;
    std::uint32_t m_kib;
    std::uint32_t t;
    std::uint8_t  p;
    std::array<unsigned char, 16> salt;
    std::uint8_t  aead_id;
    std::array<unsigned char, 24> nonce;
    std::uint8_t  keyfile_flag;
    std::array<unsigned char, 32> commit_tag;
};

std::vector<unsigned char> serialize_header(const Lgv1Header& h);
std::vector<unsigned char> serialize_header_core(const Lgv1Header& h);
Lgv1Header parse_header(std::span<const unsigned char> bytes);
}
