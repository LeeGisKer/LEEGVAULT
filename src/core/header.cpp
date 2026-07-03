#include "core/header.hpp"
#include "core/errors.hpp"
#include <cstring>

namespace lgv {
namespace {
void put_u16(std::vector<unsigned char>& b, std::uint16_t v) {
    b.push_back(static_cast<unsigned char>(v & 0xFF));
    b.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
}
void put_u32(std::vector<unsigned char>& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
}
std::uint16_t get_u16(const unsigned char* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}
std::uint32_t get_u32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::vector<unsigned char> build(const Lgv1Header& h, bool with_tag) {
    std::vector<unsigned char> b;
    b.reserve(with_tag ? kHeaderSize : kHeaderCoreSize);
    b.insert(b.end(), { 'L', 'G', 'V', '1' });
    put_u16(b, h.format_version);
    b.push_back(h.kdf_id);
    put_u32(b, h.m_kib);
    put_u32(b, h.t);
    b.push_back(h.p);
    b.insert(b.end(), h.salt.begin(), h.salt.end());
    b.push_back(h.aead_id);
    b.insert(b.end(), h.nonce.begin(), h.nonce.end());
    b.push_back(h.keyfile_flag);
    if (with_tag) b.insert(b.end(), h.commit_tag.begin(), h.commit_tag.end());
    return b;
}
} // namespace

std::vector<unsigned char> serialize_header(const Lgv1Header& h)      { return build(h, true); }
std::vector<unsigned char> serialize_header_core(const Lgv1Header& h) { return build(h, false); }

Lgv1Header parse_header(std::span<const unsigned char> bytes) {
    if (bytes.size() < kHeaderSize) throw FormatError("header too short");
    const unsigned char* p = bytes.data();
    if (std::memcmp(p, "LGV1", 4) != 0) throw FormatError("bad magic");

    Lgv1Header h{};
    h.format_version = get_u16(p + 4);
    if (h.format_version != kFormatVersion) throw FormatError("unsupported format version");
    h.kdf_id = p[6];
    h.m_kib  = get_u32(p + 7);
    h.t      = get_u32(p + 11);
    h.p      = p[15];
    std::memcpy(h.salt.data(), p + 16, 16);
    h.aead_id = p[32];
    std::memcpy(h.nonce.data(), p + 33, 24);
    h.keyfile_flag = p[57];
    std::memcpy(h.commit_tag.data(), p + 58, 32);
    return h;
}
}
