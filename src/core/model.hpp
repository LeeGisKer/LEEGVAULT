#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include "core/secure_buffer.hpp"

namespace lgv {
struct Entry {
    std::string  id;      // non-secret
    std::string  name;    // non-secret
    SecureBuffer secret;  // secret — guarded memory only
};
struct VaultBody {
    std::vector<Entry> entries;
};
inline constexpr std::uint64_t kBodySchemaVersion = 1;

SecureBuffer serialize_body(const VaultBody& body);
VaultBody    parse_body(std::span<const unsigned char> plaintext);
}
