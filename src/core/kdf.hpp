#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include "core/secure_buffer.hpp"

namespace lgv {
struct KdfParams { std::uint32_t m_kib; std::uint32_t t; std::uint8_t p; };
inline constexpr KdfParams kDefaultKdf{ 262144u, 3u, 1u }; // 256 MiB, t=3, p=1

SecureBuffer derive_master_key(std::span<const unsigned char> password,
                               std::optional<std::span<const unsigned char>> keyfile,
                               std::span<const unsigned char> salt,
                               const KdfParams& params);

struct Subkeys { SecureBuffer enc_key; SecureBuffer commit_key; };
Subkeys derive_subkeys(const SecureBuffer& master_key);
}
