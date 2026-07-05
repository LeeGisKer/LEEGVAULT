#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include "core/secure_buffer.hpp"

namespace lgv {
struct KdfParams { std::uint32_t m_kib; std::uint32_t t; std::uint8_t p; };
inline constexpr KdfParams kDefaultKdf{ 262144u, 3u, 1u }; // 256 MiB, t=3, p=1

// Policy ceiling on accepted KDF cost. libsodium's own maxima bound nothing
// here: OPSLIMIT_MAX equals the u32 field maximum, and MEMLIMIT_MAX sits just
// above the largest scaled u32 memlimit; without a real ceiling a tampered
// header can demand terabytes of memory or ~4e9 Argon2 passes before
// authentication runs. 8 GiB / t=64 is far above any sane auto-tune target
// (M2 auto-tune must clamp to these); anything higher is treated as tampering.
inline constexpr std::uint32_t kMaxKdfMKib = 8u * 1024u * 1024u; // 8 GiB in KiB
inline constexpr std::uint32_t kMaxKdfT    = 64u;

SecureBuffer derive_master_key(std::span<const unsigned char> password,
                               std::optional<std::span<const unsigned char>> keyfile,
                               std::span<const unsigned char> salt,
                               const KdfParams& params);

struct Subkeys { SecureBuffer enc_key; SecureBuffer commit_key; };
Subkeys derive_subkeys(const SecureBuffer& master_key);
}
