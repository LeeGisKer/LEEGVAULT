#pragma once
#include <filesystem>
#include <span>
#include <vector>
namespace lgv {
// Hard ceiling on vault file size. A legitimate vault (CBOR entries of
// credentials/notes) is orders of magnitude smaller; anything larger is
// corruption or a deliberate memory-exhaustion payload, so loading fails
// closed instead of buffering unbounded attacker-controlled bytes.
inline constexpr std::size_t kMaxVaultFileBytes = 64ull * 1024 * 1024;

void save_vault_atomic(const std::filesystem::path& path, std::span<const unsigned char> bytes);
std::vector<unsigned char> load_vault(const std::filesystem::path& path);
}
