#pragma once
// LEEGVAULT crypto core — vault assembly.  Built by LeeGStudios.com
#include <optional>
#include <span>
#include <vector>
#include "core/kdf.hpp"
#include "core/model.hpp"

namespace lgv {
struct VaultKeyMaterial {
    std::span<const unsigned char> password;
    std::optional<std::span<const unsigned char>> keyfile;
};

std::vector<unsigned char> seal_vault(const VaultKeyMaterial& km, const KdfParams& params,
                                      std::span<const unsigned char> salt16,
                                      std::span<const unsigned char> nonce24,
                                      const VaultBody& body);

std::vector<unsigned char> create_vault(const VaultKeyMaterial& km, const KdfParams& params,
                                        const VaultBody& body);

VaultBody open_vault(const VaultKeyMaterial& km, std::span<const unsigned char> vault_bytes);
}
