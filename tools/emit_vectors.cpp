// Prints the deterministic golden vault (hex) for the M1 known-answer test.
// Built by LeeGStudios.com
#include <array>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include "core/vault.hpp"
#include "core/sodium_init.hpp"

int main() {
    lgv::ensure_sodium();
    const std::string pw = "leegvault-kat-password";
    std::array<unsigned char, 16> salt{}; for (int i = 0; i < 16; ++i) salt[i] = static_cast<unsigned char>(i);
    std::array<unsigned char, 24> nonce{}; for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(0x40 + i);

    lgv::VaultBody body;
    lgv::Entry e; e.id = "kat-1"; e.name = "Example";
    const char* s = "s3cr3t"; e.secret = lgv::SecureBuffer(6); std::memcpy(e.secret.data(), s, 6);
    body.entries.push_back(std::move(e));

    lgv::VaultKeyMaterial km{
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pw.data()), pw.size()),
        std::nullopt };
    // Fixed KAT params (8 MiB, t=3, p=1) so the test runs fast and stays reproducible.
    auto bytes = lgv::seal_vault(km, lgv::KdfParams{ 8192u, 3u, 1u }, salt, nonce, body);

    std::printf("vault_hex=");
    for (unsigned char c : bytes) std::printf("%02x", c);
    std::printf("\n");
    return 0;
}
