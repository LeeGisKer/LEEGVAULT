#pragma once
#include <filesystem>
#include <span>
#include <vector>
namespace lgv {
void save_vault_atomic(const std::filesystem::path& path, std::span<const unsigned char> bytes);
std::vector<unsigned char> load_vault(const std::filesystem::path& path);
}
