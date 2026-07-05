#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>
#include <vector>
#include "storage/vault_file.hpp"
#include "core/errors.hpp"

namespace fs = std::filesystem;

TEST_CASE("atomic save writes bytes, load reads them back, .bak retained", "[storage]") {
    fs::path dir = fs::temp_directory_path() / "lgv_test_store";
    fs::create_directories(dir);
    fs::path p = dir / "vault.lgv";
    fs::path bak = p; bak += ".bak";
    fs::remove(p); fs::remove(bak);

    std::vector<unsigned char> v1 = { 'L','G','V','1', 0x01, 0x02, 0x03 };
    lgv::save_vault_atomic(p, v1);
    REQUIRE(fs::exists(p));
    auto back = lgv::load_vault(p);
    REQUIRE(back == v1);

    std::vector<unsigned char> v2 = { 'L','G','V','1', 0x09 };
    lgv::save_vault_atomic(p, v2);                     // second save
    REQUIRE(lgv::load_vault(p) == v2);
    REQUIRE(fs::exists(bak));                           // previous version preserved
    auto bakbytes = lgv::load_vault(bak);
    REQUIRE(bakbytes == v1);
}

TEST_CASE("loading a missing file throws FormatError", "[storage]") {
    fs::path missing = fs::temp_directory_path() / "lgv_test_store" / "does_not_exist.lgv";
    std::filesystem::remove(missing);
    REQUIRE_THROWS_AS(lgv::load_vault(missing), lgv::FormatError);
}

TEST_CASE("oversized vault is rejected on save and on load", "[storage]") {
    fs::path dir = fs::temp_directory_path() / "lgv_test_store";
    fs::create_directories(dir);
    fs::path p = dir / "oversized.lgv";
    std::vector<unsigned char> big(lgv::kMaxVaultFileBytes + 1, 0xAB);

    // Save mirrors the load cap: persisting an unloadable vault is a self-lockout.
    REQUIRE_THROWS_AS(lgv::save_vault_atomic(p, big), lgv::FormatError);
    REQUIRE_FALSE(fs::exists(p));

    // A foreign oversized file (written outside save_vault_atomic) must be
    // rejected by load before it fills memory.
    {
        std::ofstream out(p, std::ios::binary);
        out.write(reinterpret_cast<const char*>(big.data()),
                  static_cast<std::streamsize>(big.size()));
    }
    REQUIRE_THROWS_AS(lgv::load_vault(p), lgv::FormatError);
    fs::remove(p);

    std::vector<unsigned char> atLimit(lgv::kMaxVaultFileBytes, 0xCD);
    lgv::save_vault_atomic(p, atLimit);
    REQUIRE(lgv::load_vault(p).size() == lgv::kMaxVaultFileBytes);
    fs::remove(p);
}
