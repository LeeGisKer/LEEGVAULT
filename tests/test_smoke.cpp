#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <string>
#include "core/sodium_init.hpp"

TEST_CASE("libsodium links and initializes", "[smoke]") {
    REQUIRE_NOTHROW(lgv::ensure_sodium());
    // A real libsodium symbol resolves and returns a plausible version string.
    const char* v = sodium_version_string();
    REQUIRE(v != nullptr);
    REQUIRE(std::string(v).size() > 0);
}
