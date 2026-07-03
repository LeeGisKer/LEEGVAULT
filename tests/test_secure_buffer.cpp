#include <catch2/catch_test_macros.hpp>
#include <type_traits>
#include <cstring>
#include "core/secure_buffer.hpp"
#include "core/sodium_init.hpp"

TEST_CASE("SecureBuffer allocates, is move-only, and moves ownership", "[secbuf]") {
    lgv::ensure_sodium();

    static_assert(!std::is_copy_constructible_v<lgv::SecureBuffer>);
    static_assert(!std::is_copy_assignable_v<lgv::SecureBuffer>);
    static_assert(std::is_move_constructible_v<lgv::SecureBuffer>);

    lgv::SecureBuffer a(32);
    REQUIRE(a.size() == 32);
    REQUIRE(a.data() != nullptr);
    std::memset(a.data(), 0xAB, a.size());
    REQUIRE(a.data()[0] == 0xAB);

    lgv::SecureBuffer b = std::move(a);
    REQUIRE(b.size() == 32);
    REQUIRE(b.data()[0] == 0xAB);
    REQUIRE(a.data() == nullptr);   // NOLINT: moved-from is empty
    REQUIRE(a.size() == 0);

    lgv::SecureBuffer empty;
    REQUIRE(empty.empty());
    REQUIRE(empty.size() == 0);
}
