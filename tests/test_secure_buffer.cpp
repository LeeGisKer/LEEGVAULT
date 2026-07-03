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

TEST_CASE("SecureBuffer move-assignment transfers ownership and self-move is safe", "[secbuf]") {
    lgv::ensure_sodium();
    static_assert(std::is_move_assignable_v<lgv::SecureBuffer>);

    lgv::SecureBuffer x(16);
    std::memset(x.data(), 0xCD, x.size());
    lgv::SecureBuffer y(8);
    y = std::move(x);                      // move-assign over an already-allocated buffer
    REQUIRE(y.size() == 16);
    REQUIRE(y.data() != nullptr);
    REQUIRE(y.data()[0] == 0xCD);
    REQUIRE(x.data() == nullptr);          // source emptied
    REQUIRE(x.size() == 0);

    // self-move-assignment must be a no-op (the `this != &o` guard), never a free-and-null.
    lgv::SecureBuffer& ref = y;
    y = std::move(ref);
    REQUIRE(y.size() == 16);
    REQUIRE(y.data() != nullptr);
    REQUIRE(y.data()[0] == 0xCD);
}
