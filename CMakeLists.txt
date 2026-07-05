cmake_minimum_required(VERSION 3.25)
project(leegvault VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(Catch2 3 CONFIG REQUIRED)

# Core library (pure crypto + serialization; grows as tasks land).
add_library(lgv_core STATIC
  src/core/sodium_init.cpp
  src/core/kdf.cpp
  src/core/commit.cpp
  src/core/header.cpp
  src/core/aead.cpp
  src/core/cbor.cpp
  src/core/model.cpp
  src/core/vault.cpp
)
target_include_directories(lgv_core PUBLIC src)
target_link_libraries(lgv_core PUBLIC unofficial-sodium::sodium)
# Static libsodium on MSVC needs SODIUM_STATIC to avoid __imp_ dllimport symbols.
target_compile_definitions(lgv_core PUBLIC SODIUM_STATIC=1)
if (MSVC)
  target_compile_options(lgv_core PRIVATE /W4 /permissive-)
endif()

# Storage library (atomic vault file save/load — the only file I/O in M1).
add_library(lgv_storage STATIC src/storage/vault_file.cpp)
target_include_directories(lgv_storage PUBLIC src)
target_link_libraries(lgv_storage PUBLIC lgv_core)
if (MSVC)
  target_compile_options(lgv_storage PRIVATE /W4 /permissive-)
endif()

# Deterministic KAT vector generator (tool; emits the golden vault hex).
add_executable(emit_vectors tools/emit_vectors.cpp)
target_link_libraries(emit_vectors PRIVATE lgv_core unofficial-sodium::sodium)

# Interactive CLI app (M2 seed) — the double-click runnable vault.
add_executable(leegvault src/cli/main.cpp)
target_link_libraries(leegvault PRIVATE lgv_core lgv_storage unofficial-sodium::sodium)
if (MSVC)
  target_compile_options(leegvault PRIVATE /W4 /permissive-)
endif()

enable_testing()
include(CTest)
include(Catch)

add_executable(lgv_tests
  tests/test_smoke.cpp
  tests/test_secure_buffer.cpp
  tests/test_kdf.cpp
  tests/test_commit.cpp
  tests/test_header.cpp
  tests/test_aead.cpp
  tests/test_cbor_model.cpp
  tests/test_vault.cpp
  tests/test_vault_file.cpp
  tests/test_vectors.cpp
)
target_link_libraries(lgv_tests PRIVATE lgv_core lgv_storage Catch2::Catch2WithMain unofficial-sodium::sodium)
catch_discover_tests(lgv_tests)
