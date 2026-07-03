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
)
target_include_directories(lgv_core PUBLIC src)
target_link_libraries(lgv_core PUBLIC unofficial-sodium::sodium)
# Static libsodium on MSVC needs SODIUM_STATIC to avoid __imp_ dllimport symbols.
target_compile_definitions(lgv_core PUBLIC SODIUM_STATIC=1)
if (MSVC)
  target_compile_options(lgv_core PRIVATE /W4 /permissive-)
endif()

enable_testing()
include(CTest)
include(Catch)

add_executable(lgv_tests
  tests/test_smoke.cpp
  tests/test_secure_buffer.cpp
)
target_link_libraries(lgv_tests PRIVATE lgv_core Catch2::Catch2WithMain unofficial-sodium::sodium)
catch_discover_tests(lgv_tests)
