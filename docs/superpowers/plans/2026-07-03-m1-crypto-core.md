# LEEGVAULT M1 — Crypto Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the auditable cryptographic core of LEEGVAULT — key hierarchy, LGV1 vault serialization, key-commitment tag, and guarded secure memory — such that a full vault round-trips through disk and published known-answer vectors pass.

**Architecture:** `src/core/` holds pure, side-effect-free crypto and serialization (bytes in → bytes out, no file I/O). `src/storage/` holds the only disk I/O in M1 (atomic save/load of opaque vault bytes). Every crypto function that consumes randomness (salt, nonce) accepts it as an injected parameter so tests are deterministic known-answer tests; a thin public wrapper generates real randomness via `randombytes_buf`. All secret material lives in `SecureBuffer` (guarded `sodium_malloc` allocation). The vault file is one AEAD blob whose plaintext header is passed as AAD; a key-commitment tag over the header is verified in constant time *before* AEAD runs.

**Tech Stack:** C++20 · libsodium (single crypto dependency, via vcpkg static triplet) · Catch2 v3 (tests) · CMake ≥ 3.25 + presets · MSVC (Visual Studio 2022) · Windows first, format identical cross-OS.

## Global Constraints

Copied verbatim from PRD.md — every task's requirements implicitly include these:

- **Language / build:** C++20; CMake ≥ 3.25 with presets; libsodium via vcpkg **static** triplet (`x64-windows-static`); statically linked. (PRD §10, A4 blessed.)
- **Single crypto dependency:** libsodium only. No second crypto library. Non-crypto serialization is hand-rolled (no external CBOR/JSON dependency), because a JSON/CBOR library would route secret strings through `std::string` heap, violating §6.5. (PRD §6.7, A4.)
- **KDF:** Argon2id via libsodium `crypto_pwhash`. Default params **m = 256 MiB (262144 KiB), t = 3, p = 1**. `p = 1` is fixed by libsodium's high-level API (verified against libsodium docs + issues #986/#993); the header still carries a `p` byte and always records `1`. Salt = 16 bytes (`crypto_pwhash_SALTBYTES`), master key = 32 bytes. (PRD §6.1, A5 blessed + reconciled to p=1.)
- **AEAD:** XChaCha20-Poly1305-IETF; 256-bit key; 192-bit (24-byte) random nonce per save. (PRD §6.3, A2.)
- **Key commitment:** header stores `commit_tag = keyed-BLAKE2b-256(commit_key, header_core_bytes)`, verified constant-time before AEAD decryption. (PRD §6.4.)
- **Zero plaintext metadata:** entry names, URLs, timestamps, entry count all live inside the ciphertext. The header exposes only KDF/cipher parameters. (PRD §6.6, A2.)
- **Memory hardening:** all keys and decrypted secrets in `sodium_malloc` guarded allocations; move-only `SecureBuffer` RAII, zeroize-on-destroy (via `sodium_free`); secrets never enter `std::string`; constant-time comparisons via `sodium_memcmp`. (PRD §6.5.)
- **Fail closed:** wrong password, corrupt file, and tampered file all raise the *same* generic error type (`lgv::AuthError`, message "authentication failed"). No partial decryption, no oracle. (PRD §6.4, §7.)
- **Format stability:** the LGV1 on-disk byte layout defined here is final; M2 extends the *encrypted body schema* only, never the header. Unknown `format_version` → hard refuse. (PRD §6.6.)
- **Credit:** include a subtle "Built by LeeGStudios.com" mark in `README.md` and a one-line header comment banner in `src/core/vault.hpp`.

### Known-answer test (KAT) methodology — read before Task 3

libsodium's `crypto_pwhash` uses `p=1` and supports neither Argon2's *secret* nor *associated-data* inputs, so the RFC 9106 §5.3 reference vector (which uses `p=4` + secret + AD) **does not apply** to our exact call — do not assert against it. Likewise our composite-key construction and full-file layout are our own design, so no external vector exists.

Therefore each crypto KAT asserts three concrete, verifiable properties, plus a frozen golden constant:

1. **Determinism** — identical inputs produce identical output (byte-for-byte).
2. **Distinctness** — changing any input (password, keyfile, salt, nonce, one plaintext byte) changes the output.
3. **Tamper-rejection** (where applicable) — flipping any authenticated byte causes a hard failure.
4. **Golden pin** — a fixed input maps to a committed expected hex constant. The constant is **generated once** by running the just-written function via the `emit_vectors` tool (Task 10), pasted back into the test as a literal, and thereafter frozen. This is a characterization/regression lock, not a placeholder: the procedure and command are exact; only the hex chars are filled from the first green run. Never hand-invent these bytes.

Published third-party cross-checks (Argon2id RFC 9106, XChaCha20-Poly1305 draft-irtf-cfrg-xchacha) are added later in M4 as an independent audit artifact, not as M1 gating tests.

---

## File Structure

Created in M1 (each file one responsibility):

```
LEEGVAULT/
├─ .gitignore
├─ README.md                     # project intro + "Built by LeeGStudios.com"
├─ vcpkg.json                    # manifest: libsodium, catch2
├─ CMakeLists.txt                # top-level build
├─ CMakePresets.json             # MSVC + vcpkg static triplet preset
├─ src/core/
│  ├─ sodium_init.hpp/.cpp       # one-time sodium_init() guard
│  ├─ secure_buffer.hpp          # move-only guarded RAII buffer (header-only)
│  ├─ errors.hpp                 # lgv::AuthError, lgv::FormatError
│  ├─ kdf.hpp/.cpp               # composite key + Argon2id master key + subkeys
│  ├─ commit.hpp/.cpp            # keyed-BLAKE2b commit tag + constant-time verify
│  ├─ header.hpp/.cpp            # LGV1 header struct <-> bytes (90-byte layout)
│  ├─ aead.hpp/.cpp              # XChaCha20-Poly1305-IETF encrypt/decrypt
│  ├─ cbor.hpp/.cpp              # minimal CBOR subset writer/reader (no deps)
│  ├─ model.hpp/.cpp             # Entry / VaultBody + body serialize/parse
│  └─ vault.hpp/.cpp             # seal/open/create — ties the core together
├─ src/storage/
│  └─ vault_file.hpp/.cpp        # atomic save (tmp→flush→rename→.bak) + load
├─ tools/
│  └─ emit_vectors.cpp           # prints the golden KAT vault (Task 10)
├─ tests/
│  ├─ test_smoke.cpp             # Task 1
│  ├─ test_secure_buffer.cpp     # Task 2
│  ├─ test_kdf.cpp               # Task 3
│  ├─ test_commit.cpp            # Task 4
│  ├─ test_header.cpp            # Task 5
│  ├─ test_aead.cpp              # Task 6
│  ├─ test_cbor_model.cpp        # Task 7
│  ├─ test_vault.cpp             # Task 8
│  ├─ test_vault_file.cpp        # Task 9
│  └─ test_vectors.cpp           # Task 10 (golden KAT lock)
└─ tests/vectors/
   └─ lgv1-kat.json              # committed golden vectors (Task 10)
```

**Namespace:** everything is in `namespace lgv`. **Test framework include:** `#include <catch2/catch_test_macros.hpp>`.

**Byte-vector type:** use `std::vector<unsigned char>` for non-secret bytes (header bytes, ciphertext). Use `SecureBuffer` for anything secret (keys, plaintext body, secret fields).

---

## Task 1: Scaffolding, toolchain, and libsodium smoke test

**Files:**
- Create: `.gitignore`, `README.md`, `vcpkg.json`, `CMakeLists.txt`, `CMakePresets.json`
- Create: `src/core/sodium_init.hpp`, `src/core/sodium_init.cpp`
- Test: `tests/test_smoke.cpp`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `void lgv::ensure_sodium();` — call before any libsodium use; throws `std::runtime_error` if init fails. A CMake library target `lgv_core` (static) and a test executable `lgv_tests` linking `unofficial-sodium::sodium` and `Catch2::Catch2WithMain`.

- [ ] **Step 1: Verify the toolchain is present**

Run each; every line must succeed:
```powershell
git --version
cmake --version                 # must be >= 3.25
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
```
Expected: git ≥ 2.x, cmake ≥ 3.25, and a Visual Studio 2022 install path printed. If vswhere prints nothing, the C++ workload is missing — install "Desktop development with C++" before continuing.

- [ ] **Step 2: Initialize the git repository**

```powershell
cd D:\Proyectos\LEEGVAULT
git init
git add PRD.md docs
git commit -m "chore: initial commit (PRD + M1 plan)"
```
Expected: a repo with one commit. (PRD.md and the plan already exist on disk.)

- [ ] **Step 3: Bootstrap vcpkg (it is not installed on this machine)**

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", "User")
$env:VCPKG_ROOT = "C:\vcpkg"
```
Expected: `C:\vcpkg\vcpkg.exe` exists. `$env:VCPKG_ROOT` is set for this session and persisted for future ones. (If `C:\vcpkg` is undesirable, pick any path and use it consistently below.)

- [ ] **Step 4: Write the project files**

`.gitignore`:
```gitignore
/build/
/out/
vcpkg_installed/
CMakeUserPresets.json
*.lgv
*.lgv.bak
*.lgv.tmp
```

`vcpkg.json`:
```json
{
  "name": "leegvault",
  "version": "0.1.0",
  "dependencies": [
    "libsodium",
    { "name": "catch2", "version>=": "3.4.0" }
  ],
  "builtin-baseline": "REPLACE_WITH_BASELINE"
}
```
Then pin the baseline so builds are reproducible:
```powershell
cd D:\Proyectos\LEEGVAULT
git -C C:\vcpkg rev-parse HEAD
```
Paste that 40-char commit hash in place of `REPLACE_WITH_BASELINE`.

`README.md`:
```markdown
# LEEGVAULT

A portable, offline, single-binary password vault in C++ built to survive offline GPU/ASIC cracking, vault-file tampering, and memory scraping. See `PRD.md` for the full product spec and threat model.

## Build (Windows)

    git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
    C:\vcpkg\bootstrap-vcpkg.bat
    setx VCPKG_ROOT C:\vcpkg
    cmake --preset msvc-static
    cmake --build build --config Debug
    ctest --test-dir build -C Debug --output-on-failure

## Status

M1 (crypto core) in progress. See `docs/superpowers/plans/`.

---

*Built by [LeeGStudios.com](https://leegstudios.com)*
```

`CMakePresets.json`:
```json
{
  "version": 3,
  "cmakeMinimumRequired": { "major": 3, "minor": 25, "patch": 0 },
  "configurePresets": [
    {
      "name": "msvc-static",
      "displayName": "MSVC x64 static (vcpkg)",
      "generator": "Visual Studio 17 2022",
      "architecture": "x64",
      "binaryDir": "${sourceDir}/build",
      "cacheVariables": {
        "CMAKE_TOOLCHAIN_FILE": "$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake",
        "VCPKG_TARGET_TRIPLET": "x64-windows-static",
        "CMAKE_MSVC_RUNTIME_LIBRARY": "MultiThreaded$<$<CONFIG:Debug>:Debug>"
      }
    }
  ]
}
```
Notes: the "Visual Studio 17 2022" generator locates MSVC without needing a Developer Command Prompt / vcvars. If the MSYS2 `cmake` on PATH mishandles the VS generator, fall back to the CMake bundled with VS: `& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" --preset msvc-static`.

`CMakeLists.txt`:
```cmake
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
)
target_link_libraries(lgv_tests PRIVATE lgv_core Catch2::Catch2WithMain unofficial-sodium::sodium)
catch_discover_tests(lgv_tests)
```
As each later task adds source/test files, append them to `lgv_core` and `lgv_tests` respectively (each task lists exactly what to add).

- [ ] **Step 5: Write `sodium_init` and the failing smoke test**

`src/core/sodium_init.hpp`:
```cpp
#pragma once
namespace lgv {
// Idempotent, thread-safe. Throws std::runtime_error if libsodium cannot init.
void ensure_sodium();
}
```
`src/core/sodium_init.cpp`:
```cpp
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <mutex>
#include <stdexcept>

namespace lgv {
void ensure_sodium() {
    static std::once_flag flag;
    static bool ok = false;
    std::call_once(flag, [] { ok = (sodium_init() >= 0); });
    if (!ok) throw std::runtime_error("libsodium initialization failed");
}
}
```
`tests/test_smoke.cpp`:
```cpp
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
```

- [ ] **Step 6: Configure, build, and run — verify the smoke test passes**

```powershell
cmake --preset msvc-static
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "libsodium links" --output-on-failure
```
Expected: configure downloads/builds libsodium + Catch2 (first run is slow, several minutes), build succeeds, and the test reports `1 test passed`. If you see unresolved `__imp_sodium_*` link errors, confirm `SODIUM_STATIC=1` and the `x64-windows-static` triplet are both in effect.

- [ ] **Step 7: Commit**

```powershell
git add .gitignore README.md vcpkg.json CMakeLists.txt CMakePresets.json src/core/sodium_init.hpp src/core/sodium_init.cpp tests/test_smoke.cpp
git commit -m "build: scaffold CMake + vcpkg + libsodium, green smoke test"
```

---

## Task 2: SecureBuffer + error types

**Files:**
- Create: `src/core/secure_buffer.hpp`, `src/core/errors.hpp`
- Test: `tests/test_secure_buffer.cpp`
- Modify: `CMakeLists.txt` (add `tests/test_secure_buffer.cpp` to `lgv_tests`)

**Interfaces:**
- Consumes: `lgv::ensure_sodium()` (Task 1).
- Produces:
  - `class lgv::SecureBuffer` — move-only guarded allocation. Members: `SecureBuffer()`, `explicit SecureBuffer(std::size_t n)`, move ctor/assign, deleted copy, `unsigned char* data()`, `const unsigned char* data() const`, `std::size_t size() const`, `bool empty() const`.
  - `struct lgv::AuthError : std::runtime_error` (message always `"authentication failed"`), `struct lgv::FormatError : std::runtime_error`.

- [ ] **Step 1: Write the failing test**

`tests/test_secure_buffer.cpp`:
```cpp
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `secure_buffer.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/core/errors.hpp`:
```cpp
#pragma once
#include <stdexcept>
namespace lgv {
// Single generic failure for wrong password, corruption, and tampering (anti-oracle).
struct AuthError : std::runtime_error {
    AuthError() : std::runtime_error("authentication failed") {}
};
// Structural parse failure of untrusted bytes (bad magic, truncation, unknown version).
struct FormatError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
}
```
`src/core/secure_buffer.hpp`:
```cpp
#pragma once
#include <cstddef>
#include <new>
#include <sodium.h>

namespace lgv {
// Owns a sodium_malloc() region: guard pages + canary + locked + zeroized on free.
// Move-only; secrets never copied. sodium_free zeroizes before releasing.
class SecureBuffer {
public:
    SecureBuffer() noexcept = default;

    explicit SecureBuffer(std::size_t n) : size_(n) {
        if (n == 0) { return; }
        data_ = static_cast<unsigned char*>(sodium_malloc(n));
        if (data_ == nullptr) { size_ = 0; throw std::bad_alloc(); }
    }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& o) noexcept : data_(o.data_), size_(o.size_) {
        o.data_ = nullptr; o.size_ = 0;
    }
    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) { free_(); data_ = o.data_; size_ = o.size_; o.data_ = nullptr; o.size_ = 0; }
        return *this;
    }
    ~SecureBuffer() { free_(); }

    unsigned char* data() noexcept { return data_; }
    const unsigned char* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

private:
    void free_() noexcept { if (data_) { sodium_free(data_); data_ = nullptr; } size_ = 0; }
    unsigned char* data_ = nullptr;
    std::size_t size_ = 0;
};
}
```

- [ ] **Step 4: Add test to build and run — verify it passes**

Append `tests/test_secure_buffer.cpp` to the `lgv_tests` target in `CMakeLists.txt`. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "SecureBuffer" --output-on-failure
```
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/core/secure_buffer.hpp src/core/errors.hpp tests/test_secure_buffer.cpp CMakeLists.txt
git commit -m "feat(core): SecureBuffer guarded RAII + generic error types"
```

---

## Task 3: KDF — composite key, Argon2id master key, subkeys

**Files:**
- Create: `src/core/kdf.hpp`, `src/core/kdf.cpp`
- Test: `tests/test_kdf.cpp`
- Modify: `CMakeLists.txt` (add `src/core/kdf.cpp` to `lgv_core`, `tests/test_kdf.cpp` to `lgv_tests`)

**Interfaces:**
- Consumes: `SecureBuffer` (Task 2), `ensure_sodium()` (Task 1).
- Produces:
  - `struct lgv::KdfParams { std::uint32_t m_kib; std::uint32_t t; std::uint8_t p; };`
  - `inline constexpr KdfParams lgv::kDefaultKdf{262144u, 3u, 1u};` — 256 MiB, t=3, p=1.
  - `SecureBuffer lgv::derive_master_key(std::span<const unsigned char> password, std::optional<std::span<const unsigned char>> keyfile, std::span<const unsigned char> salt, const KdfParams& params);` — returns 32-byte key. `salt` must be 16 bytes; `keyfile` if present must be 32 bytes. Composite = `keyfile ? BLAKE2b(BLAKE2b(password) ‖ keyfile) : BLAKE2b(password)`; master = `Argon2id(composite, salt, t, m_kib·1024, p=1-fixed)`.
  - `struct lgv::Subkeys { SecureBuffer enc_key; SecureBuffer commit_key; };`
  - `Subkeys lgv::derive_subkeys(const SecureBuffer& master_key);` — `crypto_kdf` with context `"LGVKDF01"`, subkey id 1 → enc, id 2 → commit. Both 32 bytes.

- [ ] **Step 1: Write the failing test**

`tests/test_kdf.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include "core/kdf.hpp"
#include "core/sodium_init.hpp"

using bytes = std::span<const unsigned char>;

static lgv::KdfParams fast() { return lgv::KdfParams{ 8192u, 3u, 1u }; } // 8 MiB for fast tests

TEST_CASE("master key: deterministic, distinct, keyfile-sensitive", "[kdf]") {
    lgv::ensure_sodium();
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, salt.size());
    std::string pw = "correct horse battery staple";
    bytes pwb(reinterpret_cast<const unsigned char*>(pw.data()), pw.size());

    auto k1 = lgv::derive_master_key(pwb, std::nullopt, salt, fast());
    auto k2 = lgv::derive_master_key(pwb, std::nullopt, salt, fast());
    REQUIRE(k1.size() == 32);
    REQUIRE(std::memcmp(k1.data(), k2.data(), 32) == 0);            // deterministic

    std::array<unsigned char, 16> salt2{}; std::memset(salt2.data(), 0x22, salt2.size());
    auto k3 = lgv::derive_master_key(pwb, std::nullopt, salt2, fast());
    REQUIRE(std::memcmp(k1.data(), k3.data(), 32) != 0);            // salt changes key

    std::array<unsigned char, 32> kf{}; std::memset(kf.data(), 0x33, kf.size());
    auto k4 = lgv::derive_master_key(pwb, bytes(kf), salt, fast());
    REQUIRE(std::memcmp(k1.data(), k4.data(), 32) != 0);            // keyfile changes key
}

TEST_CASE("subkeys: enc != commit, deterministic", "[kdf]") {
    lgv::ensure_sodium();
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, salt.size());
    std::string pw = "pw"; bytes pwb(reinterpret_cast<const unsigned char*>(pw.data()), pw.size());
    auto mk = lgv::derive_master_key(pwb, std::nullopt, salt, fast());

    auto a = lgv::derive_subkeys(mk);
    auto b = lgv::derive_subkeys(mk);
    REQUIRE(a.enc_key.size() == 32);
    REQUIRE(a.commit_key.size() == 32);
    REQUIRE(std::memcmp(a.enc_key.data(), a.commit_key.data(), 32) != 0);   // independent
    REQUIRE(std::memcmp(a.enc_key.data(), b.enc_key.data(), 32) == 0);      // deterministic
    REQUIRE(std::memcmp(a.commit_key.data(), b.commit_key.data(), 32) == 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `core/kdf.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/core/kdf.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include "core/secure_buffer.hpp"

namespace lgv {
struct KdfParams { std::uint32_t m_kib; std::uint32_t t; std::uint8_t p; };
inline constexpr KdfParams kDefaultKdf{ 262144u, 3u, 1u }; // 256 MiB, t=3, p=1

SecureBuffer derive_master_key(std::span<const unsigned char> password,
                               std::optional<std::span<const unsigned char>> keyfile,
                               std::span<const unsigned char> salt,
                               const KdfParams& params);

struct Subkeys { SecureBuffer enc_key; SecureBuffer commit_key; };
Subkeys derive_subkeys(const SecureBuffer& master_key);
}
```
`src/core/kdf.cpp`:
```cpp
#include "core/kdf.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace lgv {
namespace {
SecureBuffer blake2b256(std::span<const unsigned char> in) {
    SecureBuffer out(crypto_generichash_BYTES); // 32
    if (crypto_generichash(out.data(), out.size(), in.data(), in.size(), nullptr, 0) != 0)
        throw std::runtime_error("blake2b failed");
    return out;
}
} // namespace

SecureBuffer derive_master_key(std::span<const unsigned char> password,
                               std::optional<std::span<const unsigned char>> keyfile,
                               std::span<const unsigned char> salt,
                               const KdfParams& params) {
    ensure_sodium();
    if (salt.size() != crypto_pwhash_SALTBYTES) throw std::invalid_argument("salt must be 16 bytes");

    SecureBuffer hp = blake2b256(password);              // 32
    SecureBuffer composite;
    if (keyfile.has_value()) {
        if (keyfile->size() != 32) throw std::invalid_argument("keyfile must be 32 bytes");
        SecureBuffer cat(64);
        std::memcpy(cat.data(), hp.data(), 32);
        std::memcpy(cat.data() + 32, keyfile->data(), 32);
        composite = blake2b256(std::span<const unsigned char>(cat.data(), cat.size()));
    } else {
        composite = std::move(hp);
    }

    SecureBuffer mk(crypto_kdf_KEYBYTES);                 // 32
    const int rc = crypto_pwhash(
        mk.data(), mk.size(),
        reinterpret_cast<const char*>(composite.data()), composite.size(),
        salt.data(),
        static_cast<unsigned long long>(params.t),
        static_cast<std::size_t>(params.m_kib) * 1024u,
        crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) throw std::runtime_error("argon2id failed (out of memory?)");
    return mk;
}

Subkeys derive_subkeys(const SecureBuffer& master_key) {
    ensure_sodium();
    if (master_key.size() != crypto_kdf_KEYBYTES) throw std::invalid_argument("master key must be 32 bytes");
    Subkeys sk{ SecureBuffer(32), SecureBuffer(32) };
    // context is exactly crypto_kdf_CONTEXTBYTES (8) chars.
    if (crypto_kdf_derive_from_key(sk.enc_key.data(), 32, 1, "LGVKDF01", master_key.data()) != 0)
        throw std::runtime_error("kdf(enc) failed");
    if (crypto_kdf_derive_from_key(sk.commit_key.data(), 32, 2, "LGVKDF01", master_key.data()) != 0)
        throw std::runtime_error("kdf(commit) failed");
    return sk;
}
}
```

- [ ] **Step 4: Build and run — verify it passes**

Add `src/core/kdf.cpp` to `lgv_core` and `tests/test_kdf.cpp` to `lgv_tests`. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[kdf\]" --output-on-failure
```
Expected: both KDF tests PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/core/kdf.hpp src/core/kdf.cpp tests/test_kdf.cpp CMakeLists.txt
git commit -m "feat(core): Argon2id composite key hierarchy + subkey derivation"
```

---

## Task 4: Key commitment tag

**Files:**
- Create: `src/core/commit.hpp`, `src/core/commit.cpp`
- Test: `tests/test_commit.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `SecureBuffer`, `ensure_sodium()`.
- Produces:
  - `SecureBuffer lgv::compute_commit_tag(const SecureBuffer& commit_key, std::span<const unsigned char> header_core);` — 32-byte keyed BLAKE2b MAC (`crypto_generichash` with `commit_key` as key).
  - `bool lgv::verify_commit_tag(const SecureBuffer& commit_key, std::span<const unsigned char> header_core, std::span<const unsigned char> tag);` — recomputes and compares with `sodium_memcmp` (constant time). Returns `false` for wrong-length tag.

- [ ] **Step 1: Write the failing test**

`tests/test_commit.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <vector>
#include "core/commit.hpp"
#include "core/secure_buffer.hpp"
#include "core/sodium_init.hpp"

TEST_CASE("commit tag: deterministic, verifies, rejects tamper", "[commit]") {
    lgv::ensure_sodium();
    lgv::SecureBuffer key(32); std::memset(key.data(), 0x44, 32);
    std::vector<unsigned char> hdr(58); std::memset(hdr.data(), 0x55, hdr.size());

    auto tag = lgv::compute_commit_tag(key, hdr);
    REQUIRE(tag.size() == 32);
    REQUIRE(lgv::verify_commit_tag(key, hdr,
            std::span<const unsigned char>(tag.data(), tag.size())));

    std::vector<unsigned char> hdr2 = hdr; hdr2[0] ^= 0x01; // flip 1 bit of header
    REQUIRE_FALSE(lgv::verify_commit_tag(key, hdr2,
            std::span<const unsigned char>(tag.data(), tag.size())));

    lgv::SecureBuffer key2(32); std::memset(key2.data(), 0x66, 32);
    REQUIRE_FALSE(lgv::verify_commit_tag(key2, hdr,
            std::span<const unsigned char>(tag.data(), tag.size())));    // wrong key
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `core/commit.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/core/commit.hpp`:
```cpp
#pragma once
#include <span>
#include "core/secure_buffer.hpp"
namespace lgv {
SecureBuffer compute_commit_tag(const SecureBuffer& commit_key,
                                std::span<const unsigned char> header_core);
bool verify_commit_tag(const SecureBuffer& commit_key,
                       std::span<const unsigned char> header_core,
                       std::span<const unsigned char> tag);
}
```
`src/core/commit.cpp`:
```cpp
#include "core/commit.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <stdexcept>

namespace lgv {
SecureBuffer compute_commit_tag(const SecureBuffer& commit_key,
                                std::span<const unsigned char> header_core) {
    ensure_sodium();
    if (commit_key.size() != 32) throw std::invalid_argument("commit key must be 32 bytes");
    SecureBuffer tag(crypto_generichash_BYTES); // 32
    if (crypto_generichash(tag.data(), tag.size(),
                           header_core.data(), header_core.size(),
                           commit_key.data(), commit_key.size()) != 0)
        throw std::runtime_error("commit tag hash failed");
    return tag;
}

bool verify_commit_tag(const SecureBuffer& commit_key,
                       std::span<const unsigned char> header_core,
                       std::span<const unsigned char> tag) {
    if (tag.size() != 32) return false;
    SecureBuffer expected = compute_commit_tag(commit_key, header_core);
    return sodium_memcmp(expected.data(), tag.data(), 32) == 0;
}
}
```

- [ ] **Step 4: Build and run — verify it passes**

Add `src/core/commit.cpp` and `tests/test_commit.cpp` to CMake. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[commit\]" --output-on-failure
```
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/core/commit.hpp src/core/commit.cpp tests/test_commit.cpp CMakeLists.txt
git commit -m "feat(core): key-commitment tag (keyed BLAKE2b) + constant-time verify"
```

---

## Task 5: LGV1 header serialize / parse

**Files:**
- Create: `src/core/header.hpp`, `src/core/header.cpp`
- Test: `tests/test_header.cpp`
- Modify: `CMakeLists.txt`

The fixed 90-byte header layout (little-endian, no padding):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic `"LGV1"` = `4C 47 56 31` |
| 4  | 2  | `format_version` u16 = 1 |
| 6  | 1  | `kdf_id` u8 = 1 (Argon2id) |
| 7  | 4  | `m_kib` u32 |
| 11 | 4  | `t` u32 |
| 15 | 1  | `p` u8 (always 1) |
| 16 | 16 | `salt` |
| 32 | 1  | `aead_id` u8 = 1 (XChaCha20-Poly1305-IETF) |
| 33 | 24 | `nonce` |
| 57 | 1  | `keyfile_flag` u8 (0/1) |
| **58** | 32 | `commit_tag` |
| — | **90** | total |

`header_core` = bytes `[0, 58)` (everything except `commit_tag`); the commit tag is computed over `header_core`, and the full 90-byte serialization is the AEAD AAD.

**Interfaces:**
- Consumes: `FormatError` (Task 2).
- Produces:
  - `struct lgv::Lgv1Header { std::uint16_t format_version; std::uint8_t kdf_id; std::uint32_t m_kib; std::uint32_t t; std::uint8_t p; std::array<unsigned char,16> salt; std::uint8_t aead_id; std::array<unsigned char,24> nonce; std::uint8_t keyfile_flag; std::array<unsigned char,32> commit_tag; };`
  - `inline constexpr std::size_t lgv::kHeaderSize = 90;` and `lgv::kHeaderCoreSize = 58;` and `lgv::kFormatVersion = 1;`
  - `std::vector<unsigned char> lgv::serialize_header(const Lgv1Header&);` — 90 bytes.
  - `std::vector<unsigned char> lgv::serialize_header_core(const Lgv1Header&);` — first 58 bytes (no commit tag).
  - `Lgv1Header lgv::parse_header(std::span<const unsigned char> bytes);` — throws `FormatError` on bad magic / unknown version / short input.

- [ ] **Step 1: Write the failing test**

`tests/test_header.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <vector>
#include "core/header.hpp"
#include "core/errors.hpp"

static lgv::Lgv1Header sample() {
    lgv::Lgv1Header h{};
    h.format_version = 1; h.kdf_id = 1; h.m_kib = 262144; h.t = 3; h.p = 1;
    std::memset(h.salt.data(), 0xA1, h.salt.size());
    h.aead_id = 1; std::memset(h.nonce.data(), 0xB2, h.nonce.size());
    h.keyfile_flag = 1; std::memset(h.commit_tag.data(), 0xC3, h.commit_tag.size());
    return h;
}

TEST_CASE("header round-trips and has the exact layout", "[header]") {
    auto h = sample();
    auto bytes = lgv::serialize_header(h);
    REQUIRE(bytes.size() == lgv::kHeaderSize);
    REQUIRE(bytes[0] == 'L'); REQUIRE(bytes[1] == 'G');
    REQUIRE(bytes[2] == 'V'); REQUIRE(bytes[3] == '1');
    REQUIRE(bytes[4] == 1); REQUIRE(bytes[5] == 0);      // version u16 LE
    REQUIRE(bytes[15] == 1);                             // p
    REQUIRE(bytes[57] == 1);                             // keyfile_flag

    auto core = lgv::serialize_header_core(h);
    REQUIRE(core.size() == lgv::kHeaderCoreSize);
    REQUIRE(std::memcmp(core.data(), bytes.data(), lgv::kHeaderCoreSize) == 0);

    auto h2 = lgv::parse_header(bytes);
    REQUIRE(h2.m_kib == 262144);
    REQUIRE(h2.t == 3);
    REQUIRE(h2.keyfile_flag == 1);
    REQUIRE(std::memcmp(h2.nonce.data(), h.nonce.data(), 24) == 0);
    REQUIRE(std::memcmp(h2.commit_tag.data(), h.commit_tag.data(), 32) == 0);
}

TEST_CASE("header rejects bad magic, version, truncation", "[header]") {
    auto bytes = lgv::serialize_header(sample());

    auto bad = bytes; bad[0] = 'X';
    REQUIRE_THROWS_AS(lgv::parse_header(bad), lgv::FormatError);

    auto ver = bytes; ver[4] = 2;                        // format_version = 2
    REQUIRE_THROWS_AS(lgv::parse_header(ver), lgv::FormatError);

    std::vector<unsigned char> shortb(bytes.begin(), bytes.begin() + 40);
    REQUIRE_THROWS_AS(lgv::parse_header(shortb), lgv::FormatError);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `core/header.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/core/header.hpp`:
```cpp
#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace lgv {
inline constexpr std::size_t kHeaderSize = 90;
inline constexpr std::size_t kHeaderCoreSize = 58;
inline constexpr std::uint16_t kFormatVersion = 1;

struct Lgv1Header {
    std::uint16_t format_version;
    std::uint8_t  kdf_id;
    std::uint32_t m_kib;
    std::uint32_t t;
    std::uint8_t  p;
    std::array<unsigned char, 16> salt;
    std::uint8_t  aead_id;
    std::array<unsigned char, 24> nonce;
    std::uint8_t  keyfile_flag;
    std::array<unsigned char, 32> commit_tag;
};

std::vector<unsigned char> serialize_header(const Lgv1Header& h);
std::vector<unsigned char> serialize_header_core(const Lgv1Header& h);
Lgv1Header parse_header(std::span<const unsigned char> bytes);
}
```
`src/core/header.cpp`:
```cpp
#include "core/header.hpp"
#include "core/errors.hpp"
#include <cstring>

namespace lgv {
namespace {
void put_u16(std::vector<unsigned char>& b, std::uint16_t v) {
    b.push_back(static_cast<unsigned char>(v & 0xFF));
    b.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
}
void put_u32(std::vector<unsigned char>& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
}
std::uint16_t get_u16(const unsigned char* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}
std::uint32_t get_u32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::vector<unsigned char> build(const Lgv1Header& h, bool with_tag) {
    std::vector<unsigned char> b;
    b.reserve(with_tag ? kHeaderSize : kHeaderCoreSize);
    b.insert(b.end(), { 'L', 'G', 'V', '1' });
    put_u16(b, h.format_version);
    b.push_back(h.kdf_id);
    put_u32(b, h.m_kib);
    put_u32(b, h.t);
    b.push_back(h.p);
    b.insert(b.end(), h.salt.begin(), h.salt.end());
    b.push_back(h.aead_id);
    b.insert(b.end(), h.nonce.begin(), h.nonce.end());
    b.push_back(h.keyfile_flag);
    if (with_tag) b.insert(b.end(), h.commit_tag.begin(), h.commit_tag.end());
    return b;
}
} // namespace

std::vector<unsigned char> serialize_header(const Lgv1Header& h)      { return build(h, true); }
std::vector<unsigned char> serialize_header_core(const Lgv1Header& h) { return build(h, false); }

Lgv1Header parse_header(std::span<const unsigned char> bytes) {
    if (bytes.size() < kHeaderSize) throw FormatError("header too short");
    const unsigned char* p = bytes.data();
    if (std::memcmp(p, "LGV1", 4) != 0) throw FormatError("bad magic");

    Lgv1Header h{};
    h.format_version = get_u16(p + 4);
    if (h.format_version != kFormatVersion) throw FormatError("unsupported format version");
    h.kdf_id = p[6];
    h.m_kib  = get_u32(p + 7);
    h.t      = get_u32(p + 11);
    h.p      = p[15];
    std::memcpy(h.salt.data(), p + 16, 16);
    h.aead_id = p[32];
    std::memcpy(h.nonce.data(), p + 33, 24);
    h.keyfile_flag = p[57];
    std::memcpy(h.commit_tag.data(), p + 58, 32);
    return h;
}
}
```

- [ ] **Step 4: Build and run — verify it passes**

Add `src/core/header.cpp` and `tests/test_header.cpp` to CMake. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[header\]" --output-on-failure
```
Expected: both header tests PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/core/header.hpp src/core/header.cpp tests/test_header.cpp CMakeLists.txt
git commit -m "feat(core): LGV1 90-byte header serialize/parse with strict validation"
```

---

## Task 6: AEAD — XChaCha20-Poly1305-IETF

**Files:**
- Create: `src/core/aead.hpp`, `src/core/aead.cpp`
- Test: `tests/test_aead.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `SecureBuffer`, `AuthError`, `ensure_sodium()`.
- Produces:
  - `std::vector<unsigned char> lgv::aead_encrypt(const SecureBuffer& key, std::span<const unsigned char> nonce, std::span<const unsigned char> plaintext, std::span<const unsigned char> aad);` — key 32 B, nonce 24 B; returns ciphertext including the 16-byte tag (length = plaintext + 16).
  - `SecureBuffer lgv::aead_decrypt(const SecureBuffer& key, std::span<const unsigned char> nonce, std::span<const unsigned char> ciphertext, std::span<const unsigned char> aad);` — returns plaintext in guarded memory; throws `AuthError` on any tag/AAD/key mismatch.

**Correctness anchor:** the test below proves round-trip + fail-closed behavior, which is *self-consistent* (encrypt and decrypt share this code) — it cannot catch an AEAD misuse that is wrong but symmetric. To prove our AEAD matches the **standard** and not merely itself, Task 10 adds an independent, **published** XChaCha20-Poly1305-IETF known-answer vector (`draft-irtf-cfrg-xchacha-03` Appendix A.3) for `aead_encrypt`.

- [ ] **Step 1: Write the failing test**

`tests/test_aead.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string>
#include <vector>
#include "core/aead.hpp"
#include "core/errors.hpp"
#include "core/secure_buffer.hpp"
#include "core/sodium_init.hpp"

TEST_CASE("aead: round-trip, tamper, wrong aad all fail closed", "[aead]") {
    lgv::ensure_sodium();
    lgv::SecureBuffer key(32); std::memset(key.data(), 0x77, 32);
    std::vector<unsigned char> nonce(24, 0x88);
    std::string msg = "top secret body";
    std::span<const unsigned char> pt(reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    std::vector<unsigned char> aad(90, 0x99);

    auto ct = lgv::aead_encrypt(key, nonce, pt, aad);
    REQUIRE(ct.size() == msg.size() + 16);

    auto out = lgv::aead_decrypt(key, nonce, ct, aad);
    REQUIRE(out.size() == msg.size());
    REQUIRE(std::memcmp(out.data(), msg.data(), msg.size()) == 0);

    auto ct2 = ct; ct2[0] ^= 0x01;
    REQUIRE_THROWS_AS(lgv::aead_decrypt(key, nonce, ct2, aad), lgv::AuthError);

    auto aad2 = aad; aad2[0] ^= 0x01;
    REQUIRE_THROWS_AS(lgv::aead_decrypt(key, nonce, ct, aad2), lgv::AuthError);

    lgv::SecureBuffer key2(32); std::memset(key2.data(), 0x00, 32);
    REQUIRE_THROWS_AS(lgv::aead_decrypt(key2, nonce, ct, aad), lgv::AuthError);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `core/aead.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/core/aead.hpp`:
```cpp
#pragma once
#include <span>
#include <vector>
#include "core/secure_buffer.hpp"
namespace lgv {
std::vector<unsigned char> aead_encrypt(const SecureBuffer& key,
                                        std::span<const unsigned char> nonce,
                                        std::span<const unsigned char> plaintext,
                                        std::span<const unsigned char> aad);
SecureBuffer aead_decrypt(const SecureBuffer& key,
                          std::span<const unsigned char> nonce,
                          std::span<const unsigned char> ciphertext,
                          std::span<const unsigned char> aad);
}
```
`src/core/aead.cpp`:
```cpp
#include "core/aead.hpp"
#include "core/errors.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <stdexcept>

namespace lgv {
std::vector<unsigned char> aead_encrypt(const SecureBuffer& key,
                                        std::span<const unsigned char> nonce,
                                        std::span<const unsigned char> plaintext,
                                        std::span<const unsigned char> aad) {
    ensure_sodium();
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw std::invalid_argument("key must be 32 bytes");
    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw std::invalid_argument("nonce must be 24 bytes");

    std::vector<unsigned char> ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr, nonce.data(), key.data()) != 0)
        throw std::runtime_error("aead encrypt failed");
    ct.resize(static_cast<std::size_t>(ct_len));
    return ct;
}

SecureBuffer aead_decrypt(const SecureBuffer& key,
                          std::span<const unsigned char> nonce,
                          std::span<const unsigned char> ciphertext,
                          std::span<const unsigned char> aad) {
    ensure_sodium();
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw std::invalid_argument("key must be 32 bytes");
    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw std::invalid_argument("nonce must be 24 bytes");
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) throw AuthError();

    SecureBuffer pt(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            aad.data(), aad.size(),
            nonce.data(), key.data()) != 0)
        throw AuthError();   // wrong key, tampered ct, or wrong aad — one generic failure
    // pt_len == pt.size() by construction; SecureBuffer keeps its allocated size.
    return pt;
}
}
```
Note: when `plaintext.size()` is 0, `pt` is a 0-byte `SecureBuffer` — valid. `pt_len` equals `pt.size()`; we do not shrink `SecureBuffer` (fixed size), which is correct because size is exactly plaintext length.

- [ ] **Step 4: Build and run — verify it passes**

Add `src/core/aead.cpp` and `tests/test_aead.cpp` to CMake. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[aead\]" --output-on-failure
```
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/core/aead.hpp src/core/aead.cpp tests/test_aead.cpp CMakeLists.txt
git commit -m "feat(core): XChaCha20-Poly1305-IETF AEAD, fail-closed decrypt"
```

---

## Task 7: Minimal CBOR codec + vault model

**Files:**
- Create: `src/core/cbor.hpp`, `src/core/cbor.cpp`, `src/core/model.hpp`, `src/core/model.cpp`
- Test: `tests/test_cbor_model.cpp`
- Modify: `CMakeLists.txt`

We hand-roll a minimal CBOR subset (definite-length only; major types 0 uint, 2 byte-string, 3 text-string, 4 array, 5 map) so secrets flow through `SecureBuffer` byte-strings and never touch `std::string`. The body plaintext is built into a `SecureBuffer`. In M1 the entry schema is minimal (`id`, `name`, `secret`); M2 extends the schema only (new optional keys), never the framing.

Body CBOR shape:
```
map(2) {
  "v"       : uint (schema version = 1),
  "entries" : array(N) [ map(3) { "id":tstr, "name":tstr, "secret":bstr } ... ]
}
```

**Interfaces:**
- Consumes: `SecureBuffer`, `FormatError`.
- Produces:
  - CBOR writer `class lgv::CborWriter` emitting through a `CborSink` — a `CountingSink` (pass 1, sizes the output) then a `BufferSink` over a preallocated `SecureBuffer` (pass 2, fills guarded memory so secret bytes never touch unguarded heap): `void uint(std::uint64_t)`, `void bytes(std::span<const unsigned char>)`, `void text(std::string_view)`, `void array(std::uint64_t n)`, `void map(std::uint64_t n)`.
  - CBOR reader `class lgv::CborReader` over `std::span<const unsigned char>`: `std::uint64_t read_uint()`, `std::uint64_t read_array()`, `std::uint64_t read_map()`, `std::string read_text()`, `SecureBuffer read_bytes()`; each throws `FormatError` on type/length mismatch or overrun.
  - `struct lgv::Entry { std::string id; std::string name; SecureBuffer secret; };`
  - `struct lgv::VaultBody { std::vector<Entry> entries; };`
  - `inline constexpr std::uint64_t lgv::kBodySchemaVersion = 1;`
  - `SecureBuffer lgv::serialize_body(const VaultBody&);` (plaintext in guarded memory)
  - `VaultBody lgv::parse_body(std::span<const unsigned char> plaintext);` (throws `FormatError`)

- [ ] **Step 1: Write the failing test**

`tests/test_cbor_model.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include "core/model.hpp"
#include "core/errors.hpp"
#include "core/sodium_init.hpp"

static lgv::Entry make_entry(const std::string& id, const std::string& name, const std::string& secret) {
    lgv::Entry e; e.id = id; e.name = name;
    e.secret = lgv::SecureBuffer(secret.size());
    std::memcpy(e.secret.data(), secret.data(), secret.size());
    return e;
}

TEST_CASE("vault body round-trips through CBOR, secrets preserved", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    body.entries.push_back(make_entry("id-1", "GitHub", "hunter2"));
    body.entries.push_back(make_entry("id-2", "Email",  "p@ssw0rd!"));

    auto blob = lgv::serialize_body(body);
    REQUIRE(blob.size() > 0);

    auto back = lgv::parse_body(std::span<const unsigned char>(blob.data(), blob.size()));
    REQUIRE(back.entries.size() == 2);
    REQUIRE(back.entries[0].id == "id-1");
    REQUIRE(back.entries[0].name == "GitHub");
    REQUIRE(back.entries[0].secret.size() == 7);
    REQUIRE(std::memcmp(back.entries[0].secret.data(), "hunter2", 7) == 0);
    REQUIRE(back.entries[1].secret.size() == 9);
    REQUIRE(std::memcmp(back.entries[1].secret.data(), "p@ssw0rd!", 9) == 0);
}

TEST_CASE("empty vault body round-trips", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    auto blob = lgv::serialize_body(body);
    auto back = lgv::parse_body(std::span<const unsigned char>(blob.data(), blob.size()));
    REQUIRE(back.entries.empty());
}

TEST_CASE("truncated body is rejected", "[model]") {
    lgv::ensure_sodium();
    lgv::VaultBody body;
    body.entries.push_back(make_entry("id-1", "GitHub", "hunter2"));
    auto blob = lgv::serialize_body(body);
    std::vector<unsigned char> truncated(blob.data(), blob.data() + blob.size() / 2);
    REQUIRE_THROWS_AS(
        lgv::parse_body(std::span<const unsigned char>(truncated.data(), truncated.size())),
        lgv::FormatError);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `core/model.hpp` not found.

- [ ] **Step 3: Write the CBOR codec**

`src/core/cbor.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "core/secure_buffer.hpp"

namespace lgv {
// Byte sink so the same emit logic runs twice: once to COUNT the exact size,
// then once to FILL a preallocated SecureBuffer. Secret bytes therefore never land
// in an unguarded, growable std::vector (§6.5 write-path hardening).
class CborSink {
public:
    virtual ~CborSink() = default;
    virtual void put(unsigned char b) = 0;
    virtual void put_n(const unsigned char* p, std::size_t n) = 0;
};
class CountingSink : public CborSink {
public:
    void put(unsigned char) override { ++n_; }
    void put_n(const unsigned char*, std::size_t n) override { n_ += n; }
    std::size_t size() const { return n_; }
private:
    std::size_t n_ = 0;
};
class BufferSink : public CborSink {
public:
    BufferSink(unsigned char* dst, std::size_t cap) : dst_(dst), cap_(cap) {}
    void put(unsigned char b) override;
    void put_n(const unsigned char* p, std::size_t n) override;
    std::size_t pos() const { return pos_; }
private:
    unsigned char* dst_; std::size_t cap_; std::size_t pos_ = 0;
};

class CborWriter {
public:
    explicit CborWriter(CborSink& sink) : sink_(sink) {}
    void uint(std::uint64_t v)                  { head(0, v); }
    void bytes(std::span<const unsigned char> b){ head(2, b.size()); sink_.put_n(b.data(), b.size()); }
    void text(std::string_view s)               { head(3, s.size()); sink_.put_n(reinterpret_cast<const unsigned char*>(s.data()), s.size()); }
    void array(std::uint64_t n)                 { head(4, n); }
    void map(std::uint64_t n)                   { head(5, n); }
private:
    void head(unsigned major, std::uint64_t v);
    CborSink& sink_;
};

class CborReader {
public:
    explicit CborReader(std::span<const unsigned char> in) : in_(in) {}
    std::uint64_t read_uint()  { return read_len(0); }
    std::uint64_t read_array() { return read_len(4); }
    std::uint64_t read_map()   { return read_len(5); }
    std::string   read_text();
    SecureBuffer  read_bytes();
    bool done() const { return pos_ == in_.size(); }
private:
    std::uint64_t read_len(unsigned expected_major);
    std::pair<unsigned, std::uint64_t> read_head();
    std::uint64_t need(std::size_t n);   // read n big-endian bytes, advancing pos_
    std::span<const unsigned char> in_;
    std::size_t pos_ = 0;
};
}
```
`src/core/cbor.cpp`:
```cpp
#include "core/cbor.hpp"
#include "core/errors.hpp"
#include <cstring>

namespace lgv {
void BufferSink::put(unsigned char b) {
    if (pos_ >= cap_) throw FormatError("cbor: sink overflow");
    dst_[pos_++] = b;
}
void BufferSink::put_n(const unsigned char* p, std::size_t n) {
    if (pos_ + n > cap_) throw FormatError("cbor: sink overflow");
    if (n) std::memcpy(dst_ + pos_, p, n);
    pos_ += n;
}

void CborWriter::head(unsigned major, std::uint64_t v) {
    const unsigned char m = static_cast<unsigned char>(major << 5);
    if (v < 24) {
        sink_.put(static_cast<unsigned char>(m | v));
    } else if (v <= 0xFF) {
        sink_.put(static_cast<unsigned char>(m | 24));
        sink_.put(static_cast<unsigned char>(v));
    } else if (v <= 0xFFFF) {
        sink_.put(static_cast<unsigned char>(m | 25));
        sink_.put(static_cast<unsigned char>((v >> 8) & 0xFF));
        sink_.put(static_cast<unsigned char>(v & 0xFF));
    } else if (v <= 0xFFFFFFFFull) {
        sink_.put(static_cast<unsigned char>(m | 26));
        for (int i = 3; i >= 0; --i) sink_.put(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
    } else {
        sink_.put(static_cast<unsigned char>(m | 27));
        for (int i = 7; i >= 0; --i) sink_.put(static_cast<unsigned char>((v >> (8 * i)) & 0xFF));
    }
}

std::uint64_t CborReader::need(std::size_t n) {
    if (pos_ + n > in_.size()) throw FormatError("cbor: length overrun");
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v = (v << 8) | in_[pos_++];
    return v;
}

std::pair<unsigned, std::uint64_t> CborReader::read_head() {
    if (pos_ >= in_.size()) throw FormatError("cbor: unexpected end");
    const unsigned char ib = in_[pos_++];
    const unsigned major = ib >> 5;
    const unsigned info = ib & 0x1F;
    std::uint64_t v = 0;
    if (info < 24)        { v = info; }
    else if (info == 24)  { v = need(1); }
    else if (info == 25)  { v = need(2); }
    else if (info == 26)  { v = need(4); }
    else if (info == 27)  { v = need(8); }
    else                  { throw FormatError("cbor: bad additional info"); }
    return { major, v };
}

std::uint64_t CborReader::read_len(unsigned expected_major) {
    auto [major, v] = read_head();
    if (major != expected_major) throw FormatError("cbor: unexpected major type");
    return v;
}

std::string CborReader::read_text() {
    auto [major, len] = read_head();
    if (major != 3) throw FormatError("cbor: expected text string");
    if (pos_ + len > in_.size()) throw FormatError("cbor: text overrun");
    std::string s(reinterpret_cast<const char*>(in_.data() + pos_), static_cast<std::size_t>(len));
    pos_ += static_cast<std::size_t>(len);
    return s;
}

SecureBuffer CborReader::read_bytes() {
    auto [major, len] = read_head();
    if (major != 2) throw FormatError("cbor: expected byte string");
    if (pos_ + len > in_.size()) throw FormatError("cbor: bytes overrun");
    SecureBuffer b(static_cast<std::size_t>(len));
    if (len > 0) std::memcpy(b.data(), in_.data() + pos_, static_cast<std::size_t>(len));
    pos_ += static_cast<std::size_t>(len);
    return b;
}
}
```

- [ ] **Step 4: Write the model**

`src/core/model.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include "core/secure_buffer.hpp"

namespace lgv {
struct Entry {
    std::string  id;      // non-secret
    std::string  name;    // non-secret
    SecureBuffer secret;  // secret — guarded memory only
};
struct VaultBody {
    std::vector<Entry> entries;
};
inline constexpr std::uint64_t kBodySchemaVersion = 1;

SecureBuffer serialize_body(const VaultBody& body);
VaultBody    parse_body(std::span<const unsigned char> plaintext);
}
```
`src/core/model.cpp`:
```cpp
#include "core/model.hpp"
#include "core/cbor.hpp"
#include "core/errors.hpp"
#include <sodium.h>
#include <cstring>

namespace lgv {
namespace {
void emit_body(CborWriter& w, const VaultBody& body) {
    w.map(2);
    w.text("v");        w.uint(kBodySchemaVersion);
    w.text("entries");  w.array(body.entries.size());
    for (const auto& e : body.entries) {
        w.map(3);
        w.text("id");     w.text(e.id);
        w.text("name");   w.text(e.name);
        w.text("secret"); w.bytes(std::span<const unsigned char>(e.secret.data(), e.secret.size()));
    }
}
} // namespace

SecureBuffer serialize_body(const VaultBody& body) {
    // Pass 1: count the exact serialized size (touches only lengths, never secret bytes).
    CountingSink counter;
    { CborWriter w(counter); emit_body(w, body); }
    // Pass 2: emit directly into guarded memory — secret bytes never touch unguarded heap.
    SecureBuffer out(counter.size());
    BufferSink sink(out.data(), out.size());
    CborWriter w(sink);
    emit_body(w, body);
    return out;
}

VaultBody parse_body(std::span<const unsigned char> plaintext) {
    CborReader r(plaintext);
    const std::uint64_t top = r.read_map();
    if (top != 2) throw FormatError("body: expected 2-key map");

    if (r.read_text() != "v") throw FormatError("body: expected 'v'");
    if (r.read_uint() != kBodySchemaVersion) throw FormatError("body: unsupported schema version");

    if (r.read_text() != "entries") throw FormatError("body: expected 'entries'");
    const std::uint64_t n = r.read_array();

    VaultBody body;
    body.entries.reserve(static_cast<std::size_t>(n));
    for (std::uint64_t i = 0; i < n; ++i) {
        if (r.read_map() != 3) throw FormatError("body: entry must have 3 keys");
        Entry e;
        if (r.read_text() != "id")     throw FormatError("body: expected 'id'");
        e.id = r.read_text();
        if (r.read_text() != "name")   throw FormatError("body: expected 'name'");
        e.name = r.read_text();
        if (r.read_text() != "secret") throw FormatError("body: expected 'secret'");
        e.secret = r.read_bytes();
        body.entries.push_back(std::move(e));
    }
    return body;
}
}
```

- [ ] **Step 5: Build, run, verify pass, commit**

Add `src/core/cbor.cpp`, `src/core/model.cpp` to `lgv_core` and `tests/test_cbor_model.cpp` to `lgv_tests`. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[model\]" --output-on-failure
git add src/core/cbor.hpp src/core/cbor.cpp src/core/model.hpp src/core/model.cpp tests/test_cbor_model.cpp CMakeLists.txt
git commit -m "feat(core): minimal CBOR codec + vault body model, secrets in guarded memory"
```
Expected: all `[model]` tests PASS before the commit.

---

## Task 8: Vault seal / open (core assembly)

**Files:**
- Create: `src/core/vault.hpp`, `src/core/vault.cpp`
- Test: `tests/test_vault.cpp`
- Modify: `CMakeLists.txt`

Ties the core together. `seal_vault` is deterministic (salt + nonce injected) → known-answer testable. `create_vault` is the public path that generates salt + nonce with `randombytes_buf`. `open_vault` parses, derives, verifies the commit tag *before* AEAD, then decrypts and parses the body.

**Interfaces:**
- Consumes: `derive_master_key`, `derive_subkeys`, `compute_commit_tag`, `verify_commit_tag`, `serialize_header`, `serialize_header_core`, `parse_header`, `aead_encrypt`, `aead_decrypt`, `serialize_body`, `parse_body`, `AuthError`, `FormatError`, `kHeaderSize`, `kFormatVersion`.
- Produces:
  - `struct lgv::VaultKeyMaterial { std::span<const unsigned char> password; std::optional<std::span<const unsigned char>> keyfile; };`
  - `std::vector<unsigned char> lgv::seal_vault(const VaultKeyMaterial& km, const KdfParams& params, std::span<const unsigned char> salt16, std::span<const unsigned char> nonce24, const VaultBody& body);`
  - `std::vector<unsigned char> lgv::create_vault(const VaultKeyMaterial& km, const KdfParams& params, const VaultBody& body);` — random salt+nonce, then `seal_vault`.
  - `VaultBody lgv::open_vault(const VaultKeyMaterial& km, std::span<const unsigned char> vault_bytes);` — throws `AuthError` (wrong password/keyfile, tamper) or `FormatError` (structural).

- [ ] **Step 1: Write the failing test**

`tests/test_vault.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include "core/vault.hpp"
#include "core/errors.hpp"
#include "core/sodium_init.hpp"

static lgv::KdfParams fast() { return lgv::KdfParams{ 8192u, 3u, 1u }; }

static lgv::VaultBody one_entry() {
    lgv::VaultBody b; lgv::Entry e; e.id = "1"; e.name = "GitHub";
    const char* s = "hunter2"; e.secret = lgv::SecureBuffer(7); std::memcpy(e.secret.data(), s, 7);
    b.entries.push_back(std::move(e)); return b;
}

static std::span<const unsigned char> as_bytes(const std::string& s) {
    return { reinterpret_cast<const unsigned char*>(s.data()), s.size() };
}

TEST_CASE("vault seal/open round-trip", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);

    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto bytes = lgv::seal_vault(km, fast(), salt, nonce, one_entry());
    REQUIRE(bytes.size() > lgv::kHeaderSize);

    auto body = lgv::open_vault(km, bytes);
    REQUIRE(body.entries.size() == 1);
    REQUIRE(body.entries[0].name == "GitHub");
    REQUIRE(std::memcmp(body.entries[0].secret.data(), "hunter2", 7) == 0);
}

TEST_CASE("wrong password, tampered header, tampered ciphertext all fail closed", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass", wrong = "master-Pass";
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);
    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto bytes = lgv::seal_vault(km, fast(), salt, nonce, one_entry());

    lgv::VaultKeyMaterial bad{ as_bytes(wrong), std::nullopt };
    REQUIRE_THROWS_AS(lgv::open_vault(bad, bytes), lgv::AuthError);

    auto th = bytes; th[16] ^= 0x01;   // flip a salt byte in the header
    REQUIRE_THROWS_AS(lgv::open_vault(km, th), lgv::AuthError);

    auto tc = bytes; tc.back() ^= 0x01; // flip last ciphertext/tag byte
    REQUIRE_THROWS_AS(lgv::open_vault(km, tc), lgv::AuthError);
}

TEST_CASE("keyfile is required to open a keyfile-protected vault", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    std::array<unsigned char, 32> kf{}; std::memset(kf.data(), 0x55, 32);
    std::array<unsigned char, 16> salt{}; std::memset(salt.data(), 0x11, 16);
    std::array<unsigned char, 24> nonce{}; std::memset(nonce.data(), 0x22, 24);

    lgv::VaultKeyMaterial with_kf{ as_bytes(pw),
        std::span<const unsigned char>(kf.data(), kf.size()) };
    auto bytes = lgv::seal_vault(with_kf, fast(), salt, nonce, one_entry());

    lgv::VaultKeyMaterial no_kf{ as_bytes(pw), std::nullopt };
    REQUIRE_THROWS_AS(lgv::open_vault(no_kf, bytes), lgv::AuthError);
    REQUIRE_NOTHROW(lgv::open_vault(with_kf, bytes));
}

TEST_CASE("create_vault uses fresh randomness each call", "[vault]") {
    lgv::ensure_sodium();
    std::string pw = "master-pass";
    lgv::VaultKeyMaterial km{ as_bytes(pw), std::nullopt };
    auto a = lgv::create_vault(km, fast(), one_entry());
    auto b = lgv::create_vault(km, fast(), one_entry());
    REQUIRE(a != b);                                   // different salt+nonce
    REQUIRE_NOTHROW(lgv::open_vault(km, a));
    REQUIRE_NOTHROW(lgv::open_vault(km, b));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `core/vault.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/core/vault.hpp`:
```cpp
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
```
`src/core/vault.cpp`:
```cpp
#include "core/vault.hpp"
#include "core/aead.hpp"
#include "core/commit.hpp"
#include "core/errors.hpp"
#include "core/header.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace lgv {
namespace {
Lgv1Header make_header(const KdfParams& params, std::span<const unsigned char> salt,
                       std::span<const unsigned char> nonce, bool has_keyfile) {
    if (salt.size() != 16) throw std::invalid_argument("salt must be 16 bytes");
    if (nonce.size() != 24) throw std::invalid_argument("nonce must be 24 bytes");
    Lgv1Header h{};
    h.format_version = kFormatVersion;
    h.kdf_id = 1;                 // Argon2id
    h.m_kib = params.m_kib; h.t = params.t; h.p = params.p;
    std::memcpy(h.salt.data(), salt.data(), 16);
    h.aead_id = 1;                // XChaCha20-Poly1305-IETF
    std::memcpy(h.nonce.data(), nonce.data(), 24);
    h.keyfile_flag = has_keyfile ? 1 : 0;
    return h;
}
} // namespace

std::vector<unsigned char> seal_vault(const VaultKeyMaterial& km, const KdfParams& params,
                                      std::span<const unsigned char> salt16,
                                      std::span<const unsigned char> nonce24,
                                      const VaultBody& body) {
    ensure_sodium();
    Lgv1Header h = make_header(params, salt16, nonce24, km.keyfile.has_value());

    SecureBuffer mk = derive_master_key(km.password, km.keyfile, salt16, params);
    Subkeys sk = derive_subkeys(mk);

    auto core = serialize_header_core(h);
    SecureBuffer tag = compute_commit_tag(sk.commit_key, core);
    std::memcpy(h.commit_tag.data(), tag.data(), 32);

    auto aad = serialize_header(h);                       // full 90-byte header
    SecureBuffer pt = serialize_body(body);
    auto ct = aead_encrypt(sk.enc_key,
                           std::span<const unsigned char>(h.nonce.data(), 24),
                           std::span<const unsigned char>(pt.data(), pt.size()),
                           aad);

    std::vector<unsigned char> out;
    out.reserve(aad.size() + ct.size());
    out.insert(out.end(), aad.begin(), aad.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::vector<unsigned char> create_vault(const VaultKeyMaterial& km, const KdfParams& params,
                                        const VaultBody& body) {
    ensure_sodium();
    unsigned char salt[16], nonce[24];
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);
    return seal_vault(km, params, salt, nonce, body);
}

VaultBody open_vault(const VaultKeyMaterial& km, std::span<const unsigned char> vault_bytes) {
    ensure_sodium();
    Lgv1Header h = parse_header(vault_bytes);             // may throw FormatError
    if (h.kdf_id != 1 || h.aead_id != 1) throw FormatError("unsupported kdf/aead id");
    if ((h.keyfile_flag == 1) != km.keyfile.has_value()) throw AuthError(); // keyfile presence must match

    KdfParams params{ h.m_kib, h.t, h.p };
    SecureBuffer mk = derive_master_key(km.password, km.keyfile,
                                        std::span<const unsigned char>(h.salt.data(), 16), params);
    Subkeys sk = derive_subkeys(mk);

    auto core = serialize_header_core(h);
    if (!verify_commit_tag(sk.commit_key, core,
                           std::span<const unsigned char>(h.commit_tag.data(), 32)))
        throw AuthError();                                // commitment fails -> stop before AEAD

    auto aad = serialize_header(h);
    std::span<const unsigned char> ct = vault_bytes.subspan(kHeaderSize);
    SecureBuffer pt = aead_decrypt(sk.enc_key,
                                   std::span<const unsigned char>(h.nonce.data(), 24),
                                   ct, aad);
    return parse_body(std::span<const unsigned char>(pt.data(), pt.size()));
}
}
```

- [ ] **Step 4: Build, run, verify pass, commit**

Add `src/core/vault.cpp` to `lgv_core` and `tests/test_vault.cpp` to `lgv_tests`. Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[vault\]" --output-on-failure
git add src/core/vault.hpp src/core/vault.cpp tests/test_vault.cpp CMakeLists.txt
git commit -m "feat(core): vault seal/open/create — full LGV1 assembly, commit-before-AEAD"
```
Expected: all `[vault]` tests PASS before the commit.

---

## Task 9: Storage — atomic file save / load

**Files:**
- Create: `src/storage/vault_file.hpp`, `src/storage/vault_file.cpp`
- Test: `tests/test_vault_file.cpp`
- Modify: `CMakeLists.txt` (new `lgv_storage` library, link into `lgv_tests`)

Atomic save: write `path.tmp` → flush + fsync → if `path` exists, move it to `path.bak` → rename `path.tmp` over `path`. Load: read whole file into a `std::vector<unsigned char>`. This is the only file I/O in M1.

**Interfaces:**
- Consumes: `FormatError`.
- Produces (namespace `lgv`):
  - `void lgv::save_vault_atomic(const std::filesystem::path& path, std::span<const unsigned char> bytes);`
  - `std::vector<unsigned char> lgv::load_vault(const std::filesystem::path& path);` — throws `FormatError` if missing/unreadable.

- [ ] **Step 1: Write the failing test**

`tests/test_vault_file.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug` — Expected: compile error, `storage/vault_file.hpp` not found.

- [ ] **Step 3: Write the implementation**

`src/storage/vault_file.hpp`:
```cpp
#pragma once
#include <filesystem>
#include <span>
#include <vector>
namespace lgv {
void save_vault_atomic(const std::filesystem::path& path, std::span<const unsigned char> bytes);
std::vector<unsigned char> load_vault(const std::filesystem::path& path);
}
```
`src/storage/vault_file.cpp`:
```cpp
#include "storage/vault_file.hpp"
#include "core/errors.hpp"
#include <cstdio>
#include <system_error>

#if defined(_WIN32)
#  include <io.h>
#  include <windows.h>
#endif

namespace fs = std::filesystem;

namespace lgv {
namespace {
void flush_to_disk(std::FILE* f) {
    std::fflush(f);
#if defined(_WIN32)
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(f)));
    if (h != INVALID_HANDLE_VALUE) FlushFileBuffers(h);
#endif
}
} // namespace

void save_vault_atomic(const fs::path& path, std::span<const unsigned char> bytes) {
    fs::path tmp = path; tmp += ".tmp";
    {
        std::FILE* f = nullptr;
#if defined(_WIN32)
        if (::_wfopen_s(&f, tmp.c_str(), L"wb") != 0 || f == nullptr)
            throw FormatError("cannot open temp file for writing");
#else
        f = std::fopen(tmp.c_str(), "wb");
        if (!f) throw FormatError("cannot open temp file for writing");
#endif
        if (!bytes.empty() &&
            std::fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size()) {
            std::fclose(f); throw FormatError("short write to temp file");
        }
        flush_to_disk(f);
        std::fclose(f);
    }
    std::error_code ec;
    if (fs::exists(path)) {
        fs::path bak = path; bak += ".bak";
        fs::remove(bak, ec);                 // ignore if absent
        fs::rename(path, bak, ec);           // keep previous as .bak
        if (ec) throw FormatError("cannot rotate previous vault to .bak");
    }
    fs::rename(tmp, path, ec);
    if (ec) throw FormatError("cannot commit temp file over vault");
}

std::vector<unsigned char> load_vault(const fs::path& path) {
    std::FILE* f = nullptr;
#if defined(_WIN32)
    if (::_wfopen_s(&f, path.c_str(), L"rb") != 0 || f == nullptr)
        throw FormatError("cannot open vault file");
#else
    f = std::fopen(path.c_str(), "rb");
    if (!f) throw FormatError("cannot open vault file");
#endif
    std::vector<unsigned char> out;
    unsigned char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return out;
}
}
```

- [ ] **Step 4: Wire CMake, build, run, verify, commit**

In `CMakeLists.txt` add a storage library and link it into tests:
```cmake
add_library(lgv_storage STATIC src/storage/vault_file.cpp)
target_include_directories(lgv_storage PUBLIC src)
target_link_libraries(lgv_storage PUBLIC lgv_core)
```
Add `tests/test_vault_file.cpp` to `lgv_tests` and link `lgv_storage`:
```cmake
target_link_libraries(lgv_tests PRIVATE lgv_core lgv_storage Catch2::Catch2WithMain unofficial-sodium::sodium)
```
Then:
```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug -R "\[storage\]" --output-on-failure
git add src/storage/vault_file.hpp src/storage/vault_file.cpp tests/test_vault_file.cpp CMakeLists.txt
git commit -m "feat(storage): atomic vault save (tmp->flush->rename, .bak) + load"
```
Expected: all `[storage]` tests PASS before the commit.

---

## Task 10: Published known-answer vectors (M1 exit gate)

**Files:**
- Create: `tools/emit_vectors.cpp`, `tests/vectors/lgv1-kat.json`, `tests/test_vectors.cpp`
- Modify: `CMakeLists.txt` (add `emit_vectors` executable + `tests/test_vectors.cpp`)

This is the M1 exit criterion: a **fixed** password / salt / nonce / body deterministically produces a **frozen** vault byte string. First run captures the value; thereafter the test locks it (any crypto regression flips it).

**Interfaces:**
- Consumes: `seal_vault`, `open_vault` (deterministic paths).
- Produces: a committed golden vector file + a regression test that re-derives and byte-compares.

- [ ] **Step 1: Write the generator**

`tools/emit_vectors.cpp`:
```cpp
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
```
CMake:
```cmake
add_executable(emit_vectors tools/emit_vectors.cpp)
target_link_libraries(emit_vectors PRIVATE lgv_core unofficial-sodium::sodium)
```

- [ ] **Step 2: Generate the golden value once**

```powershell
cmake --build build --config Debug --target emit_vectors
& .\build\Debug\emit_vectors.exe
```
Copy the printed `vault_hex=...` value. Write `tests/vectors/lgv1-kat.json`:
```json
{
  "description": "LEEGVAULT LGV1 M1 known-answer vector. Deterministic seal_vault output.",
  "params":   { "m_kib": 8192, "t": 3, "p": 1 },
  "password": "leegvault-kat-password",
  "salt_hex":  "000102030405060708090a0b0c0d0e0f",
  "nonce_hex": "404142434445464748494a4b4c4d4e4f5051525354555657",
  "entry":    { "id": "kat-1", "name": "Example", "secret_utf8": "s3cr3t" },
  "vault_hex": "PASTE_FROM_emit_vectors_HERE"
}
```

- [ ] **Step 2b: Obtain the published AEAD ciphertext (external correctness anchor)**

The `[aead-kat]` test needs an expected ciphertext that does NOT come from our own code. Obtain the canonical XChaCha20-Poly1305-IETF AEAD example ciphertext for these fixed inputs:
- key = `80 81 82 … 9f` (32 bytes), nonce = `40 41 42 … 57` (24 bytes)
- AAD = `50515253c0c1c2c3c4c5c6c7` (12 bytes)
- plaintext = the 114-byte "Ladies and Gentlemen … sunscreen would be it." quote

Source (authoritative): `draft-irtf-cfrg-xchacha-03` Appendix A.3 — https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3 (WebFetch it, or open in a browser). The draft lists the 114-byte ciphertext and the 16-byte Poly1305 tag; **concatenate ciphertext ‖ tag** into one 260-char lowercase hex string (130 bytes) and paste it into `kPublishedCtHex` in `tests/test_vectors.cpp` (Step 3). Cross-check option: libsodium's own `test/default/aead_xchacha20poly1305.c` computes this exact vector at runtime.

Do not derive this value from our `aead_encrypt` — its independence is the whole point: it can disprove a self-consistent AEAD bug that every round-trip test would miss.

- [ ] **Step 3: Write the locking test**

`tests/test_vectors.cpp`:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "core/vault.hpp"
#include "core/aead.hpp"
#include "core/sodium_init.hpp"

// Paste the exact value from tests/vectors/lgv1-kat.json here, then freeze it.
static const std::string kGoldenVaultHex = "PASTE_FROM_emit_vectors_HERE";

static std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> out; out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

TEST_CASE("LGV1 known-answer vector is stable and opens", "[kat]") {
    lgv::ensure_sodium();
    const std::string pw = "leegvault-kat-password";
    std::array<unsigned char, 16> salt{}; for (int i = 0; i < 16; ++i) salt[i] = static_cast<unsigned char>(i);
    std::array<unsigned char, 24> nonce{}; for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(0x40 + i);

    lgv::VaultBody body;
    lgv::Entry e; e.id = "kat-1"; e.name = "Example";
    e.secret = lgv::SecureBuffer(6); std::memcpy(e.secret.data(), "s3cr3t", 6);
    body.entries.push_back(std::move(e));

    lgv::VaultKeyMaterial km{
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pw.data()), pw.size()),
        std::nullopt };
    auto bytes = lgv::seal_vault(km, lgv::KdfParams{ 8192u, 3u, 1u }, salt, nonce, body);

    REQUIRE(bytes == unhex(kGoldenVaultHex));      // regression lock

    auto reopened = lgv::open_vault(km, bytes);    // and it actually opens
    REQUIRE(reopened.entries.size() == 1);
    REQUIRE(reopened.entries[0].name == "Example");
    REQUIRE(std::memcmp(reopened.entries[0].secret.data(), "s3cr3t", 6) == 0);
}

// Independent, PUBLISHED vector — anchors correctness against the standard, not just our
// own output. Canonical XChaCha20-Poly1305-IETF example from draft-irtf-cfrg-xchacha-03
// Appendix A.3. Expected ciphertext is copied from that source in Step 2b (NOT self-pinned).
TEST_CASE("aead matches the published XChaCha20-Poly1305-IETF vector", "[aead-kat]") {
    lgv::ensure_sodium();
    lgv::SecureBuffer key(32);
    for (int i = 0; i < 32; ++i) key.data()[i] = static_cast<unsigned char>(0x80 + i);  // 80..9f
    std::vector<unsigned char> nonce(24);
    for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(0x40 + i);        // 40..57
    std::vector<unsigned char> aad =
        { 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };
    std::string msg =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    REQUIRE(msg.size() == 114);
    std::span<const unsigned char> pt(
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

    // 130 bytes = 114 ciphertext + 16 tag. Fill from the cited source in Step 2b.
    const std::string kPublishedCtHex = "PASTE_PUBLISHED_CIPHERTEXT_HEX";
    auto expected = unhex(kPublishedCtHex);
    REQUIRE(expected.size() == 130);

    auto ct = lgv::aead_encrypt(key, nonce, pt, aad);
    REQUIRE(ct == expected);                       // our AEAD output == the published standard
}
```

- [ ] **Step 4: Build, run the full suite, verify pass, commit**

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```
Expected: the **entire** M1 suite (`[smoke] [secbuf] [kdf] [commit] [header] [aead] [aead-kat] [model] [vault] [storage] [kat]`) passes.
```powershell
git add tools/emit_vectors.cpp tests/vectors/lgv1-kat.json tests/test_vectors.cpp CMakeLists.txt
git commit -m "test(core): freeze LGV1 M1 known-answer vector; M1 crypto core complete"
```

---

## Self-Review

**1. Spec coverage (PRD → task):**

| PRD requirement | Covered by |
|---|---|
| §6.1 Argon2id, 256 MiB/t3/p1, params in header | Task 3 (KDF), Task 5 (header carries m/t/p) |
| §6.2 composite key (BLAKE2b) + optional keyfile + subkeys | Task 3 |
| §6.3 XChaCha20-Poly1305-IETF, 24-byte random nonce, header as AAD | Task 6, Task 8 (`create_vault` random nonce, full header AAD) |
| §6.4 key-commitment tag, verified constant-time before AEAD | Task 4, Task 8 (`open_vault` verifies before decrypt) |
| §6.5 guarded memory, move-only, zeroize, no `std::string` for secrets, constant-time compare | Task 2 (SecureBuffer), Task 7 (secret as bstr/SecureBuffer), Task 4 (`sodium_memcmp`) |
| §6.6 LGV1 layout, zero plaintext metadata, unknown version refused, atomic save + .bak | Task 5 (layout + version reject), Task 7/8 (metadata inside ciphertext), Task 9 (atomic save) |
| §6.7 libsodium single crypto dependency | Global constraints; Task 1 manifest |
| §9.1/§9.2 unit tests, known-answer vectors | Every task's tests; Task 10 published vector |
| §7 same generic error for wrong-password/corrupt/tampered | Task 2 `AuthError`, Task 6/8 fail-closed |

Deferred to later milestones (correctly out of M1 scope): auto-tune benchmark (§6.1 — M2 `init`), CLI commands/clipboard/generator (§7 — M2), fuzzing/sanitizers/memory-scan (§9.3–9.5 — M3), format-spec doc + cross-OS binaries + cracking challenge (§9.6, §10 — M4). Rich entry fields (user/url/notes/tags/history/timestamps, §6.6 body) — M2 extends the Task 7 schema; M1 ships the minimal `id/name/secret` triple to prove the pipeline.

**2. Placeholder scan:** Two intentional fill-from-source values, both in Task 10, each with an exact procedure — not forbidden placeholders:
- `PASTE_FROM_emit_vectors_HERE` (LGV1 golden vault) — generated by the `emit_vectors` tool built in the same task; a *regression* lock (characterization), correct because a hand-written hash would be wrong.
- `PASTE_PUBLISHED_CIPHERTEXT_HEX` (the `[aead-kat]` vector) — copied from an external published source (`draft-irtf-cfrg-xchacha-03` §A.3) in Step 2b; a *correctness* anchor, deliberately independent of our code.

Every other code step contains complete, compilable code. No "TODO"/"add error handling"/"similar to Task N".

**Coverage caveats (not gaps):** (a) all tests run the KDF at the 8 MiB `fast()` setting for speed — the production 256 MiB `kDefaultKdf` path is first exercised by the M2 `init` auto-tune, not M1. (b) After the Task 7 sink refactor the secret write-path is guarded end to end: `serialize_body` counts then emits into a `SecureBuffer`, so plaintext secrets never occupy an unguarded, growable `std::vector` — the §6.5 claim in the coverage table holds for both read and write paths.

**3. Type consistency:** `SecureBuffer`, `KdfParams{m_kib,t,p}`, `Subkeys{enc_key,commit_key}`, `Lgv1Header` fields, `Entry{id,name,secret}`, `VaultBody{entries}`, `VaultKeyMaterial{password,keyfile}` are used identically across Tasks 2–10. Function names (`derive_master_key`, `derive_subkeys`, `compute_commit_tag`, `verify_commit_tag`, `serialize_header`/`serialize_header_core`/`parse_header`, `aead_encrypt`/`aead_decrypt`, `serialize_body`/`parse_body`, `seal_vault`/`create_vault`/`open_vault`, `save_vault_atomic`/`load_vault`) match between each producing task's `Interfaces` block and every consuming call site. `kHeaderSize=90`, `kHeaderCoreSize=58` used consistently in Tasks 5 and 8. The CBOR `need` helper is declared in `cbor.hpp` and defined once in `cbor.cpp` (one name, no `need_` variant).

---

*LEEGVAULT — Built by [LeeGStudios.com](https://leegstudios.com). Plan generated with the superpowers:writing-plans skill.*
