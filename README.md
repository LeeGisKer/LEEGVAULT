# LEEGVAULT

A portable, offline, single-binary password vault in C++ built to survive offline GPU/ASIC cracking, vault-file tampering, and memory scraping. See `PRD.md` for the full product spec and threat model.

## Build (Windows)

    git clone https://github.com/microsoft/vcpkg.git D:\vcpkg
    D:\vcpkg\bootstrap-vcpkg.bat
    setx VCPKG_ROOT D:\vcpkg
    cmake --preset msvc-static
    cmake --build build --config Debug
    ctest --test-dir build -C Debug --output-on-failure

## Status

M1 (crypto core) in progress. See `docs/superpowers/plans/`.

---

*Built by [LeeGStudios.com](https://leegstudios.com)*
