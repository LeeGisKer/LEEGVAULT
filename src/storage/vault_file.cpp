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
