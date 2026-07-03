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
