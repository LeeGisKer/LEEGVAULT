#pragma once
namespace lgv {
// Idempotent, thread-safe. Throws std::runtime_error if libsodium cannot init.
void ensure_sodium();
}
