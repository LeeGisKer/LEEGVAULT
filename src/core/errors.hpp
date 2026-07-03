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
