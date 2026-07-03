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
