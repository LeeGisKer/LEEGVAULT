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
