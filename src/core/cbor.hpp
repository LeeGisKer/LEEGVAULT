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
