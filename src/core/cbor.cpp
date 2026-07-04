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
