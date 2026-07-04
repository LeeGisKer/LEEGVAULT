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
    if (n > plaintext.size()) throw FormatError("body: entry count too large");

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
    if (!r.done()) throw FormatError("body: trailing bytes");
    return body;
}
}
