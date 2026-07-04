#include "core/vault.hpp"
#include "core/aead.hpp"
#include "core/commit.hpp"
#include "core/errors.hpp"
#include "core/header.hpp"
#include "core/sodium_init.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace lgv {
namespace {
Lgv1Header make_header(const KdfParams& params, std::span<const unsigned char> salt,
                       std::span<const unsigned char> nonce, bool has_keyfile) {
    if (salt.size() != 16) throw std::invalid_argument("salt must be 16 bytes");
    if (nonce.size() != 24) throw std::invalid_argument("nonce must be 24 bytes");
    Lgv1Header h{};
    h.format_version = kFormatVersion;
    h.kdf_id = 1;                 // Argon2id
    h.m_kib = params.m_kib; h.t = params.t; h.p = params.p;
    std::memcpy(h.salt.data(), salt.data(), 16);
    h.aead_id = 1;                // XChaCha20-Poly1305-IETF
    std::memcpy(h.nonce.data(), nonce.data(), 24);
    h.keyfile_flag = has_keyfile ? 1 : 0;
    return h;
}
} // namespace

std::vector<unsigned char> seal_vault(const VaultKeyMaterial& km, const KdfParams& params,
                                      std::span<const unsigned char> salt16,
                                      std::span<const unsigned char> nonce24,
                                      const VaultBody& body) {
    ensure_sodium();
    Lgv1Header h = make_header(params, salt16, nonce24, km.keyfile.has_value());

    SecureBuffer mk = derive_master_key(km.password, km.keyfile, salt16, params);
    Subkeys sk = derive_subkeys(mk);

    auto core = serialize_header_core(h);
    SecureBuffer tag = compute_commit_tag(sk.commit_key, core);
    std::memcpy(h.commit_tag.data(), tag.data(), 32);

    auto aad = serialize_header(h);                       // full 90-byte header
    SecureBuffer pt = serialize_body(body);
    auto ct = aead_encrypt(sk.enc_key,
                           std::span<const unsigned char>(h.nonce.data(), 24),
                           std::span<const unsigned char>(pt.data(), pt.size()),
                           aad);

    std::vector<unsigned char> out;
    out.reserve(aad.size() + ct.size());
    out.insert(out.end(), aad.begin(), aad.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::vector<unsigned char> create_vault(const VaultKeyMaterial& km, const KdfParams& params,
                                        const VaultBody& body) {
    ensure_sodium();
    unsigned char salt[16], nonce[24];
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);
    return seal_vault(km, params, salt, nonce, body);
}

VaultBody open_vault(const VaultKeyMaterial& km, std::span<const unsigned char> vault_bytes) {
    ensure_sodium();
    Lgv1Header h = parse_header(vault_bytes);             // may throw FormatError
    if (h.kdf_id != 1 || h.aead_id != 1) throw FormatError("unsupported kdf/aead id");
    if ((h.keyfile_flag == 1) != km.keyfile.has_value()) throw AuthError(); // keyfile presence must match

    KdfParams params{ h.m_kib, h.t, h.p };
    // Tampered/corrupt KDF params must fail closed with the SAME generic AuthError, not leak a
    // distinct error type out of the KDF. A legitimate seal can never write params outside
    // libsodium's accepted range, so out-of-range == corruption/tampering. (In-range params that
    // still fail the KDF stay a runtime_error — that is a genuine low-memory environment, not tamper.)
    const std::size_t memlimit = static_cast<std::size_t>(params.m_kib) * 1024u;
    if (memlimit < crypto_pwhash_MEMLIMIT_MIN || memlimit > crypto_pwhash_MEMLIMIT_MAX ||
        params.t < crypto_pwhash_OPSLIMIT_MIN || params.t > crypto_pwhash_OPSLIMIT_MAX)
        throw AuthError();
    SecureBuffer mk = derive_master_key(km.password, km.keyfile,
                                        std::span<const unsigned char>(h.salt.data(), 16), params);
    Subkeys sk = derive_subkeys(mk);

    auto core = serialize_header_core(h);
    if (!verify_commit_tag(sk.commit_key, core,
                           std::span<const unsigned char>(h.commit_tag.data(), 32)))
        throw AuthError();                                // commitment fails -> stop before AEAD

    auto aad = serialize_header(h);
    std::span<const unsigned char> ct = vault_bytes.subspan(kHeaderSize);
    SecureBuffer pt = aead_decrypt(sk.enc_key,
                                   std::span<const unsigned char>(h.nonce.data(), 24),
                                   ct, aad);
    return parse_body(std::span<const unsigned char>(pt.data(), pt.size()));
}
}
