# LEEGVAULT — Product Requirements Document

**Version:** 0.2 (draft) · **Date:** 2026-07-03 · **Owner:** Lee · **Status:** M1 assumptions (A1/A2/A4/A5) blessed 2026-07-03; A3/A6 deferred to M2. M1 crypto-core plan → `docs/superpowers/plans/2026-07-03-m1-crypto-core.md`

A portable, offline, cross-platform password vault in C++ designed to survive offline brute-force by GPU/ASIC cracking rigs, vault-file tampering, and memory scraping.

---

## 1. Summary

LEEGVAULT is a single-binary CLI password manager. All secrets live in one encrypted vault file that can be copied to a USB stick and opened on any Windows, Linux, or macOS machine with the matching binary. There is no server, no sync, no telemetry — the security story is entirely local and entirely auditable. The design goal is explicit: the vault file will be handed to people running modern cracking hardware, and it must hold.

## 2. Goals

- **G1 — Survive offline attack.** An attacker with the vault file and unlimited GPU/ASIC time must face a memory-hard KDF that makes each password guess expensive.
- **G2 — Tamper-evident.** Any modification to the vault file (header or body) causes a hard, safe failure. No partial decryption, no oracle behavior.
- **G3 — Portable.** One statically linked binary per OS; one vault file format identical across all OSes. Copy binary + vault to USB → works.
- **G4 — Minimal plaintext lifetime.** Secrets exist decrypted in memory only as long as strictly needed, in locked/guarded pages, and are provably zeroized after use.
- **G5 — Auditable.** Small attack surface, one crypto dependency, published format spec, published test vectors, and a public cracking challenge.

## 3. Non-goals (v1)

- Cloud sync, browser extensions, mobile apps, GUI (all possible later on top of the same core).
- Defense against a *fully compromised OS in real time* (kernel-level malware reading memory as you type). No password manager can defend this; we document it honestly. The optional keyfile (§6.2) blunts the most common variant — a keylogger capturing the master password — because the logged password alone cannot open the vault.

## 4. Users & primary flows

Single technical user (Lee) initially; design must not preclude general users later.

- Initialize vault → add/edit/delete entries → retrieve secret to clipboard → auto-clear.
- Carry vault on USB, open on another machine.
- Hand vault file to attackers as a challenge; sleep fine.

## 5. Threat model

| # | Threat | In scope | Answer |
|---|--------|----------|--------|
| T1 | Stolen vault file, offline brute force on GPU/ASIC rigs | ✅ primary | Argon2id memory-hard KDF (§6.1), 256-bit keys |
| T2 | Tampered vault file (bit flips, header swaps, downgrade attacks) | ✅ | AEAD over body with fully authenticated header as AAD; committing MAC check (§6.4); fuzz-tested parser |
| T3 | Memory scraping while vault unlocked or after lock | ✅ | Guarded heap, mlock/VirtualLock, guaranteed zeroization, secrets purged on lock (§6.5) |
| T4 | Keylogger captures master password | ✅ partial | Optional keyfile second factor (§6.2); residual risk documented |
| T5 | Fully compromised OS, real-time | ❌ documented non-goal | Honest documentation |
| T6 | Partitioning-oracle / multi-key ciphertext attacks against password-derived keys | ✅ | Key-commitment mechanism (§6.4) |
| T7 | Quantum attack on symmetric layer | ✅ by construction | 256-bit keys; NIST: Grover gives little/no practical advantage vs AES-class ciphers — no PQ redesign needed |

## 6. Security architecture

Decisions below are grounded in the deep-research pass (25 sources, 8 claims adversarially verified 3-0, 0 refuted; full citations §13). Items marked **[verified]** passed 3-vote verification; **[sourced]** have a primary source but verification agents were cut short; **[design]** are our own engineering choices.

### 6.1 KDF — Argon2id

- **Algorithm:** Argon2id. RFC 9106 mandates it as the required variant; OWASP's top recommendation. **[verified ×2]**
- **Default parameters:** `m = 256 MiB, t = 3, p = 1`, 128-bit random salt, 256-bit output.
  - Rationale: RFC 9106's primary recommendation is m=2 GiB/t=1/p=4 and its constrained-environment floor is m=64 MiB/t=3/p=4 **[verified ×2]**; OWASP minimum is 19 MiB/t=2/p=1 **[verified]**. We sit well above both floors; 256 MiB per guess is brutal for GPU rigs (VRAM-bound parallelism) while still fine on a laptop. **[design]**
  - **p=1, not p=4:** libsodium's high-level `crypto_pwhash` fixes Argon2 parallelism to 1 — only `opslimit`/`memlimit` are tunable (verified against libsodium docs + issues #986/#993). Honoring p=4 would require a second KDF dependency, contradicting §6.7's single-dependency rationale. At a fixed 256 MiB / t=3, the security delta between p=1 and p=4 is negligible for offline-attack resistance (memory cost dominates; p mainly parallelizes the fill). Lee blessed p=1 on 2026-07-03. The header still carries a `p` byte (always 1). **[design]**
- **Auto-tune on `init`:** benchmark the host and raise parameters until unlock costs ~1000 ms, never dropping below the 64 MiB/t=3/p=4 floor. Parameters are stored in the header, so vaults remain openable on weaker machines (just slower). **[design]**
- **Explicit rejection:** PBKDF2 only makes sense under FIPS constraints (OWASP) **[verified]** — not our case; scrypt is OWASP's fallback when Argon2id is unavailable **[verified]** — it is available.

### 6.2 Key hierarchy

```
password ──BLAKE2b──┐
                    ├── composite ──Argon2id(salt, m,t,p)── master_key (32 B)
keyfile (optional)──┘                                          │
                                              ┌────────HKDF-BLAKE2b────────┐
                                              │                            │
                                         enc_key (32 B)             commit_key (32 B)
```

- Keyfile = 32 random bytes generated by us (`leegvault keyfile new`), stored on separate media. Composite keying follows the KeePass model. **[design]**
- Two independent subkeys derived from `master_key` via libsodium's KDF (BLAKE2b-based): one for AEAD encryption, one for the key-commitment tag (§6.4). **[design]**

### 6.3 AEAD — XChaCha20-Poly1305

- **Cipher:** XChaCha20-Poly1305-IETF, 256-bit key, 192-bit nonce, random nonce per save.
- Rationale:
  - libsodium's own guidance: XChaCha20-Poly1305 is the recommended default when hardware AES cannot be assumed **[verified]**; its AES-256-GCM implementation *requires* AES-NI/ARM Crypto at runtime — a portability hazard for us **[verified]**.
  - 192-bit nonces make random generation safe (collision probability < 2⁻³² up to 2⁴⁸ messages); AES-GCM's 96-bit nonce must never be random **[sourced — libsodium docs]**. A vault that re-encrypts on every save wants exactly this property.
  - Constant-time software implementation — no cache-timing side channels on machines without AES hardware. **[design]**
- The entire serialized entry database is encrypted as one blob; the complete plaintext header is passed as AAD, so header tampering breaks decryption. **[design]**

### 6.4 Key commitment — the partitioning-oracle defense

Standard AEADs (AES-GCM, ChaCha20/XChaCha20-Poly1305) are **not key-committing**: a crafted ciphertext can decrypt validly under many keys, enabling partitioning-oracle attacks that test whole sets of candidate passwords per query (Len, Grubbs & Ristenpart, USENIX Security 2021). **[sourced]**

Defense: header stores `commit_tag = BLAKE2b-256(commit_key ‖ header_bytes)`. On unlock we recompute and compare in constant time *before* attempting AEAD decryption; mismatch aborts with a single generic error. One key → one valid tag → no multi-key ciphertexts, and header authentication is enforced even before AEAD runs. **[design]**

### 6.5 Memory hardening

- All key material and decrypted entries live in `sodium_malloc()` guarded allocations: guard pages + canary + automatic lock. **[sourced — libsodium docs]**
- `sodium_mlock()` (wraps `mlock`/`VirtualLock`) keeps secret pages out of swap on all three OSes. **[sourced]**
- Zeroization via `sodium_memzero()` — survives compiler optimization; plain `memset` is dead-store-eliminated and gives no guarantee. **[sourced]**
- Lock ≠ cosmetic: the 2019 ISE study showed 1Password 7 left master password and entries readable in memory even when *locked* — our `lock` operation frees and zeroizes every secret allocation; only the vault path survives. **[sourced]**
- Core dumps disabled (`RLIMIT_CORE=0` / Windows error-reporting exclusion); secrets never written to temp files or logs. **[design]**
- C++ wrapper: a move-only `SecureBuffer` RAII type owning a `sodium_malloc` region; no copies, zeroize-on-destroy; secrets never enter `std::string`. **[design]**

### 6.6 Vault file format — `LGV1`

Lessons applied: KDBX4 authenticates its header with HMAC (Palant's format analysis); age's authentication gaps and Bitwarden's low-iteration legacy accounts show that header fields and KDF params must be under authentication and that plaintext metadata leaks. **[sourced]**

```
┌────────────────────────────── plaintext, authenticated ──┐
│ magic "LGV1" (4 B) │ format_version u16                  │
│ kdf_id u8 │ m_kib u32 │ t u32 │ p u8 │ salt (16 B)       │
│ aead_id u8 │ nonce (24 B) │ keyfile_flag u8              │
│ commit_tag (32 B)                                        │
├────────────────────────────── ciphertext ────────────────┤
│ AEAD( body, AAD = all header bytes above )               │
│   body = CBOR: entries[{id, name, user, secret, url,     │
│          notes, tags, created, modified, history[]}],    │
│          generator prefs, vault settings                 │
└──────────────────────────────────────────────────────────┘
```

- **Zero plaintext metadata**: entry names, URLs, timestamps, even the entry count are inside the ciphertext. The header reveals only KDF/cipher parameters — which the attacker gets anyway. **[design]**
- Every field length-prefixed, little-endian, no pointers; parser written to be fuzzed (§9). Unknown `format_version` → refuse with clear message (no silent downgrade). **[design]**
- **Atomic saves:** write `vault.lgv.tmp` → fsync → rename over original; previous file kept as `vault.lgv.bak` (encrypted, same format). Power loss never corrupts. **[design]**

### 6.7 Crypto library — libsodium (single dependency)

| Candidate | Verdict |
|-----------|---------|
| **libsodium** | ✅ **Chosen.** Misuse-resistant high-level API, audited, ships Argon2id + XChaCha20-Poly1305 + secure-memory suite (`sodium_malloc/mlock/memzero`) — the whole §6.5 stack in one place. Static-links cleanly on all 3 OSes. Even Monocypher's authors point to libsodium for desktop x86-64. **[verified + sourced]** |
| Botan | Strong runner-up: BSI-endorsed (only candidate with a national-agency recommendation), KeePassXC consolidated onto it. But C++98-style API is larger attack surface, and it lacks libsodium's guarded-heap allocator. Revisit if we ever need KDBX import or PKCS#11. **[sourced]** |
| Monocypher | Tiny (<2 kLOC) and audit-clean (Cure53 2020: nothing above Medium), but deliberately omits RNG *and* memory locking — we'd hand-roll exactly the §6.5 code that must not be hand-rolled. Cure53 also flagged its flat API as misuse-prone. **[sourced]** |
| OpenSSL | Huge surface, EVP API easy to misuse, no Argon2 until 3.2, no secure-memory story comparable to libsodium. ❌ |
| Crypto++ | Big C++ template surface, weaker audit trail, no memory-hardening suite. ❌ |

### 6.8 Post-quantum note

NIST: Grover's algorithm gives little to no practical advantage against AES-class symmetric ciphers; no symmetric key-size changes required. 256-bit keys already exceed the conservative bar. No PQ work needed for a symmetric-only vault; recorded here so nobody "adds Kyber" for marketing. **[sourced]**

## 7. Functional requirements (CLI)

| Command | Behavior |
|---------|----------|
| `leegvault init <file>` | Create vault; prompt master password twice (strength meter, zxcvbn-style); auto-tune KDF (§6.1); optional `--keyfile <path>` |
| `leegvault keyfile new <path>` | Generate 32-byte random keyfile |
| `leegvault add <name>` | Add entry (user, secret, url, notes, tags); `--generate [--len N --charset ...]` to auto-generate |
| `leegvault get <name>` | Copy secret to clipboard, auto-clear after 20 s (configurable); `--show` prints instead (explicit opt-in) |
| `leegvault list / search <query>` | List/filter entries (names only by default) |
| `leegvault edit / rm <name>` | Modify/delete; `rm` keeps entry in encrypted history until `--purge` |
| `leegvault gen` | Standalone password generator (CSPRNG = `randombytes_buf`) |
| `leegvault passwd` | Change master password / keyfile; full re-encrypt, new salt + nonce |
| `leegvault export / import` | Encrypted export (same format); plaintext CSV only behind `--plaintext-i-understand` |
| `leegvault check` | Verify integrity (header, commit tag, AEAD tag) without printing secrets |
| Session behavior | Every command opens → acts → locks; no daemon in v1. Interactive `shell` mode with idle auto-lock (5 min default) |

Failure UX: wrong password, corrupt file, and tampered file all return the **same** generic error (anti-oracle, §6.4) with distinct exit codes documented only as "authentication failed".

## 8. Non-functional requirements

- **Portability:** Windows 10+, Linux (glibc ≥ 2.28 + musl static build), macOS 12+ (x86-64 + ARM64). Single static binary per platform; no installer, no registry, no dotfiles unless asked.
- **Performance:** unlock ≈ 1 s by design (KDF cost); every other operation < 100 ms on a 10k-entry vault.
- **Binary size:** < 5 MB.
- **Reliability:** atomic saves (§6.6); `.bak` retention; vault never left in partial state.
- **Licensing:** libsodium ISC — compatible with any license Lee picks.

## 9. Testing & attack-readiness

This vault is *going to be attacked on purpose*. The test plan is part of the product:

1. **Unit tests** (Catch2): key hierarchy vectors, format round-trips, commit-tag rejection, wrong-password paths.
2. **Known-answer tests:** published test vectors (fixed password/salt/nonce → expected ciphertext) so third parties can verify the crypto is what the spec claims.
3. **Fuzzing:** libFuzzer + ASan/UBSan harness on the `LGV1` parser; corpus of mutated headers, truncations, flipped bits. CI gate: zero crashes.
4. **Sanitizer CI matrix:** ASan, UBSan, MSan (Linux) across GCC/Clang/MSVC on all 3 OSes.
5. **Memory discipline tests:** after `lock`, scan own process memory for known sentinel secrets (automated regression inspired by the ISE 1Password finding).
6. **Cracking challenge:** publish a test vault (known-strength password tiers: weak/medium/strong) + hashcat rule notes, and invite attack. Success criterion: strong-tier vault survives; weak-tier cost measurably matches Argon2id parameter math.
7. **Static analysis:** clang-tidy + CodeQL in CI.

## 10. Tech stack & repo layout

- **Language:** C++20. **Build:** CMake ≥ 3.25 + presets; libsodium via vcpkg (static triplets). **CI:** GitHub Actions matrix (Windows/MSVC, Linux/GCC+Clang, macOS/Clang) + sanitizer and fuzz jobs.
- Layout: `src/core/` (crypto, format, model — no I/O side effects), `src/cli/` (commands, clipboard, prompts), `tests/`, `fuzz/`, `docs/format-spec.md`.
- Clipboard: Win32 API / `wl-copy`+`xclip` fallback / `pbcopy`. Terminal input: no-echo password prompt on all platforms.

## 11. Milestones

1. **M1 — Crypto core:** key hierarchy, LGV1 read/write, commit tag, SecureBuffer. Test vectors pass.
2. **M2 — CLI MVP:** init/add/get/list/rm + clipboard + generator.
3. **M3 — Hardening:** fuzzing, sanitizers, memory-scan tests, atomic saves, `check`.
4. **M4 — Attack readiness:** format spec doc, test vectors published, cracking-challenge vaults, cross-OS release binaries.

## 12. Decisions log — what Lee confirmed vs. what needs sign-off

**Confirmed by Lee (grill session):** CLI form factor · Windows+Linux+macOS · full threat model T1–T4.

**BLESSED by Lee (2026-07-03, gate before M1):** A1 · A2 · A4 · A5 (reconciled p=4→p=1). A3 and A6 are deferred to M2 — they don't touch the M1 crypto core.
| # | Assumption | Where | Status |
|---|-----------|-------|--------|
| A1 | Password + *optional* keyfile (not mandatory, not YubiKey) | §6.2 | ✅ blessed |
| A2 | Custom `LGV1` format (not KDBX-compatible) | §6.6 | ✅ blessed |
| A3 | MVP feature list & 20 s clipboard clear | §7 | ⏳ M2 |
| A4 | C++20 / CMake / vcpkg / static link + libsodium | §10 | ✅ blessed |
| A5 | KDF default 256 MiB / t=3 / **p=1** with ~1 s auto-tune | §6.1 | ✅ blessed (p=4→p=1) |
| A6 | No daemon; per-command unlock + interactive shell mode | §7 | ⏳ M2 |

## 13. Research appendix — key sources

Verified 3-0 unless noted. Full workflow output archived in session task `wwe121twf`.

- OWASP Password Storage Cheat Sheet — Argon2id ≥ 19 MiB/t2/p1; scrypt fallback; PBKDF2 600k/FIPS-only.
- RFC 9106 — Argon2id MUST-support; recommended sets 2 GiB/t1/p4 and 64 MiB/t3/p4.
- libsodium AEAD docs — XChaCha20-Poly1305 default absent AES hardware; AES-256-GCM impl requires AES-NI/ARM Crypto; large-nonce random safety *(last point sourced, not verified)*.
- Len, Grubbs, Ristenpart — *Partitioning Oracle Attacks* (USENIX Security 2021) — non-committing AEADs; key-committing recommendation *(sourced)*.
- RFC 8452 — AES-GCM-SIV nonce-misuse resistance (considered; rejected for AES-NI dependence in practice) *(sourced)*.
- KeePassXC issue #3200 + Palant KDBX4 analysis — Botan consolidation; header-HMAC lessons *(sourced)*.
- Cure53 Monocypher audit (2020); monocypher.org/why — size vs. missing RNG/memlock *(sourced)*.
- BSI Botan recommendation *(sourced)*.
- libsodium memory-management docs; cryptologie.net on `memset` dead-store elimination *(sourced)*.
- ISE password-manager memory study (1Password 7 locked-state exposure) *(sourced)*.
- NIST PQC FAQ — symmetric ciphers need no key-size change *(sourced)*.

---

*Built by LeeGStudios.com*
