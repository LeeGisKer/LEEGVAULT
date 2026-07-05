// LEEGVAULT interactive CLI — double-click runnable vault (M2 seed).  Built by LeeGStudios.com
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <sodium.h>

#include "core/errors.hpp"
#include "core/kdf.hpp"
#include "core/model.hpp"
#include "core/secure_buffer.hpp"
#include "core/sodium_init.hpp"
#include "core/vault.hpp"
#include "storage/vault_file.hpp"

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {

bool stdin_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return true;
#endif
}

std::string read_line(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) { std::cout << "\n"; std::exit(0); }
    return line;
}

// Reads a password without echo (masked with '*') into guarded memory.
// Falls back to plain line reads when stdin is piped (scripted smoke tests).
lgv::SecureBuffer read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string buf;
#ifdef _WIN32
    if (stdin_is_tty()) {
        for (;;) {
            const int ch = _getch();
            if (ch == '\r' || ch == '\n') break;
            if (ch == 0 || ch == 224) { (void)_getch(); continue; }  // arrow/function keys
            if (ch == 3) { std::cout << "\n"; std::exit(1); }        // Ctrl+C
            if (ch == 8) {                                           // backspace
                if (!buf.empty()) { buf.pop_back(); std::cout << "\b \b" << std::flush; }
                continue;
            }
            buf.push_back(static_cast<char>(ch));
            std::cout << '*' << std::flush;
        }
        std::cout << "\n";
    } else if (!std::getline(std::cin, buf)) {
        std::cout << "\n"; std::exit(0);
    }
#else
    if (!std::getline(std::cin, buf)) { std::cout << "\n"; std::exit(0); }
#endif
    lgv::SecureBuffer out(buf.size());
    if (!buf.empty()) {
        std::memcpy(out.data(), buf.data(), buf.size());
        sodium_memzero(buf.data(), buf.size());
    }
    return out;
}

lgv::SecureBuffer read_new_password() {
    for (;;) {
        lgv::SecureBuffer a = read_password("New master password: ");
        if (a.empty()) { std::cout << "Password cannot be empty.\n"; continue; }
        lgv::SecureBuffer b = read_password("Confirm password:    ");
        if (a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0) return a;
        std::cout << "Passwords do not match, try again.\n";
    }
}

std::span<const unsigned char> as_span(const lgv::SecureBuffer& b) {
    return { b.data(), b.size() };
}

std::string make_id() {
    unsigned char r[8];
    randombytes_buf(r, sizeof r);
    static constexpr char hex[] = "0123456789abcdef";
    std::string id(16, '0');
    for (int i = 0; i < 8; ++i) { id[2 * i] = hex[r[i] >> 4]; id[2 * i + 1] = hex[r[i] & 15]; }
    return id;
}

// -1 when the input is not a valid 1-based index into the entry list.
int pick_entry(const lgv::VaultBody& body, const std::string& what) {
    if (body.entries.empty()) { std::cout << "Vault is empty.\n"; return -1; }
    const std::string in = read_line("Entry number to " + what + ": ");
    int n = 0;
    try { n = std::stoi(in); } catch (...) { n = 0; }
    if (n < 1 || static_cast<std::size_t>(n) > body.entries.size()) {
        std::cout << "No such entry.\n";
        return -1;
    }
    return n - 1;
}

void list_entries(const lgv::VaultBody& body) {
    if (body.entries.empty()) { std::cout << "Vault is empty.\n"; return; }
    for (std::size_t i = 0; i < body.entries.size(); ++i)
        std::cout << "  [" << (i + 1) << "] " << body.entries[i].name
                  << "  (id " << body.entries[i].id << ")\n";
}

bool save(const std::filesystem::path& path, const lgv::SecureBuffer& pw,
          const lgv::VaultBody& body) {
    try {
        lgv::VaultKeyMaterial km{ as_span(pw), std::nullopt };
        auto bytes = lgv::create_vault(km, lgv::kDefaultKdf, body);
        lgv::save_vault_atomic(path, bytes);
        std::cout << "Saved " << path.string() << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cout << "Save failed: " << e.what() << "\n";
        return false;
    }
}

} // namespace

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    try {
        lgv::ensure_sodium();
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }

    std::cout << "LEEGVAULT — offline password vault (LGV1)\n"
                 "Built by LeeGStudios.com\n\n";

    std::string path_in = read_line("Vault file [vault.lgv]: ");
    const std::filesystem::path path = path_in.empty() ? "vault.lgv" : path_in;

    lgv::SecureBuffer pw;
    lgv::VaultBody body;
    bool dirty = false;

    if (std::filesystem::exists(path)) {
        std::vector<unsigned char> bytes;
        try {
            bytes = lgv::load_vault(path);
        } catch (const std::exception& e) {
            std::cerr << "Cannot read vault: " << e.what() << "\n";
            if (stdin_is_tty()) read_line("Press Enter to close...");
            return 1;
        }
        bool opened = false;
        for (int attempt = 1; attempt <= 3 && !opened; ++attempt) {
            pw = read_password("Master password: ");
            try {
                lgv::VaultKeyMaterial km{ as_span(pw), std::nullopt };
                body = lgv::open_vault(km, bytes);
                opened = true;
            } catch (const lgv::AuthError&) {
                std::cout << "Authentication failed.\n";
            } catch (const std::exception& e) {
                std::cerr << "Cannot open vault: " << e.what() << "\n";
                if (stdin_is_tty()) read_line("Press Enter to close...");
                return 1;
            }
        }
        if (!opened) {
            if (stdin_is_tty()) read_line("Press Enter to close...");
            return 1;
        }
        std::cout << "Vault opened. " << body.entries.size() << " entr"
                  << (body.entries.size() == 1 ? "y" : "ies") << ".\n";
    } else {
        std::cout << "No vault at " << path.string() << " — creating a new one.\n"
                     "Key derivation uses 256 MiB Argon2id; expect a short pause.\n";
        pw = read_new_password();
        if (!save(path, pw, body)) {
            if (stdin_is_tty()) read_line("Press Enter to close...");
            return 1;
        }
    }

    for (;;) {
        std::cout << "\n[1] List  [2] Add  [3] Show secret  [4] Delete  "
                     "[5] Change password  [6] Save  [0] Quit\n";
        const std::string choice = read_line("> ");
        if (choice == "1") {
            list_entries(body);
        } else if (choice == "2") {
            lgv::Entry e;
            e.id = make_id();
            e.name = read_line("Name: ");
            if (e.name.empty()) { std::cout << "Name cannot be empty.\n"; continue; }
            lgv::SecureBuffer secret = read_password("Secret: ");
            if (secret.empty()) { std::cout << "Secret cannot be empty.\n"; continue; }
            e.secret = std::move(secret);
            body.entries.push_back(std::move(e));
            dirty = true;
            std::cout << "Added. Remember to save.\n";
        } else if (choice == "3") {
            const int i = pick_entry(body, "show");
            if (i < 0) continue;
            const lgv::Entry& e = body.entries[static_cast<std::size_t>(i)];
            std::cout << e.name << ": ";
            std::cout.write(reinterpret_cast<const char*>(e.secret.data()),
                            static_cast<std::streamsize>(e.secret.size()));
            std::cout << "\n";
        } else if (choice == "4") {
            const int i = pick_entry(body, "delete");
            if (i < 0) continue;
            body.entries.erase(body.entries.begin() + i);
            dirty = true;
            std::cout << "Deleted. Remember to save.\n";
        } else if (choice == "5") {
            pw = read_new_password();
            dirty = true;
            std::cout << "Password changed. Remember to save.\n";
        } else if (choice == "6") {
            if (save(path, pw, body)) dirty = false;
        } else if (choice == "0") {
            if (dirty) {
                const std::string yn = read_line("Unsaved changes — save before quitting? [Y/n] ");
                if (yn.empty() || yn == "y" || yn == "Y") {
                    if (!save(path, pw, body)) continue;
                }
            }
            break;
        } else {
            std::cout << "Unknown option.\n";
        }
    }
    return 0;
}
