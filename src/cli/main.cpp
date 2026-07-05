// LEEGVAULT interactive CLI — double-click runnable vault (M2 seed).  Built by LeeGStudios.com
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iomanip>
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
#else
#include <unistd.h>
#endif

namespace {

// Minimal terminal styling. Colors only when stdout is a real console that
// accepts VT sequences; piped output (scripted smoke tests) stays plain text.
namespace ui {

bool colors = false;

void init() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        colors = SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    colors = isatty(fileno(stdout)) != 0;
#endif
}

const char* reset()  { return colors ? "\x1b[0m" : ""; }
const char* bold()   { return colors ? "\x1b[1m" : ""; }
const char* dim()    { return colors ? "\x1b[90m" : ""; }
const char* green()  { return colors ? "\x1b[32m" : ""; }
const char* yellow() { return colors ? "\x1b[33m" : ""; }
const char* red()    { return colors ? "\x1b[31m" : ""; }
const char* cyan()   { return colors ? "\x1b[36m" : ""; }

void ok(const std::string& m)   { std::cout << green() << "  + " << m << reset() << "\n"; }
void warn(const std::string& m) { std::cout << yellow() << "  ! " << m << reset() << "\n"; }
void fail(const std::string& m) { std::cout << red() << "  x " << m << reset() << "\n"; }
void rule() { std::cout << dim() << "  ---------------------------------------------" << reset() << "\n"; }

} // namespace ui

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
        lgv::SecureBuffer a = read_password("  New master password: ");
        if (a.empty()) { ui::warn("Password cannot be empty."); continue; }
        lgv::SecureBuffer b = read_password("  Confirm password:    ");
        if (a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0) return a;
        ui::warn("Passwords do not match, try again.");
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
    if (body.entries.empty()) { ui::warn("Vault is empty — use [2] to add an entry."); return -1; }
    const std::string in = read_line("  Entry number to " + what + ": ");
    int n = 0;
    try { n = std::stoi(in); } catch (...) { n = 0; }
    if (n < 1 || static_cast<std::size_t>(n) > body.entries.size()) {
        ui::warn("No such entry.");
        return -1;
    }
    return n - 1;
}

void list_entries(const lgv::VaultBody& body) {
    if (body.entries.empty()) { ui::warn("Vault is empty — use [2] to add an entry."); return; }
    std::cout << ui::dim() << "    #  Name" << ui::reset() << "\n";
    for (std::size_t i = 0; i < body.entries.size(); ++i)
        std::cout << "  " << std::setw(3) << (i + 1) << "  " << body.entries[i].name
                  << ui::dim() << "  (id " << body.entries[i].id << ")" << ui::reset() << "\n";
}

bool save(const std::filesystem::path& path, const lgv::SecureBuffer& pw,
          const lgv::VaultBody& body) {
    try {
        lgv::VaultKeyMaterial km{ as_span(pw), std::nullopt };
        auto bytes = lgv::create_vault(km, lgv::kDefaultKdf, body);
        lgv::save_vault_atomic(path, bytes);
        ui::ok("Saved " + path.string());
        return true;
    } catch (const std::exception& e) {
        ui::fail(std::string("Save failed: ") + e.what());
        return false;
    }
}

void banner() {
    std::cout << "\n";
    ui::rule();
    std::cout << "  " << ui::bold() << ui::cyan() << "LEEGVAULT" << ui::reset()
              << ui::dim() << " — offline password vault (LGV1)" << ui::reset() << "\n"
              << ui::dim() << "  LeeGStudios.com" << ui::reset() << "\n";
    ui::rule();
    std::cout << "\n";
}

void menu(const std::filesystem::path& path, const lgv::VaultBody& body, bool dirty) {
    std::cout << "\n";
    ui::rule();
    std::cout << "  " << ui::bold() << path.filename().string() << ui::reset()
              << ui::dim() << " · " << body.entries.size()
              << (body.entries.size() == 1 ? " entry · " : " entries · ") << ui::reset();
    if (dirty)
        std::cout << ui::yellow() << "unsaved changes" << ui::reset() << "\n";
    else
        std::cout << ui::green() << "saved" << ui::reset() << "\n";
    ui::rule();
    std::cout << "  [1] List entries      [4] Delete entry\n"
                 "  [2] Add entry         [5] Change master password\n"
                 "  [3] Show a secret     [6] Save vault\n"
                 "  [0] Quit\n";
}

} // namespace

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    ui::init();
    try {
        lgv::ensure_sodium();
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }

    banner();

    std::string path_in = read_line("  Vault file [vault.lgv]: ");
    const std::filesystem::path path = path_in.empty() ? "vault.lgv" : path_in;

    lgv::SecureBuffer pw;
    lgv::VaultBody body;
    bool dirty = false;

    if (std::filesystem::exists(path)) {
        std::vector<unsigned char> bytes;
        try {
            bytes = lgv::load_vault(path);
        } catch (const std::exception& e) {
            ui::fail(std::string("Cannot read vault: ") + e.what());
            if (stdin_is_tty()) read_line("  Press Enter to close...");
            return 1;
        }
        bool opened = false;
        for (int attempt = 1; attempt <= 3 && !opened; ++attempt) {
            pw = read_password("  Master password: ");
            try {
                lgv::VaultKeyMaterial km{ as_span(pw), std::nullopt };
                body = lgv::open_vault(km, bytes);
                opened = true;
            } catch (const lgv::AuthError&) {
                ui::fail("Wrong password (attempt " + std::to_string(attempt) + " of 3).");
            } catch (const std::exception& e) {
                ui::fail(std::string("Cannot open vault: ") + e.what());
                if (stdin_is_tty()) read_line("  Press Enter to close...");
                return 1;
            }
        }
        if (!opened) {
            if (stdin_is_tty()) read_line("  Press Enter to close...");
            return 1;
        }
        ui::ok("Vault opened — " + std::to_string(body.entries.size()) + " entr"
               + (body.entries.size() == 1 ? "y" : "ies") + ".");
    } else {
        std::cout << "  No vault at " << path.string() << " — creating a new one.\n"
                  << ui::dim() << "  Key derivation uses 256 MiB Argon2id; expect a short pause."
                  << ui::reset() << "\n";
        pw = read_new_password();
        if (!save(path, pw, body)) {
            if (stdin_is_tty()) read_line("  Press Enter to close...");
            return 1;
        }
    }

    for (;;) {
        menu(path, body, dirty);
        const std::string choice = read_line("  > ");
        if (choice == "1") {
            list_entries(body);
        } else if (choice == "2") {
            lgv::Entry e;
            e.id = make_id();
            e.name = read_line("  Name: ");
            if (e.name.empty()) { ui::warn("Name cannot be empty."); continue; }
            lgv::SecureBuffer secret = read_password("  Secret: ");
            if (secret.empty()) { ui::warn("Secret cannot be empty."); continue; }
            e.secret = std::move(secret);
            body.entries.push_back(std::move(e));
            dirty = true;
            ui::ok("Added \"" + body.entries.back().name + "\" — save with [6].");
        } else if (choice == "3") {
            const int i = pick_entry(body, "show");
            if (i < 0) continue;
            const lgv::Entry& e = body.entries[static_cast<std::size_t>(i)];
            std::cout << "  " << ui::bold() << e.name << ui::reset() << ": ";
            std::cout.write(reinterpret_cast<const char*>(e.secret.data()),
                            static_cast<std::streamsize>(e.secret.size()));
            std::cout << "\n";
            ui::warn("Secret shown on screen — clear the terminal when done.");
        } else if (choice == "4") {
            const int i = pick_entry(body, "delete");
            if (i < 0) continue;
            const std::string name = body.entries[static_cast<std::size_t>(i)].name;
            body.entries.erase(body.entries.begin() + i);
            dirty = true;
            ui::ok("Deleted \"" + name + "\" — save with [6].");
        } else if (choice == "5") {
            pw = read_new_password();
            dirty = true;
            ui::ok("Password changed — save with [6].");
        } else if (choice == "6") {
            if (save(path, pw, body)) dirty = false;
        } else if (choice == "0") {
            if (dirty) {
                const std::string yn = read_line("  Unsaved changes — save before quitting? [Y/n] ");
                if (yn.empty() || yn == "y" || yn == "Y") {
                    if (!save(path, pw, body)) continue;
                }
            }
            break;
        } else {
            ui::warn("Unknown option — pick 0 to 6.");
        }
    }
    return 0;
}
