#pragma once
// loader_auth.hpp — User/password authentication with HWID lock
// Admin manages users via CLI, clients authenticate at launch

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>

// ── HWID fingerprint: SHA-256-like hash of machine identifiers ───────────
// Uses a simple but effective 256-bit hash for HWID binding

static uint64_t AuthRotl64(uint64_t v, int r) { return (v << r) | (v >> (64 - r)); }

static void AuthHash256(const void* data, size_t len, uint8_t out[32]) {
    uint64_t h[4] = { 0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
                       0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL };
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        h[i % 4] ^= (uint64_t)p[i] << ((i % 8) * 8);
        h[0] = AuthRotl64(h[0], 13) * 0x9E3779B97F4A7C15ULL;
        h[1] = AuthRotl64(h[1], 17) ^ h[0];
        h[2] = AuthRotl64(h[2], 23) + h[1];
        h[3] = AuthRotl64(h[3], 29) ^ h[2];
    }
    for (int r = 0; r < 16; r++) {
        h[0] += h[3]; h[1] ^= AuthRotl64(h[0], 7);
        h[2] += h[1]; h[3] ^= AuthRotl64(h[2], 11);
    }
    memcpy(out, h, 32);
}

static std::string AuthBytesToHex(const uint8_t* data, size_t len) {
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        s += buf;
    }
    return s;
}

static bool AuthHexToBytes(const std::string& hex, uint8_t* out, size_t maxLen) {
    if (hex.size() % 2 != 0 || hex.size() / 2 > maxLen) return false;
    for (size_t i = 0; i < hex.size(); i += 2) {
        char byte[3] = { hex[i], hex[i+1], 0 };
        out[i/2] = (uint8_t)strtoul(byte, nullptr, 16);
    }
    return true;
}

// ── Collect machine HWID ─────────────────────────────────────────────────
static std::string AuthCollectHWID() {
    std::string hwData;

    // 1. Volume serial of C:
    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    hwData += "VOL:" + std::to_string(volSerial) + ";";

    // 2. Computer name
    char compName[256] = {};
    DWORD compSize = sizeof(compName);
    GetComputerNameA(compName, &compSize);
    hwData += "PC:" + std::string(compName) + ";";

    // 3. Windows install date (from registry)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD installDate = 0, sz = sizeof(installDate);
        if (RegQueryValueExA(hKey, "InstallDate", nullptr, nullptr, (BYTE*)&installDate, &sz) == ERROR_SUCCESS) {
            hwData += "INST:" + std::to_string(installDate) + ";";
        }
        RegCloseKey(hKey);
    }

    // 4. Processor brand string via CPUID
    int cpuInfo[4] = {};
    char cpuBrand[49] = {};
    __cpuid(cpuInfo, 0x80000002); memcpy(cpuBrand, cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000003); memcpy(cpuBrand + 16, cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000004); memcpy(cpuBrand + 32, cpuInfo, 16);
    cpuBrand[48] = 0;
    hwData += "CPU:" + std::string(cpuBrand) + ";";

    // 5. SMBIOS system UUID (from registry)
    HKEY hBios;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hBios) == ERROR_SUCCESS) {
        char sysProduct[256] = {};
        DWORD sz = sizeof(sysProduct);
        if (RegQueryValueExA(hBios, "SystemProductName", nullptr, nullptr, (BYTE*)sysProduct, &sz) == ERROR_SUCCESS) {
            hwData += "PROD:" + std::string(sysProduct) + ";";
        }
        char baseboard[256] = {};
        sz = sizeof(baseboard);
        if (RegQueryValueExA(hBios, "BaseBoardProduct", nullptr, nullptr, (BYTE*)baseboard, &sz) == ERROR_SUCCESS) {
            hwData += "BOARD:" + std::string(baseboard) + ";";
        }
        RegCloseKey(hBios);
    }

    // Hash the combined hardware data
    uint8_t hash[32];
    AuthHash256(hwData.c_str(), hwData.size(), hash);
    return AuthBytesToHex(hash, 32);
}

// ── XOR cipher for database encryption ───────────────────────────────────
static const uint8_t AUTH_DB_KEY[] = {
    0x4B, 0x7F, 0x2A, 0xD1, 0x93, 0xE5, 0x6C, 0x38,
    0xB0, 0x14, 0xF7, 0x5D, 0xA2, 0x89, 0x3E, 0xC6,
    0x71, 0x05, 0xDB, 0x48, 0x9A, 0xF3, 0x27, 0x64,
    0xBE, 0x50, 0x1C, 0xE8, 0x76, 0xAD, 0x42, 0x8F,
};

static void AuthXorCrypt(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= AUTH_DB_KEY[i % sizeof(AUTH_DB_KEY)];
}

// ── User record ──────────────────────────────────────────────────────────
struct AuthUser {
    char     username[64];
    uint8_t  passHash[32];
    char     hwid[65];       // 64 hex chars + null (empty = not locked)
    uint32_t active;         // 1 = active, 0 = disabled
    uint32_t maxResets;      // max HWID resets allowed
    uint32_t resetsUsed;     // HWID resets consumed
    uint64_t created;        // timestamp
    uint64_t lastLogin;      // timestamp
    uint64_t expiry;         // 0 = never expires, else FILETIME
    char     reserved[128];  // future use
};

static const char AUTH_DB_MAGIC[] = "PFAUTH01";

struct AuthDB {
    char     magic[8];
    uint32_t version;
    uint32_t userCount;
    // Followed by userCount AuthUser records
};

// ── Database path (next to the exe) ──────────────────────────────────────
static std::string AuthGetDBPath() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    char* sl = strrchr(exePath, '\\');
    if (sl) *(sl + 1) = 0;
    return std::string(exePath) + "auth.dat";
}

// ── Read database ────────────────────────────────────────────────────────
static bool AuthReadDB(const std::string& path, std::vector<AuthUser>& users) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    size_t sz = (size_t)f.tellg();
    if (sz < sizeof(AuthDB)) return false;
    f.seekg(0);
    std::vector<uint8_t> data(sz);
    f.read((char*)data.data(), sz);
    f.close();

    AuthXorCrypt(data.data(), data.size());

    auto* hdr = (AuthDB*)data.data();
    if (memcmp(hdr->magic, AUTH_DB_MAGIC, 8) != 0) return false;
    if (hdr->version != 1) return false;
    if (sizeof(AuthDB) + hdr->userCount * sizeof(AuthUser) > sz) return false;

    users.resize(hdr->userCount);
    memcpy(users.data(), data.data() + sizeof(AuthDB), hdr->userCount * sizeof(AuthUser));
    return true;
}

// ── Write database ───────────────────────────────────────────────────────
static bool AuthWriteDB(const std::string& path, const std::vector<AuthUser>& users) {
    size_t totalSz = sizeof(AuthDB) + users.size() * sizeof(AuthUser);
    std::vector<uint8_t> data(totalSz, 0);

    auto* hdr = (AuthDB*)data.data();
    memcpy(hdr->magic, AUTH_DB_MAGIC, 8);
    hdr->version = 1;
    hdr->userCount = (uint32_t)users.size();
    if (!users.empty())
        memcpy(data.data() + sizeof(AuthDB), users.data(), users.size() * sizeof(AuthUser));

    AuthXorCrypt(data.data(), data.size());

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write((char*)data.data(), totalSz);
    return f.good();
}

// ── Hash a password ──────────────────────────────────────────────────────
static void AuthHashPassword(const char* pass, uint8_t out[32]) {
    // Salt with a fixed prefix for basic hardening
    std::string salted = "PF_SALT_v1:" + std::string(pass);
    // Multiple rounds
    uint8_t tmp[32];
    AuthHash256(salted.c_str(), salted.size(), tmp);
    for (int i = 0; i < 1000; i++) {
        uint8_t combined[64];
        memcpy(combined, tmp, 32);
        memcpy(combined + 32, salted.c_str(), (salted.size() < 32) ? salted.size() : 32);
        AuthHash256(combined, 64, tmp);
    }
    memcpy(out, tmp, 32);
}

// ── Admin: add user ──────────────────────────────────────────────────────
static bool AuthAdminAddUser(const char* username, const char* password, uint32_t maxResets = 3) {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    AuthReadDB(dbPath, users);  // OK if file doesn't exist yet

    // Check for duplicates
    for (auto& u : users) {
        if (_stricmp(u.username, username) == 0) {
            fprintf(stderr, "[!] User '%s' already exists\n", username);
            return false;
        }
    }

    AuthUser nu = {};
    strncpy_s(nu.username, username, _TRUNCATE);
    AuthHashPassword(password, nu.passHash);
    nu.hwid[0] = 0;  // not locked yet
    nu.active = 1;
    nu.maxResets = maxResets;
    nu.resetsUsed = 0;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    nu.created = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    nu.expiry = 0;  // no expiry

    users.push_back(nu);

    if (!AuthWriteDB(dbPath, users)) {
        fprintf(stderr, "[!] Failed to write auth database\n");
        return false;
    }
    fprintf(stderr, "[+] User '%s' added (max_resets=%u)\n", username, maxResets);
    return true;
}

// ── Admin: remove user ───────────────────────────────────────────────────
static bool AuthAdminRemoveUser(const char* username) {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    if (!AuthReadDB(dbPath, users)) {
        fprintf(stderr, "[!] No auth database found\n");
        return false;
    }

    size_t before = users.size();
    users.erase(
        std::remove_if(users.begin(), users.end(),
            [&](const AuthUser& u) { return _stricmp(u.username, username) == 0; }),
        users.end()
    );

    if (users.size() == before) {
        fprintf(stderr, "[!] User '%s' not found\n", username);
        return false;
    }

    AuthWriteDB(dbPath, users);
    fprintf(stderr, "[+] User '%s' removed\n", username);
    return true;
}

// ── Admin: reset HWID for user ───────────────────────────────────────────
static bool AuthAdminResetHWID(const char* username) {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    if (!AuthReadDB(dbPath, users)) {
        fprintf(stderr, "[!] No auth database found\n");
        return false;
    }

    for (auto& u : users) {
        if (_stricmp(u.username, username) == 0) {
            u.hwid[0] = 0;
            u.resetsUsed = 0;
            AuthWriteDB(dbPath, users);
            fprintf(stderr, "[+] HWID reset for user '%s'\n", username);
            return true;
        }
    }
    fprintf(stderr, "[!] User '%s' not found\n", username);
    return false;
}

// ── Admin: set expiry ────────────────────────────────────────────────────
static bool AuthAdminSetExpiry(const char* username, uint32_t days) {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    if (!AuthReadDB(dbPath, users)) return false;

    for (auto& u : users) {
        if (_stricmp(u.username, username) == 0) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            uint64_t now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            u.expiry = now + (uint64_t)days * 24 * 60 * 60 * 10000000ULL;
            AuthWriteDB(dbPath, users);
            fprintf(stderr, "[+] Expiry set: %u days from now for '%s'\n", days, username);
            return true;
        }
    }
    return false;
}

// ── Admin: toggle active ─────────────────────────────────────────────────
static bool AuthAdminSetActive(const char* username, bool active) {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    if (!AuthReadDB(dbPath, users)) return false;

    for (auto& u : users) {
        if (_stricmp(u.username, username) == 0) {
            u.active = active ? 1 : 0;
            AuthWriteDB(dbPath, users);
            fprintf(stderr, "[+] User '%s' %s\n", username, active ? "enabled" : "disabled");
            return true;
        }
    }
    return false;
}

// ── Admin: list users ────────────────────────────────────────────────────
static void AuthAdminListUsers() {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    if (!AuthReadDB(dbPath, users) || users.empty()) {
        fprintf(stderr, "[*] No users in database (path: %s)\n", dbPath.c_str());
        return;
    }

    fprintf(stderr, "\n=== Auth Database: %u user(s) ===\n", (unsigned)users.size());
    fprintf(stderr, "%-16s %-8s %-6s %-10s %-64s\n",
            "Username", "Active", "Resets", "Expiry", "HWID");
    fprintf(stderr, "%-16s %-8s %-6s %-10s %-64s\n",
            "--------", "------", "------", "------", "----");

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    uint64_t now = ((uint64_t)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

    for (auto& u : users) {
        const char* expStr = "never";
        char expBuf[32] = {};
        if (u.expiry != 0) {
            if (u.expiry < now) {
                expStr = "EXPIRED";
            } else {
                uint64_t remaining = (u.expiry - now) / 10000000ULL;
                uint32_t days = (uint32_t)(remaining / 86400);
                snprintf(expBuf, sizeof(expBuf), "%ud left", days);
                expStr = expBuf;
            }
        }

        fprintf(stderr, "%-16s %-8s %u/%-4u %-10s %.32s%s\n",
                u.username,
                u.active ? "YES" : "NO",
                u.resetsUsed, u.maxResets,
                expStr,
                u.hwid[0] ? u.hwid : "(unlocked)",
                (u.hwid[0] && strlen(u.hwid) > 32) ? "..." : "");
    }
    fprintf(stderr, "\n");
}

// ── Client: authenticate (returns true if auth passes) ───────────────────
enum AuthResult {
    AUTH_OK = 0,
    AUTH_NO_DB,
    AUTH_BAD_USER,
    AUTH_BAD_PASS,
    AUTH_DISABLED,
    AUTH_EXPIRED,
    AUTH_HWID_MISMATCH,
    AUTH_WRITE_FAIL,
};

static const char* AuthResultStr(AuthResult r) {
    switch (r) {
        case AUTH_OK: return "Authentication successful";
        case AUTH_NO_DB: return "No auth database found";
        case AUTH_BAD_USER: return "Invalid username";
        case AUTH_BAD_PASS: return "Invalid password";
        case AUTH_DISABLED: return "Account disabled";
        case AUTH_EXPIRED: return "Account expired";
        case AUTH_HWID_MISMATCH: return "HWID mismatch (contact admin for reset)";
        case AUTH_WRITE_FAIL: return "Failed to update auth database";
        default: return "Unknown error";
    }
}

static AuthResult AuthClientLogin(const char* username, const char* password) {
    std::string dbPath = AuthGetDBPath();
    std::vector<AuthUser> users;
    if (!AuthReadDB(dbPath, users)) return AUTH_NO_DB;

    for (size_t idx = 0; idx < users.size(); idx++) {
        if (_stricmp(users[idx].username, username) != 0) continue;

        auto& u = users[idx];

        // Check password
        uint8_t passHash[32];
        AuthHashPassword(password, passHash);
        if (memcmp(passHash, u.passHash, 32) != 0) return AUTH_BAD_PASS;

        // Check active
        if (!u.active) return AUTH_DISABLED;

        // Check expiry
        if (u.expiry != 0) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            uint64_t now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            if (now > u.expiry) return AUTH_EXPIRED;
        }

        // Collect current HWID
        std::string currentHWID = AuthCollectHWID();

        // Check HWID lock
        if (u.hwid[0] != 0) {
            if (strcmp(u.hwid, currentHWID.c_str()) != 0) {
                return AUTH_HWID_MISMATCH;
            }
        } else {
            // First login — lock HWID
            strncpy_s(u.hwid, currentHWID.c_str(), _TRUNCATE);
        }

        // Update last login
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        u.lastLogin = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

        if (!AuthWriteDB(dbPath, users)) return AUTH_WRITE_FAIL;

        return AUTH_OK;
    }
    return AUTH_BAD_USER;
}

// ── Client: interactive login prompt ─────────────────────────────────────
static AuthResult AuthInteractiveLogin() {
    char username[64] = {};
    char password[64] = {};

    // Disable console echo for password input
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    DWORD consoleMode = 0;

    fprintf(stderr, "\n");
    fprintf(stderr, "  ╔═══════════════════════════════════╗\n");
    fprintf(stderr, "  ║       Authentication Required      ║\n");
    fprintf(stderr, "  ╚═══════════════════════════════════╝\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "  Username: ");
    if (!fgets(username, sizeof(username), stdin)) return AUTH_BAD_USER;
    // Strip newline
    size_t uLen = strlen(username);
    if (uLen > 0 && username[uLen-1] == '\n') username[uLen-1] = 0;
    if (uLen > 1 && username[uLen-2] == '\r') username[uLen-2] = 0;

    fprintf(stderr, "  Password: ");
    // Hide password input
    if (GetConsoleMode(hConsole, &consoleMode)) {
        SetConsoleMode(hConsole, consoleMode & ~ENABLE_ECHO_INPUT);
    }
    if (!fgets(password, sizeof(password), stdin)) {
        SetConsoleMode(hConsole, consoleMode);
        return AUTH_BAD_PASS;
    }
    SetConsoleMode(hConsole, consoleMode);
    fprintf(stderr, "\n");

    uLen = strlen(password);
    if (uLen > 0 && password[uLen-1] == '\n') password[uLen-1] = 0;
    if (uLen > 1 && password[uLen-2] == '\r') password[uLen-2] = 0;

    AuthResult r = AuthClientLogin(username, password);

    // Zero password from memory immediately
    SecureZeroMemory(password, sizeof(password));

    if (r == AUTH_OK) {
        fprintf(stderr, "  [+] Authenticated as '%s' — HWID locked\n\n", username);
    } else {
        fprintf(stderr, "  [!] Auth failed: %s\n\n", AuthResultStr(r));
    }

    return r;
}
