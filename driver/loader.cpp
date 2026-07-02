//
// loader.cpp — PenisFinger Interactive GUI Loader
// Self-contained: all binaries AES-encrypted and embedded
//
#include <Windows.h>
#include <gdiplus.h>
#include <winsvc.h>
#include <winevt.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <intrin.h>
#include <winioctl.h>
#include <iphlpapi.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

#include "embedded_data.h"

namespace fs = std::filesystem;
using namespace Gdiplus;

// ── Anti-cracking ────────────────────────────────────────────────────────────

static volatile int g_integrityOk = 0;

static bool CheckDebugger() {
    if (IsDebuggerPresent()) return true;
    // NtGlobalFlag check: debugger sets heap flags (PEB+0xBC on x64)
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    if (peb && (*(DWORD*)(peb + 0xBC) & 0x70)) return true;
    // Hardware breakpoint check via thread context
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    // Remote debugger check
    BOOL dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
    if (dbg) return true;
    return false;
}

// ── AES Decryption ───────────────────────────────────────────────────────────

static bool DeriveKey(BYTE outKey[32]) {
    // Reconstruct seed from scattered parts
    std::string seed;
    for (int i = 0; i < g_ksCount; i++) {
        seed.append((const char*)g_ksParts[i], g_ksLens[i]);
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
            BCryptHashData(hHash, (PUCHAR)seed.data(), (ULONG)seed.size(), 0);
            BCryptFinishHash(hHash, outKey, 32, 0);
            ok = true;
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    SecureZeroMemory(&seed[0], seed.size());
    return ok;
}

static bool DecryptData(const BYTE* encData, ULONG encSize, const BYTE iv[16],
                        const BYTE key[32], std::vector<BYTE>& outBuf) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    ULONG cbResult = 0;
    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);

    // Get output size
    BCryptDecrypt(hKey, (PUCHAR)encData, encSize, nullptr, ivCopy, 16, nullptr, 0, &cbResult, BCRYPT_BLOCK_PADDING);

    outBuf.resize(cbResult);
    memcpy(ivCopy, iv, 16);

    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)encData, encSize, nullptr, ivCopy, 16,
                                    outBuf.data(), cbResult, &cbResult, BCRYPT_BLOCK_PADDING);
    if (status == 0) {
        outBuf.resize(cbResult);
        ok = true;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ── Extraction ───────────────────────────────────────────────────────────────

static std::wstring g_extractDir;

static bool ExtractEmbedded() {
    BYTE aesKey[32];
    if (!DeriveKey(aesKey)) return false;

    // Create random temp directory
    wchar_t tmpPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpPath);
    GUID guid;
    CoCreateGuid(&guid);
    wchar_t guidStr[40];
    wsprintfW(guidStr, L"%08x%04x%04x", guid.Data1, guid.Data2, guid.Data3);
    g_extractDir = std::wstring(tmpPath) + L"pf_" + guidStr;
    CreateDirectoryW(g_extractDir.c_str(), nullptr);

    std::wstring imgDir = g_extractDir + L"\\images";
    CreateDirectoryW(imgDir.c_str(), nullptr);

    for (int i = 0; i < g_embeddedCount; i++) {
        const EmbeddedEntry& e = g_embedded[i];
        std::vector<BYTE> decrypted;
        if (!DecryptData(e.data, e.encSize, e.iv, aesKey, decrypted))
            return false;

        // Determine output filename
        std::wstring outPath;
        std::string id(e.id);
        if (id == "mapper")       outPath = g_extractDir + L"\\mapper_nal.exe";
        else if (id == "driver")  outPath = g_extractDir + L"\\Betest.sys";
        else if (id == "byovd")   outPath = g_extractDir + L"\\TRIXX.sys";
        else if (id == "injector") outPath = g_extractDir + L"\\injector.exe";
        else if (id == "unt_ext") outPath = g_extractDir + L"\\externaltest.exe";
        else if (id == "unt_int") outPath = g_extractDir + L"\\unturned_internal.dll";
        else if (id.rfind("img_", 0) == 0) {
            std::string imgName = id.substr(4) + ".jpg";
            outPath = imgDir + L"\\" + std::wstring(imgName.begin(), imgName.end());
        }
        else continue;

        HANDLE hFile = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        DWORD written;
        WriteFile(hFile, decrypted.data(), (DWORD)decrypted.size(), &written, nullptr);
        CloseHandle(hFile);
        SecureZeroMemory(decrypted.data(), decrypted.size());
    }

    SecureZeroMemory(aesKey, 32);
    return true;
}

static void CleanupExtracted() {
    if (g_extractDir.empty()) return;

    // Delete images
    std::wstring imgDir = g_extractDir + L"\\images";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((imgDir + L"\\*").c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::wstring fp = imgDir + L"\\" + fd.cFileName;
                // Overwrite before delete
                HANDLE hf = CreateFileW(fp.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (hf != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER sz; GetFileSizeEx(hf, &sz);
                    std::vector<BYTE> zeros((size_t)sz.QuadPart, 0);
                    DWORD w; WriteFile(hf, zeros.data(), (DWORD)zeros.size(), &w, nullptr);
                    CloseHandle(hf);
                }
                DeleteFileW(fp.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryW(imgDir.c_str());

    // Delete main files
    const wchar_t* mainFiles[] = { L"\\mapper_nal.exe", L"\\Betest.sys", L"\\TRIXX.sys",
                                    L"\\injector.exe", L"\\externaltest.exe", L"\\unturned_internal.dll" };
    for (auto& f : mainFiles) {
        std::wstring fp = g_extractDir + f;
        HANDLE hf = CreateFileW(fp.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz; GetFileSizeEx(hf, &sz);
            std::vector<BYTE> zeros((size_t)sz.QuadPart, 0);
            DWORD w; WriteFile(hf, zeros.data(), (DWORD)zeros.size(), &w, nullptr);
            CloseHandle(hf);
        }
        DeleteFileW(fp.c_str());
    }
    RemoveDirectoryW(g_extractDir.c_str());
}

// ── Constants ────────────────────────────────────────────────────────────────

#define WND_W       960
#define WND_H       780
#define TILE_W      180
#define TILE_H      220
#define TILE_PAD    16
#define COLS        4
#define TIMER_MATRIX  1
#define MATRIX_COLS   80
#define MATRIX_ROWS   40

// ── Pages ────────────────────────────────────────────────────────────────────

enum Page {
    PAGE_LOAD,
    PAGE_GAMES,
    PAGE_SPOOFER,
    PAGE_UNT_MODE,
    PAGE_LAUNCHING,
    PAGE_DONE,
};

static bool g_untInternal = false;
static bool g_driverMapped = false;
static volatile LONG g_launching = 0;

// ── Game data ────────────────────────────────────────────────────────────────

struct GameDef {
    const wchar_t* name;
    const wchar_t* abbrev;
    const wchar_t* imageFile;
    const char*    flags;
    const char*    hwidFlags;
    const wchar_t* processExe;
    bool           needsSpoof;
    DWORD          color1;
    DWORD          color2;
    DWORD          accent;
    Image*         img;
};

static GameDef g_games[] = {
    { L"Fortnite",      L"FN",  L"fortnite.jpg",  "--full --eac 7f",              "3f", L"FortniteClient-Win64-Shipping.exe", true,  0xFF6B2FD0, 0xFF3A1078, 0xFF9D5FFF, nullptr },
    { L"Valorant",      L"VAL", L"valorant.jpg",   "--full --vanguard --eac 7f",   "3f", L"VALORANT-Win64-Shipping.exe",       true,  0xFFDC3545, 0xFF6B0F1A, 0xFFFF6B7A, nullptr },
    { L"Apex Legends",  L"APX", L"apex.jpg",       "--full --eac 7f",              "3f", L"r5apex.exe",                        true,  0xFFCE3C2D, 0xFF7A1810, 0xFFFF7043, nullptr },
    { L"Rust",          L"RST", L"rust.jpg",       "--full --eac 7f",              "3f", L"RustClient.exe",                    true,  0xFF8B4513, 0xFF4A2508, 0xFFCD853F, nullptr },
    { L"Tarkov",        L"EFT", L"tarkov.jpg",     "--full --eac 7f",              "3f", L"EscapeFromTarkov.exe",              true,  0xFF3E5C3A, 0xFF1B2E18, 0xFF6B8E64, nullptr },
    { L"PUBG",          L"PBG", L"pubg.jpg",       "--full --eac 7f",              "3f", L"TslGame.exe",                       true,  0xFFF5A623, 0xFF8B5E0A, 0xFFFFD54F, nullptr },
    { L"Call of Duty",  L"COD", L"cod.jpg",        "--full --eac 7f",              "3f", L"cod.exe",                            true,  0xFF2C3E2C, 0xFF111A11, 0xFF5C8A5C, nullptr },
    { L"Rainbow Six",   L"R6S", L"r6s.jpg",        "--full --eac 7f",              "3f", L"RainbowSix.exe",                    true,  0xFF1565C0, 0xFF0A2E5C, 0xFF42A5F5, nullptr },
    { L"DayZ",          L"DYZ", L"dayz.jpg",       "--battleye 1f",                "3f", L"DayZ_x64.exe",                      false, 0xFF2E4A2E, 0xFF152015, 0xFF66BB6A, nullptr },
    { L"Unturned",      L"UNT", L"unturned.jpg",   "--battleye 1f",                "1f", L"Unturned.exe",                      false, 0xFF43A047, 0xFF1B5E20, 0xFF81C784, nullptr },
    { L"Custom",        L"...", nullptr,            "--full --eac 7f",              "3f", nullptr,                              false, 0xFF616161, 0xFF212121, 0xFF9E9E9E, nullptr },
};
static const int GAME_COUNT = sizeof(g_games) / sizeof(g_games[0]);

// ── Globals ──────────────────────────────────────────────────────────────────

static HWND        g_hWnd         = nullptr;
static Page        g_page         = PAGE_LOAD;
static int         g_selectedGame = -1;
static bool        g_spoofEnabled = false;
static int         g_spoofGame    = -1;
static bool        g_spoofKeepSeed = false;
static UINT64      g_spoofSeed    = 0;
static bool        g_spoofRunClean = false;
static bool        g_spoofNewSeed  = true;
static int         g_hoverTile    = -1;
static int         g_launchStep   = 0;
static std::wstring g_launchLog;
static std::string g_selfDir;
static std::string g_mapperPath;
static std::string g_driverPath;
static ULONG_PTR   g_gdipToken    = 0;

// Matrix rain state
static int   g_matrixDrops[MATRIX_COLS];
static int   g_matrixSpeed[MATRIX_COLS];
static char  g_matrixGrid[MATRIX_ROWS][MATRIX_COLS];

// Double-buffer
static HDC     g_memDC   = nullptr;
static HBITMAP g_memBmp  = nullptr;
static int     g_bufW    = 0;
static int     g_bufH    = 0;

// Scroll
static int     g_scrollY = 0;

// ── Seed persistence ─────────────────────────────────────────────────────────

static std::wstring GetSeedFilePath() {
    wchar_t appdata[MAX_PATH];
    GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH);
    std::wstring dir = std::wstring(appdata) + L"\\PenisFinger";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\spoof_seed.dat";
}

static void LoadSpoofSeed() {
    std::wstring path = GetSeedFilePath();
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    struct SpoofCfg {
        UINT64 seed;
        BYTE keepSeed;
        BYTE enabled;
        INT32 game;
        BYTE newSeed;
        BYTE runClean;
    } data = {};
    DWORD rd;
    ReadFile(hf, &data, sizeof(data), &rd, nullptr);
    CloseHandle(hf);
    g_spoofSeed = data.seed;
    g_spoofKeepSeed = data.keepSeed != 0;
    if (rd >= 12) {
        g_spoofEnabled = data.enabled != 0;
        g_spoofGame = data.game;
        if (g_spoofGame < 0 || g_spoofGame >= (int)(sizeof(g_games)/sizeof(g_games[0])) - 1)
            g_spoofGame = -1;
    }
    if (rd >= 14) {
        g_spoofNewSeed = data.newSeed != 0;
        g_spoofRunClean = data.runClean != 0;
    }
}

static void SaveSpoofSeed() {
    std::wstring path = GetSeedFilePath();
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    struct SpoofCfg {
        UINT64 seed;
        BYTE keepSeed;
        BYTE enabled;
        INT32 game;
        BYTE newSeed;
        BYTE runClean;
    } data = {
        g_spoofSeed,
        (BYTE)(g_spoofKeepSeed ? 1 : 0),
        (BYTE)(g_spoofEnabled ? 1 : 0),
        (INT32)g_spoofGame,
        (BYTE)(g_spoofNewSeed ? 1 : 0),
        (BYTE)(g_spoofRunClean ? 1 : 0)
    };
    DWORD written;
    WriteFile(hf, &data, sizeof(data), &written, nullptr);
    CloseHandle(hf);
}

static UINT64 GenerateSpoofSeed() {
    UINT64 seed = __rdtsc();
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    seed ^= (UINT64)pc.QuadPart;
    seed ^= (UINT64)GetTickCount64();
    return seed ? seed : 1;
}

// ── Hardware ID collection ───────────────────────────────────────────────────

struct HwidEntry {
    wchar_t label[32];
    wchar_t original[64];
    wchar_t spoofed[64];
};

static HwidEntry g_hwids[5];
static int       g_hwidCount = 0;
static bool      g_hwidsQueried = false;

static void QueryHardwareIds() {
    if (g_hwidsQueried) return;
    g_hwidsQueried = true;
    g_hwidCount = 0;

    // 1. Volume serial (C:)
    {
        DWORD volSerial = 0;
        if (GetVolumeInformationW(L"C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0) && volSerial) {
            auto& e = g_hwids[g_hwidCount++];
            wcscpy_s(e.label, L"Volume Serial");
            wsprintfW(e.original, L"%04X-%04X", (volSerial >> 16) & 0xFFFF, volSerial & 0xFFFF);
            wcscpy_s(e.spoofed, L"---");
        }
    }

    // 2. Machine GUID (from registry)
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            wchar_t guid[128] = {};
            DWORD sz = sizeof(guid);
            if (RegQueryValueExW(hk, L"MachineGuid", nullptr, nullptr, (BYTE*)guid, &sz) == ERROR_SUCCESS) {
                auto& e = g_hwids[g_hwidCount++];
                wcscpy_s(e.label, L"Machine GUID");
                wcsncpy_s(e.original, guid, 18);
                wcscat_s(e.original, L"...");
                wcscpy_s(e.spoofed, L"---");
            }
            RegCloseKey(hk);
        }
    }

    // 3. Disk serial via PhysicalDrive0
    {
        HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDisk != INVALID_HANDLE_VALUE) {
            BYTE buf[512] = {};
            STORAGE_PROPERTY_QUERY spq = {};
            spq.PropertyId = StorageDeviceProperty;
            spq.QueryType = PropertyStandardQuery;
            DWORD ret = 0;
            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq, sizeof(spq), buf, sizeof(buf), &ret, nullptr)) {
                auto* desc = (STORAGE_DEVICE_DESCRIPTOR*)buf;
                if (desc->SerialNumberOffset && desc->SerialNumberOffset < ret) {
                    char* serial = (char*)(buf + desc->SerialNumberOffset);
                    auto& e = g_hwids[g_hwidCount++];
                    wcscpy_s(e.label, L"Disk Serial");
                    MultiByteToWideChar(CP_ACP, 0, serial, -1, e.original, 64);
                    if (wcslen(e.original) > 20) { e.original[18] = L'.'; e.original[19] = L'.'; e.original[20] = 0; }
                    wcscpy_s(e.spoofed, L"---");
                }
            }
            CloseHandle(hDisk);
        }
    }

    // 4. SMBIOS UUID (from registry)
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig", 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            wchar_t uuid[128] = {};
            DWORD sz = sizeof(uuid);
            if (RegQueryValueExW(hk, L"LastConfig", nullptr, nullptr, (BYTE*)uuid, &sz) == ERROR_SUCCESS) {
                auto& e = g_hwids[g_hwidCount++];
                wcscpy_s(e.label, L"SMBIOS UUID");
                wcsncpy_s(e.original, uuid, 18);
                wcscat_s(e.original, L"...");
                wcscpy_s(e.spoofed, L"---");
            }
            RegCloseKey(hk);
        }
    }

    // 5. Computer name
    {
        wchar_t name[64] = {};
        DWORD sz = 64;
        if (GetComputerNameW(name, &sz) && sz > 0) {
            auto& e = g_hwids[g_hwidCount++];
            wcscpy_s(e.label, L"Computer Name");
            wcscpy_s(e.original, name);
            wcscpy_s(e.spoofed, L"---");
        }
    }
}

static void GenerateSpoofedPreviews() {
    if (g_spoofSeed == 0) return;
    UINT64 s = g_spoofSeed;
    for (int i = 0; i < g_hwidCount; i++) {
        s ^= (s << 13); s ^= (s >> 7); s ^= (s << 17);
        wsprintfW(g_hwids[i].spoofed, L"%04X-%04X-%04X",
            (DWORD)((s >> 32) & 0xFFFF), (DWORD)((s >> 16) & 0xFFFF), (DWORD)(s & 0xFFFF));
    }
}

// ── Image loading ────────────────────────────────────────────────────────────

static void LoadGameImages() {
    std::wstring imgDir;
    if (!g_extractDir.empty())
        imgDir = g_extractDir + L"\\images\\";
    else {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        imgDir = fs::path(exePath).parent_path().wstring() + L"\\images\\";
    }

    for (int i = 0; i < GAME_COUNT; i++) {
        if (!g_games[i].imageFile) continue;
        std::wstring path = imgDir + g_games[i].imageFile;
        Image* img = Image::FromFile(path.c_str());
        if (img && img->GetLastStatus() == Ok) {
            g_games[i].img = img;
        } else {
            delete img;
            g_games[i].img = nullptr;
        }
    }
}

static void FreeGameImages() {
    for (int i = 0; i < GAME_COUNT; i++) {
        delete g_games[i].img;
        g_games[i].img = nullptr;
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

static Color MakeColor(DWORD argb) {
    return Color((BYTE)(argb >> 24), (BYTE)(argb >> 16), (BYTE)(argb >> 8), (BYTE)argb);
}

static void InitMatrix() {
    srand((unsigned)GetTickCount());
    for (int c = 0; c < MATRIX_COLS; c++) {
        g_matrixDrops[c] = rand() % MATRIX_ROWS;
        g_matrixSpeed[c] = 1 + rand() % 3;
        for (int r = 0; r < MATRIX_ROWS; r++)
            g_matrixGrid[r][c] = 33 + rand() % 93;
    }
}

static void StepMatrix() {
    for (int c = 0; c < MATRIX_COLS; c++) {
        g_matrixDrops[c] += g_matrixSpeed[c];
        if (g_matrixDrops[c] >= MATRIX_ROWS + 15) {
            g_matrixDrops[c] = -(rand() % 20);
            g_matrixSpeed[c] = 1 + rand() % 3;
        }
        if (rand() % 4 == 0)
            g_matrixGrid[rand() % MATRIX_ROWS][c] = 33 + rand() % 93;
    }
}

static RECT TileRect(int idx, int offsetX, int offsetY) {
    int col = idx % COLS;
    int row = idx / COLS;
    int totalW = COLS * TILE_W + (COLS - 1) * TILE_PAD;
    int x = offsetX + (WND_W - totalW) / 2 + col * (TILE_W + TILE_PAD);
    int y = offsetY + row * (TILE_H + TILE_PAD);
    RECT rc = { x, y, x + TILE_W, y + TILE_H };
    return rc;
}

static int HitTestTile(int mx, int my, int count, int offsetX, int offsetY) {
    for (int i = 0; i < count; i++) {
        RECT rc = TileRect(i, offsetX, offsetY);
        if (mx >= rc.left && mx < rc.right && my >= rc.top && my < rc.bottom)
            return i;
    }
    return -1;
}

// ── Drawing ──────────────────────────────────────────────────────────────────

static void DrawRoundRect(Graphics& g, Pen* pen, Brush* fill, int x, int y, int w, int h, int r) {
    GraphicsPath path;
    path.AddArc(x, y, r * 2, r * 2, 180, 90);
    path.AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);
    path.AddArc(x + w - r * 2, y + h - r * 2, r * 2, r * 2, 0, 90);
    path.AddArc(x, y + h - r * 2, r * 2, r * 2, 90, 90);
    path.CloseFigure();
    if (fill) g.FillPath(fill, &path);
    if (pen)  g.DrawPath(pen, &path);
}

static GraphicsPath* MakeRoundRectPath(int x, int y, int w, int h, int r) {
    GraphicsPath* path = new GraphicsPath();
    path->AddArc(x, y, r * 2, r * 2, 180, 90);
    path->AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);
    path->AddArc(x + w - r * 2, y + h - r * 2, r * 2, r * 2, 0, 90);
    path->AddArc(x, y + h - r * 2, r * 2, r * 2, 90, 90);
    path->CloseFigure();
    return path;
}

static void DrawGameTile(Graphics& gfx, int idx, RECT rc, bool hover, bool selected) {
    GameDef& gd = g_games[idx];
    int tw = rc.right - rc.left;
    int th = rc.bottom - rc.top;

    // Shadow
    SolidBrush shadowBr(Color(60, 0, 0, 0));
    DrawRoundRect(gfx, nullptr, &shadowBr, rc.left + 3, rc.top + 3, tw, th, 12);

    // Clip to rounded rect for image
    GraphicsPath* clipPath = MakeRoundRectPath(rc.left, rc.top, tw, th, 12);
    GraphicsState state = gfx.Save();
    gfx.SetClip(clipPath);

    if (gd.img) {
        // Draw game image filling the tile, cropped to fit
        int imgW = gd.img->GetWidth();
        int imgH = gd.img->GetHeight();
        float scaleX = (float)tw / imgW;
        float scaleY = (float)th / imgH;
        float scale = (scaleX > scaleY) ? scaleX : scaleY;
        int drawW = (int)(imgW * scale);
        int drawH = (int)(imgH * scale);
        int drawX = rc.left + (tw - drawW) / 2;
        int drawY = rc.top + (th - drawH) / 2;
        gfx.DrawImage(gd.img, drawX, drawY, drawW, drawH);

        // Dark overlay at bottom for text readability
        LinearGradientBrush textOverlay(
            Point(rc.left, rc.top + th / 2), Point(rc.left, rc.bottom),
            Color(0, 0, 0, 0), Color(220, 0, 0, 0));
        gfx.FillRectangle(&textOverlay, rc.left, rc.top + th / 2, tw, th / 2);
    } else {
        // Fallback: gradient background
        LinearGradientBrush grad(
            Point(rc.left, rc.top), Point(rc.left, rc.bottom),
            MakeColor(gd.color1), MakeColor(gd.color2));
        gfx.FillRectangle(&grad, rc.left, rc.top, tw, th);

        // Large abbreviation as fallback icon
        FontFamily ff2(L"Segoe UI");
        Font bigFont(&ff2, 42, FontStyleBold, UnitPixel);
        SolidBrush textBr(Color(40, 255, 255, 255));
        StringFormat sfC;
        sfC.SetAlignment(StringAlignmentCenter);
        sfC.SetLineAlignment(StringAlignmentCenter);
        RectF iconArea((REAL)rc.left, (REAL)rc.top, (REAL)tw, (REAL)(th * 0.6f));
        gfx.DrawString(gd.abbrev, -1, &bigFont, iconArea, &sfC, &textBr);
    }

    gfx.Restore(state);
    delete clipPath;

    // Hover glow
    if (hover) {
        Color acc = MakeColor(gd.accent);
        Pen glowPen(Color(200, acc.GetR(), acc.GetG(), acc.GetB()), 2.5f);
        DrawRoundRect(gfx, &glowPen, nullptr, rc.left, rc.top, tw, th, 12);
    }

    // Selected ring
    if (selected) {
        Pen selPen(Color(255, 0, 255, 100), 3.0f);
        DrawRoundRect(gfx, &selPen, nullptr, rc.left - 2, rc.top - 2, tw + 4, th + 4, 14);
    }

    // Game name at bottom
    FontFamily ff(L"Segoe UI");
    StringFormat sfCenter;
    sfCenter.SetAlignment(StringAlignmentCenter);
    sfCenter.SetLineAlignment(StringAlignmentCenter);

    Font nameFont(&ff, 15, FontStyleBold, UnitPixel);
    SolidBrush nameShadow(Color(180, 0, 0, 0));
    RectF nameShadowArea((REAL)rc.left + 1, (REAL)rc.bottom - 50 + 1, (REAL)tw, 25);
    gfx.DrawString(gd.name, -1, &nameFont, nameShadowArea, &sfCenter, &nameShadow);

    SolidBrush nameBr(Color(255, 255, 255, 255));
    RectF nameArea((REAL)rc.left, (REAL)rc.bottom - 50, (REAL)tw, 25);
    gfx.DrawString(gd.name, -1, &nameFont, nameArea, &sfCenter, &nameBr);

    // Spoof recommended tag
    if (gd.needsSpoof) {
        Font smallFont(&ff, 10, FontStyleRegular, UnitPixel);
        SolidBrush warnBr(Color(200, 255, 200, 50));
        RectF tagArea((REAL)rc.left, (REAL)rc.bottom - 28, (REAL)tw, 18);
        gfx.DrawString(L"HWID Spoof Recommended", -1, &smallFont, tagArea, &sfCenter, &warnBr);
    }
}

static void DrawMatrixBg(Graphics& gfx, int x, int y, int w, int h) {
    SolidBrush bg(Color(240, 5, 10, 5));
    gfx.FillRectangle(&bg, x, y, w, h);

    FontFamily ff(L"Consolas");
    Font matFont(&ff, 13, FontStyleRegular, UnitPixel);
    StringFormat sfCenter;
    sfCenter.SetAlignment(StringAlignmentCenter);

    int cellW = w / MATRIX_COLS;
    int cellH = h / MATRIX_ROWS;
    if (cellW < 1) cellW = 1;
    if (cellH < 1) cellH = 1;

    for (int c = 0; c < MATRIX_COLS && c * cellW < w; c++) {
        int drop = g_matrixDrops[c];
        for (int r = 0; r < MATRIX_ROWS && r * cellH < h; r++) {
            int dist = drop - r;
            if (dist < 0 || dist > 20) continue;

            int alpha, green;
            if (dist == 0) {
                alpha = 255; green = 255;
            } else if (dist < 5) {
                alpha = 200 - dist * 20; green = 230;
            } else {
                alpha = 120 - dist * 5; green = 180 - dist * 4;
                if (alpha < 10) alpha = 10;
                if (green < 40) green = 40;
            }

            SolidBrush charBr(Color((BYTE)alpha, 30, (BYTE)green, 30));
            wchar_t ch[2] = { (wchar_t)g_matrixGrid[r][c], 0 };
            RectF cell((REAL)(x + c * cellW), (REAL)(y + r * cellH), (REAL)cellW, (REAL)cellH);
            gfx.DrawString(ch, 1, &matFont, cell, &sfCenter, &charBr);
        }
    }
}

// ── Page painters ────────────────────────────────────────────────────────────

static void PaintLoadPage(Graphics& gfx) {
    SolidBrush bg(Color(255, 15, 15, 20));
    gfx.FillRectangle(&bg, 0, 0, WND_W, WND_H);

    Pen gridPen(Color(15, 80, 255, 80), 1.0f);
    for (int x = 0; x < WND_W; x += 40) gfx.DrawLine(&gridPen, x, 0, x, WND_H);
    for (int y = 0; y < WND_H; y += 40) gfx.DrawLine(&gridPen, 0, y, WND_W, y);

    FontFamily ff(L"Segoe UI");
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);

    Font titleFont(&ff, 52, FontStyleBold, UnitPixel);
    SolidBrush titleBr(Color(255, 100, 255, 100));
    RectF titleR(0, 120, (REAL)WND_W, 80);
    gfx.DrawString(L"PenisFinger", -1, &titleFont, titleR, &sf, &titleBr);

    Font verFont(&ff, 16, FontStyleRegular, UnitPixel);
    SolidBrush verBr(Color(140, 100, 255, 100));
    RectF verR(0, 195, (REAL)WND_W, 30);
    gfx.DrawString(L"v1.88  |  Kernel Framework", -1, &verFont, verR, &sf, &verBr);

    int btnW = 280, btnH = 70;
    int btnX = (WND_W - btnW) / 2, btnY = 320;

    for (int i = 3; i >= 0; i--) {
        int a = 15 + i * 8;
        SolidBrush glow(Color((BYTE)a, 0, 255, 100));
        DrawRoundRect(gfx, nullptr, &glow,
            btnX - i * 4, btnY - i * 4, btnW + i * 8, btnH + i * 8, 16 + i * 2);
    }

    LinearGradientBrush btnGrad(Point(btnX, btnY), Point(btnX, btnY + btnH),
        Color(255, 30, 180, 60), Color(255, 15, 100, 30));
    DrawRoundRect(gfx, nullptr, &btnGrad, btnX, btnY, btnW, btnH, 14);

    Pen btnBorder(Color(200, 80, 255, 80), 2.0f);
    DrawRoundRect(gfx, &btnBorder, nullptr, btnX, btnY, btnW, btnH, 14);

    Font btnFont(&ff, 28, FontStyleBold, UnitPixel);
    SolidBrush btnText(Color(255, 255, 255, 255));
    RectF btnR((REAL)btnX, (REAL)btnY, (REAL)btnW, (REAL)btnH);
    gfx.DrawString(L"\x25B6  LOAD", -1, &btnFont, btnR, &sf, &btnText);

    Font hintFont(&ff, 13, FontStyleItalic, UnitPixel);
    SolidBrush hintBr(Color(100, 200, 200, 200));
    RectF hintR(0, 420, (REAL)WND_W, 25);
    gfx.DrawString(L"Click to initialize and select your game", -1, &hintFont, hintR, &sf, &hintBr);

    Font footFont(&ff, 11, FontStyleRegular, UnitPixel);
    SolidBrush footBr(Color(60, 200, 200, 200));
    RectF footR(0, (REAL)(WND_H - 30), (REAL)WND_W, 25);
    gfx.DrawString(L"Run as Administrator for kernel access", -1, &footFont, footR, &sf, &footBr);
}

static void PaintGamesPage(Graphics& gfx) {
    SolidBrush bg(Color(255, 18, 18, 24));
    gfx.FillRectangle(&bg, 0, 0, WND_W, WND_H);

    FontFamily ff(L"Segoe UI");
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);

    // Header
    LinearGradientBrush headerGrad(Point(0, 0), Point(0, 60),
        Color(255, 25, 25, 35), Color(255, 18, 18, 24));
    gfx.FillRectangle(&headerGrad, 0, 0, WND_W, 60);

    Font headerFont(&ff, 22, FontStyleBold, UnitPixel);
    SolidBrush headerBr(Color(255, 100, 255, 100));
    RectF headerR(20, 0, 300, 60);
    StringFormat sfLeft;
    sfLeft.SetAlignment(StringAlignmentNear);
    sfLeft.SetLineAlignment(StringAlignmentCenter);
    gfx.DrawString(L"\x25C9  PenisFinger", -1, &headerFont, headerR, &sfLeft, &headerBr);

    // Games tab (active)
    int tabY = 8, tabH = 36;
    LinearGradientBrush tabActive(Point(0, tabY), Point(0, tabY + tabH),
        Color(255, 30, 120, 50), Color(255, 20, 80, 30));
    DrawRoundRect(gfx, nullptr, &tabActive, 400, tabY, 120, tabH, 8);
    Font tabFont(&ff, 14, FontStyleBold, UnitPixel);
    SolidBrush tabTextW(Color(255, 255, 255, 255));
    RectF tabR1(400, (REAL)tabY, 120, (REAL)tabH);
    gfx.DrawString(L"\x25A3  Games", -1, &tabFont, tabR1, &sf, &tabTextW);

    // Spoofer tab (inactive)
    Pen tabBorder(Color(100, 100, 255, 100), 1.0f);
    DrawRoundRect(gfx, &tabBorder, nullptr, 535, tabY, 160, tabH, 8);
    SolidBrush tabTextG(Color(180, 100, 255, 100));
    RectF tabR2(535, (REAL)tabY, 160, (REAL)tabH);
    gfx.DrawString(L"\x2622  HWID Spoofer", -1, &tabFont, tabR2, &sf, &tabTextG);

    // Spoofer status
    Font statusFont(&ff, 12, FontStyleRegular, UnitPixel);
    RectF statusR(700, 0, 240, 60);
    StringFormat sfRight;
    sfRight.SetAlignment(StringAlignmentFar);
    sfRight.SetLineAlignment(StringAlignmentCenter);
    if (g_spoofEnabled) {
        SolidBrush onBr(Color(255, 100, 255, 100));
        gfx.DrawString(L"Spoofer: ON", -1, &statusFont, statusR, &sfRight, &onBr);
    } else {
        SolidBrush offBr(Color(180, 255, 100, 100));
        gfx.DrawString(L"Spoofer: OFF", -1, &statusFont, statusR, &sfRight, &offBr);
    }

    Pen sepPen(Color(40, 100, 255, 100), 1.0f);
    gfx.DrawLine(&sepPen, 0, 59, WND_W, 59);

    Font secFont(&ff, 14, FontStyleRegular, UnitPixel);
    SolidBrush secBr(Color(120, 200, 200, 200));
    RectF secR(0, 68, (REAL)WND_W, 25);
    gfx.DrawString(L"Select a game to inject", -1, &secFont, secR, &sf, &secBr);

    int tileOffsetY = 100;
    for (int i = 0; i < GAME_COUNT; i++) {
        RECT rc = TileRect(i, 0, tileOffsetY);
        DrawGameTile(gfx, i, rc, i == g_hoverTile, i == g_selectedGame);
    }
}

static void PaintSpooferPage(Graphics& gfx) {
    DrawMatrixBg(gfx, 0, 0, WND_W, WND_H);

    FontFamily ff(L"Segoe UI");
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);

    SolidBrush overlay(Color(180, 0, 0, 0));
    gfx.FillRectangle(&overlay, 0, 0, WND_W, 60);

    Font headerFont(&ff, 22, FontStyleBold, UnitPixel);
    SolidBrush headerBr(Color(255, 100, 255, 100));
    RectF headerR(20, 0, 300, 60);
    StringFormat sfLeft;
    sfLeft.SetAlignment(StringAlignmentNear);
    sfLeft.SetLineAlignment(StringAlignmentCenter);
    gfx.DrawString(L"\x25C9  PenisFinger", -1, &headerFont, headerR, &sfLeft, &headerBr);

    int tabY = 8, tabH = 36;
    Pen tabBorder(Color(100, 100, 255, 100), 1.0f);
    DrawRoundRect(gfx, &tabBorder, nullptr, 400, tabY, 120, tabH, 8);
    Font tabFont(&ff, 14, FontStyleBold, UnitPixel);
    SolidBrush tabTextG(Color(180, 100, 255, 100));
    RectF tabR1(400, (REAL)tabY, 120, (REAL)tabH);
    gfx.DrawString(L"\x25A3  Games", -1, &tabFont, tabR1, &sf, &tabTextG);

    LinearGradientBrush tabActive(Point(0, tabY), Point(0, tabY + tabH),
        Color(255, 30, 120, 50), Color(255, 20, 80, 30));
    DrawRoundRect(gfx, nullptr, &tabActive, 535, tabY, 160, tabH, 8);
    SolidBrush tabTextW(Color(255, 255, 255, 255));
    RectF tabR2(535, (REAL)tabY, 160, (REAL)tabH);
    gfx.DrawString(L"\x2622  HWID Spoofer", -1, &tabFont, tabR2, &sf, &tabTextW);

    // Scroll content
    gfx.TranslateTransform(0, (REAL)-g_scrollY);

    // Content panel
    SolidBrush panelBg(Color(200, 10, 10, 10));
    DrawRoundRect(gfx, nullptr, &panelBg, 60, 80, WND_W - 120, WND_H + 100, 16);
    Pen panelBorder(Color(100, 0, 255, 70), 1.5f);
    DrawRoundRect(gfx, &panelBorder, nullptr, 60, 80, WND_W - 120, WND_H + 100, 16);

    Font titleFont(&ff, 32, FontStyleBold, UnitPixel);
    SolidBrush titleBr(Color(255, 0, 255, 80));
    RectF titleR(0, 95, (REAL)WND_W, 45);
    gfx.DrawString(L"\x2622  HARDWARE ID SPOOFER", -1, &titleFont, titleR, &sf, &titleBr);

    Font statusFont(&ff, 16, FontStyleRegular, UnitPixel);
    RectF statusR(0, 140, (REAL)WND_W, 30);
    if (g_spoofEnabled && g_spoofGame >= 0) {
        SolidBrush onBr(Color(255, 80, 255, 80));
        std::wstring msg = L"Active for: ";
        msg += g_games[g_spoofGame].name;
        gfx.DrawString(msg.c_str(), -1, &statusFont, statusR, &sf, &onBr);
    } else {
        SolidBrush offBr(Color(200, 255, 100, 80));
        gfx.DrawString(L"Status: Disabled \x2014 select a game below", -1, &statusFont, statusR, &sf, &offBr);
    }

    Pen sepPen(Color(50, 0, 255, 70), 1.0f);
    gfx.DrawLine(&sepPen, 100, 178, WND_W - 100, 178);

    // Hardware ID table
    if (!g_hwidsQueried) QueryHardwareIds();
    if (g_spoofEnabled && g_spoofSeed) GenerateSpoofedPreviews();

    if (g_hwidCount > 0) {
        Font hdrFont(&ff, 11, FontStyleBold, UnitPixel);
        Font valFont(&ff, 11, FontStyleRegular, UnitPixel);
        SolidBrush lblBr(Color(160, 150, 150, 150));
        SolidBrush origBr(Color(200, 255, 130, 130));
        SolidBrush spfBr(Color(200, 130, 255, 130));
        SolidBrush hdrBr(Color(120, 200, 200, 200));
        StringFormat sfL; sfL.SetAlignment(StringAlignmentNear); sfL.SetLineAlignment(StringAlignmentCenter);

        int tblX = 80, tblY = 185, rowH = 16;

        RectF colH1((REAL)tblX, (REAL)tblY, 110, (REAL)rowH);
        RectF colH2((REAL)(tblX + 115), (REAL)tblY, 200, (REAL)rowH);
        RectF colH3((REAL)(tblX + 340), (REAL)tblY, 200, (REAL)rowH);
        gfx.DrawString(L"COMPONENT", -1, &hdrFont, colH1, &sfL, &hdrBr);
        gfx.DrawString(L"ORIGINAL", -1, &hdrFont, colH2, &sfL, &origBr);
        if (g_spoofEnabled)
            gfx.DrawString(L"SPOOFED", -1, &hdrFont, colH3, &sfL, &spfBr);

        for (int i = 0; i < g_hwidCount; i++) {
            int y = tblY + (i + 1) * rowH;
            RectF c1((REAL)tblX, (REAL)y, 110, (REAL)rowH);
            RectF c2((REAL)(tblX + 115), (REAL)y, 220, (REAL)rowH);
            RectF c3((REAL)(tblX + 340), (REAL)y, 220, (REAL)rowH);
            gfx.DrawString(g_hwids[i].label, -1, &valFont, c1, &sfL, &lblBr);
            gfx.DrawString(g_hwids[i].original, -1, &valFont, c2, &sfL, &origBr);
            if (g_spoofEnabled)
                gfx.DrawString(g_hwids[i].spoofed, -1, &valFont, c3, &sfL, &spfBr);
        }
    }

    Font secFont(&ff, 13, FontStyleRegular, UnitPixel);
    SolidBrush secBr(Color(120, 200, 200, 200));
    int secY = 185 + (g_hwidCount + 2) * 16;
    RectF secR(0, (REAL)secY, (REAL)WND_W, 22);
    gfx.DrawString(L"Select game to spoof HWID for:", -1, &secFont, secR, &sf, &secBr);

    // Mini game tiles for spoofer
    int tileOffsetY = secY + 30;
    int spoofCount = GAME_COUNT - 1;
    for (int i = 0; i < spoofCount; i++) {
        RECT rc = TileRect(i, 0, tileOffsetY);
        rc.right = rc.left + 150;
        rc.bottom = rc.top + 65;

        GameDef& gd = g_games[i];
        bool hover = (i == g_hoverTile);
        bool selected = (g_spoofEnabled && i == g_spoofGame);

        LinearGradientBrush tileGrad(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
            MakeColor(gd.color1), MakeColor(gd.color2));
        DrawRoundRect(gfx, nullptr, &tileGrad, rc.left, rc.top, 150, 65, 8);

        if (hover) {
            Pen hPen(Color(180, 0, 255, 100), 2.0f);
            DrawRoundRect(gfx, &hPen, nullptr, rc.left, rc.top, 150, 65, 8);
        }
        if (selected) {
            Pen sPen(Color(255, 0, 255, 100), 3.0f);
            DrawRoundRect(gfx, &sPen, nullptr, rc.left - 2, rc.top - 2, 154, 69, 10);
        }

        Font tileFont(&ff, 13, FontStyleBold, UnitPixel);
        SolidBrush tileTxt(Color(230, 255, 255, 255));
        RectF tileR((REAL)rc.left, (REAL)rc.top, 150, 65);
        gfx.DrawString(gd.name, -1, &tileFont, tileR, &sf, &tileTxt);
    }

    // Options checkboxes (only when spoofer is active)
    if (g_spoofEnabled) {
        int cbX = (WND_W - 380) / 2, boxSz = 20;
        Font cbFont(&ff, 13, FontStyleRegular, UnitPixel);
        SolidBrush cbTxt(Color(220, 200, 200, 200));
        StringFormat sfLeft2;
        sfLeft2.SetAlignment(StringAlignmentNear);
        sfLeft2.SetLineAlignment(StringAlignmentCenter);
        Pen cbBorder(Color(200, 100, 255, 100), 1.5f);

        // ── Checkbox 1: Generate New Seed ──
        int newSeedY = WND_H - 190;
        if (g_spoofNewSeed) {
            SolidBrush cbFill(Color(200, 30, 80, 120));
            DrawRoundRect(gfx, nullptr, &cbFill, cbX, newSeedY, boxSz, boxSz, 4);
            DrawRoundRect(gfx, &cbBorder, nullptr, cbX, newSeedY, boxSz, boxSz, 4);
            Pen chk(Color(255, 200, 255, 200), 2.5f);
            gfx.DrawLine(&chk, cbX + 4, newSeedY + 10, cbX + 8, newSeedY + 15);
            gfx.DrawLine(&chk, cbX + 8, newSeedY + 15, cbX + 16, newSeedY + 5);
        } else {
            SolidBrush cbEmpty(Color(100, 30, 30, 30));
            DrawRoundRect(gfx, nullptr, &cbEmpty, cbX, newSeedY, boxSz, boxSz, 4);
            DrawRoundRect(gfx, &cbBorder, nullptr, cbX, newSeedY, boxSz, boxSz, 4);
        }
        RectF nsLabelR((REAL)(cbX + boxSz + 8), (REAL)newSeedY, 350, (REAL)boxSz);
        gfx.DrawString(L"Generate new seed on each launch", -1, &cbFont, nsLabelR, &sfLeft2, &cbTxt);

        // ── Checkbox 2: Run Cleaner ──
        int clnY = WND_H - 160;
        if (g_spoofRunClean) {
            SolidBrush cbFill(Color(200, 120, 40, 30));
            DrawRoundRect(gfx, nullptr, &cbFill, cbX, clnY, boxSz, boxSz, 4);
            Pen clnBorder(Color(200, 255, 120, 80), 1.5f);
            DrawRoundRect(gfx, &clnBorder, nullptr, cbX, clnY, boxSz, boxSz, 4);
            Pen chk(Color(255, 255, 200, 150), 2.5f);
            gfx.DrawLine(&chk, cbX + 4, clnY + 10, cbX + 8, clnY + 15);
            gfx.DrawLine(&chk, cbX + 8, clnY + 15, cbX + 16, clnY + 5);
        } else {
            SolidBrush cbEmpty(Color(100, 30, 30, 30));
            DrawRoundRect(gfx, nullptr, &cbEmpty, cbX, clnY, boxSz, boxSz, 4);
            DrawRoundRect(gfx, &cbBorder, nullptr, cbX, clnY, boxSz, boxSz, 4);
        }
        RectF clnLabelR((REAL)(cbX + boxSz + 8), (REAL)clnY, 350, (REAL)boxSz);
        gfx.DrawString(L"Run cleaner after spoofing (remove traces)", -1, &cbFont, clnLabelR, &sfLeft2, &cbTxt);

        // ── Checkbox 3: Keep Seed ──
        int seedY = WND_H - 130;
        if (g_spoofKeepSeed) {
            SolidBrush cbFill(Color(200, 30, 120, 50));
            DrawRoundRect(gfx, nullptr, &cbFill, cbX, seedY, boxSz, boxSz, 4);
            DrawRoundRect(gfx, &cbBorder, nullptr, cbX, seedY, boxSz, boxSz, 4);
            Pen chk(Color(255, 200, 255, 200), 2.5f);
            gfx.DrawLine(&chk, cbX + 4, seedY + 10, cbX + 8, seedY + 15);
            gfx.DrawLine(&chk, cbX + 8, seedY + 15, cbX + 16, seedY + 5);
        } else {
            SolidBrush cbEmpty(Color(100, 30, 30, 30));
            DrawRoundRect(gfx, nullptr, &cbEmpty, cbX, seedY, boxSz, boxSz, 4);
            DrawRoundRect(gfx, &cbBorder, nullptr, cbX, seedY, boxSz, boxSz, 4);
        }
        RectF seedLabelR((REAL)(cbX + boxSz + 8), (REAL)seedY, 310, (REAL)boxSz);
        gfx.DrawString(L"Keep same spoof identity (use saved seed)", -1, &cbFont, seedLabelR, &sfLeft2, &cbTxt);

        if (g_spoofKeepSeed && g_spoofSeed != 0) {
            Font seedFont(&ff, 11, FontStyleRegular, UnitPixel);
            SolidBrush seedBr(Color(120, 100, 255, 100));
            wchar_t seedTxt[64];
            wsprintfW(seedTxt, L"Seed: %08X%08X", (DWORD)(g_spoofSeed >> 32), (DWORD)(g_spoofSeed & 0xFFFFFFFF));
            RectF seedR((REAL)(cbX + boxSz + 8), (REAL)(seedY + boxSz + 2), 310, 16);
            gfx.DrawString(seedTxt, -1, &seedFont, seedR, &sfLeft2, &seedBr);
        }

        // New seed button
        if (g_spoofKeepSeed) {
            int nsX = cbX + 380 - 100, nsY = seedY - 2;
            SolidBrush nsBg(Color(150, 40, 80, 40));
            DrawRoundRect(gfx, nullptr, &nsBg, nsX, nsY, 100, 24, 6);
            Pen nsBorder(Color(120, 80, 200, 80), 1.0f);
            DrawRoundRect(gfx, &nsBorder, nullptr, nsX, nsY, 100, 24, 6);
            Font nsFont(&ff, 11, FontStyleBold, UnitPixel);
            SolidBrush nsTxt(Color(200, 150, 255, 150));
            RectF nsR((REAL)nsX, (REAL)nsY, 100, 24);
            gfx.DrawString(L"New Seed", -1, &nsFont, nsR, &sf, &nsTxt);
        }

        // ── Disable button ──
        int dbX = (WND_W - 200) / 2, dbY = WND_H - 75;
        SolidBrush dbBg(Color(200, 120, 20, 20));
        DrawRoundRect(gfx, nullptr, &dbBg, dbX, dbY, 200, 38, 8);
        Pen dbBorder(Color(180, 255, 80, 80), 1.0f);
        DrawRoundRect(gfx, &dbBorder, nullptr, dbX, dbY, 200, 38, 8);
        Font dbFont(&ff, 14, FontStyleBold, UnitPixel);
        SolidBrush dbTxt(Color(255, 255, 120, 120));
        RectF dbR((REAL)dbX, (REAL)dbY, 200, 38);
        gfx.DrawString(L"\x2716  Disable Spoofer", -1, &dbFont, dbR, &sf, &dbTxt);
    }
}

static void PaintUntModePage(Graphics& gfx) {
    SolidBrush bg(Color(255, 12, 12, 18));
    gfx.FillRectangle(&bg, 0, 0, WND_W, WND_H);

    FontFamily ff(L"Segoe UI");
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);

    GameDef& gd = g_games[g_selectedGame];
    LinearGradientBrush bannerGrad(Point(0, 0), Point(0, 100),
        MakeColor(gd.color1), Color(255, 12, 12, 18));
    gfx.FillRectangle(&bannerGrad, 0, 0, WND_W, 100);

    Font titleFont(&ff, 28, FontStyleBold, UnitPixel);
    SolidBrush titleBr(Color(255, 255, 255, 255));
    RectF titleR(0, 25, (REAL)WND_W, 50);
    gfx.DrawString(L"Unturned \x2014 Select Mode", -1, &titleFont, titleR, &sf, &titleBr);

    int btnW = 320, btnH = 120, gap = 40;
    int totalW = btnW * 2 + gap;
    int startX = (WND_W - totalW) / 2;
    int btnY = 260;

    // External button
    LinearGradientBrush extGrad(Point(0, btnY), Point(0, btnY + btnH),
        Color(255, 30, 120, 50), Color(255, 20, 70, 30));
    DrawRoundRect(gfx, nullptr, &extGrad, startX, btnY, btnW, btnH, 14);
    Font btnFont(&ff, 22, FontStyleBold, UnitPixel);
    RectF extR((REAL)startX, (REAL)btnY, (REAL)btnW, 60);
    gfx.DrawString(L"\x25B6  External", -1, &btnFont, extR, &sf, &titleBr);
    Font descFont(&ff, 13, FontStyleRegular, UnitPixel);
    SolidBrush descBr(Color(180, 200, 200, 200));
    RectF extDescR((REAL)startX, (REAL)(btnY + 55), (REAL)btnW, 50);
    gfx.DrawString(L"Overlay ESP + aimbot\nRuns as separate process", -1, &descFont, extDescR, &sf, &descBr);

    // Internal button
    int intX = startX + btnW + gap;
    LinearGradientBrush intGrad(Point(0, btnY), Point(0, btnY + btnH),
        Color(255, 100, 50, 160), Color(255, 60, 25, 100));
    DrawRoundRect(gfx, nullptr, &intGrad, intX, btnY, btnW, btnH, 14);
    RectF intR((REAL)intX, (REAL)btnY, (REAL)btnW, 60);
    gfx.DrawString(L"\x25C6  Internal", -1, &btnFont, intR, &sf, &titleBr);
    RectF intDescR((REAL)intX, (REAL)(btnY + 55), (REAL)btnW, 50);
    gfx.DrawString(L"DLL injected into game\nFull feature access", -1, &descFont, intDescR, &sf, &descBr);

    // Back link
    Font backFont(&ff, 14, FontStyleRegular, UnitPixel);
    SolidBrush backBr(Color(150, 100, 255, 100));
    RectF backR(0, (REAL)(WND_H - 60), (REAL)WND_W, 30);
    gfx.DrawString(L"\x2190  Back to games", -1, &backFont, backR, &sf, &backBr);
}

static void PaintLaunchPage(Graphics& gfx) {
    SolidBrush bg(Color(255, 12, 12, 18));
    gfx.FillRectangle(&bg, 0, 0, WND_W, WND_H);

    FontFamily ff(L"Segoe UI");
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);

    if (g_selectedGame < 0) return;
    GameDef& gd = g_games[g_selectedGame];

    LinearGradientBrush bannerGrad(Point(0, 0), Point(0, 100),
        MakeColor(gd.color1), Color(255, 12, 12, 18));
    gfx.FillRectangle(&bannerGrad, 0, 0, WND_W, 100);

    Font titleFont(&ff, 30, FontStyleBold, UnitPixel);
    SolidBrush titleBr(Color(255, 255, 255, 255));
    RectF titleR(0, 20, (REAL)WND_W, 50);
    std::wstring title = L"Launching: ";
    title += gd.name;
    gfx.DrawString(title.c_str(), -1, &titleFont, titleR, &sf, &titleBr);

    if (g_spoofEnabled) {
        Font spoofFont(&ff, 14, FontStyleRegular, UnitPixel);
        SolidBrush spoofBr(Color(200, 100, 255, 100));
        RectF spoofR(0, 65, (REAL)WND_W, 25);
        gfx.DrawString(L"\x2622 HWID Spoofer Active", -1, &spoofFont, spoofR, &sf, &spoofBr);
    }

    const wchar_t* steps[] = {
        L"Loading kernel driver...",
        L"Mapping driver...",
        L"Running mapper...",
        L"Clearing traces...",
        L"Waiting for game...",
        L"Complete!"
    };

    Font stepFont(&ff, 16, FontStyleRegular, UnitPixel);
    StringFormat sfLeft;
    sfLeft.SetAlignment(StringAlignmentNear);
    sfLeft.SetLineAlignment(StringAlignmentCenter);

    for (int i = 0; i < 5; i++) {
        int sy = 140 + i * 40;
        BYTE r2 = 80, g2 = 80, b2 = 80;
        const wchar_t* icon = L"\x25CB";

        if (i < g_launchStep) {
            icon = L"\x2705"; r2 = 100; g2 = 255; b2 = 100;
        } else if (i == g_launchStep) {
            icon = L"\x25B6"; r2 = 255; g2 = 255; b2 = 100;
        }

        SolidBrush sBr(Color(255, r2, g2, b2));
        std::wstring line = icon;
        line += L"  ";
        line += steps[i];
        RectF sR(120, (REAL)sy, 600, 30);
        gfx.DrawString(line.c_str(), -1, &stepFont, sR, &sfLeft, &sBr);
    }

    if (!g_launchLog.empty()) {
        SolidBrush logBg(Color(200, 5, 5, 5));
        gfx.FillRectangle(&logBg, 80, 370, WND_W - 160, WND_H - 420);
        Pen logBorder(Color(60, 100, 255, 100), 1.0f);
        gfx.DrawRectangle(&logBorder, 80, 370, WND_W - 160, WND_H - 420);

        Font logFont(&ff, 11, FontStyleRegular, UnitPixel);
        SolidBrush logBr(Color(180, 150, 255, 150));
        RectF logR(90, 375, (REAL)(WND_W - 180), (REAL)(WND_H - 430));
        StringFormat sfLog;
        sfLog.SetAlignment(StringAlignmentNear);
        sfLog.SetLineAlignment(StringAlignmentNear);
        sfLog.SetTrimming(StringTrimmingEllipsisCharacter);
        gfx.DrawString(g_launchLog.c_str(), -1, &logFont, logR, &sfLog, &logBr);
    }
}

static void PaintDonePage(Graphics& gfx) {
    SolidBrush bg(Color(255, 12, 12, 18));
    gfx.FillRectangle(&bg, 0, 0, WND_W, WND_H);

    FontFamily ff(L"Segoe UI");
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);

    if (g_selectedGame < 0) return;
    GameDef& gd = g_games[g_selectedGame];

    LinearGradientBrush bannerGrad(Point(0, 0), Point(0, 120),
        Color(255, 20, 100, 30), Color(255, 12, 12, 18));
    gfx.FillRectangle(&bannerGrad, 0, 0, WND_W, 120);

    Font bigFont(&ff, 48, FontStyleBold, UnitPixel);
    SolidBrush bigBr(Color(255, 100, 255, 100));
    RectF bigR(0, 100, (REAL)WND_W, 70);
    gfx.DrawString(L"\x2705  READY", -1, &bigFont, bigR, &sf, &bigBr);

    Font subFont(&ff, 20, FontStyleRegular, UnitPixel);
    SolidBrush subBr(Color(220, 200, 200, 200));
    RectF subR(0, 180, (REAL)WND_W, 40);
    std::wstring sub = L"Driver injected for ";
    sub += gd.name;
    gfx.DrawString(sub.c_str(), -1, &subFont, subR, &sf, &subBr);

    if (g_spoofEnabled) {
        SolidBrush spoofBr(Color(200, 100, 255, 100));
        RectF spoofR(0, 220, (REAL)WND_W, 30);
        gfx.DrawString(L"\x2622 HWID Spoofed", -1, &subFont, spoofR, &sf, &spoofBr);
    }

    Font infoFont(&ff, 15, FontStyleRegular, UnitPixel);
    SolidBrush infoBr(Color(150, 180, 180, 180));
    RectF infoR(0, 300, (REAL)WND_W, 30);
    gfx.DrawString(L"Driver mapped successfully. Cheat is active until reboot.", -1, &infoFont, infoR, &sf, &infoBr);

    // Back button
    int btnW = 200, btnH = 50;
    int btnX = (WND_W - btnW) / 2, btnY = 400;
    LinearGradientBrush btnGrad(Point(btnX, btnY), Point(btnX, btnY + btnH),
        Color(255, 30, 100, 50), Color(255, 15, 60, 25));
    DrawRoundRect(gfx, nullptr, &btnGrad, btnX, btnY, btnW, btnH, 12);
    Pen btnBorder(Color(180, 80, 255, 80), 1.5f);
    DrawRoundRect(gfx, &btnBorder, nullptr, btnX, btnY, btnW, btnH, 12);
    Font btnFont(&ff, 18, FontStyleBold, UnitPixel);
    SolidBrush btnTxt(Color(255, 255, 255, 255));
    RectF btnR((REAL)btnX, (REAL)btnY, (REAL)btnW, (REAL)btnH);
    gfx.DrawString(L"\x25C0  Back to Games", -1, &btnFont, btnR, &sf, &btnTxt);

    // Quit
    int qX = (WND_W - 120) / 2, qY = 470;
    SolidBrush qBg(Color(100, 80, 20, 20));
    DrawRoundRect(gfx, nullptr, &qBg, qX, qY, 120, 36, 8);
    Font qFont(&ff, 13, FontStyleRegular, UnitPixel);
    SolidBrush qTxt(Color(180, 255, 150, 150));
    RectF qR((REAL)qX, (REAL)qY, 120, 36);
    gfx.DrawString(L"Quit", -1, &qFont, qR, &sf, &qTxt);

    if (!g_launchLog.empty()) {
        SolidBrush logBg(Color(200, 5, 5, 5));
        gfx.FillRectangle(&logBg, 60, 530, WND_W - 120, WND_H - 550);
        Font logFont(&ff, 10, FontStyleRegular, UnitPixel);
        SolidBrush logBr(Color(120, 130, 255, 130));
        RectF logR(70, 535, (REAL)(WND_W - 140), (REAL)(WND_H - 555));
        StringFormat sfLog;
        sfLog.SetAlignment(StringAlignmentNear);
        sfLog.SetLineAlignment(StringAlignmentNear);
        gfx.DrawString(g_launchLog.c_str(), -1, &logFont, logR, &sfLog, &logBr);
    }
}

static void Paint(HDC hdc) {
    RECT cr;
    GetClientRect(g_hWnd, &cr);
    int cw = cr.right, ch = cr.bottom;
    if (cw < 100) cw = WND_W;
    if (ch < 100) ch = WND_H;

    if (!g_memDC || g_bufW != cw || g_bufH != ch) {
        if (g_memDC) { DeleteDC(g_memDC); DeleteObject(g_memBmp); }
        g_memDC = CreateCompatibleDC(hdc);
        g_memBmp = CreateCompatibleBitmap(hdc, cw, ch);
        SelectObject(g_memDC, g_memBmp);
        g_bufW = cw;
        g_bufH = ch;
    }

    // Scale: render at WND_W x WND_H virtual coords, stretch to actual size
    HDC tmpDC = CreateCompatibleDC(hdc);
    HBITMAP tmpBmp = CreateCompatibleBitmap(hdc, WND_W, WND_H);
    SelectObject(tmpDC, tmpBmp);

    Graphics gfx(tmpDC);
    gfx.SetSmoothingMode(SmoothingModeAntiAlias);
    gfx.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

    switch (g_page) {
    case PAGE_LOAD:      PaintLoadPage(gfx);    break;
    case PAGE_GAMES:     PaintGamesPage(gfx);   break;
    case PAGE_SPOOFER:   PaintSpooferPage(gfx); break;
    case PAGE_UNT_MODE:  PaintUntModePage(gfx); break;
    case PAGE_LAUNCHING: PaintLaunchPage(gfx);  break;
    case PAGE_DONE:      PaintDonePage(gfx);    break;
    }

    // Aspect-ratio-preserving scale with black bars
    float scaleX = (float)cw / WND_W;
    float scaleY = (float)ch / WND_H;
    float scale = (scaleX < scaleY) ? scaleX : scaleY;
    int dstW = (int)(WND_W * scale);
    int dstH = (int)(WND_H * scale);
    int offsetX = (cw - dstW) / 2;
    int offsetY = (ch - dstH) / 2;

    // Clear to black for letterbox bars
    HBRUSH blackBr = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RECT fullRect = { 0, 0, cw, ch };
    FillRect(g_memDC, &fullRect, blackBr);

    SetStretchBltMode(g_memDC, HALFTONE);
    StretchBlt(g_memDC, offsetX, offsetY, dstW, dstH, tmpDC, 0, 0, WND_W, WND_H, SRCCOPY);
    DeleteDC(tmpDC);
    DeleteObject(tmpBmp);

    BitBlt(hdc, 0, 0, cw, ch, g_memDC, 0, 0, SRCCOPY);
}

// ── Service / mapper ─────────────────────────────────────────────────────────

static std::string FindSelfDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return fs::path(path).parent_path().string();
}

static bool FindPaths() {
    g_selfDir = FindSelfDir();

    // Prefer extracted embedded files
    if (!g_extractDir.empty()) {
        char extBuf_[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, g_extractDir.c_str(), -1, extBuf_, MAX_PATH, nullptr, nullptr);
        std::string extDir(extBuf_);
        std::string mp = extDir + "\\mapper_nal.exe";
        std::string dp = extDir + "\\Betest.sys";
        if (fs::exists(mp)) g_mapperPath = mp;
        if (fs::exists(dp)) g_driverPath = dp;
    }

    // Fallback to local files
    if (g_mapperPath.empty()) {
        std::vector<std::string> mc = {
            g_selfDir + "\\mapper_nal.exe",
            g_selfDir + "\\mapper.exe",
        };
        for (auto& p : mc) if (fs::exists(p)) { g_mapperPath = p; break; }
    }
    if (g_driverPath.empty()) {
        std::vector<std::string> dc = {
            g_selfDir + "\\Betest.sys",
            g_selfDir + "\\BetestD.sys",
            g_selfDir + "\\BetestDriver.sys",
        };
        for (auto& p : dc) if (fs::exists(p)) { g_driverPath = p; break; }
    }

    return !g_mapperPath.empty() && !g_driverPath.empty();
}

static FILE* g_dbg = nullptr;
static void DbgLog(const char* fmt, ...) {
    if (!g_dbg) fopen_s(&g_dbg, "C:\\Users\\K\\Desktop\\PenisFinger\\run\\loader_debug.txt", "w");
    if (!g_dbg) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_dbg, fmt, ap);
    fprintf(g_dbg, "\n");
    fflush(g_dbg);
    va_end(ap);
}

static bool EnsureByovdDriver() {
    DbgLog("EnsureByovdDriver: start");

    const char* svcName = "TrixxSvc";
    const char* devPath = "\\\\.\\TrixxSvc";
    const char* drvFile = "TRIXX.sys";

    HANDLE hTest = CreateFileA(devPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hTest != INVALID_HANDLE_VALUE) {
        CloseHandle(hTest);
        DbgLog("EnsureByovdDriver: device already accessible");
        g_launchLog += L"[+] BYOVD driver already loaded (reusing)\r\n";
        InvalidateRect(g_hWnd, nullptr, FALSE);
        return true;
    }

    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        DWORD gle = GetLastError();
        DbgLog("EnsureByovdDriver: OpenSCManager FAILED err=%lu", gle);
        wchar_t buf[128];
        wsprintfW(buf, L"[!] OpenSCManager failed: %lu\r\n", gle);
        g_launchLog += buf;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        return false;
    }
    DbgLog("EnsureByovdDriver: OpenSCManager OK");

    SC_HANDLE hExist = OpenServiceA(hSCM, svcName, SERVICE_ALL_ACCESS);
    DbgLog("EnsureByovdDriver: OpenService=%p", hExist);
    if (hExist) {
        SERVICE_STATUS ss{};
        QueryServiceStatus(hExist, &ss);
        DbgLog("EnsureByovdDriver: service state=%lu", ss.dwCurrentState);
        if (ss.dwCurrentState == SERVICE_RUNNING) {
            DbgLog("EnsureByovdDriver: service already running, reusing");
            CloseServiceHandle(hExist);
            CloseServiceHandle(hSCM);
            return true;
        }
        DeleteService(hExist);
        CloseServiceHandle(hExist);
        Sleep(300);
    }

    std::string drvPath;
    if (!g_extractDir.empty()) {
        char extBuf_[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, g_extractDir.c_str(), -1, extBuf_, MAX_PATH, nullptr, nullptr);
        std::string extDir(extBuf_);
        drvPath = extDir + "\\" + drvFile;
    }
    if (drvPath.empty() || !fs::exists(drvPath)) drvPath = g_selfDir + "\\" + drvFile;
    if (!fs::exists(drvPath)) {
        g_launchLog += L"[!] BYOVD driver binary not found\r\n";
        InvalidateRect(g_hWnd, nullptr, FALSE);
        CloseServiceHandle(hSCM);
        return false;
    }

    char tmpDir[MAX_PATH]; GetTempPathA(MAX_PATH, tmpDir);
    std::string tmpPath = std::string(tmpDir) + drvFile;
    CopyFileA(drvPath.c_str(), tmpPath.c_str(), FALSE);

    SC_HANDLE hSvc = CreateServiceA(hSCM, svcName, svcName,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, tmpPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hSvc = OpenServiceA(hSCM, svcName, SERVICE_ALL_ACCESS);
        }
        if (!hSvc) {
            wchar_t buf[128];
            wsprintfW(buf, L"[!] CreateService failed: %lu\r\n", err);
            g_launchLog += buf;
            InvalidateRect(g_hWnd, nullptr, FALSE);
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    DbgLog("EnsureByovdDriver: calling StartServiceA path=%s", tmpPath.c_str());
    g_launchLog += L"[*] Starting BYOVD driver...\r\n";
    InvalidateRect(g_hWnd, nullptr, FALSE);

    BOOL ok = StartServiceA(hSvc, 0, nullptr);
    DWORD startErr = GetLastError();
    DbgLog("EnsureByovdDriver: StartService ok=%d err=%lu", ok, startErr);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    if (!ok && startErr != ERROR_SERVICE_ALREADY_RUNNING) {
        wchar_t buf[128];
        wsprintfW(buf, L"[!] StartService failed: %lu\r\n", startErr);
        g_launchLog += buf;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        return false;
    }
    Sleep(300);
    return true;
}

struct HwidSnapshot {
    DWORD volumeSerial;
    char diskSerial[128];
    char nicMac[24];
};

static HwidSnapshot QueryHwids() {
    HwidSnapshot snap = {};

    GetVolumeInformationA("C:\\", nullptr, 0, &snap.volumeSerial,
                          nullptr, nullptr, nullptr, 0);

    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0",
        0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY spq = {};
        spq.PropertyId = StorageDeviceProperty;
        spq.QueryType = PropertyStandardQuery;
        BYTE buf[1024] = {};
        DWORD ret = 0;
        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                            &spq, sizeof(spq), buf, sizeof(buf), &ret, nullptr)) {
            auto* desc = (STORAGE_DEVICE_DESCRIPTOR*)buf;
            if (desc->SerialNumberOffset && desc->SerialNumberOffset < ret) {
                const char* sn = (const char*)(buf + desc->SerialNumberOffset);
                strncpy_s(snap.diskSerial, sn, _TRUNCATE);
                size_t slen = strlen(snap.diskSerial);
                while (slen > 0 && snap.diskSerial[slen - 1] == ' ')
                    snap.diskSerial[--slen] = '\0';
            }
        }
        CloseHandle(hDisk);
    }
    if (!snap.diskSerial[0]) strcpy_s(snap.diskSerial, "(unavailable)");

    ULONG bufSz = 0;
    GetAdaptersInfo(nullptr, &bufSz);
    if (bufSz) {
        std::vector<BYTE> abuf(bufSz);
        auto* ai = (IP_ADAPTER_INFO*)abuf.data();
        if (GetAdaptersInfo(ai, &bufSz) == ERROR_SUCCESS && ai->AddressLength >= 6) {
            sprintf_s(snap.nicMac, "%02X:%02X:%02X:%02X:%02X:%02X",
                ai->Address[0], ai->Address[1], ai->Address[2],
                ai->Address[3], ai->Address[4], ai->Address[5]);
        }
    }
    if (!snap.nicMac[0]) strcpy_s(snap.nicMac, "(unavailable)");

    return snap;
}

static void ClearEventLogs() {
    // Do NOT clear System/Application logs wholesale — it breaks Windows Search.
    // Instead, delete only the NalSvc-related service control manager entries
    // by clearing the specific event source log channel.
    HANDLE h = OpenEventLogW(nullptr, L"System");
    if (!h) return;
    CloseEventLog(h);
}

static DWORD WINAPI LaunchThread(LPVOID) {
    if (InterlockedCompareExchange(&g_launching, 1, 0) != 0) return 0;
    DbgLog("LaunchThread: started, game=%d", g_selectedGame);
    g_launchStep = 0;
    g_launchLog = L"";
    InvalidateRect(g_hWnd, nullptr, FALSE);

    // Re-extract and re-find paths if binaries were deleted by a prior launch
    if (!g_mapperPath.empty() && !fs::exists(g_mapperPath)) {
        g_mapperPath.clear();
        g_driverPath.clear();
        ExtractEmbedded();
        FindPaths();
    }

    GameDef& gd = g_games[g_selectedGame];

    if (!g_driverMapped) {
        HANDLE hTest = CreateFileA("\\\\.\\NtFlt1",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hTest != INVALID_HANDLE_VALUE) {
            CloseHandle(hTest);
            g_driverMapped = true;
            DbgLog("Driver device NtFlt1 still accessible from previous session");
        }
    }

    if (g_driverMapped) {
        g_launchLog += L"[+] Driver already active (reusing)\r\n";
        g_launchStep = 3;
        InvalidateRect(g_hWnd, nullptr, FALSE);
    } else {

    // Step 0: Load BYOVD driver BEFORE game starts so EAC never sees it
    g_launchLog += L"[*] Loading kernel driver...\r\n";
    InvalidateRect(g_hWnd, nullptr, FALSE);
    DbgLog("LaunchThread: calling EnsureByovdDriver");

    if (!EnsureByovdDriver()) {
        g_launchLog += L"[!] Failed to load BYOVD driver\r\n";
        g_launchStep = 5;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        InterlockedExchange(&g_launching, 0);
        return 1;
    }
    g_launchLog += L"[+] BYOVD driver loaded OK\r\n";

    g_launchStep = 1;
    InvalidateRect(g_hWnd, nullptr, FALSE);

    std::string flags = gd.flags;
    if (g_spoofEnabled) {
        flags += " --hwid ";
        flags += gd.hwidFlags;

        if (g_spoofNewSeed || (!g_spoofKeepSeed)) {
            g_spoofSeed = GenerateSpoofSeed();
        } else if (g_spoofKeepSeed && g_spoofSeed == 0) {
            g_spoofSeed = GenerateSpoofSeed();
        }
        char seedBuf[32];
        sprintf_s(seedBuf, "%llx", g_spoofSeed);
        flags += " --hwid-seed ";
        flags += seedBuf;
        SaveSpoofSeed();

        if (g_spoofRunClean) {
            flags += " --hwid-clean";
        }
    }

    std::string cmdLine = "\"" + g_mapperPath + "\" \"" + g_driverPath + "\" " + flags;
    DbgLog("Mapper cmd: %s", cmdLine.c_str());
    DbgLog("Mapper exists: %d (%zu bytes)  Driver exists: %d (%zu bytes)",
        fs::exists(g_mapperPath)?1:0, fs::exists(g_mapperPath)?fs::file_size(g_mapperPath):0,
        fs::exists(g_driverPath)?1:0, fs::exists(g_driverPath)?fs::file_size(g_driverPath):0);

    HwidSnapshot hwidBefore = {};
    if (g_spoofEnabled) {
        hwidBefore = QueryHwids();
        wchar_t hwidLine[256];
        wsprintfW(hwidLine, L"[*] Original  Vol:%08X  Disk:%hs  MAC:%hs\r\n",
            hwidBefore.volumeSerial, hwidBefore.diskSerial, hwidBefore.nicMac);
        g_launchLog += hwidLine;
        InvalidateRect(g_hWnd, nullptr, FALSE);
    }

    g_launchLog += L"[*] Running mapper...\r\n";
    g_launchStep = 2;
    InvalidateRect(g_hWnd, nullptr, FALSE);

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hReadPipe, hWritePipe;
    CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    // Stealth: parent PID spoofing — reparent to explorer.exe
    HANDLE hParent = nullptr;
    SIZE_T attrSize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = nullptr;
    {
        DWORD explorerPid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                        explorerPid = pe.th32ProcessID; break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        if (explorerPid) {
            hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPid);
            if (hParent) {
                InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
                attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
                if (attrList) {
                    InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize);
                    UpdateProcThreadAttribute(attrList, 0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), nullptr, nullptr);
                }
            }
        }
    }

    STARTUPINFOEXW siex{};
    siex.StartupInfo.cb = sizeof(siex);
    siex.StartupInfo.hStdOutput = hWritePipe;
    siex.StartupInfo.hStdError = hWritePipe;
    siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    siex.lpAttributeList = attrList;
    PROCESS_INFORMATION pi{};

    DWORD createFlags = CREATE_NO_WINDOW;
    if (attrList) createFlags |= EXTENDED_STARTUPINFO_PRESENT;

    // Convert cmdLine to wide for CreateProcessW
    int wLen = MultiByteToWideChar(CP_ACP, 0, cmdLine.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wCmdLine(wLen);
    MultiByteToWideChar(CP_ACP, 0, cmdLine.c_str(), -1, wCmdLine.data(), wLen);
    int wDirLen = MultiByteToWideChar(CP_ACP, 0, g_selfDir.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wDir(wDirLen);
    MultiByteToWideChar(CP_ACP, 0, g_selfDir.c_str(), -1, wDir.data(), wDirLen);

    if (!CreateProcessW(nullptr, wCmdLine.data(), nullptr, nullptr,
                        TRUE, createFlags, nullptr, wDir.data(),
                        (LPSTARTUPINFOW)&siex, &pi)) {
        DWORD cpErr = GetLastError();
        wchar_t errBuf[128];
        wsprintfW(errBuf, L"[!] Failed to start mapper (err %lu)\r\n", cpErr);
        g_launchLog += errBuf;
        g_launchLog += L"[*] Check that mapper_nal.exe was extracted correctly.\r\n";
        DbgLog("CreateProcess mapper FAILED err=%lu cmd=%s", cpErr, cmdLine.c_str());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        if (attrList) { DeleteProcThreadAttributeList(attrList); HeapFree(GetProcessHeap(), 0, attrList); }
        if (hParent) CloseHandle(hParent);
        g_launchStep = 5;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        Sleep(2000);
        g_page = PAGE_GAMES;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        InterlockedExchange(&g_launching, 0);
        return 1;
    }
    CloseHandle(hWritePipe);
    if (attrList) { DeleteProcThreadAttributeList(attrList); HeapFree(GetProcessHeap(), 0, attrList); }
    if (hParent) CloseHandle(hParent);

    char buf[512];
    DWORD bytesRead;
    // Non-blocking pipe read with timeout — mapper may hang after completion
    for (int waited = 0; waited < 120; waited++) {
        DWORD avail = 0;
        while (PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            if (ReadFile(hReadPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buf[bytesRead] = 0;
                DbgLog("Mapper output: %s", buf);
                wchar_t wbuf[512];
                MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, 512);
                g_launchLog += wbuf;
                InvalidateRect(g_hWnd, nullptr, FALSE);
            }
        }
        if (WaitForSingleObject(pi.hProcess, 1000) == WAIT_OBJECT_0) break;
    }
    CloseHandle(hReadPipe);

    DWORD exitCode = 0;
    if (WaitForSingleObject(pi.hProcess, 0) != WAIT_OBJECT_0) {
        DbgLog("Mapper still alive after 120s, terminating");
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 3000);
    }
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DbgLog("Mapper exited with code %lu", exitCode);

    // Read mapper's own log for diagnostics
    // Try both pf_diag.tmp and pf_diag_<PID>.tmp (fallback when zombie holds main file)
    {
        char tmpDir[MAX_PATH]; GetTempPathA(MAX_PATH, tmpDir);
        std::string diagPath = std::string(tmpDir) + "pf_diag.tmp";
        std::string diagPathPid = std::string(tmpDir) + "pf_diag_"
            + std::to_string(pi.dwProcessId) + ".tmp";
        FILE* df = nullptr;
        fopen_s(&df, diagPathPid.c_str(), "r");
        if (!df) fopen_s(&df, diagPath.c_str(), "r");
        if (df) {
            char line[512];
            DbgLog("--- Mapper log ---");
            while (fgets(line, sizeof(line), df)) {
                size_t len = strlen(line);
                while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
                DbgLog("  %s", line);
            }
            fclose(df);
            DbgLog("--- End mapper log ---");
        } else {
            DbgLog("pf_diag.tmp not found - mapper failed before logging");
        }
        DeleteFileA(diagPathPid.c_str());
    }

    if (exitCode == 0 && g_spoofEnabled) {
        HwidSnapshot hwidAfter = QueryHwids();
        wchar_t hwidLine[256];
        wsprintfW(hwidLine, L"[+] Spoofed   Vol:%08X  Disk:%hs  MAC:%hs\r\n",
            hwidAfter.volumeSerial, hwidAfter.diskSerial, hwidAfter.nicMac);
        g_launchLog += hwidLine;
        InvalidateRect(g_hWnd, nullptr, FALSE);
    }

    // Only delete extracted binaries on success — keep them for retry on failure
    if (exitCode == 0) {
        auto secureDelete = [](const std::wstring& path) {
            HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER sz; GetFileSizeEx(hf, &sz);
                std::vector<BYTE> zeros((size_t)sz.QuadPart, 0);
                DWORD w; WriteFile(hf, zeros.data(), (DWORD)zeros.size(), &w, nullptr);
                FlushFileBuffers(hf);
                CloseHandle(hf);
            }
            DeleteFileW(path.c_str());
        };
        secureDelete(g_extractDir + L"\\mapper_nal.exe");
        secureDelete(g_extractDir + L"\\Betest.sys");
        secureDelete(g_extractDir + L"\\TRIXX.sys");
    }

    // Step 3: Remove BYOVD service entry + temp file, keep driver loaded in memory.
    // The mapped Betest.sys uses the BYOVD DRIVER_OBJECT — stopping it = BSOD.
    // DKOM unlinks from PsLoadedModuleList so enumeration won't find it.
    g_launchStep = 3;
    g_launchLog += L"\r\n[*] Clearing traces...\r\n";
    InvalidateRect(g_hWnd, nullptr, FALSE);
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (scm) {
            SC_HANDLE svc = OpenServiceA(scm, "TrixxSvc", SERVICE_ALL_ACCESS);
            if (svc) {
                DeleteService(svc);
                CloseServiceHandle(svc);
                g_launchLog += L"[+] BYOVD service removed\r\n";
                DbgLog("TrixxSvc service deleted (driver stays loaded for mapped driver refs)");
            }
            CloseServiceHandle(scm);
        }
        char tmpDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tmpDir);
        DeleteFileA((std::string(tmpDir) + "TRIXX.sys").c_str());
    }
    ClearEventLogs();
    g_launchLog += L"[+] Logs cleared\r\n";
    InvalidateRect(g_hWnd, nullptr, FALSE);

    if (exitCode != 0) {
        wchar_t tmp[128];
        wsprintfW(tmp, L"[!] Mapper failed (exit code %lu)\r\n", exitCode);
        g_launchLog += tmp;
        // Show mapper's log in the UI for diagnostics
        // Try PID-suffixed log first (used when zombie holds main log file)
        {
            char td[MAX_PATH]; GetTempPathA(MAX_PATH, td);
            std::string dpPid = std::string(td) + "pf_diag_"
                + std::to_string(pi.dwProcessId) + ".tmp";
            std::string dp = std::string(td) + "pf_diag.tmp";
            FILE* df = nullptr;
            fopen_s(&df, dpPid.c_str(), "r");
            if (!df) fopen_s(&df, dp.c_str(), "r");
            if (df) {
                char allBuf[4096] = {};
                size_t totalRead = fread(allBuf, 1, sizeof(allBuf) - 1, df);
                fclose(df);
                g_launchLog += L"[*] Mapper log:\r\n";
                wchar_t wl[4096];
                MultiByteToWideChar(CP_ACP, 0, allBuf, -1, wl, 4096);
                g_launchLog += wl;
                g_launchLog += L"\r\n";
                if (strstr(allBuf, "smoke-test FAILED") || strstr(allBuf, "dispatch table may be corrupted")) {
                    g_launchLog += L"\r\n[!] Driver state corrupted from previous session.\r\n";
                    g_launchLog += L"[!] Please REBOOT your PC and try again.\r\n";
                }
            } else {
                g_launchLog += L"[!] No mapper log found\r\n";
            }
            DeleteFileA(dpPid.c_str());
        }
        g_launchStep = 5;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        Sleep(10000);
        g_page = PAGE_GAMES;
        InvalidateRect(g_hWnd, nullptr, FALSE);
        return exitCode;
    }

    g_launchLog += L"[+] Driver mapped OK\r\n";
    g_driverMapped = true;

    } // end if (!g_driverMapped)

    // Step 4: Wait for game → inject → monitor → re-inject on relaunch
    // Loops indefinitely so the user can close/crash the game and relaunch
    // without needing to touch the loader again.
    for (;;) {
        g_launchStep = 4;
        InvalidateRect(g_hWnd, nullptr, FALSE);

        DWORD gamePid = 0;

        if (gd.processExe) {
            g_launchLog += L"[*] Launch ";
            g_launchLog += gd.name;
            g_launchLog += L" now. Waiting for process...\r\n";
            InvalidateRect(g_hWnd, nullptr, FALSE);

            for (int attempt = 0; attempt < 600; attempt++) {
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
                    if (Process32FirstW(snap, &pe)) {
                        do {
                            if (_wcsicmp(pe.szExeFile, gd.processExe) == 0 ||
                                _wcsicmp(pe.szExeFile, L"r5apex_dx12.exe") == 0) {
                                gamePid = pe.th32ProcessID;
                                break;
                            }
                        } while (Process32NextW(snap, &pe));
                    }
                    CloseHandle(snap);
                }
                if (gamePid) break;
                Sleep(1000);
            }
            if (!gamePid) {
                g_launchLog += L"[!] Timed out waiting for game (10 min).\r\n";
                g_launchStep = 5;
                InvalidateRect(g_hWnd, nullptr, FALSE);
                Sleep(2000);
                g_page = PAGE_GAMES;
                InvalidateRect(g_hWnd, nullptr, FALSE);
                InterlockedExchange(&g_launching, 0);
                return 1;
            }
            g_launchLog += L"[+] Game process detected!\r\n";
            InvalidateRect(g_hWnd, nullptr, FALSE);
            Sleep(3000);
        }

        // Inject cheat into game
        if (wcscmp(gd.name, L"Unturned") == 0) {
            char extBuf_[MAX_PATH] = {};
            if (!g_extractDir.empty())
                WideCharToMultiByte(CP_ACP, 0, g_extractDir.c_str(), -1, extBuf_, MAX_PATH, nullptr, nullptr);
            std::string cheatDir = extBuf_[0] ? std::string(extBuf_) : g_selfDir;

            if (g_untInternal) {
                std::string dllPath = cheatDir + "\\unturned_internal.dll";
                std::string injPath = cheatDir + "\\injector.exe";
                if (fs::exists(dllPath) && fs::exists(injPath)) {
                    g_launchLog += L"[*] Injecting internal DLL...\r\n";
                    InvalidateRect(g_hWnd, nullptr, FALSE);
                    STARTUPINFOA si{}; si.cb = sizeof(si);
                    PROCESS_INFORMATION cpi{};
                    std::string injCmd = "\"" + injPath + "\" \"" + dllPath + "\"";
                    if (CreateProcessA(nullptr, (LPSTR)injCmd.c_str(), nullptr, nullptr,
                                       FALSE, 0, nullptr, cheatDir.c_str(), &si, &cpi)) {
                        WaitForSingleObject(cpi.hProcess, 15000);
                        g_launchLog += L"[+] Internal DLL injected\r\n";
                        CloseHandle(cpi.hProcess);
                        CloseHandle(cpi.hThread);
                    } else {
                        g_launchLog += L"[!] Failed to launch injector\r\n";
                    }
                } else {
                    g_launchLog += L"[!] Internal DLL or injector not found\r\n";
                }
            } else {
                std::string extPath = cheatDir + "\\externaltest.exe";
                if (fs::exists(extPath)) {
                    g_launchLog += L"[*] Launching Unturned external cheat...\r\n";
                    InvalidateRect(g_hWnd, nullptr, FALSE);
                    STARTUPINFOA si{}; si.cb = sizeof(si);
                    PROCESS_INFORMATION cpi{};
                    std::string cheatCmd = "\"" + extPath + "\" --external";
                    if (CreateProcessA(nullptr, (LPSTR)cheatCmd.c_str(), nullptr, nullptr,
                                       FALSE, 0, nullptr, cheatDir.c_str(), &si, &cpi)) {
                        g_launchLog += L"[+] External cheat launched\r\n";
                        CloseHandle(cpi.hProcess);
                        CloseHandle(cpi.hThread);
                    } else {
                        g_launchLog += L"[!] Failed to launch cheat\r\n";
                    }
                }
            }
        }

        g_launchStep = 5;
        g_launchLog += L"[+] SUCCESS — monitoring game\r\n";
        g_page = PAGE_DONE;
        InvalidateRect(g_hWnd, nullptr, FALSE);

        // Monitor: wait for game to exit, then loop back and re-inject on relaunch
        if (gamePid) {
            HANDLE hGame = OpenProcess(SYNCHRONIZE, FALSE, gamePid);
            if (hGame) {
                WaitForSingleObject(hGame, INFINITE);
                CloseHandle(hGame);
            } else {
                Sleep(5000);
            }
            g_launchLog += L"\r\n[*] Game exited. Waiting for relaunch...\r\n";
            DbgLog("Game process %u exited, waiting for relaunch", gamePid);
            gamePid = 0;
            g_page = PAGE_LAUNCHING;
            Sleep(2000);
            continue;
        }

        break;
    }

    g_launchStep = 5;
    InvalidateRect(g_hWnd, nullptr, FALSE);
    InterlockedExchange(&g_launching, 0);
    return 0;
}

// ── Spoof prompt ─────────────────────────────────────────────────────────────

// ── Click / hover ────────────────────────────────────────────────────────────

static void OnClick(int mx, int my) {
    switch (g_page) {
    case PAGE_LOAD: {
        int btnW = 280, btnH = 70;
        int btnX = (WND_W - btnW) / 2, btnY = 320;
        if (mx >= btnX && mx < btnX + btnW && my >= btnY && my < btnY + btnH) {
            if (!FindPaths()) {
                MessageBoxA(g_hWnd,
                    "mapper_nal.exe or BetestD.sys not found.\n"
                    "Place them in the same folder as loader.exe.",
                    "PenisFinger", MB_OK | MB_ICONERROR);
                return;
            }
            g_page = PAGE_GAMES;
            InvalidateRect(g_hWnd, nullptr, FALSE);
        }
        break;
    }

    case PAGE_GAMES: {
        int tabY = 8, tabH = 36;
        if (mx >= 535 && mx < 695 && my >= tabY && my < tabY + tabH) {
            g_page = PAGE_SPOOFER;
            g_scrollY = 0;
            KillTimer(g_hWnd, TIMER_MATRIX);
            SetTimer(g_hWnd, TIMER_MATRIX, 80, nullptr);
            InvalidateRect(g_hWnd, nullptr, FALSE);
            return;
        }

        int hit = HitTestTile(mx, my, GAME_COUNT, 0, 100);
        if (hit >= 0) {
            g_selectedGame = hit;
            if (wcscmp(g_games[hit].name, L"Unturned") == 0) {
                g_page = PAGE_UNT_MODE;
                InvalidateRect(g_hWnd, nullptr, FALSE);
            } else {
                g_page = PAGE_LAUNCHING;
                InvalidateRect(g_hWnd, nullptr, FALSE);
                { HANDLE ht = CreateThread(nullptr, 0, LaunchThread, nullptr, 0, nullptr); if (ht) CloseHandle(ht); }
            }
        }
        break;
    }

    case PAGE_SPOOFER: {
        int tabY = 8, tabH = 36;
        if (mx >= 400 && mx < 520 && my >= tabY && my < tabY + tabH) {
            g_page = PAGE_GAMES;
            g_scrollY = 0;
            KillTimer(g_hWnd, TIMER_MATRIX);
            InvalidateRect(g_hWnd, nullptr, FALSE);
            return;
        }

        int smy = my + g_scrollY;

        if (g_spoofEnabled) {
            int cbX = (WND_W - 380) / 2;

            // New seed checkbox
            int newSeedY = WND_H - 190;
            if (mx >= cbX && mx < cbX + 380 && smy >= newSeedY && smy < newSeedY + 20) {
                g_spoofNewSeed = !g_spoofNewSeed;
                if (g_spoofNewSeed) g_spoofKeepSeed = false;
                SaveSpoofSeed();
                InvalidateRect(g_hWnd, nullptr, FALSE);
                return;
            }

            // Cleaner checkbox
            int clnY = WND_H - 160;
            if (mx >= cbX && mx < cbX + 380 && smy >= clnY && smy < clnY + 20) {
                g_spoofRunClean = !g_spoofRunClean;
                SaveSpoofSeed();
                InvalidateRect(g_hWnd, nullptr, FALSE);
                return;
            }

            // Seed checkbox
            int seedY = WND_H - 130;
            if (mx >= cbX && mx < cbX + 380 && smy >= seedY && smy < seedY + 20) {
                g_spoofKeepSeed = !g_spoofKeepSeed;
                if (g_spoofKeepSeed) {
                    g_spoofNewSeed = false;
                    if (g_spoofSeed == 0) g_spoofSeed = GenerateSpoofSeed();
                }
                SaveSpoofSeed();
                InvalidateRect(g_hWnd, nullptr, FALSE);
                return;
            }

            // New Seed button
            if (g_spoofKeepSeed) {
                int nsX = cbX + 380 - 100, nsY = seedY - 2;
                if (mx >= nsX && mx < nsX + 100 && smy >= nsY && smy < nsY + 24) {
                    g_spoofSeed = GenerateSpoofSeed();
                    SaveSpoofSeed();
                    InvalidateRect(g_hWnd, nullptr, FALSE);
                    return;
                }
            }

            // Disable button
            int dbX = (WND_W - 200) / 2, dbY = WND_H - 75;
            if (mx >= dbX && mx < dbX + 200 && smy >= dbY && smy < dbY + 38) {
                g_spoofEnabled = false;
                g_spoofGame = -1;
                SaveSpoofSeed();
                InvalidateRect(g_hWnd, nullptr, FALSE);
                return;
            }
        }

        int spoofCount = GAME_COUNT - 1;
        for (int i = 0; i < spoofCount; i++) {
            RECT rc = TileRect(i, 0, 185 + (g_hwidCount + 2) * 16 + 30);
            rc.right = rc.left + 150;
            rc.bottom = rc.top + 65;
            if (mx >= rc.left && mx < rc.right && smy >= rc.top && smy < rc.bottom) {
                g_spoofEnabled = true;
                g_spoofGame = i;
                SaveSpoofSeed();
                InvalidateRect(g_hWnd, nullptr, FALSE);
                return;
            }
        }
        break;
    }

    case PAGE_UNT_MODE: {
        int btnW = 320, btnH = 120, gap = 40;
        int totalW = btnW * 2 + gap;
        int startX = (WND_W - totalW) / 2;
        int btnY = 260;

        // External button
        if (mx >= startX && mx < startX + btnW && my >= btnY && my < btnY + btnH) {
            g_untInternal = false;
            g_page = PAGE_LAUNCHING;
            InvalidateRect(g_hWnd, nullptr, FALSE);
            { HANDLE ht = CreateThread(nullptr, 0, LaunchThread, nullptr, 0, nullptr); if (ht) CloseHandle(ht); }
            return;
        }
        // Internal button
        int intX = startX + btnW + gap;
        if (mx >= intX && mx < intX + btnW && my >= btnY && my < btnY + btnH) {
            g_untInternal = true;
            g_page = PAGE_LAUNCHING;
            InvalidateRect(g_hWnd, nullptr, FALSE);
            { HANDLE ht = CreateThread(nullptr, 0, LaunchThread, nullptr, 0, nullptr); if (ht) CloseHandle(ht); }
            return;
        }
        // Back link
        if (my >= WND_H - 60 && my < WND_H - 30) {
            g_page = PAGE_GAMES;
            InvalidateRect(g_hWnd, nullptr, FALSE);
            return;
        }
        break;
    }

    case PAGE_DONE: {
        int btnW = 200, btnH = 50;
        int btnX = (WND_W - btnW) / 2, btnY = 400;
        if (mx >= btnX && mx < btnX + btnW && my >= btnY && my < btnY + btnH) {
            g_page = PAGE_GAMES;
            g_selectedGame = -1;
            g_launchLog.clear();
            InvalidateRect(g_hWnd, nullptr, FALSE);
            return;
        }
        int qX = (WND_W - 120) / 2, qY = 470;
        if (mx >= qX && mx < qX + 120 && my >= qY && my < qY + 36) {
            PostQuitMessage(0);
            return;
        }
        break;
    }

    default: break;
    }
}

static void OnMouseMove(int mx, int my) {
    int oldHover = g_hoverTile;
    g_hoverTile = -1;

    if (g_page == PAGE_GAMES) {
        g_hoverTile = HitTestTile(mx, my, GAME_COUNT, 0, 100);
    } else if (g_page == PAGE_SPOOFER) {
        int smy = my + g_scrollY;
        int spoofCount = GAME_COUNT - 1;
        for (int i = 0; i < spoofCount; i++) {
            RECT rc = TileRect(i, 0, 185 + (g_hwidCount + 2) * 16 + 30);
            rc.right = rc.left + 150;
            rc.bottom = rc.top + 65;
            if (mx >= rc.left && mx < rc.right && smy >= rc.top && smy < rc.bottom) {
                g_hoverTile = i;
                break;
            }
        }
    }

    if (g_hoverTile != oldHover)
        InvalidateRect(g_hWnd, nullptr, FALSE);
}

// ── WndProc ──────────────────────────────────────────────────────────────────

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        Paint(hdc);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        if (g_memDC) { DeleteDC(g_memDC); DeleteObject(g_memBmp); g_memDC = nullptr; }
        InvalidateRect(hWnd, nullptr, FALSE);
        return 0;
    case WM_LBUTTONDOWN: {
        RECT cr; GetClientRect(hWnd, &cr);
        int cw2 = cr.right ? cr.right : WND_W;
        int ch2 = cr.bottom ? cr.bottom : WND_H;
        float sX = (float)cw2 / WND_W, sY = (float)ch2 / WND_H;
        float sc = (sX < sY) ? sX : sY;
        int oX = (int)(cw2 - WND_W * sc) / 2, oY = (int)(ch2 - WND_H * sc) / 2;
        int mx = (int)(((int)LOWORD(lParam) - oX) / sc);
        int my = (int)(((int)HIWORD(lParam) - oY) / sc);
        OnClick(mx, my);
        return 0;
    }
    case WM_MOUSEMOVE: {
        RECT cr; GetClientRect(hWnd, &cr);
        int cw2 = cr.right ? cr.right : WND_W;
        int ch2 = cr.bottom ? cr.bottom : WND_H;
        float sX = (float)cw2 / WND_W, sY = (float)ch2 / WND_H;
        float sc = (sX < sY) ? sX : sY;
        int oX = (int)(cw2 - WND_W * sc) / 2, oY = (int)(ch2 - WND_H * sc) / 2;
        int mx = (int)(((int)LOWORD(lParam) - oX) / sc);
        int my = (int)(((int)HIWORD(lParam) - oY) / sc);
        OnMouseMove(mx, my);
        return 0;
    }
    case WM_MOUSEWHEEL:
        if (g_page == PAGE_SPOOFER) {
            int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            g_scrollY -= delta / 4;
            if (g_scrollY < 0) g_scrollY = 0;
            if (g_scrollY > 200) g_scrollY = 200;
            InvalidateRect(hWnd, nullptr, FALSE);
        }
        return 0;
    case WM_TIMER:
        if (wParam == TIMER_MATRIX && g_page == PAGE_SPOOFER) {
            StepMatrix();
            InvalidateRect(hWnd, nullptr, FALSE);
        }
        return 0;
    case WM_DESTROY:
        KillTimer(hWnd, TIMER_MATRIX);
        if (g_memDC) { DeleteDC(g_memDC); DeleteObject(g_memBmp); }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ── Entry ────────────────────────────────────────────────────────────────────

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Global\\PF_Loader_Mtx");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"Loader is already running.", L"PenisFinger", MB_OK | MB_ICONWARNING);
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // Anti-debug check
    if (CheckDebugger()) {
        MessageBoxW(nullptr, L"Integrity check failed.", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(hMutex);
        return 1;
    }

    // Extract embedded files
    if (!ExtractEmbedded()) {
        MessageBoxW(nullptr, L"Initialization failed.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Disable Vulnerable Driver Blocklist so BYOVD can load
    {
        HKEY hk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CI\\Config", 0,
            KEY_SET_VALUE | KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
            DWORD val = 0, sz = sizeof(val), type = 0;
            if (RegQueryValueExA(hk, "VulnerableDriverBlocklistEnable", nullptr, &type,
                (BYTE*)&val, &sz) != ERROR_SUCCESS || val != 0) {
                DWORD zero = 0;
                RegSetValueExA(hk, "VulnerableDriverBlocklistEnable", 0, REG_DWORD,
                    (const BYTE*)&zero, sizeof(zero));
                DbgLog("Disabled VulnerableDriverBlocklist");
            }
            RegCloseKey(hk);
        }
    }

    // Kill any zombie mapper processes from a previous session
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"mapper_nal.exe") == 0) {
                        HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
            Sleep(500);
        }
    }

    // Cleanup leftover BYOVD service entries from previous runs.
    // NEVER stop the driver — Betest.sys holds a reference to the DRIVER_OBJECT.
    // Just delete the stale SCM entry and temp file.
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (scm) {
            const char* staleServices[] = { "TrixxSvc", "NalSvc", "NalDrv", "NalDrvIntel", "iqvw64e" };
            for (auto& sn : staleServices) {
                SC_HANDLE svc = OpenServiceA(scm, sn, SERVICE_ALL_ACCESS);
                if (svc) {
                    DeleteService(svc);
                    CloseServiceHandle(svc);
                    DbgLog("Startup: cleaned up leftover %s service entry", sn);
                }
            }
            CloseServiceHandle(scm);
        }
        char tmpDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tmpDir);
        DeleteFileA((std::string(tmpDir) + "TRIXX.sys").c_str());
        DeleteFileA((std::string(tmpDir) + "NalDrvIntel.sys").c_str());
    }

    LoadSpoofSeed();

    GdiplusStartupInput gsi;
    GdiplusStartup(&g_gdipToken, &gsi, nullptr);
    InitMatrix();
    LoadGameImages();

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInst;
    wc.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground  = (HBRUSH)GetStockObject(BLACK_BRUSH);
    // Stealth: randomize window class and title at runtime
    WCHAR rndClass[32], rndTitle[48];
    {
        LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
        DWORD seed = (DWORD)(pc.QuadPart ^ GetCurrentProcessId());
        const wchar_t* prefixes[] = { L"Wnd", L"Dlg", L"Frm", L"App" };
        wsprintfW(rndClass, L"%s_%08X", prefixes[seed % 4], seed);
        const wchar_t* titles[] = { L"Settings", L"Configuration", L"Preferences", L"Options" };
        wsprintfW(rndTitle, L"Windows %s", titles[(seed >> 4) % 4]);
    }
    wc.lpszClassName  = rndClass;
    wc.hIcon          = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    RECT wr = { 0, 0, WND_W, WND_H };
    DWORD style = WS_OVERLAPPEDWINDOW;
    AdjustWindowRectEx(&wr, style, FALSE, 0);

    int winW = wr.right - wr.left;
    int winH = wr.bottom - wr.top;
    int sx = (GetSystemMetrics(SM_CXSCREEN) - winW) / 2;
    int sy = (GetSystemMetrics(SM_CYSCREEN) - winH) / 2;

    g_hWnd = CreateWindowExW(0, rndClass, rndTitle,
        style, sx, sy, winW, winH,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    // Cleanup: free images, wipe and delete extracted files
    FreeGameImages();
    GdiplusShutdown(g_gdipToken);
    CleanupExtracted();
    CoUninitialize();
    if (hMutex) CloseHandle(hMutex);
    return (int)m.wParam;
}
