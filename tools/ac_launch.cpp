// Anti-Cheat Bypass Launcher for Game Dumping
// Launches game processes without AC active so memory can be dumped
//
// BattlEye:  stops BEService, launches game exe directly (BE never injects)
// EAC:       launches game SUSPENDED, PE is mapped but EAC init never runs
// ACE:       launches game SUSPENDED, same approach
// None:      launches normally
//
// After launch, use dumper2.exe --proc <name> to dump the process

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

// ── Known game profiles ─────────────────────────────────────────────────────────

enum ACType { AC_NONE, AC_BATTLEYE, AC_EAC, AC_ACE, AC_VANGUARD };

struct GameProfile {
    const char* name;
    const char* processName;
    const char* steamDir;       // relative to steamapps/common/
    const char* exePath;        // relative to game dir
    const char* acLauncher;     // the AC-wrapped launcher (what Steam normally runs)
    ACType ac;
    const char* launchArgs;     // extra args for the game exe
};

static const GameProfile g_profiles[] = {
    {
        "Apex Legends", "r5apex_dx12.exe",
        "Apex Legends",
        "r5apex_dx12.exe",
        "start_protected_game.exe",
        AC_EAC, ""
    },
    {
        "Rainbow Six Siege", "RainbowSix.exe",
        "Tom Clancy's Rainbow Six Siege",
        "RainbowSix.exe",
        "RainbowSix_BE.exe",
        AC_BATTLEYE, ""
    },
    {
        "Unturned", "Unturned.exe",
        "Unturned",
        "Unturned.exe",
        "Unturned_BE.exe",
        AC_BATTLEYE, ""
    },
    {
        "Rust", "RustClient.exe",
        "Rust",
        "RustClient.exe",
        nullptr,
        AC_EAC, ""
    },
    {
        "Delta Force", "DeltaForceClient-Win64-Shipping.exe",
        "Delta Force",
        "Game\\DeltaForce\\Binaries\\Win64\\DeltaForceClient-Win64-Shipping.exe",
        "Game\\DeltaForceClient.exe",
        AC_ACE, ""
    },
    {
        "STALZONE", "stalzone.exe",
        "STALZONE",
        "bin_global\\win64\\java\\bin\\stalzone.exe",
        nullptr,
        AC_NONE, ""
    },
    {
        "Counter-Strike 2", "cs2.exe",
        "Counter-Strike Global Offensive",
        "game\\bin\\win64\\cs2.exe",
        nullptr,
        AC_NONE, "-insecure"
    },
};

static const int NUM_PROFILES = sizeof(g_profiles) / sizeof(g_profiles[0]);

// ── Helpers ─────────────────────────────────────────────────────────────────────

static std::string FindSteamPath() {
    HKEY hKey;
    char path[MAX_PATH]{};
    DWORD size = sizeof(path);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS ||
        RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, (LPBYTE)path, &size);
        RegCloseKey(hKey);
    }
    if (path[0]) return std::string(path);
    if (GetFileAttributesA("C:\\Program Files (x86)\\Steam") != INVALID_FILE_ATTRIBUTES)
        return "C:\\Program Files (x86)\\Steam";
    return "";
}

static bool StopService(const char* serviceName) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }

    SERVICE_STATUS ss{};
    QueryServiceStatus(svc, &ss);
    if (ss.dwCurrentState == SERVICE_RUNNING) {
        printf("[*] Stopping %s service...\n", serviceName);
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 30; i++) {
            Sleep(500);
            QueryServiceStatus(svc, &ss);
            if (ss.dwCurrentState == SERVICE_STOPPED) break;
        }
        if (ss.dwCurrentState == SERVICE_STOPPED) {
            printf("[+] %s stopped\n", serviceName);
        } else {
            printf("[-] %s did not stop in time\n", serviceName);
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ss.dwCurrentState == SERVICE_STOPPED;
}

static DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(name, pe.szExeFile) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static bool WaitForModules(DWORD pid, int timeoutMs) {
    int waited = 0;
    while (waited < timeoutMs) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me{};
            me.dwSize = sizeof(me);
            int count = 0;
            if (Module32First(snap, &me)) {
                do { count++; } while (Module32Next(snap, &me));
            }
            CloseHandle(snap);
            if (count >= 1) return true;
        }
        Sleep(100);
        waited += 100;
    }
    return false;
}

// ── Launch strategies ───────────────────────────────────────────────────────────

static bool LaunchBattlEyeGame(const GameProfile* prof, const std::string& gamePath, bool waitForDump) {
    // Stop BEService so it doesn't interfere
    StopService("BEService");

    std::string exeFull = gamePath + "\\" + prof->exePath;
    printf("[*] Launching %s directly (no BattlEye)...\n", prof->name);
    printf("[*] Path: %s\n", exeFull.c_str());

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::string cmdLine = "\"" + exeFull + "\"";
    if (prof->launchArgs && prof->launchArgs[0])
        cmdLine += std::string(" ") + prof->launchArgs;

    if (!CreateProcessA(nullptr, (LPSTR)cmdLine.c_str(), nullptr, nullptr, FALSE,
                        0, nullptr, gamePath.c_str(), &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return false;
    }

    printf("[+] Process created: PID %lu\n", pi.dwProcessId);
    printf("[+] BattlEye is NOT running — process is unprotected\n");

    if (waitForDump) {
        printf("[*] Waiting for modules to load...\n");
        WaitForModules(pi.dwProcessId, 10000);
        printf("\n[+] Ready for dump. Run:\n");
        printf("    dumper2.exe --proc %s --offsets --report\n\n", prof->processName);
        printf("[*] Press Enter to close the game process...\n");
        getchar();
        TerminateProcess(pi.hProcess, 0);
        printf("[+] Process terminated\n");
    } else {
        printf("\n[+] Game launched. Run dumper2.exe when ready.\n");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

static bool LaunchSuspended(const GameProfile* prof, const std::string& gamePath, bool waitForDump) {
    std::string exeFull = gamePath + "\\" + prof->exePath;
    printf("[*] Launching %s SUSPENDED (bypassing %s)...\n", prof->name,
           prof->ac == AC_EAC ? "EAC" : "ACE");
    printf("[*] Path: %s\n", exeFull.c_str());

    // Get the working directory (game binary's parent folder)
    std::string workDir = exeFull;
    size_t lastSlash = workDir.rfind('\\');
    if (lastSlash != std::string::npos) workDir = workDir.substr(0, lastSlash);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::string cmdLine = "\"" + exeFull + "\"";
    if (prof->launchArgs && prof->launchArgs[0])
        cmdLine += std::string(" ") + prof->launchArgs;

    if (!CreateProcessA(nullptr, (LPSTR)cmdLine.c_str(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, workDir.c_str(), &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return false;
    }

    printf("[+] Process created SUSPENDED: PID %lu\n", pi.dwProcessId);
    printf("[+] Main thread suspended — anti-cheat init has NOT run\n");
    printf("[+] PE image is mapped in memory and ready to dump\n");

    // The main exe PE is already mapped even though the process is suspended.
    // ntdll is loaded but nothing else — LdrInitializeThunk hasn't run yet.
    // For a full module list we need to briefly resume then re-suspend.

    printf("\n[*] Briefly resuming to let the loader map DLLs...\n");
    ResumeThread(pi.hThread);
    Sleep(2000);
    SuspendThread(pi.hThread);
    printf("[+] Re-suspended after DLL load window\n");

    // Check what we got
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pi.dwProcessId);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);
        int count = 0;
        if (Module32First(snap, &me)) {
            do { count++; } while (Module32Next(snap, &me));
        }
        CloseHandle(snap);
        printf("[+] %d modules loaded in suspended process\n", count);
    }

    printf("\n[+] Ready for dump. Run:\n");
    printf("    dumper2.exe --proc %s --offsets --report\n\n", prof->processName);

    if (waitForDump) {
        printf("[*] Process is frozen — anti-cheat cannot interfere.\n");
        printf("[*] Press Enter when done dumping to terminate...\n");
        getchar();
        TerminateProcess(pi.hProcess, 0);
        printf("[+] Process terminated\n");
    } else {
        printf("[*] Process left suspended. Terminate manually when done.\n");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

static bool LaunchNormal(const GameProfile* prof, const std::string& gamePath) {
    std::string exeFull = gamePath + "\\" + prof->exePath;
    printf("[*] Launching %s (no anti-cheat to bypass)...\n", prof->name);
    printf("[*] Path: %s\n", exeFull.c_str());

    std::string workDir = exeFull;
    size_t lastSlash = workDir.rfind('\\');
    if (lastSlash != std::string::npos) workDir = workDir.substr(0, lastSlash);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::string cmdLine = "\"" + exeFull + "\"";
    if (prof->launchArgs && prof->launchArgs[0])
        cmdLine += std::string(" ") + prof->launchArgs;

    if (!CreateProcessA(nullptr, (LPSTR)cmdLine.c_str(), nullptr, nullptr, FALSE,
                        0, nullptr, workDir.c_str(), &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return false;
    }

    printf("[+] Process created: PID %lu\n", pi.dwProcessId);
    printf("\n[+] Game launched. Run dumper2.exe when ready.\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// ── Usage ───────────────────────────────────────────────────────────────────────

static void PrintUsage(const char* exe) {
    printf("Usage: %s <game> [options]\n\n", exe);
    printf("Launches games without anti-cheat for memory dumping.\n\n");
    printf("Games:\n");
    for (int i = 0; i < NUM_PROFILES; i++) {
        const char* acName = "None";
        switch (g_profiles[i].ac) {
            case AC_BATTLEYE: acName = "BattlEye"; break;
            case AC_EAC:      acName = "EAC"; break;
            case AC_ACE:      acName = "ACE"; break;
            case AC_VANGUARD: acName = "Vanguard"; break;
            default: break;
        }
        printf("  %-12s  %-25s  AC: %s\n",
               g_profiles[i].processName, g_profiles[i].name, acName);
    }
    printf("\nOptions:\n");
    printf("  --wait        Keep process alive until you press Enter (default)\n");
    printf("  --no-wait     Launch and exit immediately\n");
    printf("  --steam <path>  Override Steam install path\n");
    printf("  --exe <path>    Launch a custom exe path directly\n");
    printf("  --list        List available game profiles\n\n");
    printf("Examples:\n");
    printf("  %s apex\n", exe);
    printf("  %s r6\n", exe);
    printf("  %s rust\n", exe);
    printf("  %s --exe \"C:\\Games\\MyGame\\game.exe\" --suspended\n", exe);
}

// ── Game name matching ──────────────────────────────────────────────────────────

static const GameProfile* FindProfile(const char* query) {
    std::string q = query;
    for (auto& c : q) c = (char)tolower((unsigned char)c);

    // Exact process name match
    for (int i = 0; i < NUM_PROFILES; i++) {
        std::string pn = g_profiles[i].processName;
        for (auto& c : pn) c = (char)tolower((unsigned char)c);
        if (q == pn) return &g_profiles[i];
    }

    // Short name aliases
    struct Alias { const char* alias; int idx; };
    static const Alias aliases[] = {
        {"apex",      0},
        {"r6",        1}, {"siege",     1}, {"rainbow",   1}, {"rainbowsix", 1},
        {"unturned",  2},
        {"rust",      3},
        {"deltaforce",4}, {"delta",     4}, {"df",        4},
        {"stalzone",  5}, {"stalcraft", 5},
        {"cs2",       6}, {"counterstrike", 6},
    };
    for (auto& a : aliases) {
        if (q == a.alias) return &g_profiles[a.idx];
    }

    // Substring match
    for (int i = 0; i < NUM_PROFILES; i++) {
        std::string name = g_profiles[i].name;
        for (auto& c : name) c = (char)tolower((unsigned char)c);
        if (name.find(q) != std::string::npos) return &g_profiles[i];
    }

    return nullptr;
}

// ── Main ────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== AC Bypass Launcher ===\n\n");

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string gameName;
    std::string customExe;
    std::string steamOverride;
    bool waitForDump = true;
    bool forceSuspended = false;
    bool listOnly = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wait") == 0) waitForDump = true;
        else if (strcmp(argv[i], "--no-wait") == 0) waitForDump = false;
        else if (strcmp(argv[i], "--suspended") == 0) forceSuspended = true;
        else if (strcmp(argv[i], "--steam") == 0 && i+1 < argc) steamOverride = argv[++i];
        else if (strcmp(argv[i], "--exe") == 0 && i+1 < argc) customExe = argv[++i];
        else if (strcmp(argv[i], "--list") == 0) listOnly = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]); return 0;
        }
        else if (gameName.empty()) gameName = argv[i];
        else { printf("[-] Unknown option: %s\n", argv[i]); return 1; }
    }

    if (listOnly) {
        printf("%-25s  %-35s  %-10s  %s\n", "PROCESS", "GAME", "AC", "METHOD");
        printf("%-25s  %-35s  %-10s  %s\n", "-------", "----", "--", "------");
        for (int i = 0; i < NUM_PROFILES; i++) {
            const char* acName = "None";
            const char* method = "Normal launch";
            switch (g_profiles[i].ac) {
                case AC_BATTLEYE: acName = "BattlEye"; method = "Direct launch (skip BE)"; break;
                case AC_EAC:      acName = "EAC";      method = "Suspended launch"; break;
                case AC_ACE:      acName = "ACE";      method = "Suspended launch"; break;
                case AC_VANGUARD: acName = "Vanguard";  method = "Cannot bypass"; break;
                default: break;
            }
            printf("%-25s  %-35s  %-10s  %s\n",
                   g_profiles[i].processName, g_profiles[i].name, acName, method);
        }
        return 0;
    }

    // Custom exe mode
    if (!customExe.empty()) {
        if (GetFileAttributesA(customExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] File not found: %s\n", customExe.c_str());
            return 1;
        }
        GameProfile custom{};
        custom.name = "Custom";
        custom.processName = customExe.c_str();
        custom.exePath = "";
        custom.ac = forceSuspended ? AC_EAC : AC_NONE;

        std::string dir = customExe;
        size_t ls = dir.rfind('\\');
        if (ls != std::string::npos) dir = dir.substr(0, ls);

        if (forceSuspended) {
            // Build a temp profile pointing at the custom exe
            GameProfile cp = custom;
            std::string relPath = customExe;
            if (relPath.find(dir) == 0) relPath = relPath.substr(dir.length() + 1);
            cp.exePath = relPath.c_str();
            return LaunchSuspended(&cp, dir, waitForDump) ? 0 : 1;
        }
        return LaunchNormal(&custom, "") ? 0 : 1;
    }

    if (gameName.empty()) {
        printf("[-] No game specified. Use --list to see available games.\n");
        return 1;
    }

    const GameProfile* prof = FindProfile(gameName.c_str());
    if (!prof) {
        printf("[-] Unknown game: %s\n", gameName.c_str());
        printf("[*] Use --list to see available games, or --exe <path> for custom.\n");
        return 1;
    }

    // Find Steam
    std::string steamPath = steamOverride.empty() ? FindSteamPath() : steamOverride;
    if (steamPath.empty()) {
        printf("[-] Steam not found. Use --steam <path> to specify.\n");
        return 1;
    }

    std::string gamePath = steamPath + "\\steamapps\\common\\" + prof->steamDir;
    std::string exeFull = gamePath + "\\" + prof->exePath;

    if (GetFileAttributesA(exeFull.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Game exe not found: %s\n", exeFull.c_str());
        printf("[*] Is %s installed?\n", prof->name);
        return 1;
    }

    printf("[+] Game: %s\n", prof->name);
    printf("[+] Anti-Cheat: %s\n",
           prof->ac == AC_BATTLEYE ? "BattlEye" :
           prof->ac == AC_EAC ? "EAC" :
           prof->ac == AC_ACE ? "ACE" :
           prof->ac == AC_VANGUARD ? "Vanguard" : "None");

    // Check if game is already running
    DWORD existing = FindProcess(prof->processName);
    if (existing) {
        printf("[!] %s is already running (PID %lu)\n", prof->processName, existing);
        printf("[*] Kill it first or just run dumper2.exe --proc %s\n", prof->processName);
        return 1;
    }

    printf("\n");

    switch (prof->ac) {
        case AC_BATTLEYE:
            return LaunchBattlEyeGame(prof, gamePath, waitForDump) ? 0 : 1;

        case AC_EAC:
        case AC_ACE:
            return LaunchSuspended(prof, gamePath, waitForDump) ? 0 : 1;

        case AC_NONE:
            return LaunchNormal(prof, gamePath) ? 0 : 1;

        case AC_VANGUARD:
            printf("[-] Vanguard cannot be bypassed with this method.\n");
            printf("[*] Use --static mode in dumper2.exe for disk-based analysis.\n");
            return 1;

        default:
            return LaunchNormal(prof, gamePath) ? 0 : 1;
    }
}
