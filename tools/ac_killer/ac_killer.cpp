// AC Killer — background watchdog that terminates anti-cheat on sight
// Run this, then launch your game normally through Steam.
// BattlEye/EAC/ACE processes and services get killed as they spawn.

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

// ── State tracking (don't spam repeat kills) ──────────────────────────────────

#include <set>
static std::set<std::string> g_stoppedServices;
static std::set<std::string> g_unloadedDrivers;

// ── AC process and service names ────────────────────────────────────────────────

static const char* g_acProcesses[] = {
    // BattlEye
    "BEService_x64.exe",
    "BEService.exe",

    // EAC
    "EasyAntiCheat_EOS.exe",
    "EasyAntiCheat.exe",
    "start_protected_game.exe",
    "EasyAntiCheat_EOS_Setup.exe",

    // ACE (Tencent)
    "ACE-Service64.exe",
    "ACE-Setup64.exe",
    "SGuardSvc64.exe",
    "SGuard64.exe",
    "sgame_auth.exe",
    "tp_smb.exe",

    // EXENS (EXBO — used by Stalcraft/STALZONE)
    "ExensLauncher.exe",
    "exens_launcher.exe",

    nullptr
};

static const char* g_acServices[] = {
    // BattlEye
    "BEService",
    "BEDaisy",

    // EAC
    "EasyAntiCheat",
    "EasyAntiCheat_EOS",

    // ACE
    "ACE-Service",
    "SGuardSvc",
    "TP_AAAA",

    // EXENS
    "ExensService",
    "ExensAC",

    nullptr
};

static const char* g_acDrivers[] = {
    "BEDaisy",
    "EasyAntiCheatSys",
    "ACE-BASE",
    "ACE-CORE",
    nullptr
};

// ── Kill helpers ────────────────────────────────────────────────────────────────

struct KillStats {
    int processesKilled;
    int servicesStopped;
    int driversUnloaded;
};

static int KillProcessesByName(const char* name) {
    int killed = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    if (TerminateProcess(hProc, 1)) {
                        killed++;
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return killed;
}

static bool StopAndDisableService(const char* svcName) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS ss{};
    QueryServiceStatus(svc, &ss);

    if (ss.dwCurrentState != SERVICE_STOPPED) {
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 20; i++) {
            Sleep(250);
            QueryServiceStatus(svc, &ss);
            if (ss.dwCurrentState == SERVICE_STOPPED) break;
        }
    }

    // Set to disabled so it doesn't auto-restart
    ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                         SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ss.dwCurrentState == SERVICE_STOPPED;
}

static void ReenableService(const char* svcName) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, svcName, SERVICE_CHANGE_CONFIG);
    if (svc) {
        ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                             SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static bool UnloadDriver(const char* drvName) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, drvName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }

    SERVICE_STATUS ss{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    for (int i = 0; i < 20; i++) {
        Sleep(250);
        QueryServiceStatus(svc, &ss);
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ss.dwCurrentState == SERVICE_STOPPED;
}

// ── Scan and kill all AC ────────────────────────────────────────────────────────

static KillStats SweepAC(bool verbose) {
    KillStats stats{};

    for (int i = 0; g_acProcesses[i]; i++) {
        int k = KillProcessesByName(g_acProcesses[i]);
        if (k > 0) {
            stats.processesKilled += k;
            if (verbose)
                printf("  [KILL] %s (%d instance%s)\n", g_acProcesses[i], k, k > 1 ? "s" : "");
        }
    }

    for (int i = 0; g_acServices[i]; i++) {
        if (g_stoppedServices.count(g_acServices[i])) continue;
        if (StopAndDisableService(g_acServices[i])) {
            stats.servicesStopped++;
            g_stoppedServices.insert(g_acServices[i]);
            if (verbose)
                printf("  [STOP] Service: %s (disabled)\n", g_acServices[i]);
        }
    }

    for (int i = 0; g_acDrivers[i]; i++) {
        if (g_unloadedDrivers.count(g_acDrivers[i])) continue;
        if (UnloadDriver(g_acDrivers[i])) {
            stats.driversUnloaded++;
            g_unloadedDrivers.insert(g_acDrivers[i]);
            if (verbose)
                printf("  [UNLOAD] Driver: %s\n", g_acDrivers[i]);
        }
    }

    return stats;
}

// ── Check what's running ────────────────────────────────────────────────────────

static int CountACProcesses() {
    int count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; g_acProcesses[i]; i++) {
                if (_stricmp(pe.szExeFile, g_acProcesses[i]) == 0) {
                    count++;
                    break;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return count;
}

// ── Main ────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== AC Killer — Anti-Cheat Watchdog ===\n\n");

    bool oneShot = false;
    bool quiet = false;
    int intervalMs = 500;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--once") == 0) oneShot = true;
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) quiet = true;
        else if (strcmp(argv[i], "--interval") == 0 && i+1 < argc) intervalMs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("Runs as a background watchdog, killing anti-cheat processes on sight.\n");
            printf("Launch this first, then start your game through Steam.\n\n");
            printf("Options:\n");
            printf("  --once        Kill once and exit (don't monitor)\n");
            printf("  --quiet       Only print when something is killed\n");
            printf("  --interval N  Check interval in ms (default: 500)\n");
            printf("  --help        Show this help\n\n");
            printf("Targets:\n");
            printf("  BattlEye:  BEService, BEDaisy driver\n");
            printf("  EAC:       EasyAntiCheat service + processes\n");
            printf("  ACE:       ACE-Service, SGuard, ACE-BASE/CORE drivers\n");
            printf("  EXENS:     ExensLauncher (Stalcraft/STALZONE)\n\n");
            printf("After you're done, close this window — services get re-enabled on exit.\n");
            return 0;
        }
    }

    // Initial sweep
    printf("[*] Initial sweep — killing all anti-cheat...\n");
    auto stats = SweepAC(true);

    if (stats.processesKilled + stats.servicesStopped + stats.driversUnloaded > 0) {
        printf("[+] Killed %d process(es), stopped %d service(s), unloaded %d driver(s)\n\n",
               stats.processesKilled, stats.servicesStopped, stats.driversUnloaded);
    } else {
        printf("[+] No anti-cheat found running\n\n");
    }

    if (oneShot) {
        printf("[+] Done (one-shot mode)\n");
        return 0;
    }

    // Watchdog loop
    printf("[*] Watchdog active — monitoring every %dms\n", intervalMs);
    printf("[*] Launch your game through Steam now.\n");
    printf("[*] Press Ctrl+C to stop and re-enable services.\n\n");

    // Re-enable services on ANY exit — Ctrl+C, window close, or normal exit
    static bool s_running = true;
    static bool s_cleaned = false;
    auto cleanup = []() {
        if (s_cleaned) return;
        s_cleaned = true;
        printf("\n[*] Shutting down — re-enabling AC services...\n");
        for (int i = 0; g_acServices[i]; i++)
            ReenableService(g_acServices[i]);
        printf("[+] Services re-enabled. Anti-cheat will work normally next launch.\n");
    };
    atexit([]() { if (!s_cleaned) { s_cleaned = true; for (int i = 0; g_acServices[i]; i++) ReenableService(g_acServices[i]); } });
    SetConsoleCtrlHandler([](DWORD type) -> BOOL {
        if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_BREAK_EVENT) {
            s_running = false;
            if (!s_cleaned) {
                s_cleaned = true;
                printf("\n[*] Shutting down — re-enabling AC services...\n");
                for (int i = 0; g_acServices[i]; i++)
                    ReenableService(g_acServices[i]);
                printf("[+] Services re-enabled. Anti-cheat will work normally next launch.\n");
            }
            ExitProcess(0);
        }
        return TRUE;
    }, TRUE);

    int totalKills = stats.processesKilled;
    DWORD lastPrint = GetTickCount();

    while (s_running) {
        Sleep(intervalMs);

        auto sweep = SweepAC(!quiet);
        int killed = sweep.processesKilled + sweep.servicesStopped + sweep.driversUnloaded;
        totalKills += sweep.processesKilled;

        if (killed > 0 && quiet) {
            printf("[KILL] %d proc / %d svc / %d drv  (total kills: %d)\n",
                   sweep.processesKilled, sweep.servicesStopped, sweep.driversUnloaded, totalKills);
        }

        // Periodic heartbeat every 30s if not quiet
        DWORD now = GetTickCount();
        if (!quiet && (now - lastPrint > 30000)) {
            int alive = CountACProcesses();
            if (alive == 0)
                printf("[*] Watchdog alive — no AC detected (total kills: %d)\n", totalKills);
            else
                printf("[!] %d AC process(es) still alive — retrying...\n", alive);
            lastPrint = now;
        }
    }

    return 0;
}
