// BE Freeze — suspend BattlEye's heartbeat threads inside the game process
// so the game stays alive after BEService is killed.
//
// Flow:
//   1. Find game process (e.g. RainbowSix.exe)
//   2. Find BEClient_x64.dll module loaded in it
//   3. Suspend all threads whose start address falls within BEClient's range
//   4. Kill BEService + BEDaisy
//   5. Game keeps running — heartbeat is frozen, game never knows BE died
//   6. Dump freely with dumper2.exe

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

struct ModuleRange {
    uintptr_t base;
    uintptr_t end;
    std::string name;
};

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

static std::vector<ModuleRange> GetBEModules(DWORD pid) {
    std::vector<ModuleRange> results;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return results;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            std::string name = me.szModule;
            for (auto& c : name) c = (char)tolower((unsigned char)c);
            if (name.find("beclient") != std::string::npos ||
                name.find("battleye") != std::string::npos ||
                name.find("bedaisy") != std::string::npos) {
                ModuleRange mr;
                mr.base = (uintptr_t)me.modBaseAddr;
                mr.end = mr.base + me.modBaseSize;
                mr.name = me.szModule;
                results.push_back(mr);
                printf("[+] Found BE module: %s [0x%llX - 0x%llX] (%u KB)\n",
                       me.szModule, (unsigned long long)mr.base,
                       (unsigned long long)mr.end, me.modBaseSize / 1024);
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return results;
}

typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static uintptr_t GetThreadStartAddress(HANDLE hThread) {
    static auto NtQueryInformationThread = (pNtQueryInformationThread)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread) return 0;

    uintptr_t startAddr = 0;
    // ThreadQuerySetWin32StartAddress = 9
    NtQueryInformationThread(hThread, 9, &startAddr, sizeof(startAddr), nullptr);
    return startAddr;
}

static int SuspendBEThreads(DWORD pid, const std::vector<ModuleRange>& beModules) {
    int suspended = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                FALSE, te.th32ThreadID);
            if (!hThread) continue;

            uintptr_t startAddr = GetThreadStartAddress(hThread);

            bool isBE = false;
            for (auto& mod : beModules) {
                if (startAddr >= mod.base && startAddr < mod.end) {
                    isBE = true;
                    printf("[+] Suspending thread %lu (start: 0x%llX in %s)\n",
                           te.th32ThreadID, (unsigned long long)startAddr,
                           mod.name.c_str());
                    break;
                }
            }

            if (isBE) {
                SuspendThread(hThread);
                suspended++;
            }

            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return suspended;
}

static void KillBEService() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;

    const char* services[] = {"BEService", "BEDaisy", nullptr};
    for (int i = 0; services[i]; i++) {
        SC_HANDLE svc = OpenServiceA(scm, services[i],
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
        if (!svc) continue;

        SERVICE_STATUS ss{};
        QueryServiceStatus(svc, &ss);
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            ControlService(svc, SERVICE_CONTROL_STOP, &ss);
            for (int j = 0; j < 20; j++) {
                Sleep(250);
                QueryServiceStatus(svc, &ss);
                if (ss.dwCurrentState == SERVICE_STOPPED) break;
            }
        }
        ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                             SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr);
        CloseServiceHandle(svc);

        if (ss.dwCurrentState == SERVICE_STOPPED)
            printf("[+] Stopped & disabled: %s\n", services[i]);
    }

    // Kill BE processes
    const char* procs[] = {"BEService_x64.exe", "BEService.exe", nullptr};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                for (int i = 0; procs[i]; i++) {
                    if (_stricmp(pe.szExeFile, procs[i]) == 0) {
                        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
                        printf("[+] Killed: %s (PID %lu)\n", procs[i], pe.th32ProcessID);
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    CloseServiceHandle(scm);
}

static void ReenableBE() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    const char* services[] = {"BEService", "BEDaisy", nullptr};
    for (int i = 0; services[i]; i++) {
        SC_HANDLE svc = OpenServiceA(scm, services[i], SERVICE_CHANGE_CONFIG);
        if (svc) {
            ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                                 SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                                 nullptr, nullptr, nullptr, nullptr);
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(scm);
}

int main(int argc, char* argv[]) {
    printf("=== BE Freeze — BattlEye Heartbeat Neutralizer ===\n\n");

    const char* procName = "RainbowSix.exe";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--proc") == 0 && i+1 < argc) procName = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--proc <name>]\n\n", argv[0]);
            printf("Suspends BattlEye threads inside the game so it stays alive\n");
            printf("after BEService is killed. Defaults to RainbowSix.exe.\n\n");
            printf("Steps:\n");
            printf("  1. Launch game normally through Steam (with BE)\n");
            printf("  2. Get to main menu or tutorial\n");
            printf("  3. Run this tool\n");
            printf("  4. Dump with: dumper2.exe --proc %s\n\n", procName);
            printf("Press Enter when done to re-enable BE services.\n");
            return 0;
        }
    }

    // Find game
    DWORD pid = FindProcess(procName);
    if (!pid) {
        printf("[-] %s not found. Launch the game first, get to menu, then run this.\n", procName);
        return 1;
    }
    printf("[+] Found %s — PID %lu\n\n", procName, pid);

    // Find BE modules
    printf("[*] Scanning for BattlEye modules...\n");
    auto beModules = GetBEModules(pid);
    if (beModules.empty()) {
        printf("[-] No BattlEye modules found in process. Is BE active?\n");
        return 1;
    }
    printf("\n");

    // Suspend BE threads
    printf("[*] Suspending BattlEye threads...\n");
    int count = SuspendBEThreads(pid, beModules);
    if (count == 0) {
        printf("[!] No BE threads found to suspend. Trying all threads in BE modules...\n");
    }
    printf("[+] Suspended %d BE thread(s)\n\n", count);

    // Kill BEService
    printf("[*] Killing BEService...\n");
    KillBEService();
    printf("\n");

    // Verify game is still alive
    Sleep(2000);
    if (FindProcess(procName)) {
        printf("[+] SUCCESS — %s is still running with BE frozen!\n", procName);
        printf("[+] Dump now: dumper2.exe --proc %s --offsets --report\n\n", procName);
    } else {
        printf("[-] Game closed. BE integration might be too tight for this method.\n");
        printf("[*] Try ac_launch.exe with suspended launch instead.\n\n");
        ReenableBE();
        return 1;
    }

    // Wait for user
    printf("[*] Press Enter when done dumping to re-enable BE...\n");
    getchar();

    ReenableBE();
    printf("[+] BE services re-enabled.\n");
    return 0;
}
