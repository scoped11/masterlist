// DMA Dumper — reads game memory via FPGA DMA card using MemProcFS/VMM API
// Interactive process selection, engine detection, auto offset scanning.
// Supports Unreal Engine 4/5 (Arena Breakout, Delta Force, etc.)
// and Unity IL2CPP (Rust, etc.) with Dumper-7 style auto detection.
//
// Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.
// Completely invisible to all anti-cheat — reads happen at the hardware level.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS release)
// Build: cl /O2 /EHsc dumper_dma.cpp shell32.lib /link /SUBSYSTEM:CONSOLE

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <set>
#include <shlobj.h>
#include <direct.h>

// ── VMM API types (dynamically loaded from vmm.dll) ────────────────────────────

typedef void* VMM_HANDLE;

#pragma pack(push, 8)

typedef struct {
    ULONG64 vaBase;
    ULONG64 vaEntry;
    DWORD   cbImageSize;
    BOOL    fWoW64;
    CHAR    uszText[260];
    CHAR    uszFullName[260];
    DWORD   tp;
    DWORD   cbFileSizeRaw;
    DWORD   cSection;
    DWORD   cEAT;
    DWORD   cIAT;
    DWORD   _Reserved2;
    ULONG64 _Reserved3[3];
} VMMDLL_MAP_MODULEENTRY_V1;

typedef struct {
    DWORD   dwVersion;
    DWORD   _Reserved1[5];
    PBYTE   pbMultiText;
    DWORD   cbMultiText;
    DWORD   cMap;
} VMMDLL_MAP_MODULE_HDR;

typedef struct {
    ULONG64 magic;
    WORD    wVersion;
    WORD    wSize;
    DWORD   tpMemoryModel;
    DWORD   tpSystem;
    BOOL    fAbort;
    DWORD   dwPID;
    DWORD   dwPPID;
    DWORD   dwState;
    CHAR    szName[16];
    CHAR    szNameLong[64];
    ULONG64 paDTB;
    ULONG64 paDTB_UserOpt;
} VMMDLL_PROCESS_INFORMATION;

#pragma pack(pop)

// VMM function pointers
typedef VMM_HANDLE  (__cdecl *fn_VMMDLL_Initialize)(DWORD argc, LPCSTR argv[]);
typedef VOID        (__cdecl *fn_VMMDLL_Close)(VMM_HANDLE hVMM);
typedef VOID        (__cdecl *fn_VMMDLL_CloseAll)();
typedef BOOL        (__cdecl *fn_VMMDLL_PidGetFromName)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL        (__cdecl *fn_VMMDLL_PidList)(VMM_HANDLE hVMM, PDWORD pPIDs, PULONG64 pcPIDs);
typedef BOOL        (__cdecl *fn_VMMDLL_MemReadEx)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef BOOL        (__cdecl *fn_VMMDLL_ProcessGetInformationString)(VMM_HANDLE hVMM, DWORD dwPID, DWORD fOptionString, LPSTR *pszStr);
typedef VOID        (__cdecl *fn_VMMDLL_MemFree)(PVOID pv);
typedef HANDLE      (__cdecl *fn_VMMDLL_Scatter_Initialize)(VMM_HANDLE hVMM, DWORD dwPID, DWORD flags);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Prepare)(HANDLE hS, ULONG64 va, DWORD cb);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Execute)(HANDLE hS);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Read)(HANDLE hS, ULONG64 va, DWORD cb, PBYTE pb, PDWORD pcbRead);
typedef VOID        (__cdecl *fn_VMMDLL_Scatter_CloseHandle)(HANDLE hS);
typedef ULONG64     (__cdecl *fn_VMMDLL_ProcessGetModuleBaseU)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef BOOL        (__cdecl *fn_VMMDLL_ProcessGetInformation)(VMM_HANDLE hVMM, DWORD dwPID, PVOID pProcessInformation, PSIZE_T pcbProcessInformation);
typedef BOOL        (__cdecl *fn_VMMDLL_Map_GetModuleU)(VMM_HANDLE hVMM, DWORD dwPID, PVOID *ppModuleMap, DWORD flags);

// ── Global state ───────────────────────────────────────────────────────────────

static HMODULE g_hVMM = nullptr;
static VMM_HANDLE g_hVmmHandle = nullptr;
static DWORD g_targetPid = 0;

static fn_VMMDLL_Initialize             pVMMDLL_Initialize = nullptr;
static fn_VMMDLL_Close                  pVMMDLL_Close = nullptr;
static fn_VMMDLL_PidGetFromName         pVMMDLL_PidGetFromName = nullptr;
static fn_VMMDLL_PidList                pVMMDLL_PidList = nullptr;
static fn_VMMDLL_MemReadEx              pVMMDLL_MemReadEx = nullptr;
static fn_VMMDLL_ProcessGetInformationString pVMMDLL_ProcessGetInformationString = nullptr;
static fn_VMMDLL_MemFree               pVMMDLL_MemFree = nullptr;
static fn_VMMDLL_Scatter_Initialize     pVMMDLL_Scatter_Initialize = nullptr;
static fn_VMMDLL_Scatter_Prepare        pVMMDLL_Scatter_Prepare = nullptr;
static fn_VMMDLL_Scatter_Execute        pVMMDLL_Scatter_Execute = nullptr;
static fn_VMMDLL_Scatter_Read           pVMMDLL_Scatter_Read = nullptr;
static fn_VMMDLL_Scatter_CloseHandle    pVMMDLL_Scatter_CloseHandle = nullptr;
static fn_VMMDLL_ProcessGetModuleBaseU  pVMMDLL_ProcessGetModuleBaseU = nullptr;
static fn_VMMDLL_ProcessGetInformation  pVMMDLL_ProcessGetInformation = nullptr;
static fn_VMMDLL_Map_GetModuleU         pVMMDLL_Map_GetModuleU = nullptr;

// ── VMM loader ─────────────────────────────────────────────────────────────────

static bool LoadVMM() {
    g_hVMM = LoadLibraryA("vmm.dll");
    if (!g_hVMM) {
        printf("[-] vmm.dll not found. Place vmm.dll + leechcore.dll in the same directory.\n");
        return false;
    }

    #define LOAD(name) p##name = (fn_##name)GetProcAddress(g_hVMM, #name)
    LOAD(VMMDLL_Initialize);
    LOAD(VMMDLL_Close);
    LOAD(VMMDLL_PidGetFromName);
    LOAD(VMMDLL_PidList);
    LOAD(VMMDLL_MemReadEx);
    LOAD(VMMDLL_ProcessGetInformationString);
    LOAD(VMMDLL_MemFree);
    LOAD(VMMDLL_Scatter_Initialize);
    LOAD(VMMDLL_Scatter_Prepare);
    LOAD(VMMDLL_Scatter_Execute);
    LOAD(VMMDLL_Scatter_Read);
    LOAD(VMMDLL_Scatter_CloseHandle);
    LOAD(VMMDLL_ProcessGetModuleBaseU);
    LOAD(VMMDLL_ProcessGetInformation);
    LOAD(VMMDLL_Map_GetModuleU);
    #undef LOAD

    if (!pVMMDLL_Initialize || !pVMMDLL_MemReadEx) {
        printf("[-] Failed to resolve VMM API functions.\n");
        return false;
    }

    return true;
}

// ── DMA memory read wrappers ───────────────────────────────────────────────────

static bool DmaRead(DWORD pid, uint64_t va, void* buf, size_t size) {
    DWORD cbRead = 0;
    return pVMMDLL_MemReadEx(g_hVmmHandle, pid, va, (PBYTE)buf, (DWORD)size, &cbRead, 0x0002) && cbRead > 0;
}

template<typename T>
static T DmaRead(uint64_t va) {
    T val{};
    DmaRead(g_targetPid, va, &val, sizeof(T));
    return val;
}

static bool DmaReadBuf(uint64_t va, void* buf, size_t size) {
    return DmaRead(g_targetPid, va, buf, size);
}

static uint64_t GetModBase(const char* name) {
    if (pVMMDLL_ProcessGetModuleBaseU)
        return pVMMDLL_ProcessGetModuleBaseU(g_hVmmHandle, g_targetPid, name);
    return 0;
}

// ── PE parsing helpers ─────────────────────────────────────────────────────────

struct ModuleInfo {
    std::string name;
    uint64_t    base;
    uint32_t    size;
};

struct SectionInfo {
    char     name[9];
    uint64_t base;
    uint32_t virtualSize;
    uint32_t characteristics;
};

struct ExportEntry {
    std::string name;
    uint32_t    rva;
};

static bool ReadPEHeaders(uint64_t base, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt) {
    if (!DmaReadBuf(base, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!DmaReadBuf(base + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    return true;
}

static std::vector<SectionInfo> GetSections(uint64_t modBase) {
    std::vector<SectionInfo> result;
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(modBase, dos, nt)) return result;

    uint64_t secAddr = modBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec{};
        if (!DmaReadBuf(secAddr + i * sizeof(sec), &sec, sizeof(sec))) continue;
        SectionInfo si{};
        memcpy(si.name, sec.Name, 8);
        si.name[8] = 0;
        si.base = modBase + sec.VirtualAddress;
        si.virtualSize = sec.Misc.VirtualSize;
        si.characteristics = sec.Characteristics;
        result.push_back(si);
    }
    return result;
}

static std::vector<ExportEntry> ReadExports(uint64_t base) {
    std::vector<ExportEntry> exports;
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(base, dos, nt)) return exports;

    auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return exports;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!DmaReadBuf(base + dir.VirtualAddress, &exp, sizeof(exp))) return exports;

    std::vector<DWORD> funcs(exp.NumberOfFunctions);
    std::vector<DWORD> names(exp.NumberOfNames);
    std::vector<WORD>  ords(exp.NumberOfNames);

    if (exp.NumberOfFunctions)
        DmaReadBuf(base + exp.AddressOfFunctions, funcs.data(), exp.NumberOfFunctions * sizeof(DWORD));
    if (exp.NumberOfNames) {
        DmaReadBuf(base + exp.AddressOfNames, names.data(), exp.NumberOfNames * sizeof(DWORD));
        DmaReadBuf(base + exp.AddressOfNameOrdinals, ords.data(), exp.NumberOfNames * sizeof(WORD));
    }

    for (DWORD i = 0; i < exp.NumberOfNames && i < 2000; i++) {
        char nameBuf[256]{};
        if (DmaReadBuf(base + names[i], nameBuf, sizeof(nameBuf) - 1)) {
            ExportEntry e;
            e.name = nameBuf;
            e.rva = (ords[i] < funcs.size()) ? funcs[ords[i]] : 0;
            exports.push_back(e);
        }
    }
    return exports;
}

static std::vector<std::string> ReadImports(uint64_t base) {
    std::vector<std::string> dlls;
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(base, dos, nt)) return dlls;

    auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return dlls;

    for (int i = 0; i < 256; i++) {
        IMAGE_IMPORT_DESCRIPTOR imp{};
        if (!DmaReadBuf(base + dir.VirtualAddress + i * sizeof(imp), &imp, sizeof(imp))) break;
        if (!imp.Name) break;
        char dllName[128]{};
        if (DmaReadBuf(base + imp.Name, dllName, sizeof(dllName) - 1))
            dlls.push_back(dllName);
    }
    return dlls;
}

// ── Pattern scanner ────────────────────────────────────────────────────────────

struct PatternByte { uint8_t value; bool wildcard; };

static std::vector<PatternByte> ParsePattern(const char* pattern) {
    std::vector<PatternByte> result;
    const char* p = pattern;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            result.push_back({0, true});
            p++;
            if (*p == '?') p++;
        } else {
            char hex[3] = {p[0], p[1], 0};
            result.push_back({(uint8_t)strtol(hex, nullptr, 16), false});
            p += 2;
        }
    }
    return result;
}

static uint64_t ScanPattern(uint64_t base, uint32_t size, const char* pattern) {
    auto pat = ParsePattern(pattern);
    if (pat.empty()) return 0;

    const uint32_t chunkSize = 0x100000;
    uint32_t overlap = (uint32_t)pat.size();

    for (uint32_t offset = 0; offset < size; offset += chunkSize - overlap) {
        uint32_t toRead = min(chunkSize, size - offset);
        if (toRead < pat.size()) break;
        std::vector<uint8_t> chunk(toRead);
        DmaReadBuf(base + offset, chunk.data(), toRead);

        for (uint32_t i = 0; i + pat.size() <= toRead; i++) {
            bool match = true;
            for (size_t j = 0; j < pat.size(); j++) {
                if (!pat[j].wildcard && chunk[i + j] != pat[j].value)
                { match = false; break; }
            }
            if (match) return base + offset + i;
        }
    }
    return 0;
}

static uint64_t ResolveRIP(uint64_t instrAddr, int opcodeLen) {
    int32_t disp = DmaRead<int32_t>(instrAddr + opcodeLen);
    return instrAddr + opcodeLen + 4 + disp;
}

// ── Engine types and game definitions ──────────────────────────────────────────

enum EngineType { ENGINE_UNKNOWN, ENGINE_UE4, ENGINE_UE5, ENGINE_IL2CPP, ENGINE_MONO, ENGINE_SOURCE2, ENGINE_NATIVE };

static const char* EngineNames[] = {
    "Unknown", "Unreal Engine 4", "Unreal Engine 5",
    "Unity (IL2CPP)", "Unity (Mono)", "Source 2", "Native"
};

struct GameDef {
    const char* alias;
    const char* processName;
    EngineType  engine;
    const char* coreModule;
};

static const GameDef KnownGames[] = {
    {"arenabreakout",  "ArenaBreakoutInfinite-Win64-Shipping.exe", ENGINE_UE5,    "ArenaBreakoutInfinite-Win64-Shipping.exe"},
    {"abi",            "ArenaBreakoutInfinite-Win64-Shipping.exe", ENGINE_UE5,    "ArenaBreakoutInfinite-Win64-Shipping.exe"},
    {"arenabreakout",  "ArenaBreakout.exe",                        ENGINE_UE5,    "ArenaBreakout.exe"},
    {"hunger",         "Hunger-Win64-Shipping.exe",                ENGINE_UE5,    "Hunger-Win64-Shipping.exe"},
    {"hunger",         "HungerGame-Win64-Shipping.exe",            ENGINE_UE5,    "HungerGame-Win64-Shipping.exe"},
    {"hunger",         "Hunger.exe",                               ENGINE_UE5,    "Hunger.exe"},
    {"rust",           "RustClient.exe",                           ENGINE_IL2CPP, "GameAssembly.dll"},
    {"deltaforce",     "DeltaForceClient-Win64-Shipping.exe",      ENGINE_UE5,    "DeltaForceClient-Win64-Shipping.exe"},
    {"df",             "DeltaForceClient-Win64-Shipping.exe",      ENGINE_UE5,    "DeltaForceClient-Win64-Shipping.exe"},
    {"squad",          "SquadGame-Win64-Shipping.exe",             ENGINE_UE4,    "SquadGame-Win64-Shipping.exe"},
    {"cs2",            "cs2.exe",                                  ENGINE_SOURCE2,"client.dll"},
    {"apex",           "r5apex_dx12.exe",                          ENGINE_NATIVE, "r5apex_dx12.exe"},
    {"r6",             "RainbowSix.exe",                           ENGINE_NATIVE, "RainbowSix.exe"},
    {"siege",          "RainbowSix.exe",                           ENGINE_NATIVE, "RainbowSix.exe"},
    {"unturned",       "Unturned.exe",                             ENGINE_MONO,   "Assembly-CSharp.dll"},
    {"stalcraft",      "stalzone.exe",                             ENGINE_NATIVE, "stalzone.exe"},
    {nullptr, nullptr, ENGINE_UNKNOWN, nullptr}
};

// ── Interactive process selection ──────────────────────────────────────────────

struct ProcessEntry {
    DWORD       pid;
    std::string name;
    std::string path;
};

static std::vector<ProcessEntry> GetProcessList() {
    std::vector<ProcessEntry> result;
    ULONG64 count = 0;
    if (!pVMMDLL_PidList(g_hVmmHandle, nullptr, &count) || count == 0)
        return result;

    std::vector<DWORD> pids((size_t)count);
    pVMMDLL_PidList(g_hVmmHandle, pids.data(), &count);

    for (DWORD i = 0; i < (DWORD)count; i++) {
        ProcessEntry pe;
        pe.pid = pids[i];
        pe.name = "(unknown)";

        LPSTR name = nullptr;
        if (pVMMDLL_ProcessGetInformationString &&
            pVMMDLL_ProcessGetInformationString(g_hVmmHandle, pids[i], 2, &name) && name) {
            pe.path = name;
            const char* slash = strrchr(name, '\\');
            pe.name = slash ? (slash + 1) : name;
            pVMMDLL_MemFree(name);
        } else if (pVMMDLL_ProcessGetInformationString &&
                   pVMMDLL_ProcessGetInformationString(g_hVmmHandle, pids[i], 1, &name) && name) {
            pe.name = name;
            pVMMDLL_MemFree(name);
        }

        result.push_back(pe);
    }
    return result;
}

static bool IsGameProcess(const std::string& name) {
    static const char* skipList[] = {
        "svchost.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "smss.exe", "System", "Registry", "dwm.exe",
        "conhost.exe", "fontdrvhost.exe", "WmiPrvSE.exe", "dllhost.exe",
        "sihost.exe", "taskhostw.exe", "RuntimeBroker.exe", "SearchHost.exe",
        "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
        "TextInputHost.exe", "ctfmon.exe", "spoolsv.exe", "audiodg.exe",
        "SecurityHealthService.exe", "SecurityHealthSystray.exe",
        "MsMpEng.exe", "NisSrv.exe", "WUDFHost.exe", "dasHost.exe",
        "MemCompression", "(unknown)", nullptr
    };
    for (int i = 0; skipList[i]; i++)
        if (_stricmp(name.c_str(), skipList[i]) == 0) return false;
    if (name.size() < 4) return false;
    return true;
}

static DWORD SelectProcess() {
    auto procs = GetProcessList();

    // Filter to likely game/app processes
    std::vector<ProcessEntry> games;
    for (auto& p : procs)
        if (IsGameProcess(p.name)) games.push_back(p);

    // Sort alphabetically
    std::sort(games.begin(), games.end(),
        [](const ProcessEntry& a, const ProcessEntry& b) {
            std::string la = a.name, lb = b.name;
            for (auto& c : la) c = (char)tolower((unsigned char)c);
            for (auto& c : lb) c = (char)tolower((unsigned char)c);
            return la < lb;
        });

    printf("\n=== Process List (%zu processes on target) ===\n\n", games.size());
    for (size_t i = 0; i < games.size(); i++) {
        // Highlight known game processes
        bool known = false;
        for (int k = 0; KnownGames[k].alias; k++) {
            if (_stricmp(games[i].name.c_str(), KnownGames[k].processName) == 0) {
                known = true; break;
            }
        }
        printf("  %s[%3zu]%s  %-8lu  %s\n",
            known ? ">>>" : "   ",
            i + 1,
            known ? "<<<" : "   ",
            games[i].pid,
            games[i].name.c_str());
    }

    printf("\n  Enter number (or process name): ");
    char input[256]{};
    if (!fgets(input, sizeof(input), stdin)) return 0;
    input[strcspn(input, "\r\n")] = 0;
    if (input[0] == 0) return 0;

    // Try as number
    int idx = atoi(input);
    if (idx >= 1 && idx <= (int)games.size())
        return games[idx - 1].pid;

    // Try as process name
    for (auto& p : procs) {
        if (_stricmp(p.name.c_str(), input) == 0)
            return p.pid;
    }

    // Try as alias
    for (int k = 0; KnownGames[k].alias; k++) {
        if (_stricmp(input, KnownGames[k].alias) == 0) {
            DWORD pid = 0;
            if (pVMMDLL_PidGetFromName(g_hVmmHandle, KnownGames[k].processName, &pid) && pid)
                return pid;
        }
    }

    printf("[-] Process not found: %s\n", input);
    return 0;
}

// ── Engine auto-detection ──────────────────────────────────────────────────────

static EngineType DetectEngine(DWORD pid, const std::string& procName) {
    // Check known games first
    for (int i = 0; KnownGames[i].alias; i++) {
        if (_stricmp(procName.c_str(), KnownGames[i].processName) == 0)
            return KnownGames[i].engine;
    }

    // Probe for engine-specific modules
    if (GetModBase("GameAssembly.dll")) return ENGINE_IL2CPP;
    if (GetModBase("mono-2.0-bdwgc.dll") || GetModBase("mono.dll")) return ENGINE_MONO;
    if (GetModBase("client.dll") && GetModBase("engine2.dll")) return ENGINE_SOURCE2;

    // UE4/5 heuristic: check for -Shipping.exe pattern or UE modules
    std::string lower = procName;
    for (auto& c : lower) c = (char)tolower((unsigned char)c);
    if (lower.find("-shipping.exe") != std::string::npos) return ENGINE_UE5;
    if (lower.find("-win64-") != std::string::npos) return ENGINE_UE5;

    return ENGINE_UNKNOWN;
}

static EngineType SelectEngine(EngineType detected) {
    printf("\n=== Engine Selection ===\n\n");
    printf("  Auto-detected: %s\n\n", EngineNames[detected]);
    printf("  [1]  Unreal Engine 4\n");
    printf("  [2]  Unreal Engine 5\n");
    printf("  [3]  Unity (IL2CPP)  — Rust, etc.\n");
    printf("  [4]  Unity (Mono)    — Unturned, etc.\n");
    printf("  [5]  Source 2        — CS2, etc.\n");
    printf("  [6]  Native/Other    — R6 Siege, Apex, etc.\n");
    if (detected != ENGINE_UNKNOWN)
        printf("  [Enter] Use auto-detected (%s)\n", EngineNames[detected]);

    printf("\n  Select engine: ");
    char input[64]{};
    if (!fgets(input, sizeof(input), stdin)) return detected;
    input[strcspn(input, "\r\n")] = 0;

    if (input[0] == 0) return detected;
    int choice = atoi(input);
    switch (choice) {
        case 1: return ENGINE_UE4;
        case 2: return ENGINE_UE5;
        case 3: return ENGINE_IL2CPP;
        case 4: return ENGINE_MONO;
        case 5: return ENGINE_SOURCE2;
        case 6: return ENGINE_NATIVE;
        default: return detected;
    }
}

// ── Output directory ───────────────────────────────────────────────────────────

static std::string MakeOutputDir(const char* procName) {
    char desktop[MAX_PATH] = {};
    SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop);
    std::string dumps = std::string(desktop) + "\\Dumps";
    _mkdir(dumps.c_str());

    std::string gameName = procName;
    auto dot = gameName.rfind('.');
    if (dot != std::string::npos) gameName = gameName.substr(0, dot);

    time_t now = time(nullptr);
    struct tm t{};
    localtime_s(&t, &now);
    char date[32];
    sprintf_s(date, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

    std::string dir = dumps + "\\" + gameName + "_" + date;
    _mkdir(dir.c_str());
    return dir;
}

// ── UE FName reader ────────────────────────────────────────────────────────────

static std::string ReadUEFName(uint64_t gnamesBase, int32_t nameIndex) {
    if (nameIndex <= 0 || !gnamesBase) return "";

    int blockIdx = (nameIndex >> 16) & 0xFFFF;
    int offsetInBlock = nameIndex & 0xFFFF;

    uint64_t block = DmaRead<uint64_t>(gnamesBase + 0x10 + blockIdx * 8);
    if (block > 0x10000 && block < 0x7FFFFFFFFFFF) {
        uint64_t entry = block + (uint64_t)offsetInBlock * 2;
        uint16_t header = DmaRead<uint16_t>(entry);
        int len = header >> 6;
        if (len > 0 && len <= 256) {
            char buf[257]{};
            DmaReadBuf(entry + 2, buf, len);
            bool valid = (strlen(buf) > 0);
            for (int i = 0; buf[i] && valid; i++)
                if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) valid = false;
            if (valid) return std::string(buf);
        }
    }

    // Fallback: old-style chunked array (UE4 < 4.23)
    int chunkIdx = nameIndex / 16384;
    int chunkOff = nameIndex % 16384;
    uint64_t chunk = DmaRead<uint64_t>(gnamesBase + chunkIdx * 8);
    if (chunk > 0x10000 && chunk < 0x7FFFFFFFFFFF) {
        uint64_t entryPtr = DmaRead<uint64_t>(chunk + chunkOff * 8);
        if (entryPtr > 0x10000 && entryPtr < 0x7FFFFFFFFFFF) {
            for (int off : {0x10, 0x0C, 0x08}) {
                char buf[257]{};
                DmaReadBuf(entryPtr + off, buf, 256);
                bool valid = (strlen(buf) > 1);
                for (int i = 0; buf[i] && valid; i++)
                    if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) valid = false;
                if (valid) return std::string(buf);
            }
        }
    }
    return "";
}

// ── Unreal Engine offset scanner (Dumper-7 style) ──────────────────────────────

static bool DumpUEOffsets(const char* procName, uint64_t modBase, bool isUE5, const std::string& outDir) {
    auto sections = GetSections(modBase);
    uint64_t textBase = 0;
    uint32_t textSize = 0;

    for (auto& s : sections) {
        if (strcmp(s.name, ".text") == 0)
        { textBase = s.base; textSize = s.virtualSize; break; }
    }
    if (!textBase) {
        for (auto& s : sections) {
            if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
            { textBase = s.base; textSize = s.virtualSize; break; }
        }
    }
    if (!textBase) { printf("[-] No executable section found\n"); return false; }

    printf("[*] Scanning %s .text: 0x%llX (%u MB)\n",
        isUE5 ? "UE5" : "UE4", (unsigned long long)textBase, textSize / (1024 * 1024));

    // === GWorld ===
    uint64_t gworldPtr = 0;
    const char* gworldSigs[] = {
        "48 8B 1D ?? ?? ?? ?? 48 85 DB 74",
        "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? 00 00 48 85 C9 74 06 48 8B 49",
        "48 89 05 ?? ?? ?? ?? 48 8B 4B",
        "48 8B 05 ?? ?? ?? ?? 48 3B C3 48 0F 44 05",
        nullptr
    };
    for (int i = 0; gworldSigs[i] && !gworldPtr; i++) {
        uint64_t addr = ScanPattern(textBase, textSize, gworldSigs[i]);
        if (addr) {
            uint64_t resolved = ResolveRIP(addr, 3);
            uint64_t val = DmaRead<uint64_t>(resolved);
            if (val > 0x10000 && val < 0x7FFFFFFFFFFF) {
                gworldPtr = resolved;
                printf("[+] GWorld @ 0x%llX (sig #%d)\n", (unsigned long long)resolved, i);
            }
        }
    }
    if (!gworldPtr) printf("[!] GWorld not found\n");

    // === GNames ===
    uint64_t gnamesPtr = 0;
    const char* gnamesSigs[] = {
        "48 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05",
        "4C 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D",
        "48 8D 35 ?? ?? ?? ?? EB ?? 48 8D 0D",
        nullptr
    };
    for (int i = 0; gnamesSigs[i] && !gnamesPtr; i++) {
        uint64_t addr = ScanPattern(textBase, textSize, gnamesSigs[i]);
        if (addr) {
            gnamesPtr = ResolveRIP(addr, 3);
            uint64_t block0 = DmaRead<uint64_t>(gnamesPtr + 0x10);
            if (block0 > 0x10000 && block0 < 0x7FFFFFFFFFFF) {
                std::string testName = ReadUEFName(gnamesPtr, 1);
                if (!testName.empty()) {
                    printf("[+] GNames @ 0x%llX (test='%s')\n", (unsigned long long)gnamesPtr, testName.c_str());
                    break;
                }
            }
            gnamesPtr = 0;
        }
    }
    if (!gnamesPtr) printf("[!] GNames not found\n");

    // === GObjects ===
    uint64_t gobjectsPtr = 0;
    const char* gobjectsSigs[] = {
        "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1",
        "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1",
        "48 8B 05 ?? ?? ?? ?? 48 63 C9 48 8B 0C C8",
        "89 0D ?? ?? ?? ?? 48 8B DF 48 89 5C 24",
        nullptr
    };
    for (int i = 0; gobjectsSigs[i] && !gobjectsPtr; i++) {
        uint64_t addr = ScanPattern(textBase, textSize, gobjectsSigs[i]);
        if (addr) {
            gobjectsPtr = ResolveRIP(addr, 3);
            printf("[+] GObjects @ 0x%llX (sig #%d)\n", (unsigned long long)gobjectsPtr, i);
            break;
        }
    }
    if (!gobjectsPtr) printf("[!] GObjects not found\n");

    // === Write output ===
    std::string filePath = outDir + "\\offsets.h";
    FILE* f = fopen(filePath.c_str(), "w");
    if (!f) { printf("[-] Failed to create %s\n", filePath.c_str()); return false; }

    time_t now = time(nullptr);
    struct tm ti{};
    localtime_s(&ti, &now);
    char date[32];
    sprintf_s(date, "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);

    fprintf(f, "// %s Offset Dump - %s\n", procName, date);
    fprintf(f, "// Engine: %s\n", isUE5 ? "Unreal Engine 5" : "Unreal Engine 4");
    fprintf(f, "// Auto-generated via DMA pattern scanning (Dumper-7 style)\n");
    fprintf(f, "// Module base: 0x%llX\n\n", (unsigned long long)modBase);
    fprintf(f, "#pragma once\n#include <cstdint>\n\n");

    fprintf(f, "namespace UE_Globals {\n");
    fprintf(f, "    constexpr uintptr_t ModuleBase = 0x%llX;\n", (unsigned long long)modBase);
    auto writeGlobal = [&](const char* name, uint64_t ptr) {
        if (ptr)
            fprintf(f, "    constexpr uintptr_t %s = 0x%llX;  // RVA=0x%llX\n",
                name, (unsigned long long)ptr, (unsigned long long)(ptr - modBase));
        else
            fprintf(f, "    constexpr uintptr_t %s = 0x0;  // NOT FOUND\n", name);
    };
    writeGlobal("GWorld", gworldPtr);
    writeGlobal("GNames", gnamesPtr);
    writeGlobal("GObjects", gobjectsPtr);
    fprintf(f, "}\n\n");

    // Common UE structure offsets
    fprintf(f, "namespace UObject {\n");
    fprintf(f, "    constexpr int VTable        = 0x00;\n");
    fprintf(f, "    constexpr int ClassPrivate   = 0x10;\n");
    fprintf(f, "    constexpr int NamePrivate    = 0x18;\n");
    fprintf(f, "    constexpr int OuterPrivate   = 0x20;\n");
    fprintf(f, "}\n\n");

    int persLevelOff  = 0x30;
    int gameStateOff  = isUE5 ? 0x158 : 0x128;
    int gameInstOff   = isUE5 ? 0x1B8 : 0x180;
    int rootCompOff   = isUE5 ? 0x198 : 0x130;
    int relLocOff     = isUE5 ? 0x128 : 0x11C;
    int compToWorld   = 0x1C0;
    int pawnStateOff  = isUE5 ? 0x2A8 : 0x248;
    int controllerOff = isUE5 ? 0x290 : 0x230;
    int meshOff       = isUE5 ? 0x318 : 0x280;
    int pcCamMgr      = isUE5 ? 0x338 : 0x2B8;
    int ackPawnOff    = isUE5 ? 0x330 : 0x2B0;
    int camCacheOff   = isUE5 ? 0x2220 : 0x1AB0;
    int boneArrayOff  = isUE5 ? 0x5B0 : 0x480;

    fprintf(f, "namespace UWorld {\n");
    fprintf(f, "    constexpr int PersistentLevel    = 0x%X;\n", persLevelOff);
    fprintf(f, "    constexpr int OwningGameInstance = 0x%X;\n", gameInstOff);
    fprintf(f, "    constexpr int GameState          = 0x%X;\n", gameStateOff);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace ULevel {\n");
    fprintf(f, "    constexpr int Actors     = 0x98;\n");
    fprintf(f, "    constexpr int ActorCount = 0xA0;\n");
    fprintf(f, "}\n\n");

    fprintf(f, "namespace AActor {\n");
    fprintf(f, "    constexpr int RootComponent = 0x%X;\n", rootCompOff);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace USceneComponent {\n");
    fprintf(f, "    constexpr int RelativeLocation  = 0x%X;\n", relLocOff);
    fprintf(f, "    constexpr int ComponentToWorld  = 0x%X;\n", compToWorld);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace APawn {\n");
    fprintf(f, "    constexpr int PlayerState = 0x%X;\n", pawnStateOff);
    fprintf(f, "    constexpr int Controller  = 0x%X;\n", controllerOff);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace ACharacter {\n");
    fprintf(f, "    constexpr int Mesh          = 0x%X;\n", meshOff);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace APlayerController {\n");
    fprintf(f, "    constexpr int PlayerCameraManager = 0x%X;\n", pcCamMgr);
    fprintf(f, "    constexpr int AcknowledgedPawn    = 0x%X;\n", ackPawnOff);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace APlayerCameraManager {\n");
    fprintf(f, "    constexpr int CameraCachePrivate = 0x%X;\n", camCacheOff);
    fprintf(f, "}\n\n");

    fprintf(f, "namespace UGameInstance {\n");
    fprintf(f, "    constexpr int LocalPlayers = 0x38;\n");
    fprintf(f, "}\n\n");

    fprintf(f, "namespace ULocalPlayer {\n");
    fprintf(f, "    constexpr int PlayerController = 0x30;\n");
    fprintf(f, "}\n\n");

    fprintf(f, "namespace USkeletalMeshComponent {\n");
    fprintf(f, "    constexpr int BoneArray = 0x%X;\n", boneArrayOff);
    fprintf(f, "}\n\n");

    // Walk GWorld chain for live data
    if (gworldPtr) {
        uint64_t world = DmaRead<uint64_t>(gworldPtr);
        if (world > 0x10000) {
            uint64_t persLevel = DmaRead<uint64_t>(world + persLevelOff);
            uint64_t gameState = DmaRead<uint64_t>(world + gameStateOff);
            uint64_t gameInst  = DmaRead<uint64_t>(world + gameInstOff);

            fprintf(f, "// === Live GWorld Chain ===\n");
            fprintf(f, "// UWorld           = 0x%llX\n", (unsigned long long)world);
            fprintf(f, "// PersistentLevel  = 0x%llX\n", (unsigned long long)persLevel);
            fprintf(f, "// GameState        = 0x%llX\n", (unsigned long long)gameState);
            fprintf(f, "// GameInstance     = 0x%llX\n\n", (unsigned long long)gameInst);

            if (persLevel > 0x10000) {
                uint64_t actorsPtr = DmaRead<uint64_t>(persLevel + 0x98);
                int32_t actorCount = DmaRead<int32_t>(persLevel + 0xA0);
                fprintf(f, "// Actors: 0x%llX, count=%d\n", (unsigned long long)actorsPtr, actorCount);

                if (actorsPtr > 0x10000 && actorCount > 0 && actorCount < 100000 && gnamesPtr) {
                    fprintf(f, "// First 20 actors:\n");
                    int shown = 0;
                    for (int i = 0; i < min(actorCount, 100) && shown < 20; i++) {
                        uint64_t actor = DmaRead<uint64_t>(actorsPtr + i * 8);
                        if (!actor) continue;
                        int32_t nameIdx = DmaRead<int32_t>(actor + 0x18);
                        std::string actorName = ReadUEFName(gnamesPtr, nameIdx);
                        uint64_t classPtr = DmaRead<uint64_t>(actor + 0x10);
                        std::string className;
                        if (classPtr) {
                            int32_t classNameIdx = DmaRead<int32_t>(classPtr + 0x18);
                            className = ReadUEFName(gnamesPtr, classNameIdx);
                        }
                        fprintf(f, "//   [%d] 0x%llX  %s (%s)\n",
                            i, (unsigned long long)actor, actorName.c_str(), className.c_str());
                        shown++;
                    }
                }
                fprintf(f, "\n");
            }
        }
    }

    // Walk GObjects for class property dumps
    if (gobjectsPtr && gnamesPtr) {
        fprintf(f, "// === GObjects Class/Property Scan ===\n\n");

        uint64_t objArray = DmaRead<uint64_t>(gobjectsPtr);
        int32_t objCount = DmaRead<int32_t>(gobjectsPtr + 0x14);
        if (objCount <= 0 || objCount > 10000000) {
            objArray = DmaRead<uint64_t>(gobjectsPtr + 0x10);
            objCount = DmaRead<int32_t>(gobjectsPtr + 0x0C);
        }

        if (objArray > 0x10000 && objCount > 0 && objCount < 10000000) {
            printf("[*] Scanning %d GObjects for class properties...\n", objCount);

            const int CHUNK_SIZE = 65536;
            int classesFound = 0;
            int maxScan = min(objCount, 200000);

            for (int i = 0; i < maxScan && classesFound < 300; i++) {
                int chunkIdx = i / CHUNK_SIZE;
                int chunkOff = i % CHUNK_SIZE;
                uint64_t chunk = DmaRead<uint64_t>(objArray + chunkIdx * 8);
                if (!chunk) continue;

                uint64_t obj = DmaRead<uint64_t>(chunk + chunkOff * 24);
                if (!obj || obj < 0x10000 || obj > 0x7FFFFFFFFFFF) continue;

                uint64_t classPtr = DmaRead<uint64_t>(obj + 0x10);
                if (!classPtr || classPtr < 0x10000) continue;
                uint64_t classOfClass = DmaRead<uint64_t>(classPtr + 0x10);
                if (classOfClass != classPtr) continue;

                int32_t nameIdx = DmaRead<int32_t>(obj + 0x18);
                std::string name = ReadUEFName(gnamesPtr, nameIdx);
                if (name.empty()) continue;

                const char* keywords[] = {
                    "Player", "Pawn", "Character", "Controller", "Weapon",
                    "Vehicle", "Health", "Camera", "Soldier", "Team",
                    "Inventory", "Item", "Projectile", "Component",
                    nullptr
                };
                bool interesting = false;
                for (int k = 0; keywords[k]; k++) {
                    if (name.find(keywords[k]) != std::string::npos)
                    { interesting = true; break; }
                }
                if (!interesting) continue;

                // Walk ChildProperties (FField chain at UStruct+0x50)
                uint64_t propPtr = DmaRead<uint64_t>(obj + 0x50);
                bool hasProp = false;
                int propCount = 0;

                while (propPtr > 0x10000 && propPtr < 0x7FFFFFFFFFFF && propCount < 200) {
                    int32_t propNameIdx = DmaRead<int32_t>(propPtr + 0x28);
                    std::string propName = ReadUEFName(gnamesPtr, propNameIdx);
                    int32_t propOffset = DmaRead<int32_t>(propPtr + 0x4C);

                    if (!propName.empty() && propOffset >= 0 && propOffset < 0x10000) {
                        if (!hasProp) {
                            fprintf(f, "namespace %s {\n", name.c_str());
                            hasProp = true;
                        }
                        fprintf(f, "    constexpr int %s = 0x%X;\n", propName.c_str(), propOffset);
                    }
                    propPtr = DmaRead<uint64_t>(propPtr + 0x20);
                    propCount++;
                }

                if (hasProp) {
                    fprintf(f, "}\n\n");
                    classesFound++;
                }
            }
            printf("[+] Found %d classes with properties\n", classesFound);
        }
    }

    // Pointer chain reference
    fprintf(f, "// === Pointer Chain Reference ===\n");
    fprintf(f, "// Local player: [GWorld] -> GameInstance (+0x%X) -> LocalPlayers (+0x38)\n", gameInstOff);
    fprintf(f, "//   -> [0] -> PlayerController (+0x30) -> AcknowledgedPawn (+0x%X)\n", ackPawnOff);
    fprintf(f, "// Actors: [GWorld] -> PersistentLevel (+0x30) -> Actors (+0x98)\n");
    fprintf(f, "// Camera: PlayerController -> PlayerCameraManager (+0x%X)\n", pcCamMgr);
    fprintf(f, "//   -> CameraCachePrivate (+0x%X)\n\n", camCacheOff);

    fclose(f);

    // INI file
    std::string iniPath = outDir + "\\offsets.ini";
    FILE* ini = fopen(iniPath.c_str(), "w");
    if (ini) {
        fprintf(ini, "# %s — Auto-generated Offsets\n", procName);
        fprintf(ini, "# Date: %s\n# Engine: %s\n\n", date, isUE5 ? "UE5" : "UE4");
        fprintf(ini, "[Identity]\nProcessName=%s\nEngine=%s\n\n", procName, isUE5 ? "ue5" : "ue4");
        fprintf(ini, "[Globals]\nGWorld=0x%llX\nGNames=0x%llX\nGObjects=0x%llX\n\n",
            (unsigned long long)(gworldPtr ? gworldPtr - modBase : 0),
            (unsigned long long)(gnamesPtr ? gnamesPtr - modBase : 0),
            (unsigned long long)(gobjectsPtr ? gobjectsPtr - modBase : 0));
        fprintf(ini, "[UWorld]\nPersistentLevel=0x30\nOwningGameInstance=0x%X\nGameState=0x%X\n\n", gameInstOff, gameStateOff);
        fprintf(ini, "[ULevel]\nActors=0x98\nActorCount=0xA0\n\n");
        fprintf(ini, "[AActor]\nRootComponent=0x%X\n\n", rootCompOff);
        fprintf(ini, "[USceneComponent]\nRelativeLocation=0x%X\nComponentToWorld=0x%X\n\n", relLocOff, compToWorld);
        fprintf(ini, "[APawn]\nPlayerState=0x%X\nController=0x%X\n\n", pawnStateOff, controllerOff);
        fprintf(ini, "[APlayerController]\nPlayerCameraManager=0x%X\nAcknowledgedPawn=0x%X\n\n", pcCamMgr, ackPawnOff);
        fprintf(ini, "[APlayerCameraManager]\nCameraCachePrivate=0x%X\n\n", camCacheOff);
        fprintf(ini, "[ACharacter]\nMesh=0x%X\n\n", meshOff);
        fprintf(ini, "[USkeletalMeshComponent]\nBoneArray=0x%X\n\n", boneArrayOff);
        fclose(ini);
        printf("[+] INI: %s\n", iniPath.c_str());
    }

    printf("[+] Offsets: %s\n", filePath.c_str());
    return true;
}

// ── IL2CPP offset scanner ──────────────────────────────────────────────────────

#pragma pack(push, 1)
struct Il2CppMetadataHeader {
    uint32_t magic;         // 0xFAB11BAF
    int32_t  version;
    int32_t  stringLiteralOffset;
    int32_t  stringLiteralCount;
    int32_t  stringLiteralDataOffset;
    int32_t  stringLiteralDataCount;
    int32_t  stringOffset;
    int32_t  stringCount;
    int32_t  eventsOffset;
    int32_t  eventsCount;
    int32_t  propertiesOffset;
    int32_t  propertiesCount;
    int32_t  methodsOffset;
    int32_t  methodsCount;
    int32_t  parameterDefaultValuesOffset;
    int32_t  parameterDefaultValuesCount;
    int32_t  fieldDefaultValuesOffset;
    int32_t  fieldDefaultValuesCount;
    int32_t  fieldAndParameterDefaultValueDataOffset;
    int32_t  fieldAndParameterDefaultValueDataCount;
    int32_t  fieldMarshaledSizesOffset;
    int32_t  fieldMarshaledSizesCount;
    int32_t  parametersOffset;
    int32_t  parametersCount;
    int32_t  fieldsOffset;
    int32_t  fieldsCount;
    int32_t  genericParametersOffset;
    int32_t  genericParametersCount;
    int32_t  genericParameterConstraintsOffset;
    int32_t  genericParameterConstraintsCount;
    int32_t  genericContainersOffset;
    int32_t  genericContainersCount;
    int32_t  nestedTypesOffset;
    int32_t  nestedTypesCount;
    int32_t  interfacesOffset;
    int32_t  interfacesCount;
    int32_t  vtableMethodsOffset;
    int32_t  vtableMethodsCount;
    int32_t  interfaceOffsetsOffset;
    int32_t  interfaceOffsetsCount;
    int32_t  typeDefinitionsOffset;
    int32_t  typeDefinitionsCount;
    int32_t  imagesOffset;
    int32_t  imagesCount;
    int32_t  assembliesOffset;
    int32_t  assembliesCount;
};

struct Il2CppFieldDefinition {
    int32_t  nameIndex;
    int32_t  typeIndex;
    uint32_t token;
};

struct Il2CppTypeDefinition {
    int32_t  nameIndex;
    int32_t  namespaceIndex;
    int32_t  byvalTypeIndex;
    int32_t  declaringTypeIndex;
    int32_t  parentIndex;
    int32_t  elementTypeIndex;
    int32_t  genericContainerIndex;
    uint32_t flags;
    int32_t  fieldStart;
    int32_t  methodStart;
    int32_t  eventStart;
    int32_t  propertyStart;
    int32_t  nestedTypesStart;
    int32_t  interfacesStart;
    int32_t  vtableStart;
    int32_t  interfaceOffsetsStart;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint32_t bitfield;
    uint32_t token;
};

struct Il2CppImageDefinition {
    int32_t  nameIndex;
    int32_t  assemblyIndex;
    int32_t  typeStart;
    uint32_t typeCount;
    int32_t  exportedTypeStart;
    uint32_t exportedTypeCount;
    int32_t  entryPointIndex;
    uint32_t token;
    int32_t  customAttributeStart;
    uint32_t customAttributeCount;
};
#pragma pack(pop)

static std::string ReadMetaString(uint64_t metaBase, int32_t stringOffset, int32_t index) {
    if (index < 0 || index >= stringOffset) return "";
    char buf[512]{};
    DmaReadBuf(metaBase + stringOffset + index, buf, 511);
    return std::string(buf);
}

// Read a C string from target memory
static std::string ReadCString(uint64_t ptr, int maxLen = 256) {
    if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) return "";
    char buf[512]{};
    int len = min(maxLen, 511);
    DmaReadBuf(ptr, buf, len);
    buf[len] = 0;
    for (int i = 0; buf[i]; i++)
        if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) { buf[i] = 0; break; }
    return std::string(buf);
}

// Find il2cpp_domain_get export and extract the domain pointer
static uint64_t FindIl2CppDomain(uint64_t gaBase) {
    auto exports = ReadExports(gaBase);
    uint64_t domainGetRva = 0;
    for (auto& e : exports) {
        if (e.name == "il2cpp_domain_get") { domainGetRva = e.rva; break; }
    }
    if (!domainGetRva) return 0;

    uint64_t funcAddr = gaBase + domainGetRva;
    uint8_t code[32]{};
    DmaReadBuf(funcAddr, code, 32);

    // Pattern: 48 8B 05 XX XX XX XX (mov rax, [rip+disp32]) then C3 (ret)
    for (int i = 0; i < 24; i++) {
        if (code[i] == 0x48 && code[i+1] == 0x8B && code[i+2] == 0x05) {
            int32_t disp = *(int32_t*)(code + i + 3);
            uint64_t staticAddr = funcAddr + i + 7 + disp;
            uint64_t domain = DmaRead<uint64_t>(staticAddr);
            if (domain > 0x10000 && domain < 0x7FFFFFFFFFFF)
                return domain;
        }
        // LEA variant: 48 8D 05 XX XX XX XX
        if (code[i] == 0x48 && code[i+1] == 0x8D && code[i+2] == 0x05) {
            int32_t disp = *(int32_t*)(code + i + 3);
            uint64_t staticAddr = funcAddr + i + 7 + disp;
            uint64_t domain = DmaRead<uint64_t>(staticAddr);
            if (domain > 0x10000 && domain < 0x7FFFFFFFFFFF)
                return domain;
        }
    }
    return 0;
}

// Find s_TypeInfoTable — the global array of Il2CppClass* indexed by type definition index
static uint64_t FindTypeInfoTable(uint64_t gaBase) {
    auto exports = ReadExports(gaBase);
    // il2cpp_class_from_il2cpp_type or MetadataCache::GetTypeInfoFromTypeDefinitionIndex
    // These reference s_TypeInfoTable or s_GlobalMetadata
    // Scan .data for a large pointer array where entries point to valid Il2CppClass structs
    // Heuristic: look for il2cpp_class_get_name export, trace to find the name offset

    // Alternative: find "il2cpp_image_get_class" which directly indexes into typesByDefinitionId
    uint64_t funcRva = 0;
    for (auto& e : exports) {
        if (e.name == "il2cpp_class_from_system_type" || e.name == "il2cpp_class_from_type") {
            funcRva = e.rva; break;
        }
    }
    if (!funcRva) {
        // Try scanning .data for the table heuristically
        // Look for a pointer that, when dereferenced twice, gives valid class structs
        auto sections = GetSections(gaBase);
        for (auto& s : sections) {
            if (strcmp(s.name, ".data") != 0) continue;
            uint32_t scanSize = min(s.virtualSize, 16u * 1024 * 1024);
            // Sample every 8 bytes looking for pointer arrays
            for (uint32_t off = 0; off < scanSize; off += 0x1000) {
                uint32_t toRead = min(0x1000u, scanSize - off);
                std::vector<uint8_t> chunk(toRead);
                DmaReadBuf(s.base + off, chunk.data(), toRead);

                for (uint32_t j = 0; j + 8 <= toRead; j += 8) {
                    uint64_t candidate = *(uint64_t*)(chunk.data() + j);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;

                    // Check if this looks like a pointer to Il2CppClass
                    // Il2CppClass has name at +0x10 (pointer to string)
                    uint64_t namePtr = DmaRead<uint64_t>(candidate + 0x10);
                    std::string name = ReadCString(namePtr);
                    if (name.size() < 2 || name.size() > 128) continue;

                    // Check namespace at +0x18
                    uint64_t nsPtr = DmaRead<uint64_t>(candidate + 0x18);
                    std::string ns = ReadCString(nsPtr);

                    // Check if next entry also looks valid
                    uint64_t next = *(uint64_t*)(chunk.data() + j + 8);
                    if (next < 0x10000 || next > 0x7FFFFFFFFFFF) continue;
                    uint64_t nextNamePtr = DmaRead<uint64_t>(next + 0x10);
                    std::string nextName = ReadCString(nextNamePtr);
                    if (nextName.size() < 2) continue;

                    // Found what looks like a TypeInfoTable
                    return s.base + off + j;
                }
            }
        }
    }
    return 0;
}

// Il2CppFieldInfo layout (stable across versions 24-31):
//   +0x00: const char* name
//   +0x08: Il2CppType* type
//   +0x10: Il2CppClass* parent
//   +0x18: int32_t offset      <-- the runtime field offset we want
//   +0x1C: uint32_t token
static const int FIELDINFO_SIZE = 0x20;
static const int FIELDINFO_NAME = 0x00;
static const int FIELDINFO_OFFSET = 0x18;

// Read runtime field offsets from an Il2CppClass pointer
struct RuntimeField {
    std::string name;
    int32_t offset;
    uint32_t token;
};

static std::vector<RuntimeField> ReadClassFields(uint64_t klassPtr) {
    std::vector<RuntimeField> result;
    if (!klassPtr) return result;

    // Il2CppClass::fields pointer — try common offsets across versions
    // v24-27: fields at +0x60, field_count at various
    // v27-29: fields at +0x80
    // v29-31: fields at +0x80
    const int fieldsPtrOffsets[] = {0x80, 0x60, 0x78, 0x88, 0x70};
    const int fieldCountOffsets[] = {0x120, 0x11C, 0x118, 0xF4, 0xF0, 0x100, 0x114, 0x124};

    uint64_t fieldsPtr = 0;
    int fieldCount = 0;

    // Try each fields pointer offset
    for (int fpOff : fieldsPtrOffsets) {
        uint64_t candidatePtr = DmaRead<uint64_t>(klassPtr + fpOff);
        if (candidatePtr < 0x10000 || candidatePtr > 0x7FFFFFFFFFFF) continue;

        // Validate: first entry should have a valid name pointer
        uint64_t firstName = DmaRead<uint64_t>(candidatePtr + FIELDINFO_NAME);
        std::string testName = ReadCString(firstName);
        if (testName.empty() || testName.size() > 128) continue;

        // Check offset value is sane
        int32_t testOff = DmaRead<int32_t>(candidatePtr + FIELDINFO_OFFSET);
        if (testOff < 0 || testOff > 0x10000) continue;

        fieldsPtr = candidatePtr;

        // Find field count
        for (int fcOff : fieldCountOffsets) {
            uint16_t fc = DmaRead<uint16_t>(klassPtr + fcOff);
            if (fc > 0 && fc < 500) {
                // Validate: check that field[fc-1] also has a valid name
                uint64_t lastFieldName = DmaRead<uint64_t>(fieldsPtr + (fc - 1) * FIELDINFO_SIZE + FIELDINFO_NAME);
                std::string lastName = ReadCString(lastFieldName);
                if (!lastName.empty()) { fieldCount = fc; break; }
            }
        }
        if (fieldCount > 0) break;

        // Fallback: count fields until we hit an invalid entry
        for (int i = 0; i < 200; i++) {
            uint64_t fnPtr = DmaRead<uint64_t>(fieldsPtr + i * FIELDINFO_SIZE + FIELDINFO_NAME);
            std::string fn = ReadCString(fnPtr);
            if (fn.empty()) { fieldCount = i; break; }
        }
        break;
    }

    if (!fieldsPtr || fieldCount <= 0) return result;

    for (int i = 0; i < fieldCount; i++) {
        uint64_t entry = fieldsPtr + i * FIELDINFO_SIZE;
        uint64_t namePtr = DmaRead<uint64_t>(entry + FIELDINFO_NAME);
        std::string name = ReadCString(namePtr);
        if (name.empty()) continue;

        RuntimeField rf;
        rf.name = name;
        rf.offset = DmaRead<int32_t>(entry + FIELDINFO_OFFSET);
        rf.token = DmaRead<uint32_t>(entry + 0x1C);

        // Filter out unreasonable offsets (static fields often have offset 0 or negative thread-local)
        if (rf.offset >= 0 && rf.offset < 0x10000)
            result.push_back(rf);
    }
    return result;
}

static bool DumpIL2CPPOffsets(const char* procName, const std::string& outDir) {
    uint64_t gaBase = GetModBase("GameAssembly.dll");
    if (!gaBase) { printf("[-] GameAssembly.dll not found\n"); return false; }
    printf("[+] GameAssembly.dll -> 0x%llX\n", (unsigned long long)gaBase);

    uint64_t unityBase = GetModBase("UnityPlayer.dll");
    if (unityBase) printf("[+] UnityPlayer.dll -> 0x%llX\n", (unsigned long long)unityBase);

    // ── Phase 1: Find IL2CPP metadata (type/field names) ──
    printf("[*] Scanning for IL2CPP metadata (0xFAB11BAF)...\n");
    uint64_t metaBase = 0;

    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(gaBase, dos, nt)) return false;

    uint64_t secAddr = gaBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int si = 0; si < nt.FileHeader.NumberOfSections && !metaBase; si++) {
        IMAGE_SECTION_HEADER sec{};
        if (!DmaReadBuf(secAddr + si * sizeof(sec), &sec, sizeof(sec))) continue;

        char secName[9]{};
        memcpy(secName, sec.Name, 8);
        if (strcmp(secName, ".data") != 0 && strcmp(secName, ".rdata") != 0) continue;

        uint32_t scanSize = min(sec.Misc.VirtualSize, 64u * 1024 * 1024);
        uint32_t chunkSize = 0x10000;

        for (uint32_t offset = 0; offset < scanSize && !metaBase; offset += chunkSize) {
            uint32_t toRead = min(chunkSize, scanSize - offset);
            std::vector<uint8_t> chunk(toRead);
            DmaReadBuf(gaBase + sec.VirtualAddress + offset, chunk.data(), toRead);

            for (uint32_t j = 0; j + 8 <= toRead; j += 8) {
                uint64_t ptr = *(uint64_t*)(chunk.data() + j);
                if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;
                uint32_t magic = 0;
                DmaReadBuf(ptr, &magic, 4);
                if (magic == 0xFAB11BAF) {
                    metaBase = ptr;
                    printf("[+] IL2CPP metadata at 0x%llX\n", (unsigned long long)metaBase);
                    break;
                }
            }
        }
    }

    // ── Phase 2: Find Il2Cpp runtime domain (for runtime offsets) ──
    printf("[*] Finding Il2Cpp runtime domain...\n");
    uint64_t domain = FindIl2CppDomain(gaBase);
    if (domain)
        printf("[+] Il2CppDomain @ 0x%llX\n", (unsigned long long)domain);
    else
        printf("[!] Domain not found — will use metadata-only mode\n");

    // ── Phase 3: Walk runtime classes for actual field offsets ──
    // Build a map of className -> list of {fieldName, offset}
    struct ClassDump {
        std::string ns;
        std::string name;
        std::vector<RuntimeField> fields;
        uint32_t instanceSize;
    };
    std::vector<ClassDump> runtimeClasses;

    if (domain) {
        printf("[*] Walking Il2Cpp runtime classes for field offsets...\n");

        // Walk domain->domain_assemblies (GList at domain + offset)
        // Try common offsets for domain_assemblies: +0x18, +0x20, +0x28, +0x48, +0x68
        const int domainAsmOffsets[] = {0x18, 0x20, 0x28, 0x48, 0x68, 0x88};
        uint64_t asmListHead = 0;

        for (int daOff : domainAsmOffsets) {
            uint64_t candidate = DmaRead<uint64_t>(domain + daOff);
            if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;

            // GList: data at +0x00, next at +0x08
            uint64_t data = DmaRead<uint64_t>(candidate);
            if (data < 0x10000 || data > 0x7FFFFFFFFFFF) continue;

            // Assembly has image at +0x00 or +0x08
            // Image has name pointer at +0x00 or +0x08
            for (int imgOff : {0, 8}) {
                uint64_t img = DmaRead<uint64_t>(data + imgOff);
                if (img < 0x10000 || img > 0x7FFFFFFFFFFF) continue;
                for (int nameOff : {0, 8, 0x10}) {
                    uint64_t namePtr = DmaRead<uint64_t>(img + nameOff);
                    std::string imgName = ReadCString(namePtr);
                    if (imgName.size() > 3 && imgName.find(".dll") != std::string::npos) {
                        asmListHead = candidate;
                        printf("[+] Assembly list at domain+0x%X (first image: %s)\n", daOff, imgName.c_str());
                        goto foundAsmList;
                    }
                }
            }
        }
        foundAsmList:

        if (asmListHead) {
            uint64_t cursor = asmListHead;
            int asmCount = 0;
            std::set<uint64_t> visited;

            while (cursor > 0x10000 && cursor < 0x7FFFFFFFFFFF && asmCount < 256) {
                if (visited.count(cursor)) break;
                visited.insert(cursor);

                uint64_t asmData = DmaRead<uint64_t>(cursor);
                if (!asmData || asmData < 0x10000) break;

                // Find image in assembly (try +0x00 and +0x08)
                for (int imgOff : {0, 8}) {
                    uint64_t img = DmaRead<uint64_t>(asmData + imgOff);
                    if (img < 0x10000 || img > 0x7FFFFFFFFFFF) continue;

                    // Read image name
                    std::string imgName;
                    for (int no : {0, 8, 0x10}) {
                        uint64_t np = DmaRead<uint64_t>(img + no);
                        imgName = ReadCString(np);
                        if (imgName.size() > 3 && imgName.find(".dll") != std::string::npos) break;
                        imgName.clear();
                    }
                    if (imgName.empty()) continue;

                    // Find class count and class array in image
                    // Il2CppImage layout varies but typeCount is usually a uint32 and
                    // typesByDefinitionId is a Il2CppClass** array
                    // Try finding typeCount then the class pointer array near it
                    for (int tcOff = 0x18; tcOff <= 0x50; tcOff += 4) {
                        uint32_t typeCount = DmaRead<uint32_t>(img + tcOff);
                        if (typeCount <= 0 || typeCount > 50000) continue;

                        // The class array pointer should be nearby
                        for (int caOff = tcOff - 16; caOff <= tcOff + 16; caOff += 8) {
                            if (caOff < 0 || caOff == tcOff) continue;
                            uint64_t classArray = DmaRead<uint64_t>(img + caOff);
                            if (classArray < 0x10000 || classArray > 0x7FFFFFFFFFFF) continue;

                            // Validate: first few entries should be valid class pointers
                            uint64_t firstClass = DmaRead<uint64_t>(classArray);
                            if (firstClass < 0x10000 || firstClass > 0x7FFFFFFFFFFF) continue;
                            uint64_t firstNamePtr = DmaRead<uint64_t>(firstClass + 0x10);
                            std::string firstName = ReadCString(firstNamePtr);
                            if (firstName.empty()) continue;

                            printf("[*] %s: %u classes at img+0x%X\n", imgName.c_str(), typeCount, caOff);

                            int classesRead = 0;
                            for (uint32_t ci = 0; ci < typeCount && classesRead < 5000; ci++) {
                                uint64_t klass = DmaRead<uint64_t>(classArray + ci * 8);
                                if (klass < 0x10000 || klass > 0x7FFFFFFFFFFF) continue;

                                uint64_t namePtr = DmaRead<uint64_t>(klass + 0x10);
                                uint64_t nsPtr = DmaRead<uint64_t>(klass + 0x18);
                                std::string className = ReadCString(namePtr);
                                std::string classNs = ReadCString(nsPtr);
                                if (className.empty()) continue;

                                auto fields = ReadClassFields(klass);
                                if (fields.empty()) continue;

                                // Read instance size (try common offsets)
                                uint32_t instSize = 0;
                                for (int isOff : {0x100, 0xFC, 0x104, 0xF8, 0x108}) {
                                    uint32_t candidate = DmaRead<uint32_t>(klass + isOff);
                                    if (candidate > 0 && candidate < 0x10000 && candidate >= fields.back().offset) {
                                        instSize = candidate; break;
                                    }
                                }

                                ClassDump cd;
                                cd.ns = classNs;
                                cd.name = className;
                                cd.fields = std::move(fields);
                                cd.instanceSize = instSize;
                                runtimeClasses.push_back(std::move(cd));
                                classesRead++;
                            }
                            goto nextAsm;
                        }
                    }
                }
                nextAsm:
                cursor = DmaRead<uint64_t>(cursor + 8); // GList->next
                asmCount++;
            }
            printf("[+] Resolved runtime offsets for %zu classes\n", runtimeClasses.size());
        }
    }

    // ── Phase 4: Write output ──
    std::string filePath = outDir + "\\offsets.h";
    FILE* f = fopen(filePath.c_str(), "w");
    if (!f) return false;

    time_t now = time(nullptr);
    struct tm ti{};
    localtime_s(&ti, &now);
    char date[32];
    sprintf_s(date, "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);

    fprintf(f, "// %s Offset Dump - %s\n", procName, date);
    fprintf(f, "// Engine: Unity (IL2CPP)\n");
    fprintf(f, "// Auto-generated via DMA — runtime field offsets resolved\n");
    fprintf(f, "// GameAssembly.dll: 0x%llX\n", (unsigned long long)gaBase);
    if (unityBase) fprintf(f, "// UnityPlayer.dll:  0x%llX\n", (unsigned long long)unityBase);
    if (metaBase) fprintf(f, "// global-metadata:  0x%llX\n", (unsigned long long)metaBase);
    if (domain) fprintf(f, "// Il2CppDomain:     0x%llX\n", (unsigned long long)domain);
    fprintf(f, "\n#pragma once\n#include <cstdint>\n\n");

    // Runtime classes with actual offsets (most useful)
    if (!runtimeClasses.empty()) {
        // Prioritize game-relevant classes
        const char* priorityClasses[] = {
            "BasePlayer", "BaseEntity", "BaseCombatEntity", "BaseProjectile",
            "PlayerModel", "PlayerEyes", "PlayerInventory", "PlayerMetabolism",
            "Item", "ItemContainer", "ItemDefinition", "ItemModProjectile",
            "BuildingBlock", "BuildingPrivlidge", "BaseHelicopter",
            "HeldEntity", "AttackEntity", "BaseVehicle", "Recycler",
            "StorageContainer", "SupplyDrop", "AutoTurret", "BradleyAPC",
            "PlayerCorpse", "DroppedItem", "WorldItem", "OreResourceEntity",
            "TreeEntity", "ResourceEntity", "CollectibleEntity",
            "GameManager", "MainCamera", "TOD_Sky", "TerrainMeta",
            "ConVar", "ConsoleSystem", "SteamClient",
            "BaseNetworkable", "Model", "Renderer",
            nullptr
        };

        fprintf(f, "// ============================================\n");
        fprintf(f, "// Runtime Classes — REAL Field Offsets\n");
        fprintf(f, "// ============================================\n\n");

        // Priority classes first
        std::set<std::string> printed;
        for (int p = 0; priorityClasses[p]; p++) {
            for (auto& cd : runtimeClasses) {
                if (cd.name != priorityClasses[p]) continue;
                if (printed.count(cd.name)) continue;
                printed.insert(cd.name);

                std::string safeName = cd.ns.empty() ? cd.name : cd.ns + "_" + cd.name;
                for (auto& ch : safeName)
                    if (ch == '.' || ch == '<' || ch == '>' || ch == '`' || ch == '/' || ch == '+')
                        ch = '_';

                fprintf(f, "// %s%s%s", cd.ns.c_str(), cd.ns.empty() ? "" : ".", cd.name.c_str());
                if (cd.instanceSize) fprintf(f, "  (size=0x%X)", cd.instanceSize);
                fprintf(f, "\n");
                fprintf(f, "namespace %s {\n", safeName.c_str());
                for (auto& rf : cd.fields)
                    fprintf(f, "    constexpr int %s = 0x%X;\n", rf.name.c_str(), rf.offset);
                fprintf(f, "}\n\n");
            }
        }

        // Then all remaining classes
        fprintf(f, "// ============================================\n");
        fprintf(f, "// All Other Runtime Classes\n");
        fprintf(f, "// ============================================\n\n");

        for (auto& cd : runtimeClasses) {
            if (printed.count(cd.name)) continue;
            printed.insert(cd.name);

            std::string safeName = cd.ns.empty() ? cd.name : cd.ns + "_" + cd.name;
            for (auto& ch : safeName)
                if (ch == '.' || ch == '<' || ch == '>' || ch == '`' || ch == '/' || ch == '+')
                    ch = '_';

            fprintf(f, "// %s%s%s (fields=%zu)\n", cd.ns.c_str(), cd.ns.empty() ? "" : ".", cd.name.c_str(), cd.fields.size());
            fprintf(f, "namespace %s {\n", safeName.c_str());
            for (auto& rf : cd.fields)
                fprintf(f, "    constexpr int %s = 0x%X;\n", rf.name.c_str(), rf.offset);
            fprintf(f, "}\n\n");
        }
    }

    // Metadata dump (field names even if runtime offsets weren't resolved)
    if (metaBase && runtimeClasses.empty()) {
        Il2CppMetadataHeader header{};
        DmaReadBuf(metaBase, &header, sizeof(header));
        printf("[+] IL2CPP metadata version: %d\n", header.version);
        fprintf(f, "// IL2CPP version: %d\n", header.version);
        fprintf(f, "// WARNING: Runtime offsets not resolved — showing metadata tokens only.\n");
        fprintf(f, "// For full offsets, run il2cppdumper on the PE dump files.\n\n");

        int typeDefSize = (int)sizeof(Il2CppTypeDefinition);
        int fieldDefSize = (int)sizeof(Il2CppFieldDefinition);
        int numTypes = header.typeDefinitionsCount / typeDefSize;
        if (numTypes <= 0 || numTypes > 200000) numTypes = header.typeDefinitionsCount;

        int numImages = header.imagesCount / (int)sizeof(Il2CppImageDefinition);
        if (numImages <= 0 || numImages > 5000) numImages = header.imagesCount;

        if (numTypes > 0 && numTypes <= 200000) {
            std::vector<Il2CppImageDefinition> images;
            if (numImages > 0 && numImages < 5000) {
                images.resize(numImages);
                DmaReadBuf(metaBase + header.imagesOffset, images.data(), numImages * sizeof(Il2CppImageDefinition));
            }

            std::vector<Il2CppTypeDefinition> types(numTypes);
            DmaReadBuf(metaBase + header.typeDefinitionsOffset, types.data(), numTypes * typeDefSize);

            int actualFields = header.fieldsCount / fieldDefSize;
            if (actualFields <= 0) actualFields = header.fieldsCount;
            if (actualFields > 500000) actualFields = 500000;

            std::vector<Il2CppFieldDefinition> fields(actualFields);
            DmaReadBuf(metaBase + header.fieldsOffset, fields.data(), actualFields * fieldDefSize);

            for (int img = 0; img < (int)images.size(); img++) {
                std::string imgName = ReadMetaString(metaBase, header.stringOffset, images[img].nameIndex);
                if (imgName.empty()) continue;

                int typeStart = images[img].typeStart;
                int typeCount = images[img].typeCount;
                if (typeCount <= 0 || typeStart < 0) continue;

                fprintf(f, "// Image: %s (%u types)\n\n", imgName.c_str(), typeCount);

                for (int ti2 = typeStart; ti2 < typeStart + (int)typeCount && ti2 < numTypes; ti2++) {
                    auto& td = types[ti2];
                    std::string typeName = ReadMetaString(metaBase, header.stringOffset, td.nameIndex);
                    std::string typeNs = ReadMetaString(metaBase, header.stringOffset, td.namespaceIndex);
                    if (typeName.empty() || td.field_count == 0) continue;

                    std::string fullName = typeNs.empty() ? typeName : typeNs + "." + typeName;
                    std::string safeName = fullName;
                    for (auto& ch : safeName)
                        if (ch == '.' || ch == '<' || ch == '>' || ch == ' ' || ch == '/' || ch == '+' || ch == '-' || ch == '`')
                            ch = '_';

                    fprintf(f, "// %s (fields=%d) — METADATA ONLY, no runtime offsets\n", fullName.c_str(), td.field_count);
                    fprintf(f, "namespace %s {\n", safeName.c_str());
                    for (int fi = 0; fi < td.field_count && (td.fieldStart + fi) < actualFields; fi++) {
                        auto& fd = fields[td.fieldStart + fi];
                        std::string fname = ReadMetaString(metaBase, header.stringOffset, fd.nameIndex);
                        if (fname.empty()) continue;
                        std::string safeFname = fname;
                        for (auto& ch : safeFname)
                            if (ch == '<' || ch == '>' || ch == ' ' || ch == '/')
                                ch = '_';
                        fprintf(f, "    // token=0x%08X  %s\n", fd.token, fname.c_str());
                    }
                    fprintf(f, "}\n\n");
                }
            }
        }
    }

    if (!metaBase && runtimeClasses.empty()) {
        // Fallback: at least dump exports
        auto exports = ReadExports(gaBase);
        if (!exports.empty()) {
            fprintf(f, "// GameAssembly.dll exports\n");
            fprintf(f, "namespace GameAssembly_Exports {\n");
            for (auto& e : exports)
                fprintf(f, "    // 0x%08X  %s\n", e.rva, e.name.c_str());
            fprintf(f, "}\n\n");
        }
        fprintf(f, "// No metadata or runtime classes found.\n");
        fprintf(f, "// Dump GameAssembly.dll and use il2cppdumper offline.\n");
    }

    // Pointer chain reference for Rust
    fprintf(f, "\n// ============================================\n");
    fprintf(f, "// IL2CPP / Rust Pointer Chain Reference\n");
    fprintf(f, "// ============================================\n");
    fprintf(f, "//\n");
    fprintf(f, "// GameObjectManager (Unity):\n");
    fprintf(f, "//   UnityPlayer.dll + GOM_OFFSET -> tagged objects list\n");
    fprintf(f, "//   Walk: lastTaggedObject -> nextObject chain\n");
    fprintf(f, "//   Each object: +0x10 = tag, +0x30 = GameObject, +0x60 = Transform\n");
    fprintf(f, "//\n");
    fprintf(f, "// BasePlayer (Rust):\n");
    fprintf(f, "//   BasePlayer -> playerModel (+PlayerModel offset) -> Transform\n");
    fprintf(f, "//   BasePlayer -> eyes (+PlayerEyes offset) -> viewOffset, bodyRotation\n");
    fprintf(f, "//   BasePlayer -> inventory -> containerMain/containerBelt/containerWear\n");
    fprintf(f, "//   BasePlayer -> metabolism -> health/hydration/calories/etc.\n");
    fprintf(f, "//\n");
    fprintf(f, "// Position:\n");
    fprintf(f, "//   Any BaseCombatEntity -> transform -> get_position()\n");
    fprintf(f, "//   Or: BaseEntity + ._transform (cached Transform pointer)\n\n");

    fclose(f);
    printf("[+] IL2CPP offsets: %s\n", filePath.c_str());

    // Also write INI
    if (!runtimeClasses.empty()) {
        std::string iniPath = outDir + "\\offsets.ini";
        FILE* ini = fopen(iniPath.c_str(), "w");
        if (ini) {
            fprintf(ini, "# %s — IL2CPP Runtime Offsets\n", procName);
            fprintf(ini, "# Date: %s\n# Engine: Unity (IL2CPP)\n\n", date);
            fprintf(ini, "[Identity]\nProcessName=%s\nEngine=il2cpp\n\n", procName);
            fprintf(ini, "[Modules]\nGameAssembly=0x%llX\n", (unsigned long long)gaBase);
            if (unityBase) fprintf(ini, "UnityPlayer=0x%llX\n", (unsigned long long)unityBase);
            fprintf(ini, "\n");

            for (auto& cd : runtimeClasses) {
                if (cd.fields.size() < 2) continue;
                fprintf(ini, "[%s]\n", cd.name.c_str());
                for (auto& rf : cd.fields)
                    fprintf(ini, "%s=0x%X\n", rf.name.c_str(), rf.offset);
                fprintf(ini, "\n");
            }
            fclose(ini);
            printf("[+] INI: %s\n", iniPath.c_str());
        }
    }

    return true;
}

// ── Module dumping ─────────────────────────────────────────────────────────────

static bool DumpModuleToFile(uint64_t base, uint32_t size, const std::string& outPath) {
    printf("[*] Dumping %u KB to %s...\n", size / 1024, outPath.c_str());
    std::vector<uint8_t> buffer(size, 0);

    if (pVMMDLL_Scatter_Initialize) {
        HANDLE hScatter = pVMMDLL_Scatter_Initialize(g_hVmmHandle, g_targetPid, 0x0002);
        if (hScatter) {
            for (uint32_t off = 0; off < size; off += 0x1000) {
                uint32_t readSz = min(0x1000u, size - off);
                pVMMDLL_Scatter_Prepare(hScatter, base + off, readSz);
            }
            pVMMDLL_Scatter_Execute(hScatter);
            for (uint32_t off = 0; off < size; off += 0x1000) {
                uint32_t readSz = min(0x1000u, size - off);
                DWORD cbRead = 0;
                pVMMDLL_Scatter_Read(hScatter, base + off, readSz, buffer.data() + off, &cbRead);
            }
            pVMMDLL_Scatter_CloseHandle(hScatter);
        }
    } else {
        for (uint32_t off = 0; off < size; off += 0x1000) {
            uint32_t readSz = min(0x1000u, size - off);
            DmaRead(g_targetPid, base + off, buffer.data() + off, readSz);
        }
    }

    FILE* f = fopen(outPath.c_str(), "wb");
    if (!f) { printf("[-] Failed to write %s\n", outPath.c_str()); return false; }
    fwrite(buffer.data(), 1, size, f);
    fclose(f);
    printf("[+] Dumped %s (%u KB)\n", outPath.c_str(), size / 1024);
    return true;
}

// ── Main ───────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== DMA Dumper — Auto Offset Detection ===\n");
    printf("=== Dumper-7 style for UE4/5 + IL2CPP   ===\n");
    printf("=== Invisible to all anti-cheat          ===\n\n");

    std::string deviceStr = "fpga";
    bool autoMode = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) deviceStr = argv[++i];
        else if (strcmp(argv[i], "--auto") == 0) autoMode = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("Interactive DMA game dumper with auto offset detection.\n\n");
            printf("Options:\n");
            printf("  --device <str>  LeechCore device (default: fpga)\n");
            printf("  --auto          Skip menus, auto-detect everything\n");
            printf("  --help          Show this help\n\n");
            printf("Supported engines:\n");
            printf("  Unreal Engine 4/5  — GWorld, GNames, GObjects scan\n");
            printf("  Unity IL2CPP       — metadata parsing (Rust, etc.)\n");
            printf("  Unity Mono         — reflection walking\n");
            printf("  Source 2           — SchemaSystem (CS2)\n\n");
            printf("Supported games:\n");
            printf("  Arena Breakout Infinite (UE5, EAC)\n");
            printf("  Hunger (UE5)\n");
            printf("  Rust (Unity IL2CPP, EAC)\n");
            printf("  Delta Force (UE5)\n");
            printf("  CS2 (Source 2)\n");
            printf("  And any other UE4/5 or IL2CPP game\n");
            return 0;
        }
    }

    // Load VMM
    printf("[*] Loading MemProcFS (vmm.dll)...\n");
    if (!LoadVMM()) return 1;
    printf("[+] VMM loaded\n");

    // Initialize DMA
    printf("[*] Connecting to DMA device: %s\n", deviceStr.c_str());
    LPCSTR initArgs[] = {"", "-device", deviceStr.c_str(), "-v"};
    g_hVmmHandle = pVMMDLL_Initialize(4, initArgs);
    if (!g_hVmmHandle) {
        printf("[-] DMA init failed. Check: FPGA connected? USB cable on data port?\n");
        return 1;
    }
    printf("[+] DMA connection established!\n");

    // Select process
    g_targetPid = SelectProcess();
    if (!g_targetPid) {
        printf("[-] No process selected.\n");
        pVMMDLL_Close(g_hVmmHandle);
        return 1;
    }

    // Get process name
    std::string procName = "unknown.exe";
    LPSTR pName = nullptr;
    if (pVMMDLL_ProcessGetInformationString &&
        pVMMDLL_ProcessGetInformationString(g_hVmmHandle, g_targetPid, 2, &pName) && pName) {
        const char* slash = strrchr(pName, '\\');
        procName = slash ? (slash + 1) : pName;
        pVMMDLL_MemFree(pName);
    }
    printf("\n[+] Selected: %s (PID %lu)\n", procName.c_str(), g_targetPid);

    // Detect engine
    EngineType engine = DetectEngine(g_targetPid, procName);
    if (engine == ENGINE_UNKNOWN && !autoMode)
        engine = SelectEngine(engine);
    else if (!autoMode)
        engine = SelectEngine(engine);

    printf("\n[+] Engine: %s\n", EngineNames[engine]);

    // Create output directory
    std::string outDir = MakeOutputDir(procName.c_str());
    printf("[+] Output: %s\n\n", outDir.c_str());

    // Find core module
    std::string coreModule = procName;
    for (int i = 0; KnownGames[i].alias; i++) {
        if (_stricmp(procName.c_str(), KnownGames[i].processName) == 0) {
            coreModule = KnownGames[i].coreModule;
            break;
        }
    }

    uint64_t modBase = GetModBase(coreModule.c_str());
    if (!modBase) modBase = GetModBase(procName.c_str());
    if (!modBase) {
        printf("[-] Could not find module base for %s\n", coreModule.c_str());
        pVMMDLL_Close(g_hVmmHandle);
        return 1;
    }
    printf("[+] %s base: 0x%llX\n\n", coreModule.c_str(), (unsigned long long)modBase);

    // Run engine-specific offset detection
    bool success = false;
    switch (engine) {
        case ENGINE_UE4:
            success = DumpUEOffsets(procName.c_str(), modBase, false, outDir);
            break;
        case ENGINE_UE5:
            success = DumpUEOffsets(procName.c_str(), modBase, true, outDir);
            break;
        case ENGINE_IL2CPP:
            success = DumpIL2CPPOffsets(procName.c_str(), outDir);
            break;
        default: {
            printf("[*] No auto-detection for this engine. Dumping PE info + modules.\n\n");
            IMAGE_DOS_HEADER dosH{};
            IMAGE_NT_HEADERS64 ntH{};
            if (ReadPEHeaders(modBase, dosH, ntH)) {
                auto secs = GetSections(modBase);
                printf("  Sections (%d):\n", (int)secs.size());
                for (auto& s : secs)
                    printf("    %-10s  VA=0x%llX  Size=0x%X\n",
                        s.name, (unsigned long long)s.base, s.virtualSize);

                auto exps = ReadExports(modBase);
                if (!exps.empty()) {
                    printf("\n  Exports (%zu):\n", exps.size());
                    for (int i = 0; i < (int)exps.size() && i < 30; i++)
                        printf("    0x%08X  %s\n", exps[i].rva, exps[i].name.c_str());
                    if (exps.size() > 30)
                        printf("    ... and %zu more\n", exps.size() - 30);
                }

                auto imps = ReadImports(modBase);
                if (!imps.empty()) {
                    printf("\n  Imports (%zu DLLs):\n", imps.size());
                    for (auto& dll : imps)
                        printf("    %s\n", dll.c_str());
                }
            }
            success = true;
            break;
        }
    }

    // Dump module PE files
    printf("\n[*] Dump module PE files? (y/n): ");
    char dumpChoice[16]{};
    if (fgets(dumpChoice, sizeof(dumpChoice), stdin) && (dumpChoice[0] == 'y' || dumpChoice[0] == 'Y')) {
        const char* modules[] = {
            procName.c_str(),
            "GameAssembly.dll", "UnityPlayer.dll", "mono-2.0-bdwgc.dll",
            "client.dll", "engine2.dll", "schemasystem.dll",
            "ntdll.dll", "kernel32.dll",
            nullptr
        };

        for (int i = 0; modules[i]; i++) {
            uint64_t base = GetModBase(modules[i]);
            if (!base) continue;
            IMAGE_DOS_HEADER d{};
            IMAGE_NT_HEADERS64 n{};
            if (!ReadPEHeaders(base, d, n)) continue;
            uint32_t imgSize = n.OptionalHeader.SizeOfImage;
            if (imgSize > 512 * 1024 * 1024) continue;

            std::string path = outDir + "\\" + modules[i] + ".dma_dump";
            DumpModuleToFile(base, imgSize, path);
        }
    }

    printf("\n[+] Done. Output in: %s\n", outDir.c_str());

    pVMMDLL_Close(g_hVmmHandle);
    return 0;
}
