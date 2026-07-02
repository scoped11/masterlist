// Game Dumper — standalone, no driver required
// Modes: live process (ReadProcessMemory) or static disk analysis
// Engine detection, game-specific profiles, pattern scanning, offset extraction

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ── Globals ────────────────────────────────────────────────────────────────────

static HANDLE g_hProc = nullptr;
static DWORD  g_pid   = 0;
static bool   g_staticMode = false;

// ── Memory read (ReadProcessMemory wrapper) ────────────────────────────────────

static bool MemRead(uint64_t addr, void* buf, size_t size) {
    if (!g_hProc || g_staticMode) return false;
    SIZE_T read = 0;
    if (!ReadProcessMemory(g_hProc, (LPCVOID)addr, buf, size, &read))
        return false;
    return read == size;
}

static bool MemReadChunked(uint64_t addr, void* buf, size_t totalSize) {
    const size_t CHUNK = 0x1000;
    uint8_t* dst = (uint8_t*)buf;
    size_t remaining = totalSize;
    size_t offset = 0;
    while (remaining > 0) {
        size_t toRead = (remaining > CHUNK) ? CHUNK : remaining;
        SIZE_T read = 0;
        if (!ReadProcessMemory(g_hProc, (LPCVOID)(addr + offset), dst + offset, toRead, &read))
            memset(dst + offset, 0, toRead);
        remaining -= toRead;
        offset    += toRead;
    }
    return true;
}

// ── Process discovery ───────────────────────────────────────────────────────────

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

// ── Module enumeration (Toolhelp32) ─────────────────────────────────────────────

struct ModuleInfo {
    uint64_t base;
    uint32_t size;
    char     name[256];
};

static std::vector<ModuleInfo> GetModules(DWORD pid) {
    std::vector<ModuleInfo> mods;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return mods;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi{};
            mi.base = (uint64_t)me.modBaseAddr;
            mi.size = me.modBaseSize;
            strncpy(mi.name, me.szModule, sizeof(mi.name) - 1);
            mods.push_back(mi);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return mods;
}

// ── PE parsing helpers ──────────────────────────────────────────────────────────

static bool ReadPEHeaders(uint64_t base, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt) {
    if (g_staticMode) return false;
    if (!MemRead(base, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!MemRead(base + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    return true;
}

static std::vector<IMAGE_SECTION_HEADER> ReadSections(uint64_t base, const IMAGE_DOS_HEADER& dos,
                                                       const IMAGE_NT_HEADERS64& nt) {
    uint32_t secOff = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                    + nt.FileHeader.SizeOfOptionalHeader;
    uint16_t numSec = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> secs(numSec);
    MemRead(base + secOff, secs.data(), numSec * sizeof(IMAGE_SECTION_HEADER));
    return secs;
}

// PE parsing from file on disk
static bool ReadPEHeadersFromFile(const char* path, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt,
                                   std::vector<IMAGE_SECTION_HEADER>& secs,
                                   std::vector<uint8_t>& fileData) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < (long)sizeof(IMAGE_DOS_HEADER)) { fclose(f); return false; }

    fileData.resize(fsize);
    fread(fileData.data(), 1, fsize, f);
    fclose(f);

    memcpy(&dos, fileData.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos.e_lfanew + sizeof(nt) > (DWORD)fsize) return false;

    memcpy(&nt, fileData.data() + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;

    uint32_t secOff = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                    + nt.FileHeader.SizeOfOptionalHeader;
    uint16_t numSec = nt.FileHeader.NumberOfSections;
    secs.resize(numSec);
    if (secOff + numSec * sizeof(IMAGE_SECTION_HEADER) <= (uint32_t)fsize)
        memcpy(secs.data(), fileData.data() + secOff, numSec * sizeof(IMAGE_SECTION_HEADER));

    return true;
}

// ── Engine Detection ────────────────────────────────────────────────────────────

enum GameEngine {
    ENGINE_UNKNOWN = 0,
    ENGINE_UNREAL,
    ENGINE_UNITY,
    ENGINE_SOURCE,
    ENGINE_SOURCE2,
    ENGINE_CRYENGINE,
    ENGINE_IDTECH,
    ENGINE_FROSTBITE,
    ENGINE_GAMEMAKER,
    ENGINE_GODOT,
    ENGINE_CUSTOM
};

struct EngineSignature {
    GameEngine engine;
    const char* name;
    const char* modulePatterns[8];
    const char* sectionPatterns[4];
    const char* exportPatterns[4];
};

static const EngineSignature g_engineSigs[] = {
    {
        ENGINE_UNREAL, "Unreal Engine",
        {"UE4-", "UE5-", "UnrealEngine", "PhysX3", "nvToolsExt", "tbb.dll", "tbbmalloc.dll", nullptr},
        {".udata", ".uedata", nullptr, nullptr},
        {"GUObjectArray", "GNames", "GWorld", nullptr}
    },
    {
        ENGINE_UNITY, "Unity",
        {"UnityPlayer.dll", "GameAssembly.dll", "mono-2.0-bdwgc.dll", "il2cpp_", "unity_builtin_extra", nullptr, nullptr, nullptr},
        {".il2cpp", nullptr, nullptr, nullptr},
        {"il2cpp_init", "mono_jit_init", "il2cpp_domain_get", nullptr}
    },
    {
        ENGINE_SOURCE, "Source Engine (Valve)",
        {"engine.dll", "client.dll", "server.dll", "materialsystem.dll", "vphysics.dll", "tier0.dll", "vstdlib.dll", nullptr},
        {nullptr, nullptr, nullptr, nullptr},
        {"CreateInterface", nullptr, nullptr, nullptr}
    },
    {
        ENGINE_SOURCE2, "Source 2 (Valve)",
        {"engine2.dll", "client.dll", "schemasystem.dll", "resourcesystem.dll", "tier0.dll", "animationsystem.dll", nullptr, nullptr},
        {nullptr, nullptr, nullptr, nullptr},
        {"CreateInterface", nullptr, nullptr, nullptr}
    },
    {
        ENGINE_CRYENGINE, "CryEngine",
        {"CrySystem.dll", "CryRenderD3D", "CryPhysics.dll", "CryAction.dll", "CryNetwork.dll", nullptr, nullptr, nullptr},
        {nullptr, nullptr, nullptr, nullptr},
        {"CreateSystemInterface", nullptr, nullptr, nullptr}
    },
    {
        ENGINE_IDTECH, "id Tech",
        {"idRenderModelStatic", "idLib", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr},
        {".pdata", nullptr, nullptr, nullptr},
        {nullptr, nullptr, nullptr, nullptr}
    },
    {
        ENGINE_FROSTBITE, "Frostbite",
        {"fb.dll", "FrostyModManager", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr},
        {nullptr, nullptr, nullptr, nullptr},
        {nullptr, nullptr, nullptr, nullptr}
    },
    {
        ENGINE_GODOT, "Godot",
        {"godot.", "libgodot", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr},
        {nullptr, nullptr, nullptr, nullptr},
        {"godot_gdnative_init", nullptr, nullptr, nullptr}
    },
};

struct DetectedEngine {
    GameEngine engine;
    const char* name;
    int confidence;
    std::vector<std::string> evidence;
};

static std::string ToLower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

static bool ContainsCI(const char* haystack, const char* needle) {
    std::string h = ToLower(haystack);
    std::string n = ToLower(needle);
    return h.find(n) != std::string::npos;
}

static DetectedEngine DetectEngine(const std::vector<ModuleInfo>& modules,
                                   const std::vector<IMAGE_SECTION_HEADER>& mainSections,
                                   const std::vector<uint8_t>& headerDump,
                                   const IMAGE_NT_HEADERS64& nt) {
    DetectedEngine best{ENGINE_UNKNOWN, "Unknown", 0, {}};

    for (auto& sig : g_engineSigs) {
        DetectedEngine candidate{sig.engine, sig.name, 0, {}};

        for (int p = 0; sig.modulePatterns[p]; p++) {
            for (auto& mod : modules) {
                if (ContainsCI(mod.name, sig.modulePatterns[p])) {
                    candidate.confidence += 30;
                    char buf[512];
                    snprintf(buf, sizeof(buf), "Module match: %s (%s)", mod.name, sig.modulePatterns[p]);
                    candidate.evidence.push_back(buf);
                    break;
                }
            }
        }

        for (int p = 0; sig.sectionPatterns[p]; p++) {
            for (auto& sec : mainSections) {
                char name[9]{};
                memcpy(name, sec.Name, 8);
                if (ContainsCI(name, sig.sectionPatterns[p])) {
                    candidate.confidence += 20;
                    char buf[256];
                    snprintf(buf, sizeof(buf), "Section match: %s", name);
                    candidate.evidence.push_back(buf);
                }
            }
        }

        if (sig.exportPatterns[0] && !headerDump.empty()) {
            auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (expDir.VirtualAddress && expDir.Size &&
                expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) <= headerDump.size()) {
                auto* exp = (IMAGE_EXPORT_DIRECTORY*)(headerDump.data() + expDir.VirtualAddress);
                uint32_t numNames = exp->NumberOfNames;
                uint32_t nameRva  = exp->AddressOfNames;
                if (numNames > 0 && numNames < 100000 && nameRva + numNames * 4 <= headerDump.size()) {
                    auto* names = (uint32_t*)(headerDump.data() + nameRva);
                    for (uint32_t i = 0; i < min(numNames, (uint32_t)5000); i++) {
                        if (names[i] < headerDump.size()) {
                            const char* n = (const char*)(headerDump.data() + names[i]);
                            for (int p = 0; sig.exportPatterns[p]; p++) {
                                if (ContainsCI(n, sig.exportPatterns[p])) {
                                    candidate.confidence += 25;
                                    char buf[512];
                                    snprintf(buf, sizeof(buf), "Export match: %s", n);
                                    candidate.evidence.push_back(buf);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (candidate.confidence > best.confidence)
            best = candidate;
    }

    if (best.confidence == 0) {
        best.name = "Custom/Unknown";
        best.evidence.push_back("No engine signature matched");
    }

    return best;
}

// Engine detection from file data (for static mode)
static DetectedEngine DetectEngineFromFile(const std::vector<IMAGE_SECTION_HEADER>& secs,
                                            const std::vector<uint8_t>& fileData,
                                            const IMAGE_NT_HEADERS64& nt,
                                            const char* fileName) {
    std::vector<ModuleInfo> fakeMods;
    ModuleInfo mi{};
    mi.base = nt.OptionalHeader.ImageBase;
    mi.size = nt.OptionalHeader.SizeOfImage;
    strncpy(mi.name, fileName, sizeof(mi.name) - 1);
    fakeMods.push_back(mi);

    return DetectEngine(fakeMods, secs, fileData, nt);
}

// ── Known Game Processes ────────────────────────────────────────────────────────

struct KnownGame {
    const char* processName;
    const char* gameName;
    GameEngine engine;
    const char* antiCheat;
    const char* dumpModules[4];
};

static const KnownGame g_knownGames[] = {
    {"r5apex.exe",         "Apex Legends",           ENGINE_SOURCE2,   "EAC",       {"r5apex.exe", "client.dll", nullptr, nullptr}},
    {"r5apex_dx12.exe",    "Apex Legends (DX12)",    ENGINE_SOURCE2,   "EAC",       {"r5apex_dx12.exe", "client.dll", nullptr, nullptr}},
    {"FortniteClient-Win64-Shipping.exe", "Fortnite", ENGINE_UNREAL,   "EAC",       {nullptr, nullptr, nullptr, nullptr}},
    {"VALORANT-Win64-Shipping.exe", "VALORANT",       ENGINE_UNREAL,   "Vanguard",  {nullptr, nullptr, nullptr, nullptr}},
    {"csgo.exe",           "CS:GO",                  ENGINE_SOURCE,    "VAC",       {"csgo.exe", "client.dll", "engine.dll", "server.dll"}},
    {"cs2.exe",            "Counter-Strike 2",       ENGINE_SOURCE2,   "VAC",       {"cs2.exe", "client.dll", "engine2.dll", nullptr}},
    {"RustClient.exe",     "Rust",                   ENGINE_UNITY,     "EAC",       {"RustClient.exe", "GameAssembly.dll", nullptr, nullptr}},
    {"EscapeFromTarkov.exe","Escape from Tarkov",    ENGINE_UNITY,     "BattlEye",  {"EscapeFromTarkov.exe", "GameAssembly.dll", nullptr, nullptr}},
    {"Unturned.exe",       "Unturned",               ENGINE_UNITY,     "BattlEye",  {"Unturned.exe", "UnityPlayer.dll", nullptr, nullptr}},
    {"DayZ_x64.exe",       "DayZ",                   ENGINE_CUSTOM,    "BattlEye",  {"DayZ_x64.exe", nullptr, nullptr, nullptr}},
    {"PUBG-Win64-Shipping.exe", "PUBG",              ENGINE_UNREAL,    "BattlEye",  {nullptr, nullptr, nullptr, nullptr}},
    {"GTA5.exe",           "GTA V",                  ENGINE_CUSTOM,    "None",      {"GTA5.exe", nullptr, nullptr, nullptr}},
    {"RDR2.exe",           "Red Dead Redemption 2",  ENGINE_CUSTOM,    "None",      {"RDR2.exe", nullptr, nullptr, nullptr}},
    {"eldenring.exe",      "Elden Ring",             ENGINE_CUSTOM,    "EAC",       {"eldenring.exe", nullptr, nullptr, nullptr}},
    {"OverwatchPE.exe",    "Overwatch 2",            ENGINE_CUSTOM,    "Custom",    {"OverwatchPE.exe", nullptr, nullptr, nullptr}},
    {"destiny2.exe",       "Destiny 2",              ENGINE_CUSTOM,    "Custom",    {"destiny2.exe", nullptr, nullptr, nullptr}},
    {"RainbowSix.exe",     "Rainbow Six Siege",      ENGINE_CUSTOM,    "BattlEye",  {"RainbowSix.exe", nullptr, nullptr, nullptr}},
    {"HogwartsLegacy.exe", "Hogwarts Legacy",        ENGINE_UNREAL,    "None",      {nullptr, nullptr, nullptr, nullptr}},
    {"Cyberpunk2077.exe",  "Cyberpunk 2077",         ENGINE_CUSTOM,    "None",      {"Cyberpunk2077.exe", nullptr, nullptr, nullptr}},
    {"deadlock.exe",       "Deadlock",               ENGINE_SOURCE2,   "VAC",       {"deadlock.exe", "client.dll", nullptr, nullptr}},
    {"DFGame-Win64-Shipping.exe", "Delta Force",     ENGINE_UNREAL,    "ACE",       {"DFGame-Win64-Shipping.exe", nullptr, nullptr, nullptr}},
    {"STALZONE.exe",       "STALZONE",               ENGINE_CUSTOM,    "Unknown",   {"STALZONE.exe", nullptr, nullptr, nullptr}},
    {"explorer.exe",       "Windows Explorer",       ENGINE_CUSTOM,    "None",      {"explorer.exe", nullptr, nullptr, nullptr}},
};

// ── Engine-Specific Offset Tables ───────────────────────────────────────────────

struct EngineOffset {
    const char* name;
    const char* description;
    const char* scanPattern;
    int patternLen;
};

struct EngineOffsetTable {
    GameEngine engine;
    const char* engineName;
    EngineOffset offsets[16];
};

static const EngineOffsetTable g_offsetTables[] = {
    {
        ENGINE_UNREAL, "Unreal Engine",
        {
            {"GObjects",        "Global UObject array",
             "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x0C\xC8\x48\x8D\x04\xD1", 15},
            {"GNames",          "Global name pool",
             "\x48\x8D\x05\x00\x00\x00\x00\xEB\x00\x48\x8D\x0D\x00\x00\x00\x00", 16},
            {"GWorld",          "UWorld pointer",
             "\x48\x8B\x1D\x00\x00\x00\x00\x48\x85\xDB\x74\x00\x48\x8B\x5B\x78", 16},
            {"GEngine",         "UEngine pointer",
             "\x48\x89\x05\x00\x00\x00\x00\x48\x85\xC9\x74\x00\xE8", 13},
            {"ProcessEvent",    "UObject::ProcessEvent",
             "\x40\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8D\x6C\x24", 23},
            {"GetBoneMatrix",   "USkeletalMeshComponent::GetBoneMatrix",
             "\x48\x8B\xC4\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68", 18},
            {nullptr, nullptr, nullptr, 0}
        }
    },
    {
        ENGINE_UNITY, "Unity (il2cpp)",
        {
            {"il2cpp_domain_get",         "Get application domain",       nullptr, 0},
            {"il2cpp_thread_attach",      "Attach thread to il2cpp",      nullptr, 0},
            {"il2cpp_class_from_name",    "Resolve class by name",        nullptr, 0},
            {"il2cpp_class_get_methods",  "Enumerate methods",            nullptr, 0},
            {"il2cpp_class_get_fields",   "Enumerate fields",             nullptr, 0},
            {"il2cpp_field_get_offset",   "Get field offset",             nullptr, 0},
            {"il2cpp_method_get_param",   "Get method parameter info",    nullptr, 0},
            {"il2cpp_string_new",         "Create managed string",        nullptr, 0},
            {"il2cpp_runtime_invoke",     "Invoke managed method",        nullptr, 0},
            {nullptr, nullptr, nullptr, 0}
        }
    },
    {
        ENGINE_SOURCE, "Source Engine",
        {
            {"CreateInterface",  "Module interface factory",
             "\x55\x8B\xEC\x56\x8B\x35\x00\x00\x00\x00\x57\x85\xF6", 13},
            {"ClientMode",       "IClientMode interface pointer",
             "\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\xFF\x50\x00\x84\xC0", 15},
            {"EntityList",       "C_BaseEntityList global pointer",
             "\x48\x8B\x0D\x00\x00\x00\x00\x48\x63\xC2\x48\x8D\x14\x40", 14},
            {"GlobalVars",       "CGlobalVarsBase",
             "\x48\x8B\x05\x00\x00\x00\x00\x44\x8B\x40\x00\xE8", 12},
            {"ViewMatrix",       "World-to-screen matrix",
             "\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x44\x24\x00\x48\x8D\x0D", 15},
            {nullptr, nullptr, nullptr, 0}
        }
    },
    {
        ENGINE_SOURCE2, "Source 2",
        {
            {"SchemaSystem",     "CSchemaSystem runtime type info",    nullptr, 0},
            {"EntitySystem",     "CGameEntitySystem entity list",
             "\x48\x8B\x1D\x00\x00\x00\x00\x48\x89\x5C\x24", 11},
            {"ConVarAccessor",   "CConVar manager",                    nullptr, 0},
            {"InputSystem",      "CInputSystem keyboard/mouse",        nullptr, 0},
            {"ViewMatrix",       "VMatrix for W2S",
             "\x48\x8D\x05\x00\x00\x00\x00\x48\xC1\xE0\x06", 11},
            {nullptr, nullptr, nullptr, 0}
        }
    },
};

// Forward declare PatternResult
struct PatternResult {
    std::string name;
    uint64_t rva;
    uint64_t resolvedAddr;
};

// ── Game-Specific Pattern Tables ────────────────────────────────────────────────

struct GamePattern {
    const char* name;
    const char* description;
    const char* pattern;
    int patLen;
    int resolveOffset;
};

struct GamePatternTable {
    const char* processName;
    const char* gameName;
    GamePattern patterns[24];
};

static const GamePatternTable g_gamePatterns[] = {
    {
        "r5apex.exe", "Apex Legends (Source 2 / Respawn)",
        {
            {"EntityList",      "CEntInfoList global entity list",
             "\x4C\x8B\x15\x00\x00\x00\x00\x33\xF6\x49\x63\xC0", 12, 3},
            {"LocalPlayer",     "C_BasePlayer* local player pointer",
             "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x48\x8B\x40\x08", 16, 3},
            {"ViewRender",      "ViewRender pointer",
             "\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\xFF\x50\x00\x48\x8D\x4C\x24", 17, 3},
            {"ViewMatrix",      "World-to-screen view matrix",
             "\x48\x8D\x05\x00\x00\x00\x00\x48\xC1\xE0\x06", 11, 3},
            {"GlobalVars",      "CGlobalVarsBase timing/tick info",
             "\x48\x8B\x05\x00\x00\x00\x00\xF3\x0F\x10\x40\x00\x0F\x2E\xC1", 15, 3},
            {"InputSystem",     "CInputSystem",
             "\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\xFF\x90\x00\x00\x00\x00\x48\x85\xC0", 19, 3},
            {"NameList",        "Player name list array",
             "\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x44\x24\x00\x4C\x8D\x0D", 15, 3},
            {"SignifierName",   "m_iSignifierName offset",
             "\x48\x8B\x91\x00\x00\x00\x00\x48\x85\xD2\x74\x00\x4C\x8D\x44\x24", 16, 3},
            {"GlowEnable",      "Glow highlight enable",
             "\x80\xB9\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\xF3\x0F\x10\x89", 17, 2},
            {"HealthOffset",    "m_iHealth field offset",
             "\x8B\x81\x00\x00\x00\x00\x89\x44\x24\x00\x85\xC0", 12, 2},
            {"ShieldOffset",    "m_shieldHealth field offset",
             "\x8B\x89\x00\x00\x00\x00\x85\xC9\x78\x00\x89\x4C\x24", 13, 2},
            {"TeamNumOffset",   "m_iTeamNum",
             "\x8B\x91\x00\x00\x00\x00\x3B\x91\x00\x00\x00\x00\x75", 13, 2},
            {"OriginOffset",    "m_vecAbsOrigin world position",
             "\xF3\x0F\x10\x81\x00\x00\x00\x00\xF3\x0F\x10\x89\x00\x00\x00\x00\xF3\x0F\x10\x91", 20, 4},
            {"BoneMatrix",      "Bone matrix array for skeleton",
             "\x48\x8B\x89\x00\x00\x00\x00\x4C\x8B\xC6\x48\x8D\x54\x24", 14, 3},
            {nullptr, nullptr, nullptr, 0, 0}
        }
    },
    {
        "DFGame-Win64-Shipping.exe", "Delta Force (Unreal Engine / ACE)",
        {
            {"GWorld",          "UWorld global pointer",
             "\x48\x8B\x1D\x00\x00\x00\x00\x48\x85\xDB\x74\x00\x48\x8B\x5B\x78", 16, 3},
            {"GNames",          "FNamePool global name table",
             "\x48\x8D\x05\x00\x00\x00\x00\xEB\x00\x48\x8D\x0D\x00\x00\x00\x00", 16, 3},
            {"GObjects",        "FUObjectArray global object array",
             "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x0C\xC8\x48\x8D\x04\xD1", 15, 3},
            {"GEngine",         "UEngine global pointer",
             "\x48\x89\x05\x00\x00\x00\x00\x48\x85\xC9\x74\x00\xE8", 13, 3},
            {"ProcessEvent",    "UObject::ProcessEvent dispatcher",
             "\x40\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC", 15, -1},
            {"GetBoneMatrix",   "USkeletalMeshComponent::GetBoneMatrix",
             "\x48\x8B\xC4\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68", 18, -1},
            {"GetPlayerViewPoint", "APlayerController::GetPlayerViewPoint",
             "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xF9\x48\x8B\xDA\xE8", 17, -1},
            {"GetPlayerName",   "APlayerState::GetPlayerName",
             "\x40\x53\x48\x83\xEC\x00\x48\x8B\xD9\x48\x8B\x89\x00\x00\x00\x00\x48\x85\xC9", 19, -1},
            {nullptr, nullptr, nullptr, 0, 0}
        }
    },
};

static const GamePatternTable* FindGamePatterns(const char* procName) {
    for (auto& gp : g_gamePatterns) {
        if (_stricmp(gp.processName, procName) == 0) return &gp;
    }
    return nullptr;
}

static std::vector<PatternResult> ScanGamePatterns(const std::vector<uint8_t>& image,
                                                    uint64_t imageBase,
                                                    const std::vector<IMAGE_SECTION_HEADER>& secs,
                                                    const GamePatternTable* gpt) {
    std::vector<PatternResult> results;
    if (!gpt) return results;

    // Collect all executable sections (some games pack .text and use custom sections)
    struct ExecSection { uint32_t va; uint32_t size; };
    std::vector<ExecSection> execSecs;
    for (auto& s : secs) {
        if ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) && s.Misc.VirtualSize > 0) {
            uint32_t va = s.VirtualAddress;
            uint32_t sz = s.Misc.VirtualSize;
            if (s.SizeOfRawData > 0 && va + sz <= image.size())
                execSecs.push_back({va, sz});
        }
    }
    // Fallback to .text if nothing found
    if (execSecs.empty()) {
        for (auto& s : secs) {
            char name[9]{}; memcpy(name, s.Name, 8);
            if (strcmp(name, ".text") == 0 && s.VirtualAddress + s.Misc.VirtualSize <= image.size()) {
                execSecs.push_back({s.VirtualAddress, s.Misc.VirtualSize});
                break;
            }
        }
    }
    if (execSecs.empty()) return results;

    for (int p = 0; gpt->patterns[p].name; p++) {
        auto& pat = gpt->patterns[p];
        const uint8_t* sig = (const uint8_t*)pat.pattern;
        bool found = false;

        for (auto& es : execSecs) {
            if (found) break;
            const uint8_t* data = image.data() + es.va;
            for (uint32_t i = 0; i + pat.patLen < es.size; i++) {
                bool match = true;
                for (int j = 0; j < pat.patLen; j++) {
                    if (sig[j] == 0x00 && (j >= 3 && sig[j-1] != 0x00 && j < pat.patLen - 1))
                        continue;
                    if (data[i + j] != sig[j]) { match = false; break; }
                }
                if (match) {
                    PatternResult pr{};
                    pr.name = pat.name;
                    pr.rva = es.va + i;
                    if (pat.resolveOffset >= 0 && (int)i + pat.resolveOffset + 4 < (int)es.size) {
                        int32_t disp = *(int32_t*)(data + i + pat.resolveOffset);
                        uint32_t instrEnd = es.va + i + pat.resolveOffset + 4;
                        pr.resolvedAddr = imageBase + instrEnd + disp;
                    }
                    results.push_back(pr);
                    found = true;
                    break;
                }
            }
        }
    }
    return results;
}

// ── Dump Strategy ───────────────────────────────────────────────────────────────

struct DumpStrategy {
    const char* name;
    bool dumpMainExe;
    bool dumpAllModules;
    std::vector<std::string> specificModules;
    bool extractExports;
    bool extractImports;
    bool scanPatterns;
    bool scanEngineOffsets;
    bool dumpIl2cppMetadata;
};

static DumpStrategy ChooseStrategy(const DetectedEngine& engine, const KnownGame* game,
                                    const std::vector<ModuleInfo>& modules) {
    DumpStrategy strat{};
    strat.dumpMainExe = true;
    strat.extractExports = true;
    strat.extractImports = true;
    strat.scanPatterns = true;
    strat.scanEngineOffsets = true;

    switch (engine.engine) {
        case ENGINE_UNITY:
            strat.name = "Unity IL2CPP Strategy";
            for (auto& m : modules) {
                if (ContainsCI(m.name, "GameAssembly.dll")) {
                    strat.specificModules.push_back(m.name);
                    break;
                }
            }
            for (auto& m : modules) {
                if (ContainsCI(m.name, "UnityPlayer.dll")) {
                    strat.specificModules.push_back(m.name);
                    break;
                }
            }
            strat.dumpIl2cppMetadata = true;
            break;

        case ENGINE_SOURCE:
        case ENGINE_SOURCE2:
            strat.name = "Source/Source2 Interface Strategy";
            for (auto& m : modules) {
                std::string lower = ToLower(m.name);
                if (lower.find("client.dll") != std::string::npos ||
                    lower.find("engine.dll") != std::string::npos ||
                    lower.find("engine2.dll") != std::string::npos ||
                    lower.find("server.dll") != std::string::npos ||
                    lower.find("schemasystem.dll") != std::string::npos ||
                    lower.find("materialsystem") != std::string::npos ||
                    lower.find("tier0.dll") != std::string::npos) {
                    strat.specificModules.push_back(m.name);
                }
            }
            break;

        case ENGINE_UNREAL:
            strat.name = "Unreal GObjects/GNames Strategy";
            break;

        case ENGINE_CRYENGINE:
            strat.name = "CryEngine Module Strategy";
            for (auto& m : modules) {
                if (ContainsCI(m.name, "Cry")) {
                    strat.specificModules.push_back(m.name);
                }
            }
            break;

        default:
            strat.name = "Generic Full Dump";
            break;
    }

    if (game) {
        for (int i = 0; game->dumpModules[i]; i++) {
            bool already = false;
            for (auto& s : strat.specificModules) {
                if (_stricmp(s.c_str(), game->dumpModules[i]) == 0) { already = true; break; }
            }
            if (!already) strat.specificModules.push_back(game->dumpModules[i]);
        }
    }

    return strat;
}

// ── Pattern Scanner ─────────────────────────────────────────────────────────────

static bool MatchPattern(const uint8_t* data, const uint8_t* pattern, int len) {
    for (int i = 0; i < len; i++) {
        if (pattern[i] != 0x00 && data[i] != pattern[i]) {
            if (pattern[i] == 0x00) continue;
            return false;
        }
    }
    return true;
}

static std::vector<PatternResult> ScanEngineOffsets(const std::vector<uint8_t>& image,
                                                     uint64_t imageBase,
                                                     const IMAGE_NT_HEADERS64& nt,
                                                     const std::vector<IMAGE_SECTION_HEADER>& secs,
                                                     GameEngine engine) {
    std::vector<PatternResult> results;

    const IMAGE_SECTION_HEADER* textSec = nullptr;
    for (auto& s : secs) {
        char name[9]{};
        memcpy(name, s.Name, 8);
        if (strcmp(name, ".text") == 0) { textSec = &s; break; }
    }
    if (!textSec) return results;

    uint32_t textVA   = textSec->VirtualAddress;
    uint32_t textSize = textSec->Misc.VirtualSize;
    if (textVA + textSize > image.size()) return results;

    const EngineOffsetTable* table = nullptr;
    for (auto& t : g_offsetTables) {
        if (t.engine == engine) { table = &t; break; }
    }
    if (!table) return results;

    const uint8_t* text = image.data() + textVA;

    for (int o = 0; table->offsets[o].name; o++) {
        auto& ofs = table->offsets[o];
        if (!ofs.scanPattern || ofs.patternLen <= 0) {
            if (engine == ENGINE_UNITY) {
                auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (expDir.VirtualAddress && expDir.Size &&
                    expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) <= image.size()) {
                    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(image.data() + expDir.VirtualAddress);
                    uint32_t numNames = exp->NumberOfNames;
                    uint32_t nameRva  = exp->AddressOfNames;
                    uint32_t funcRva  = exp->AddressOfFunctions;
                    uint32_t ordRva   = exp->AddressOfNameOrdinals;
                    if (numNames > 0 && numNames < 100000 &&
                        nameRva + numNames * 4 <= image.size() &&
                        ordRva + numNames * 2 <= image.size()) {
                        auto* names = (uint32_t*)(image.data() + nameRva);
                        auto* ords  = (uint16_t*)(image.data() + ordRva);
                        auto* funcs = (uint32_t*)(image.data() + funcRva);
                        for (uint32_t i = 0; i < numNames; i++) {
                            if (names[i] < image.size()) {
                                const char* n = (const char*)(image.data() + names[i]);
                                if (strcmp(n, ofs.name) == 0 && ords[i] < exp->NumberOfFunctions) {
                                    results.push_back({ofs.name, funcs[ords[i]], imageBase + funcs[ords[i]]});
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            continue;
        }

        for (uint32_t i = 0; i + ofs.patternLen < textSize; i++) {
            if (MatchPattern(text + i, (const uint8_t*)ofs.scanPattern, ofs.patternLen)) {
                uint64_t rva = textVA + i;
                uint64_t resolved = 0;
                if (ofs.patternLen >= 7 && ((uint8_t*)ofs.scanPattern)[0] == 0x48) {
                    int32_t disp = *(int32_t*)(text + i + 3);
                    resolved = imageBase + rva + 7 + disp;
                }
                results.push_back({ofs.name, rva, resolved});
                break;
            }
        }
    }

    return results;
}

// ── String reference scanner ────────────────────────────────────────────────────

struct StringRef {
    uint64_t codeRva;
    uint64_t stringRva;
    std::string value;
};

static std::vector<StringRef> ScanStringRefs(const std::vector<uint8_t>& image,
                                              uint64_t imageBase,
                                              const std::vector<IMAGE_SECTION_HEADER>& secs,
                                              int maxResults = 50) {
    std::vector<StringRef> refs;
    const IMAGE_SECTION_HEADER* textSec = nullptr;
    for (auto& s : secs) {
        char name[9]{};
        memcpy(name, s.Name, 8);
        if (strcmp(name, ".text") == 0) { textSec = &s; break; }
    }
    if (!textSec) return refs;

    uint32_t textVA   = textSec->VirtualAddress;
    uint32_t textSize = textSec->Misc.VirtualSize;
    if (textVA + textSize > image.size()) return refs;
    const uint8_t* text = image.data() + textVA;

    for (uint32_t i = 0; i + 7 < textSize && (int)refs.size() < maxResults; i++) {
        if (text[i] == 0x48 && text[i+1] == 0x8D &&
            (text[i+2] == 0x0D || text[i+2] == 0x15 || text[i+2] == 0x05)) {
            int32_t disp = *(int32_t*)(text + i + 3);
            uint64_t targetRva = textVA + i + 7 + disp;
            if (targetRva < image.size()) {
                const char* str = (const char*)(image.data() + targetRva);
                bool readable = true;
                int len = 0;
                for (int j = 0; j < 80 && str[j]; j++) {
                    if (str[j] < 0x20 || str[j] > 0x7E) { readable = false; break; }
                    len++;
                }
                if (readable && len >= 6 && len < 80) {
                    refs.push_back({textVA + i, targetRva, std::string(str, len)});
                }
            }
        }
    }
    return refs;
}

// ── Heuristic Offset Discovery (string xrefs → global pointers → struct fields) ─

struct FoundString {
    std::string value;
    uint64_t    rva;
};

static std::vector<FoundString> FindTargetStrings(
    const std::vector<uint8_t>& image,
    const std::vector<IMAGE_SECTION_HEADER>& secs,
    const std::vector<std::string>& targets)
{
    std::vector<FoundString> found;
    for (auto& s : secs) {
        char sname[9]{};
        memcpy(sname, s.Name, 8);
        if (strcmp(sname, ".rdata") != 0 && strcmp(sname, ".data") != 0 &&
            strcmp(sname, ".text") != 0)
            continue;
        uint32_t va = s.VirtualAddress;
        uint32_t sz = s.Misc.VirtualSize;
        if (va + sz > image.size()) continue;

        for (uint32_t i = 0; i + 4 < sz; i++) {
            const char* p = (const char*)(image.data() + va + i);
            if (*p < 0x20 || *p > 0x7e) continue;
            int len = 0;
            while (len < 80 && p[len] >= 0x20 && p[len] <= 0x7e) len++;
            if (len < 4 || p[len] != 0) continue;

            std::string str(p, len);
            for (auto& t : targets) {
                if (ContainsCI(str.c_str(), t.c_str())) {
                    found.push_back({str, va + i});
                    break;
                }
            }
            i += len;
        }
    }
    return found;
}

struct CodeXref {
    uint64_t codeRva;
    uint64_t targetRva;
};

static std::vector<CodeXref> FindCodeXrefs(
    const std::vector<uint8_t>& image,
    const std::vector<IMAGE_SECTION_HEADER>& secs,
    uint64_t targetRva,
    uint64_t imageBase)
{
    std::vector<CodeXref> xrefs;
    for (auto& s : secs) {
        char sname[9]{};
        memcpy(sname, s.Name, 8);
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint32_t va = s.VirtualAddress;
        uint32_t sz = s.Misc.VirtualSize;
        if (va + sz > image.size()) continue;
        const uint8_t* text = image.data() + va;

        for (uint32_t i = 0; i + 7 < sz; i++) {
            // LEA reg, [rip+disp32]:  48 8D xx xxxxxxxx
            // MOV reg, [rip+disp32]:  48 8B xx xxxxxxxx
            if (text[i] == 0x48 && (text[i+1] == 0x8D || text[i+1] == 0x8B)) {
                uint8_t modrm = text[i+2];
                if ((modrm & 0xC7) == 0x05 || (modrm & 0xC7) == 0x0D ||
                    (modrm & 0xC7) == 0x15 || (modrm & 0xC7) == 0x1D ||
                    (modrm & 0xC7) == 0x25 || (modrm & 0xC7) == 0x2D ||
                    (modrm & 0xC7) == 0x35 || (modrm & 0xC7) == 0x3D) {
                    int32_t disp = *(int32_t*)(text + i + 3);
                    uint64_t instrEnd = va + i + 7;
                    uint64_t resolved = instrEnd + disp;
                    if (resolved == targetRva) {
                        xrefs.push_back({va + i, targetRva});
                    }
                }
            }
            // 4C 8D / 4C 8B variants (R8-R15)
            if (text[i] == 0x4C && (text[i+1] == 0x8D || text[i+1] == 0x8B)) {
                uint8_t modrm = text[i+2];
                if ((modrm & 0xC7) == 0x05 || (modrm & 0xC7) == 0x0D ||
                    (modrm & 0xC7) == 0x15 || (modrm & 0xC7) == 0x1D ||
                    (modrm & 0xC7) == 0x25 || (modrm & 0xC7) == 0x2D ||
                    (modrm & 0xC7) == 0x35 || (modrm & 0xC7) == 0x3D) {
                    int32_t disp = *(int32_t*)(text + i + 3);
                    uint64_t instrEnd = va + i + 7;
                    uint64_t resolved = instrEnd + disp;
                    if (resolved == targetRva) {
                        xrefs.push_back({va + i, targetRva});
                    }
                }
            }
        }
    }
    return xrefs;
}

struct NearbyGlobal {
    uint64_t codeRva;
    uint64_t globalRva;
    bool     isLoad; // true = MOV (load ptr value), false = LEA (load address)
};

static std::vector<NearbyGlobal> FindNearbyGlobals(
    const std::vector<uint8_t>& image,
    const std::vector<IMAGE_SECTION_HEADER>& secs,
    uint64_t nearRva,
    int range = 128)
{
    uint64_t dataStart = 0, dataEnd = 0;
    for (auto& s : secs) {
        char sname[9]{};
        memcpy(sname, s.Name, 8);
        if (strcmp(sname, ".data") == 0 || strcmp(sname, ".bss") == 0) {
            if (dataStart == 0 || s.VirtualAddress < dataStart) dataStart = s.VirtualAddress;
            uint64_t e = s.VirtualAddress + s.Misc.VirtualSize;
            if (e > dataEnd) dataEnd = e;
        }
    }
    if (dataStart == 0) {
        // Fallback: anything past .text is probably data
        for (auto& s : secs) {
            char sname[9]{};
            memcpy(sname, s.Name, 8);
            if (strcmp(sname, ".text") == 0) {
                dataStart = s.VirtualAddress + s.Misc.VirtualSize;
                dataEnd = (uint64_t)image.size();
                break;
            }
        }
    }

    std::vector<NearbyGlobal> results;
    uint64_t start = nearRva > (uint64_t)range ? nearRva - range : 0;
    uint64_t end = nearRva + range;
    if (end + 7 > image.size()) end = image.size() - 7;

    for (uint64_t i = start; i < end; i++) {
        if (i + 7 > image.size()) break;
        const uint8_t* b = image.data() + i;
        if ((b[0] == 0x48 || b[0] == 0x4C) && (b[1] == 0x8B || b[1] == 0x8D)) {
            uint8_t modrm = b[2];
            if ((modrm & 0x07) == 0x05) { // RIP-relative
                int32_t disp = *(int32_t*)(b + 3);
                uint64_t instrEnd = i + 7;
                uint64_t target = instrEnd + disp;
                if (target >= dataStart && target < dataEnd) {
                    results.push_back({i, target, b[1] == 0x8B});
                }
            }
        }
    }
    return results;
}

struct FieldAccess {
    uint32_t offset;
    int      count;
};

static std::vector<FieldAccess> DiscoverFieldOffsets(
    const std::vector<uint8_t>& image,
    const std::vector<IMAGE_SECTION_HEADER>& secs,
    uint64_t globalRva,
    uint64_t imageBase)
{
    auto xrefs = FindCodeXrefs(image, secs, globalRva, imageBase);
    std::map<uint32_t, int> offsetVotes;

    for (auto& xr : xrefs) {
        // Scan forward ~256 bytes from the xref for [reg+offset] patterns
        uint64_t start = xr.codeRva;
        uint64_t end = start + 256;
        if (end > image.size()) end = image.size();
        const uint8_t* code = image.data();

        for (uint64_t ea = start; ea + 4 < end; ea++) {
            // MOV reg, [reg+disp32]:  48 8B xx xxxxxxxx where modrm has mod=10
            if (code[ea] == 0x48 && (code[ea+1] == 0x8B || code[ea+1] == 0x89 || code[ea+1] == 0x8D)) {
                uint8_t modrm = code[ea+2];
                uint8_t mod = (modrm >> 6) & 3;
                if (mod == 2 && ea + 7 <= end) { // [reg+disp32]
                    int32_t disp = *(int32_t*)(code + ea + 3);
                    if (disp > 0 && disp < 0x2000) {
                        offsetVotes[disp]++;
                    }
                }
                if (mod == 1 && ea + 4 <= end) { // [reg+disp8]
                    int8_t disp = (int8_t)code[ea+3];
                    if (disp > 0) {
                        offsetVotes[(uint32_t)disp]++;
                    }
                }
            }
        }
    }

    std::vector<FieldAccess> fields;
    for (auto& [off, cnt] : offsetVotes) {
        if (cnt >= 2) // Only report offsets accessed at least twice
            fields.push_back({off, cnt});
    }
    std::sort(fields.begin(), fields.end(), [](auto& a, auto& b){ return a.count > b.count; });
    return fields;
}

static std::string BuildSigPattern(const std::vector<uint8_t>& image, uint64_t instrRva, int contextAfter = 8) {
    if (instrRva + 7 > image.size()) return "";
    const uint8_t* b = image.data() + instrRva;
    // Instruction is 7 bytes: REX + opcode + modrm + 4-byte displacement
    // Wildcard the displacement (bytes 3-6)
    std::string pat;
    char hex[4];
    for (int i = 0; i < 3; i++) {
        if (i > 0) pat += " ";
        snprintf(hex, sizeof(hex), "%02X", b[i]);
        pat += hex;
    }
    pat += " ?? ?? ?? ??";
    // Add context bytes after the instruction
    for (int i = 7; i < 7 + contextAfter && instrRva + i < image.size(); i++) {
        snprintf(hex, sizeof(hex), " %02X", b[i]);
        pat += hex;
    }
    return pat;
}

struct ManagerCandidate {
    std::string name;
    uint64_t    globalRva;
    std::string sigPattern;
    int         votes;
    std::vector<FieldAccess> fields;
};

static std::vector<ManagerCandidate> HeuristicManagerScan(
    const std::vector<uint8_t>& image,
    uint64_t imageBase,
    const std::vector<IMAGE_SECTION_HEADER>& secs,
    const std::vector<std::string>& managerStrings)
{
    printf("  [*] Heuristic manager discovery via string xrefs...\n");

    auto foundStrings = FindTargetStrings(image, secs, managerStrings);
    printf("    Found %zu matching strings in data sections\n", foundStrings.size());

    std::map<std::string, std::map<uint64_t, int>> candidateVotes; // name -> {globalRva -> votes}

    for (auto& fs : foundStrings) {
        auto xrefs = FindCodeXrefs(image, secs, fs.rva, imageBase);
        if (xrefs.empty()) continue;
        printf("    '%s' @ RVA 0x%llX: %zu code xrefs\n",
               fs.value.c_str(), (unsigned long long)fs.rva, xrefs.size());

        // Determine which manager name this string corresponds to
        std::string mgrName = "";
        for (auto& t : managerStrings) {
            if (ContainsCI(fs.value.c_str(), t.c_str())) {
                mgrName = t;
                break;
            }
        }
        if (mgrName.empty()) continue;

        for (auto& xr : xrefs) {
            auto globals = FindNearbyGlobals(image, secs, xr.codeRva);
            for (auto& g : globals) {
                if (g.isLoad) { // MOV = loading a pointer value (singleton access)
                    candidateVotes[mgrName][g.globalRva]++;
                }
            }
        }
    }

    // Also run structural pattern scanning (MOV+TEST+JZ heuristic)
    printf("  [*] Structural pattern scan (MOV+TEST+JZ → singleton access)...\n");
    uint64_t dataStart = 0, dataEnd = 0;
    for (auto& s : secs) {
        char sname[9]{};
        memcpy(sname, s.Name, 8);
        if (strcmp(sname, ".data") == 0 || strcmp(sname, ".bss") == 0) {
            if (dataStart == 0 || s.VirtualAddress < dataStart) dataStart = s.VirtualAddress;
            uint64_t e = s.VirtualAddress + s.Misc.VirtualSize;
            if (e > dataEnd) dataEnd = e;
        }
    }

    for (auto& s : secs) {
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint32_t va = s.VirtualAddress;
        uint32_t sz = s.Misc.VirtualSize;
        if (va + sz > image.size()) continue;
        const uint8_t* text = image.data() + va;

        for (uint32_t i = 0; i + 20 < sz; i++) {
            // MOV reg, [rip+disp32]
            if (text[i] != 0x48 || text[i+1] != 0x8B) continue;
            uint8_t modrm = text[i+2];
            if ((modrm & 0x07) != 0x05) continue; // not RIP-relative

            int32_t disp = *(int32_t*)(text + i + 3);
            uint64_t instrEnd = va + i + 7;
            uint64_t target = instrEnd + disp;
            if (target < dataStart || target >= dataEnd) continue;

            // Check next instruction: TEST reg,reg (48 85 xx)
            uint32_t next = i + 7;
            if (next + 3 >= sz) continue;
            if (text[next] != 0x48 || text[next+1] != 0x85) continue;

            // Check: JZ/JE (74 xx or 0F 84 xx xx xx xx)
            uint32_t jmp = next + 3;
            if (jmp >= sz) continue;
            if (text[jmp] != 0x74 && !(text[jmp] == 0x0F && jmp+1 < sz && text[jmp+1] == 0x84)) continue;

            // This looks like a singleton access pattern
            candidateVotes["_structural"][target]++;
        }
    }

    // Build results: pick best candidate per manager name
    std::vector<ManagerCandidate> results;
    for (auto& [name, votes] : candidateVotes) {
        if (votes.empty()) continue;
        // Find the RVA with most votes
        uint64_t bestRva = 0;
        int bestVotes = 0;
        for (auto& [rva, v] : votes) {
            if (v > bestVotes) { bestVotes = v; bestRva = rva; }
        }
        if (bestRva == 0) continue;

        ManagerCandidate mc;
        mc.name = name;
        mc.globalRva = bestRva;
        mc.votes = bestVotes;

        // Extract sig pattern from the first xref to this global
        auto xrefs = FindCodeXrefs(image, secs, bestRva, imageBase);
        if (!xrefs.empty()) {
            mc.sigPattern = BuildSigPattern(image, xrefs[0].codeRva);
        }

        // Discover struct field offsets
        mc.fields = DiscoverFieldOffsets(image, secs, bestRva, imageBase);

        printf("    %s: RVA 0x%llX (%d votes, %zu xrefs, %zu field offsets)\n",
               name.c_str(), (unsigned long long)bestRva, bestVotes,
               xrefs.size(), mc.fields.size());
        if (!mc.sigPattern.empty())
            printf("      Sig: %s\n", mc.sigPattern.c_str());
        for (auto& f : mc.fields) {
            if (f.count >= 3)
                printf("      +0x%X (%d accesses)\n", f.offset, f.count);
        }

        results.push_back(mc);
    }

    std::sort(results.begin(), results.end(), [](auto& a, auto& b){ return a.votes > b.votes; });
    return results;
}

static void WriteDiscoveredINI(const char* path,
                                const std::vector<ManagerCandidate>& managers,
                                const std::vector<PatternResult>& engineOffsets,
                                uint64_t imageBase,
                                const char* gameName)
{
    FILE* f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "; Auto-discovered offsets for %s\n", gameName);
    fprintf(f, "; Image base: 0x%llX\n", (unsigned long long)imageBase);
    fprintf(f, "; Run dumper again after game update to refresh\n\n");

    fprintf(f, "[Game]\n");
    fprintf(f, "Name=%s\n\n", gameName);

    fprintf(f, "[Managers]\n");
    for (auto& m : managers) {
        if (m.name[0] == '_') continue; // skip internal names like _structural
        fprintf(f, "%s=0x%llX\n", m.name.c_str(), (unsigned long long)m.globalRva);
    }
    fprintf(f, "\n");

    if (!engineOffsets.empty()) {
        fprintf(f, "[EngineOffsets]\n");
        for (auto& o : engineOffsets) {
            if (o.resolvedAddr)
                fprintf(f, "%s=0x%llX\n", o.name.c_str(), (unsigned long long)(o.resolvedAddr - imageBase));
            else
                fprintf(f, "%s=0x%llX\n", o.name.c_str(), (unsigned long long)o.rva);
        }
        fprintf(f, "\n");
    }

    fprintf(f, "[Patterns]\n");
    for (auto& m : managers) {
        if (m.name[0] == '_' || m.sigPattern.empty()) continue;
        fprintf(f, "%s_Bytes=%s\n", m.name.c_str(), m.sigPattern.c_str());
        fprintf(f, "%s_RipOffset=3\n", m.name.c_str());
    }
    fprintf(f, "\n");

    fprintf(f, "[FieldOffsets]\n");
    fprintf(f, "; Most-accessed struct field offsets (higher count = more likely real)\n");
    for (auto& m : managers) {
        if (m.name[0] == '_' || m.fields.empty()) continue;
        fprintf(f, "; %s fields:\n", m.name.c_str());
        for (auto& fl : m.fields) {
            if (fl.count >= 2)
                fprintf(f, ";   +0x%X = %d accesses\n", fl.offset, fl.count);
        }
    }
    fprintf(f, "\n");

    fprintf(f, "[Encryption]\n");
    fprintf(f, "DecryptKey=0x0\n");
    fprintf(f, "DecryptRotation=0\n");

    fclose(f);
    printf("[+] Discovered offsets written: %s\n", path);
}

// ── Auto-Detect Running Games ───────────────────────────────────────────────────

struct DetectedGame {
    DWORD pid;
    const KnownGame* info;
    char processName[MAX_PATH];
};

static std::vector<DetectedGame> ScanForGames() {
    std::vector<DetectedGame> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            for (auto& g : g_knownGames) {
                if (_stricmp(pe.szExeFile, g.processName) == 0) {
                    DetectedGame dg{};
                    dg.pid = pe.th32ProcessID;
                    dg.info = &g;
                    strncpy(dg.processName, pe.szExeFile, MAX_PATH - 1);
                    found.push_back(dg);
                    break;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ── Live process dump (ReadProcessMemory) ───────────────────────────────────────

static bool DumpModuleLive(uint64_t base, const char* moduleName, const char* outPath) {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(base, dos, nt)) {
        printf("[-] Failed to read PE headers for %s\n", moduleName);
        return false;
    }

    auto secs = ReadSections(base, dos, nt);
    uint32_t imageSize = nt.OptionalHeader.SizeOfImage;
    printf("\n[*] Dumping %s @ 0x%llX (0x%X bytes, %u sections)\n",
           moduleName, (unsigned long long)base, imageSize, (unsigned)secs.size());

    std::vector<uint8_t> image(imageSize, 0);

    uint32_t headerSize = nt.OptionalHeader.SizeOfHeaders;
    MemRead(base, image.data(), headerSize);

    for (auto& s : secs) {
        char name[9]{};
        memcpy(name, s.Name, 8);
        uint32_t va  = s.VirtualAddress;
        uint32_t vSz = s.Misc.VirtualSize;
        if (!va || !vSz) continue;
        if (va + vSz > imageSize) vSz = imageSize - va;

        auto t0 = std::chrono::steady_clock::now();
        MemReadChunked(base + va, image.data() + va, vSz);
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        printf("    %-8s  VA=0x%08X  Size=0x%08X  [%.0fms]\n", name, va, vSz, ms);
    }

    auto* fixedNt = (IMAGE_NT_HEADERS64*)(image.data() + dos.e_lfanew);
    fixedNt->OptionalHeader.ImageBase = base;
    uint32_t secFixOff = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                       + fixedNt->FileHeader.SizeOfOptionalHeader;
    auto* fixedSecs = (IMAGE_SECTION_HEADER*)(image.data() + secFixOff);
    for (uint16_t i = 0; i < fixedNt->FileHeader.NumberOfSections; i++) {
        fixedSecs[i].PointerToRawData = fixedSecs[i].VirtualAddress;
        fixedSecs[i].SizeOfRawData    = fixedSecs[i].Misc.VirtualSize;
    }

    FILE* f = fopen(outPath, "wb");
    if (!f) { printf("[-] Cannot write %s\n", outPath); return false; }
    fwrite(image.data(), 1, imageSize, f);
    fclose(f);
    printf("[+] Wrote %s (%u MB)\n", outPath, imageSize / (1024*1024));
    return true;
}

// ── Static file dump (copy + analyze from disk) ─────────────────────────────────

static bool DumpModuleStatic(const char* filePath, const char* outPath) {
    FILE* src = fopen(filePath, "rb");
    if (!src) { printf("[-] Cannot open %s\n", filePath); return false; }
    fseek(src, 0, SEEK_END);
    long fsize = ftell(src);
    fseek(src, 0, SEEK_SET);

    printf("\n[*] Static dump: %s (%ld bytes)\n", filePath, fsize);

    std::vector<uint8_t> data(fsize);
    fread(data.data(), 1, fsize, src);
    fclose(src);

    FILE* dst = fopen(outPath, "wb");
    if (!dst) { printf("[-] Cannot write %s\n", outPath); return false; }
    fwrite(data.data(), 1, fsize, dst);
    fclose(dst);
    printf("[+] Wrote %s (%.1f MB)\n", outPath, fsize / (1024.0 * 1024.0));
    return true;
}

// ── Report Generation ───────────────────────────────────────────────────────────

static void WriteReport(const char* reportPath,
                        const char* procName, DWORD pid,
                        const DetectedEngine& engine,
                        const KnownGame* game,
                        const DumpStrategy& strat,
                        const std::vector<ModuleInfo>& modules,
                        const std::vector<PatternResult>& engineOffsets,
                        const std::vector<StringRef>& stringRefs,
                        uint64_t mainBase) {
    FILE* f = fopen(reportPath, "w");
    if (!f) return;

    fprintf(f, "================================================================\n");
    fprintf(f, "  Game Dumper Report\n");
    fprintf(f, "================================================================\n\n");

    fprintf(f, "Process:       %s (PID %u)\n", procName, pid);
    fprintf(f, "Mode:          %s\n", g_staticMode ? "Static (disk)" : "Live (ReadProcessMemory)");
    if (game) {
        fprintf(f, "Game:          %s\n", game->gameName);
        fprintf(f, "Anti-Cheat:    %s\n", game->antiCheat);
    }
    fprintf(f, "Engine:        %s (confidence: %d%%)\n", engine.name, min(engine.confidence, 100));
    fprintf(f, "Strategy:      %s\n", strat.name);
    fprintf(f, "Main Base:     0x%llX\n\n", (unsigned long long)mainBase);

    fprintf(f, "--- Engine Detection Evidence ---\n");
    for (auto& e : engine.evidence)
        fprintf(f, "  %s\n", e.c_str());
    fprintf(f, "\n");

    if (!engineOffsets.empty()) {
        fprintf(f, "--- Engine-Specific Offsets ---\n");
        for (auto& o : engineOffsets) {
            fprintf(f, "  %-30s  RVA=0x%08llX", o.name.c_str(), (unsigned long long)o.rva);
            if (o.resolvedAddr)
                fprintf(f, "  -> 0x%llX", (unsigned long long)o.resolvedAddr);
            fprintf(f, "\n");
        }
        fprintf(f, "\n");
    }

    if (!stringRefs.empty()) {
        fprintf(f, "--- String References (first %zu) ---\n", stringRefs.size());
        for (auto& s : stringRefs)
            fprintf(f, "  RVA 0x%08llX -> \"%s\"\n", (unsigned long long)s.codeRva, s.value.c_str());
        fprintf(f, "\n");
    }

    fprintf(f, "--- Loaded Modules (%zu) ---\n", modules.size());
    fprintf(f, "%-16s  %-10s  %s\n", "BASE", "SIZE", "NAME");
    for (auto& m : modules)
        fprintf(f, "0x%014llX  0x%08X  %s\n", (unsigned long long)m.base, m.size, m.name);

    fprintf(f, "\n--- Dump Strategy Details ---\n");
    fprintf(f, "Main EXE dump:     %s\n", strat.dumpMainExe ? "YES" : "NO");
    fprintf(f, "Export extraction:  %s\n", strat.extractExports ? "YES" : "NO");
    fprintf(f, "Import extraction:  %s\n", strat.extractImports ? "YES" : "NO");
    fprintf(f, "Pattern scanning:   %s\n", strat.scanPatterns ? "YES" : "NO");
    fprintf(f, "Engine offsets:     %s\n", strat.scanEngineOffsets ? "YES" : "NO");
    if (!strat.specificModules.empty()) {
        fprintf(f, "Additional modules:\n");
        for (auto& m : strat.specificModules)
            fprintf(f, "  - %s\n", m.c_str());
    }

    fprintf(f, "\n================================================================\n");
    fprintf(f, "  End of Report\n");
    fprintf(f, "================================================================\n");
    fclose(f);
    printf("[+] Report written: %s\n", reportPath);
}

// ── Usage ───────────────────────────────────────────────────────────────────────

static void PrintUsage(const char* exe) {
    printf("Usage: %s [options]\n\n", exe);
    printf("Modes:\n");
    printf("  (default)           Live process dump via ReadProcessMemory\n");
    printf("  --static --path <dir>  Static analysis from game files on disk\n\n");
    printf("Auto-Detection:\n");
    printf("  --scan              Scan for running games and suggest dump targets\n");
    printf("  --auto              Auto-detect engine + choose optimal dump strategy\n\n");
    printf("Target:\n");
    printf("  --proc <name>       Process name (or filename for static mode)\n");
    printf("  --path <dir>        Game installation directory (static mode)\n");
    printf("  --module <name>     Specific module to dump\n");
    printf("  --out <path>        Output directory (default: current dir)\n\n");
    printf("Dump Options:\n");
    printf("  --full              Full process dump (main EXE + key modules)\n");
    printf("  --main-only         Only dump main EXE\n");
    printf("  --all-modules       Dump ALL loaded modules\n");
    printf("  --offsets           Extract exports + imports + engine offsets\n");
    printf("  --strings           Scan for string references\n");
    printf("  --report            Generate analysis report\n");
    printf("  --list-modules      List loaded modules and exit\n");
    printf("  --esp-header        Generate C++ header with offsets for ESP use\n\n");
    printf("Engine Override:\n");
    printf("  --engine <name>     Force engine (unreal/unity/source/source2/cry)\n\n");
    printf("Examples:\n");
    printf("  %s --scan\n", exe);
    printf("  %s --auto --offsets --report\n", exe);
    printf("  %s --proc r5apex.exe --offsets --strings --report\n", exe);
    printf("  %s --proc RustClient.exe --engine unity --full --offsets\n", exe);
    printf("  %s --static --path \"C:\\Games\\Apex\" --proc r5apex.exe --offsets\n", exe);
}

// ── Static mode: find game executables in a directory ────────────────────────────

static std::vector<std::string> FindGameFiles(const char* dir) {
    std::vector<std::string> files;
    std::string searchPath = std::string(dir) + "\\*.exe";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                files.push_back(std::string(dir) + "\\" + fd.cFileName);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    searchPath = std::string(dir) + "\\*.dll";
    hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string lower = ToLower(fd.cFileName);
                if (lower.find("gameassembly") != std::string::npos ||
                    lower.find("unityplayer") != std::string::npos ||
                    lower.find("client.dll") != std::string::npos ||
                    lower.find("engine") != std::string::npos)
                    files.push_back(std::string(dir) + "\\" + fd.cFileName);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    return files;
}

// ── Main ────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== Game Dumper (standalone — no driver required) ===\n\n");

    std::string procName;
    std::string moduleName;
    std::string outDir = ".";
    std::string gamePath;
    bool doScan = false;
    bool doAuto = true;
    bool fullDump = true;
    bool mainOnly = false;
    bool allModules = false;
    bool extractOffsets = false;
    bool scanStrings = false;
    bool generateReport = false;
    bool listModules = false;
    bool espHeader = false;
    GameEngine forceEngine = ENGINE_UNKNOWN;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scan") == 0)           doScan = true;
        else if (strcmp(argv[i], "--auto") == 0)       doAuto = true;
        else if (strcmp(argv[i], "--static") == 0)     g_staticMode = true;
        else if (strcmp(argv[i], "--proc") == 0 && i+1 < argc)   procName = argv[++i];
        else if (strcmp(argv[i], "--path") == 0 && i+1 < argc)   gamePath = argv[++i];
        else if (strcmp(argv[i], "--module") == 0 && i+1 < argc) moduleName = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i+1 < argc)    outDir = argv[++i];
        else if (strcmp(argv[i], "--full") == 0)       { fullDump = true; mainOnly = false; }
        else if (strcmp(argv[i], "--main-only") == 0)  { mainOnly = true; fullDump = false; }
        else if (strcmp(argv[i], "--all-modules") == 0) allModules = true;
        else if (strcmp(argv[i], "--offsets") == 0)    extractOffsets = true;
        else if (strcmp(argv[i], "--strings") == 0)    scanStrings = true;
        else if (strcmp(argv[i], "--report") == 0)     generateReport = true;
        else if (strcmp(argv[i], "--list-modules") == 0) listModules = true;
        else if (strcmp(argv[i], "--engine") == 0 && i+1 < argc) {
            i++;
            if (_stricmp(argv[i], "unreal") == 0)       forceEngine = ENGINE_UNREAL;
            else if (_stricmp(argv[i], "unity") == 0)    forceEngine = ENGINE_UNITY;
            else if (_stricmp(argv[i], "source") == 0)   forceEngine = ENGINE_SOURCE;
            else if (_stricmp(argv[i], "source2") == 0)  forceEngine = ENGINE_SOURCE2;
            else if (_stricmp(argv[i], "cry") == 0)      forceEngine = ENGINE_CRYENGINE;
            else { printf("[-] Unknown engine: %s\n", argv[i]); return 1; }
        }
        else if (strcmp(argv[i], "--esp-header") == 0)    espHeader = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]); return 0;
        }
        else { printf("[-] Unknown option: %s\n", argv[i]); PrintUsage(argv[0]); return 1; }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STATIC MODE — analyze PE files directly from disk
    // ════════════════════════════════════════════════════════════════════════════
    if (g_staticMode) {
        if (gamePath.empty()) {
            printf("[-] Static mode requires --path <game directory>\n");
            return 1;
        }
        printf("[*] Static mode — reading files from: %s\n\n", gamePath.c_str());

        auto gameFiles = FindGameFiles(gamePath.c_str());
        if (gameFiles.empty()) {
            printf("[-] No EXE/DLL files found in %s\n", gamePath.c_str());
            return 1;
        }

        // If --proc specified, filter to that file
        if (!procName.empty()) {
            std::vector<std::string> filtered;
            for (auto& f : gameFiles) {
                const char* fname = PathFindFileNameA(f.c_str());
                if (_stricmp(fname, procName.c_str()) == 0)
                    filtered.push_back(f);
            }
            if (filtered.empty()) {
                // Try as a substring
                for (auto& f : gameFiles) {
                    if (ContainsCI(f.c_str(), procName.c_str()))
                        filtered.push_back(f);
                }
            }
            if (!filtered.empty()) gameFiles = filtered;
        }

        printf("[+] Found %zu files to analyze:\n", gameFiles.size());
        for (auto& f : gameFiles)
            printf("    %s\n", f.c_str());
        printf("\n");

        std::vector<std::string> dumpedFiles;
        std::vector<PatternResult> allOffsets;
        std::vector<StringRef> allStrRefs;
        DetectedEngine bestEngine{ENGINE_UNKNOWN, "Unknown", 0, {}};
        const KnownGame* knownGame = nullptr;
        uint64_t mainBase = 0;

        for (auto& filePath : gameFiles) {
            const char* fname = PathFindFileNameA(filePath.c_str());

            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};
            std::vector<IMAGE_SECTION_HEADER> secs;
            std::vector<uint8_t> fileData;

            if (!ReadPEHeadersFromFile(filePath.c_str(), dos, nt, secs, fileData)) {
                printf("[-] %s: not a valid PE file\n", fname);
                continue;
            }

            printf("=== %s ===\n", fname);
            printf("  Image Base: 0x%llX  Sections: %u  Size: %.1f MB\n",
                   (unsigned long long)nt.OptionalHeader.ImageBase,
                   nt.FileHeader.NumberOfSections,
                   fileData.size() / (1024.0 * 1024.0));

            // Check known games
            for (auto& g : g_knownGames) {
                {
                    // Exact match or fuzzy: strip .exe from known name and check if dump filename contains it
                    std::string stem(g.processName);
                    auto dot = stem.rfind('.');
                    if (dot != std::string::npos) stem = stem.substr(0, dot);
                    if (_stricmp(fname, g.processName) == 0 || (stem.size() >= 4 && ContainsCI(fname, stem.c_str())))
                    { knownGame = &g; break; }
                }
            }

            // Engine detection
            DetectedEngine engine;
            if (forceEngine != ENGINE_UNKNOWN) {
                engine.engine = forceEngine;
                for (auto& sig : g_engineSigs) {
                    if (sig.engine == forceEngine) { engine.name = sig.name; break; }
                }
                engine.confidence = 100;
                engine.evidence.push_back("Forced via --engine flag");
            } else {
                engine = DetectEngineFromFile(secs, fileData, nt, fname);
                if (knownGame && engine.engine == ENGINE_UNKNOWN) {
                    engine.engine = knownGame->engine;
                    for (auto& sig : g_engineSigs) {
                        if (sig.engine == knownGame->engine) { engine.name = sig.name; break; }
                    }
                    engine.confidence = 80;
                    engine.evidence.push_back("Known game database match");
                }
            }

            printf("  Engine: %s (confidence: %d%%)\n", engine.name, min(engine.confidence, 100));
            if (knownGame)
                printf("  Game: %s | Anti-Cheat: %s\n", knownGame->gameName, knownGame->antiCheat);

            if (engine.confidence > bestEngine.confidence) {
                bestEngine = engine;
                mainBase = nt.OptionalHeader.ImageBase;
            }

            // Build a virtual image for analysis (map sections to VAs)
            uint32_t imageSize = nt.OptionalHeader.SizeOfImage;
            std::vector<uint8_t> image(imageSize, 0);
            uint32_t headerSize = min((uint32_t)nt.OptionalHeader.SizeOfHeaders, (uint32_t)fileData.size());
            memcpy(image.data(), fileData.data(), headerSize);
            for (auto& s : secs) {
                uint32_t rawOff = s.PointerToRawData;
                uint32_t rawSz  = s.SizeOfRawData;
                uint32_t va     = s.VirtualAddress;
                uint32_t vSz    = s.Misc.VirtualSize;
                if (!rawOff || !rawSz || !va) continue;
                uint32_t copySize = min(rawSz, vSz);
                if (rawOff + copySize > fileData.size()) copySize = (uint32_t)fileData.size() - rawOff;
                if (va + copySize > imageSize) copySize = imageSize - va;
                if (copySize > 0)
                    memcpy(image.data() + va, fileData.data() + rawOff, copySize);
            }

            // Dump file
            std::string outName = std::string(fname) + ".dump.bin";
            if (outDir != ".") outName = outDir + "\\" + outName;
            if (DumpModuleStatic(filePath.c_str(), outName.c_str()))
                dumpedFiles.push_back(outName);

            // Pattern scan
            auto* gpt = FindGamePatterns(fname);
            if (gpt) {
                printf("\n  [*] Game-specific patterns (%s):\n", gpt->gameName);
                auto gameOffsets = ScanGamePatterns(image, nt.OptionalHeader.ImageBase, secs, gpt);
                for (auto& o : gameOffsets) {
                    printf("    %-25s  RVA=0x%08llX", o.name.c_str(), (unsigned long long)o.rva);
                    if (o.resolvedAddr)
                        printf("  -> 0x%llX", (unsigned long long)o.resolvedAddr);
                    printf("\n");
                    allOffsets.push_back(o);
                }
                if (gameOffsets.empty())
                    printf("    (no game-specific patterns matched — may need runtime dump)\n");
            }

            if (extractOffsets) {
                printf("\n  [*] Engine-specific offsets:\n");
                auto eo = ScanEngineOffsets(image, nt.OptionalHeader.ImageBase, nt, secs, engine.engine);
                for (auto& o : eo) {
                    printf("    %-30s  RVA=0x%08llX", o.name.c_str(), (unsigned long long)o.rva);
                    if (o.resolvedAddr)
                        printf("  -> 0x%llX", (unsigned long long)o.resolvedAddr);
                    printf("\n");
                    allOffsets.push_back(o);
                }
                if (eo.empty())
                    printf("    (no engine-specific patterns found)\n");

                // Exports
                printf("\n  [*] Exports:\n");
                auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (expDir.VirtualAddress && expDir.Size &&
                    expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) <= image.size()) {
                    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(image.data() + expDir.VirtualAddress);
                    uint32_t numNames = exp->NumberOfNames;
                    uint32_t nameRva  = exp->AddressOfNames;
                    uint32_t funcRva  = exp->AddressOfFunctions;
                    uint32_t ordRva   = exp->AddressOfNameOrdinals;
                    int printed = 0;
                    if (numNames > 0 && numNames < 100000 &&
                        nameRva + numNames * 4 <= image.size() &&
                        ordRva + numNames * 2 <= image.size()) {
                        auto* names = (uint32_t*)(image.data() + nameRva);
                        auto* ords  = (uint16_t*)(image.data() + ordRva);
                        auto* funcs = (uint32_t*)(image.data() + funcRva);
                        for (uint32_t i = 0; i < numNames && printed < 50; i++) {
                            if (names[i] < image.size()) {
                                const char* n = (const char*)(image.data() + names[i]);
                                uint16_t ord = ords[i];
                                if (ord < exp->NumberOfFunctions) {
                                    printf("    0x%08X  %s\n", funcs[ord], n);
                                    printed++;
                                }
                            }
                        }
                    }
                    printf("    (%u total exports)\n", numNames);
                } else {
                    printf("    (no exports)\n");
                }

                // Imports
                printf("\n  [*] Imports:\n");
                auto& impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (impDir.VirtualAddress && impDir.Size && impDir.VirtualAddress < image.size()) {
                    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(image.data() + impDir.VirtualAddress);
                    int count = 0;
                    while (desc->Name && desc->Name < image.size() && count < 100) {
                        printf("    %s\n", (const char*)(image.data() + desc->Name));
                        desc++;
                        count++;
                    }
                    printf("    (%d imported DLLs)\n", count);
                }
            }

            if (scanStrings) {
                printf("\n  [*] String references:\n");
                auto sr = ScanStringRefs(image, nt.OptionalHeader.ImageBase, secs, 50);
                for (auto& s : sr)
                    printf("    RVA 0x%08llX -> \"%s\"\n", (unsigned long long)s.codeRva, s.value.c_str());
                printf("    (%zu string references)\n", sr.size());
                for (auto& s : sr) allStrRefs.push_back(s);
            }

            // Heuristic manager discovery
            if (extractOffsets && image.size() > 0x1000) {
                std::vector<std::string> mgrStrings;
                GameEngine eng = (forceEngine != ENGINE_UNKNOWN) ? forceEngine
                               : (knownGame ? knownGame->engine : engine.engine);
                if (eng == ENGINE_CUSTOM) {
                    mgrStrings = {"GameManager","EntityManager","CameraManager",
                                  "PlayerManager","StatusManager","NetworkManager",
                                  "RoundManager","SpawnManager","MatchManager"};
                } else if (eng == ENGINE_UNREAL) {
                    mgrStrings = {"GWorld","UWorld","GEngine","GameInstance",
                                  "PlayerController","GameState","APlayerState",
                                  "ULocalPlayer","ACharacter","APawn"};
                } else if (eng == ENGINE_UNITY) {
                    mgrStrings = {"global-metadata","il2cpp_domain_get",
                                  "GameManager","PlayerManager","Camera",
                                  "BaseNetworkable","BuildingBlock"};
                }
                if (!mgrStrings.empty()) {
                    printf("\n  [*] Heuristic offset discovery (%s):\n", engine.name);
                    auto managers = HeuristicManagerScan(image, nt.OptionalHeader.ImageBase, secs, mgrStrings);
                    if (!managers.empty()) {
                        std::string iniName = std::string(fname);
                        auto dot = iniName.rfind('.');
                        if (dot != std::string::npos) iniName = iniName.substr(0, dot);
                        iniName += "_offsets.ini";
                        WriteDiscoveredINI(iniName.c_str(), managers, allOffsets,
                                           nt.OptionalHeader.ImageBase, fname);
                        dumpedFiles.push_back(iniName);
                    } else {
                        printf("    (no manager candidates found)\n");
                    }
                }
            }

            // Section details
            printf("\n  Sections:\n");
            printf("  %-8s %-12s %-12s %-12s %-12s %s\n", "Name", "VirtAddr", "VirtSize", "RawSize", "RawPtr", "Flags");
            for (auto& s : secs) {
                char name[9]{};
                memcpy(name, s.Name, 8);
                printf("  %-8s 0x%08X   0x%08X   0x%08X   0x%08X   0x%08X",
                       name, s.VirtualAddress, s.Misc.VirtualSize,
                       s.SizeOfRawData, s.PointerToRawData, s.Characteristics);
                if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) printf(" X");
                if (s.Characteristics & IMAGE_SCN_MEM_READ)    printf(" R");
                if (s.Characteristics & IMAGE_SCN_MEM_WRITE)   printf(" W");
                if (s.SizeOfRawData == 0 && s.Misc.VirtualSize > 0)
                    printf(" [PACKED — needs runtime dump]");
                printf("\n");
            }
            printf("\n");
        }

        // Report
        if (generateReport && !dumpedFiles.empty()) {
            std::string reportName = procName.empty() ? "static_dump" : procName;
            std::string reportFile = reportName + ".report.txt";
            std::vector<ModuleInfo> fakeMods;
            DumpStrategy strat{};
            strat.name = "Static Disk Analysis";
            strat.dumpMainExe = true;
            strat.extractExports = extractOffsets;
            strat.extractImports = extractOffsets;
            strat.scanPatterns = true;
            strat.scanEngineOffsets = extractOffsets;
            WriteReport(reportFile.c_str(), reportName.c_str(), 0,
                        bestEngine, knownGame, strat, fakeMods,
                        allOffsets, allStrRefs, mainBase);
        }

        printf("\n[+] Static analysis complete. Files generated:\n");
        for (auto& f : dumpedFiles)
            printf("    - %s\n", f.c_str());
        return 0;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // LIVE MODE — ReadProcessMemory from a running process
    // ════════════════════════════════════════════════════════════════════════════

    // Scan mode
    if (doScan || procName.empty()) {
        printf("[*] Scanning for known game processes...\n");
        auto games = ScanForGames();
        if (games.empty()) {
            printf("[-] No known game processes found.\n");
            if (procName.empty()) {
                printf("[*] Use --proc <name> to specify a process manually.\n");
                printf("[*] Or use --static --path <dir> to analyze files on disk.\n");
                if (!doScan) PrintUsage(argv[0]);
                return doScan ? 0 : 1;
            }
        } else {
            printf("\n  %-6s  %-30s  %-20s  %-10s  %s\n", "PID", "PROCESS", "GAME", "ENGINE", "AC");
            printf("  %-6s  %-30s  %-20s  %-10s  %s\n", "---", "-------", "----", "------", "--");
            for (auto& g : games) {
                const char* engineName = "Custom";
                for (auto& sig : g_engineSigs) {
                    if (sig.engine == g.info->engine) { engineName = sig.name; break; }
                }
                printf("  %-6u  %-30s  %-20s  %-10s  %s\n",
                       g.pid, g.processName, g.info->gameName, engineName, g.info->antiCheat);
            }
            printf("\n");

            if (procName.empty() && !doScan) {
                procName = games[0].processName;
                printf("[*] Auto-selected: %s (%s)\n", games[0].info->gameName, procName.c_str());
            }
            if (doScan && procName.empty()) return 0;
        }
    }

    // Find process
    DWORD pid = FindProcess(procName.c_str());
    if (!pid) {
        printf("[-] Process '%s' not found.\n", procName.c_str());
        printf("[*] Make sure the game is running, or use --static --path <dir> for disk analysis.\n");
        return 1;
    }
    g_pid = pid;
    printf("[+] Found %s (PID %u)\n", procName.c_str(), pid);

    // Open process
    g_hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_hProc) {
        DWORD err = GetLastError();
        printf("[-] OpenProcess failed (error %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            printf("[!] Access denied — try running as Administrator.\n");
            printf("[!] If anti-cheat is protecting the process, use --static --path <dir> instead.\n");
        }
        return 1;
    }
    printf("[+] Process opened (ReadProcessMemory access)\n");

    // Enumerate modules
    printf("[*] Enumerating modules...\n");
    auto modules = GetModules(pid);
    if (modules.empty()) {
        printf("[-] No modules found (access may be blocked by anti-cheat)\n");
        printf("[*] Try --static --path <dir> for disk-based analysis instead.\n");
        CloseHandle(g_hProc);
        return 1;
    }
    printf("[+] Found %zu modules\n", modules.size());

    if (listModules) {
        printf("\n%-16s  %-10s  %s\n", "BASE", "SIZE", "NAME");
        for (auto& m : modules)
            printf("0x%014llX  0x%08X  %s\n", (unsigned long long)m.base, m.size, m.name);
        CloseHandle(g_hProc);
        return 0;
    }

    // Read main module PE
    uint64_t mainBase = modules[0].base;
    const char* mainName = modules[0].name;

    if (!moduleName.empty()) {
        for (auto& m : modules) {
            if (_stricmp(m.name, moduleName.c_str()) == 0) {
                mainBase = m.base;
                mainName = m.name;
                break;
            }
        }
    }

    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(mainBase, dos, nt)) {
        printf("[-] Failed to read PE headers at 0x%llX\n", (unsigned long long)mainBase);
        printf("[*] Process may be protected. Try --static --path <dir> instead.\n");
        CloseHandle(g_hProc);
        return 1;
    }

    auto mainSections = ReadSections(mainBase, dos, nt);
    printf("[+] Target: %s @ 0x%llX  Sections=%u  ImageSize=0x%X\n",
           mainName, (unsigned long long)mainBase,
           nt.FileHeader.NumberOfSections, nt.OptionalHeader.SizeOfImage);

    // Detect engine
    const KnownGame* knownGame = nullptr;
    for (auto& g : g_knownGames) {
        if (_stricmp(procName.c_str(), g.processName) == 0) { knownGame = &g; break; }
    }

    std::vector<uint8_t> headerDump;
    DetectedEngine engine;

    if (forceEngine != ENGINE_UNKNOWN) {
        engine.engine = forceEngine;
        for (auto& sig : g_engineSigs) {
            if (sig.engine == forceEngine) { engine.name = sig.name; break; }
        }
        engine.confidence = 100;
        engine.evidence.push_back("Forced via --engine flag");
        printf("[*] Engine forced: %s\n", engine.name);
    } else {
        printf("[*] Detecting game engine...\n");
        engine = DetectEngine(modules, mainSections, headerDump, nt);
        if (knownGame && engine.engine == ENGINE_UNKNOWN) {
            engine.engine = knownGame->engine;
            for (auto& sig : g_engineSigs) {
                if (sig.engine == knownGame->engine) { engine.name = sig.name; break; }
            }
            engine.confidence = 80;
            engine.evidence.push_back("Known game database match");
        }
    }

    printf("[+] Engine: %s (confidence: %d%%)\n", engine.name, min(engine.confidence, 100));
    for (auto& e : engine.evidence)
        printf("    - %s\n", e.c_str());

    if (knownGame)
        printf("[+] Game: %s | Anti-Cheat: %s\n", knownGame->gameName, knownGame->antiCheat);

    // Choose dump strategy
    DumpStrategy strat = ChooseStrategy(engine, knownGame, modules);
    printf("[*] Strategy: %s\n", strat.name);
    if (!strat.specificModules.empty()) {
        printf("[*] Key modules to dump:\n");
        for (auto& m : strat.specificModules)
            printf("    - %s\n", m.c_str());
    }

    // Execute dumps
    auto totalT0 = std::chrono::steady_clock::now();
    std::vector<std::string> dumpedFiles;

    // Main EXE dump
    if (strat.dumpMainExe && !mainOnly) {
        std::string mainOut = outDir + "\\" + std::string(mainName) + ".dump.bin";
        if (outDir == ".") mainOut = std::string(mainName) + ".dump.bin";
        if (DumpModuleLive(mainBase, mainName, mainOut.c_str()))
            dumpedFiles.push_back(mainOut);
    } else if (mainOnly) {
        std::string mainOut = std::string(mainName) + ".dump.bin";
        if (DumpModuleLive(mainBase, mainName, mainOut.c_str()))
            dumpedFiles.push_back(mainOut);
    }

    // Additional engine-specific modules
    if (!mainOnly) {
        for (auto& targetMod : strat.specificModules) {
            if (_stricmp(targetMod.c_str(), mainName) == 0) continue;
            for (auto& m : modules) {
                if (_stricmp(m.name, targetMod.c_str()) == 0) {
                    std::string modOut = std::string(m.name) + ".dump.bin";
                    if (DumpModuleLive(m.base, m.name, modOut.c_str()))
                        dumpedFiles.push_back(modOut);
                    break;
                }
            }
        }
    }

    // All modules dump
    if (allModules) {
        for (auto& m : modules) {
            bool already = false;
            for (auto& d : dumpedFiles) {
                if (d.find(m.name) != std::string::npos) { already = true; break; }
            }
            if (already) continue;
            std::string modOut = std::string(m.name) + ".dump.bin";
            if (DumpModuleLive(m.base, m.name, modOut.c_str()))
                dumpedFiles.push_back(modOut);
        }
    }

    auto totalT1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(totalT1 - totalT0).count();
    printf("\n[+] All dumps completed in %.1f seconds (%zu files)\n", elapsed, dumpedFiles.size());

    // Post-dump analysis
    std::vector<PatternResult> engineOffsets;
    std::vector<StringRef> stringRefs;

    if ((extractOffsets || scanStrings || generateReport || espHeader) && !dumpedFiles.empty()) {
        printf("\n[*] === Post-Dump Analysis ===\n");

        FILE* df = fopen(dumpedFiles[0].c_str(), "rb");
        if (df) {
            fseek(df, 0, SEEK_END);
            long fsize = ftell(df);
            fseek(df, 0, SEEK_SET);
            std::vector<uint8_t> image(fsize);
            fread(image.data(), 1, fsize, df);
            fclose(df);

            auto* gpt = FindGamePatterns(procName.c_str());
            if (gpt) {
                printf("\n[*] --- Game-Specific Patterns (%s) ---\n", gpt->gameName);
                auto gameOffsets = ScanGamePatterns(image, mainBase, mainSections, gpt);
                for (auto& o : gameOffsets) {
                    printf("    %-25s  RVA=0x%08llX", o.name.c_str(), (unsigned long long)o.rva);
                    if (o.resolvedAddr)
                        printf("  -> 0x%llX", (unsigned long long)o.resolvedAddr);
                    printf("\n");
                    engineOffsets.push_back(o);
                }
                if (gameOffsets.empty())
                    printf("    (no game-specific patterns matched — game may have updated)\n");
                else
                    printf("    (%zu game-specific patterns found)\n", gameOffsets.size());
            }

            if (extractOffsets) {
                printf("\n[*] --- Engine-Specific Offsets ---\n");
                engineOffsets = ScanEngineOffsets(image, mainBase, nt, mainSections, engine.engine);
                if (engineOffsets.empty()) {
                    printf("    (no engine-specific patterns found for %s)\n", engine.name);
                } else {
                    for (auto& o : engineOffsets) {
                        printf("    %-30s  RVA=0x%08llX", o.name.c_str(), (unsigned long long)o.rva);
                        if (o.resolvedAddr)
                            printf("  -> 0x%llX", (unsigned long long)o.resolvedAddr);
                        printf("\n");
                    }
                }

                printf("\n[*] --- Exports ---\n");
                auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (expDir.VirtualAddress && expDir.Size &&
                    expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) <= image.size()) {
                    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(image.data() + expDir.VirtualAddress);
                    uint32_t numNames = exp->NumberOfNames;
                    uint32_t nameRva  = exp->AddressOfNames;
                    uint32_t funcRva  = exp->AddressOfFunctions;
                    uint32_t ordRva   = exp->AddressOfNameOrdinals;
                    int printed = 0;
                    if (numNames > 0 && numNames < 100000 &&
                        nameRva + numNames * 4 <= image.size() &&
                        ordRva + numNames * 2 <= image.size()) {
                        auto* names = (uint32_t*)(image.data() + nameRva);
                        auto* ords  = (uint16_t*)(image.data() + ordRva);
                        auto* funcs = (uint32_t*)(image.data() + funcRva);
                        for (uint32_t i = 0; i < numNames && printed < 50; i++) {
                            if (names[i] < image.size()) {
                                const char* n = (const char*)(image.data() + names[i]);
                                uint16_t ord = ords[i];
                                if (ord < exp->NumberOfFunctions) {
                                    printf("    0x%08X  %s\n", funcs[ord], n);
                                    printed++;
                                }
                            }
                        }
                    }
                    printf("    (%u total exports, showing first %d)\n", numNames, printed);
                } else {
                    printf("    (no exports)\n");
                }

                printf("\n[*] --- Imports ---\n");
                auto& impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (impDir.VirtualAddress && impDir.Size && impDir.VirtualAddress < image.size()) {
                    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(image.data() + impDir.VirtualAddress);
                    int count = 0;
                    while (desc->Name && desc->Name < image.size() && count < 100) {
                        printf("    %s\n", (const char*)(image.data() + desc->Name));
                        desc++;
                        count++;
                    }
                    printf("    (%d imported DLLs)\n", count);
                }

                std::string ofsFile = dumpedFiles[0] + ".offsets.txt";
                FILE* of = fopen(ofsFile.c_str(), "w");
                if (of) {
                    fprintf(of, "// Game Dumper Offsets — %s (PID %u)\n", procName.c_str(), pid);
                    fprintf(of, "// Engine: %s | Strategy: %s\n\n", engine.name, strat.name);
                    if (!engineOffsets.empty()) {
                        fprintf(of, "// === Engine-Specific Offsets ===\n");
                        for (auto& o : engineOffsets)
                            fprintf(of, "0x%08llX  %s\n", (unsigned long long)o.rva, o.name.c_str());
                        fprintf(of, "\n");
                    }
                    fclose(of);
                    printf("[+] Offsets written: %s\n", ofsFile.c_str());
                }
            }

            if (scanStrings) {
                printf("\n[*] --- String References ---\n");
                stringRefs = ScanStringRefs(image, mainBase, mainSections, 50);
                for (auto& s : stringRefs)
                    printf("    RVA 0x%08llX -> \"%s\"\n",
                           (unsigned long long)s.codeRva, s.value.c_str());
                printf("    (%zu string references found)\n", stringRefs.size());
            }

            // Heuristic manager discovery
            if (strat.scanEngineOffsets && image.size() > 0x1000) {
                std::vector<std::string> mgrStrings;
                GameEngine eng = engine.engine;
                if (eng == ENGINE_CUSTOM) {
                    mgrStrings = {"GameManager","EntityManager","CameraManager",
                                  "PlayerManager","StatusManager","NetworkManager",
                                  "RoundManager","SpawnManager","MatchManager"};
                } else if (eng == ENGINE_UNREAL) {
                    mgrStrings = {"GWorld","UWorld","GEngine","GameInstance",
                                  "PlayerController","GameState","APlayerState",
                                  "ULocalPlayer","ACharacter","APawn"};
                } else if (eng == ENGINE_UNITY) {
                    mgrStrings = {"global-metadata","il2cpp_domain_get",
                                  "GameManager","PlayerManager","Camera",
                                  "BaseNetworkable","BuildingBlock"};
                }
                if (!mgrStrings.empty()) {
                    printf("\n[*] --- Heuristic Offset Discovery (%s) ---\n", engine.name);
                    auto managers = HeuristicManagerScan(image, mainBase, mainSections, mgrStrings);
                    if (!managers.empty()) {
                        std::string iniName = procName;
                        auto dot = iniName.rfind('.');
                        if (dot != std::string::npos) iniName = iniName.substr(0, dot);
                        iniName += "_offsets.ini";
                        WriteDiscoveredINI(iniName.c_str(), managers, engineOffsets,
                                           mainBase, procName.c_str());
                        dumpedFiles.push_back(iniName);
                    } else {
                        printf("    (no manager candidates found)\n");
                    }
                }
            }
        }
    }

    // Report
    if (generateReport) {
        std::string reportFile = procName + ".report.txt";
        WriteReport(reportFile.c_str(), procName.c_str(), pid, engine, knownGame,
                    strat, modules, engineOffsets, stringRefs, mainBase);
    }

    // ESP Header
    if (espHeader && !engineOffsets.empty()) {
        std::string hdrFile = procName + "_offsets.h";
        FILE* hf = fopen(hdrFile.c_str(), "w");
        if (hf) {
            fprintf(hf, "#pragma once\n");
            fprintf(hf, "// Auto-generated offset header for %s\n", procName.c_str());
            fprintf(hf, "// Engine: %s | Anti-Cheat: %s\n",
                    engine.name, knownGame ? knownGame->antiCheat : "Unknown");
            fprintf(hf, "// Base: 0x%llX\n\n", (unsigned long long)mainBase);
            fprintf(hf, "#include <cstdint>\n\n");
            fprintf(hf, "namespace offsets {\n\n");

            fprintf(hf, "constexpr uint64_t IMAGE_BASE = 0x%llXULL;\n\n", (unsigned long long)mainBase);

            for (auto& o : engineOffsets) {
                std::string safeName = o.name;
                for (auto& c : safeName) {
                    if (c == ' ' || c == '-' || c == ':') c = '_';
                    if (c == '(' || c == ')') c = '_';
                }
                fprintf(hf, "constexpr uint64_t %s = 0x%llXULL;\n",
                        safeName.c_str(), (unsigned long long)o.rva);
            }

            fprintf(hf, "\n} // namespace offsets\n\n");

            fprintf(hf, "namespace mem {\n\n");
            fprintf(hf, "template<typename T>\n");
            fprintf(hf, "inline T Read(HANDLE hProc, uint64_t addr) {\n");
            fprintf(hf, "    T val{};\n");
            fprintf(hf, "    ReadProcessMemory(hProc, (LPCVOID)addr, &val, sizeof(T), nullptr);\n");
            fprintf(hf, "    return val;\n");
            fprintf(hf, "}\n\n");
            fprintf(hf, "} // namespace mem\n\n");

            fprintf(hf, "namespace esp {\n\n");
            fprintf(hf, "struct Vec3 { float x, y, z; };\n");
            fprintf(hf, "struct Vec2 { float x, y; };\n\n");
            fprintf(hf, "struct ViewMatrix {\n");
            fprintf(hf, "    float m[4][4];\n");
            fprintf(hf, "    bool WorldToScreen(const Vec3& world, Vec2& screen, float w, float h) const {\n");
            fprintf(hf, "        float clipX = m[0][0]*world.x + m[0][1]*world.y + m[0][2]*world.z + m[0][3];\n");
            fprintf(hf, "        float clipY = m[1][0]*world.x + m[1][1]*world.y + m[1][2]*world.z + m[1][3];\n");
            fprintf(hf, "        float clipW = m[3][0]*world.x + m[3][1]*world.y + m[3][2]*world.z + m[3][3];\n");
            fprintf(hf, "        if (clipW < 0.001f) return false;\n");
            fprintf(hf, "        float ndcX = clipX / clipW;\n");
            fprintf(hf, "        float ndcY = clipY / clipW;\n");
            fprintf(hf, "        screen.x = (w * 0.5f) * (1.0f + ndcX);\n");
            fprintf(hf, "        screen.y = (h * 0.5f) * (1.0f - ndcY);\n");
            fprintf(hf, "        return true;\n");
            fprintf(hf, "    }\n");
            fprintf(hf, "};\n\n");
            fprintf(hf, "} // namespace esp\n");
            fclose(hf);
            printf("[+] ESP header written: %s\n", hdrFile.c_str());
        }
    }

    printf("\n[+] Done. Files generated:\n");
    for (auto& f : dumpedFiles)
        printf("    - %s\n", f.c_str());
    if (generateReport)
        printf("    - %s.report.txt\n", procName.c_str());
    if (espHeader && !engineOffsets.empty())
        printf("    - %s_offsets.h\n", procName.c_str());

    CloseHandle(g_hProc);
    return 0;
}
