// Rust DMA Radar — reads player positions via FPGA DMA card using MemProcFS
// Engine: Unity (IL2CPP) — walks BaseNetworkable.clientEntities for entity list
// Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.
// Auto-fetches latest offsets from GitHub on startup.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS)
// Build: cl /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS rust_dma.cpp gdi32.lib user32.lib ws2_32.lib wininet.lib /link /SUBSYSTEM:WINDOWS
//
// Usage: rust_dma.exe
//        rust_dma.exe --port 9000
//        rust_dma.exe --offsets rust_offsets.ini
//
// Compatible with esp_client.exe (same /api/gamedata + /api/config format)

#undef UNICODE
#undef _UNICODE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <sstream>
#include <wininet.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")


// =============================================================================
// VMM API
// =============================================================================

typedef void* VMM_HANDLE;
typedef VMM_HANDLE  (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID        (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL        (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL        (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64     (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef HANDLE      (__cdecl *fn_ScatInit)(VMM_HANDLE hVMM, DWORD dwPID, DWORD flags);
typedef BOOL        (__cdecl *fn_ScatPrep)(HANDLE hS, ULONG64 va, DWORD cb);
typedef BOOL        (__cdecl *fn_ScatExec)(HANDLE hS);
typedef BOOL        (__cdecl *fn_ScatRead)(HANDLE hS, ULONG64 va, DWORD cb, PBYTE pb, PDWORD pcbRead);
typedef VOID        (__cdecl *fn_ScatClose)(HANDLE hS);

static VMM_HANDLE g_vmm = nullptr;
static DWORD      g_pid = 0;

static fn_Init      pInit = nullptr;
static fn_Close     pClose = nullptr;
static fn_PidGet    pPidGet = nullptr;
static fn_MemRead   pMemRead = nullptr;
static fn_ModBase   pModBase = nullptr;
static fn_ScatInit  pScatInit = nullptr;
static fn_ScatPrep  pScatPrep = nullptr;
static fn_ScatExec  pScatExec = nullptr;
static fn_ScatRead  pScatRead = nullptr;
static fn_ScatClose pScatClose = nullptr;

static bool LoadVMM() {
    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) {
        MessageBoxA(NULL, "vmm.dll not found.\nPlace vmm.dll + leechcore.dll here.", "DMA Error", MB_ICONERROR);
        return false;
    }
    pInit     = (fn_Init)    GetProcAddress(h, "VMMDLL_Initialize");
    pClose    = (fn_Close)   GetProcAddress(h, "VMMDLL_Close");
    pPidGet   = (fn_PidGet)  GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead  = (fn_MemRead) GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase  = (fn_ModBase) GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");
    pScatInit = (fn_ScatInit)GetProcAddress(h, "VMMDLL_Scatter_Initialize");
    pScatPrep = (fn_ScatPrep)GetProcAddress(h, "VMMDLL_Scatter_Prepare");
    pScatExec = (fn_ScatExec)GetProcAddress(h, "VMMDLL_Scatter_Execute");
    pScatRead = (fn_ScatRead)GetProcAddress(h, "VMMDLL_Scatter_Read");
    pScatClose= (fn_ScatClose)GetProcAddress(h,"VMMDLL_Scatter_CloseHandle");
    return pInit && pMemRead;
}

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cbRead = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cbRead, 0x0002) && cbRead > 0;
}

template<class T> T rpm(uint64_t addr) { T v{}; DmaRead(addr, &v, sizeof(T)); return v; }

static std::string ReadString(uint64_t ptr, int maxLen = 128) {
    if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) return "";
    char buf[256]{};
    int len = (maxLen < 255) ? maxLen : 255;
    DmaRead(ptr, buf, len);
    buf[len] = 0;
    for (int i = 0; buf[i]; i++)
        if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) { buf[i] = 0; break; }
    return std::string(buf);
}

// IL2CPP string: +0x10 = length (int32), +0x14 = wchar_t[] data
static std::string ReadIl2CppString(uint64_t strPtr) {
    if (strPtr < 0x10000 || strPtr > 0x7FFFFFFFFFFF) return "";
    int32_t len = rpm<int32_t>(strPtr + 0x10);
    if (len <= 0 || len > 128) return "";
    wchar_t wbuf[130]{};
    DmaRead(strPtr + 0x14, wbuf, len * 2);
    char out[130]{};
    WideCharToMultiByte(CP_ACP, 0, wbuf, len, out, 129, NULL, NULL);
    return std::string(out);
}


// =============================================================================
// Config — feature toggles from web menu
// =============================================================================

namespace Config {
    inline std::atomic<bool> radar{true};
    inline std::atomic<bool> espBox{false};
    inline std::atomic<bool> espName{true};
    inline std::atomic<bool> espHealth{true};
    inline std::atomic<bool> espDistance{true};
    inline std::atomic<bool> espSnaplines{false};
    inline std::atomic<bool> filterSleepers{true};
    inline std::atomic<bool> filterNPC{false};
    inline std::atomic<bool> showAnimals{false};
    inline std::atomic<bool> showStash{false};
    inline std::atomic<bool> showTC{true};

    inline std::atomic<float> maxRange{400.0f};
}


// =============================================================================
// Offset config — loaded from INI, auto-updated from GitHub
// =============================================================================

static std::unordered_map<std::string, std::string> g_strConfig;
static std::unordered_map<std::string, uint64_t>    g_offsets;

static void LoadConfig(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) { printf("[!] Could not open config: %s\n", path); return; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        val.erase(val.find_last_not_of(" \t\r\n") + 1);
        val.erase(0, val.find_first_not_of(" \t\r\n"));
        if (key.empty()) continue;
        g_strConfig[key] = val;
        if (val.size() > 2 && val[0] == '0' && (val[1] == 'x' || val[1] == 'X'))
            g_offsets[key] = strtoull(val.c_str(), nullptr, 16);
        else if (!val.empty() && (isdigit(val[0]) || val[0] == '-'))
            g_offsets[key] = strtoull(val.c_str(), nullptr, 0);
    }
    printf("[+] Loaded config: %s (%zu offsets)\n", path, g_offsets.size());
}

static std::string Str(const char* key, const char* fallback = "") {
    auto it = g_strConfig.find(key);
    return (it != g_strConfig.end()) ? it->second : fallback;
}

static uint64_t Off(const char* key, uint64_t fallback = 0) {
    auto it = g_offsets.find(key);
    return (it != g_offsets.end()) ? it->second : fallback;
}


// =============================================================================
// GitHub auto-updater
// =============================================================================

static const char* GITHUB_RAW_BASE =
    "https://raw.githubusercontent.com/scoped11/masterlist/master/cheat/dma/";

static std::string HttpGet(const char* url) {
    HINTERNET hInet = InternetOpenA("RustDMA/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) return "";
    HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) { InternetCloseHandle(hInet); return ""; }
    std::string result;
    char buf[8192];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &bytesRead) && bytesRead > 0)
        result.append(buf, bytesRead);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);
    return result;
}

static std::string ReadFileStr(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static bool WriteFileStr(const char* path, const std::string& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(data.data(), data.size());
    return f.good();
}

static bool TryAutoUpdate(const std::string& localPath) {
    std::string url = std::string(GITHUB_RAW_BASE) + "rust_offsets.ini";
    printf("[*] Checking GitHub for offset updates...\n");

    std::string remote = HttpGet(url.c_str());
    if (remote.empty() || remote.size() < 20) {
        printf("[!] No remote offsets found (offline or not published yet)\n");
        return false;
    }
    if (remote[0] != '#' && remote[0] != ';' && remote[0] != '[') {
        printf("[!] Remote response doesn't look like an INI file\n");
        return false;
    }

    std::string local = ReadFileStr(localPath.c_str());
    std::string remoteNorm = remote, localNorm = local;
    remoteNorm.erase(std::remove(remoteNorm.begin(), remoteNorm.end(), '\r'), remoteNorm.end());
    localNorm.erase(std::remove(localNorm.begin(), localNorm.end(), '\r'), localNorm.end());

    if (remoteNorm == localNorm) {
        printf("[+] Offsets are up to date\n");
        return false;
    }

    if (WriteFileStr(localPath.c_str(), remote)) {
        printf("[+] UPDATED offsets from GitHub -> %s\n", localPath.c_str());
        return true;
    }
    printf("[!] Failed to write updated offsets\n");
    return false;
}


// =============================================================================
// Rust-specific offsets — loaded from INI
// =============================================================================

namespace O {
    // Static pointers (GameAssembly.dll + offset → pointer)
    uint64_t ClientEntities;     // BaseNetworkable.clientEntities
    uint64_t LocalPlayerEnt;     // LocalPlayer.Entity
    uint64_t MainCamera;         // Camera._main (UnityPlayer.dll)

    // EntityRealm → ListDictionary chain
    uint64_t ER_EntityList;      // EntityRealm.entityList
    uint64_t LD_Vals;            // ListDictionary.vals (BufferList)
    uint64_t LD_Count;           // ListDictionary.count
    uint64_t BL_Buffer;          // BufferList.buffer (array ptr)
    uint64_t BL_Size;            // BufferList.size

    // Il2CppObject class identification
    uint64_t Obj_Klass;          // Il2CppObject.klass (+0x00)
    uint64_t Klass_Name;         // Il2CppClass.name (+0x10)
    uint64_t Klass_Namespace;    // Il2CppClass.namespaze (+0x18)
    uint64_t Klass_Parent;       // Il2CppClass.parent (+0x30)

    // BaseNetworkable
    uint64_t BN_PrefabID;
    uint64_t BN_Net;

    // BaseEntity
    uint64_t BE_Model;           // BaseEntity.model (PlayerModel)
    uint64_t BE_Flags;           // BaseEntity.flags
    uint64_t BE_Transform;       // Cached transform pointer

    // BaseCombatEntity
    uint64_t BCE_Health;         // _health (float)
    uint64_t BCE_MaxHealth;      // _maxHealth (float)

    // BasePlayer
    uint64_t BP_DisplayName;     // _displayName (Il2CppString*)
    uint64_t BP_PlayerFlags;     // playerFlags (int)
    uint64_t BP_PlayerModel;     // playerModel
    uint64_t BP_Eyes;            // eyes (PlayerEyes)
    uint64_t BP_Inventory;       // inventory
    uint64_t BP_UserID;          // userID (ulong)
    uint64_t BP_Team;            // currentTeam (ulong)
    uint64_t BP_ModelState;      // modelState
    uint64_t BP_Metabolism;      // metabolism
    uint64_t BP_ActiveItem;      // clActiveItem (uint)
    uint64_t BP_Movement;        // movement (BaseMovement)
    uint64_t BP_Input;           // input (InputState)
    uint64_t BP_MountEntity;     // mounted (BaseMountable)
    uint64_t BP_SteamID;         // SteamID or userID for friend check
    uint64_t BP_ClientTeam;      // clientTeam

    // PlayerModel
    uint64_t PM_Position;        // newPosition or position (Vec3)
    uint64_t PM_Rotation;        // rotation (Quaternion)

    // ModelState
    uint64_t MS_Flags;           // flags (int — ducked, sprinting, etc.)
    uint64_t MS_Position;        // position (Vec3 — client-predicted)

    // PlayerEyes
    uint64_t PE_BodyRotation;    // bodyRotation (Quaternion)
    uint64_t PE_ViewOffset;      // viewOffset (Vec3)
    uint64_t PE_HeadAngles;      // head angles or bodyLeanOffset

    // PlayerMetabolism
    uint64_t PM_Health;
    uint64_t PM_Hydration;
    uint64_t PM_Calories;
    uint64_t PM_Comfort;
    uint64_t PM_Radiation;
    uint64_t PM_Bleeding;

    // Camera (UnityPlayer.dll)
    uint64_t Cam_ViewMatrix;
    uint64_t Cam_FOV;

    void Init() {
        ClientEntities     = Off("ClientEntities");
        LocalPlayerEnt     = Off("LocalPlayer");
        MainCamera         = Off("MainCamera");

        ER_EntityList      = Off("ER_EntityList",    0x28);
        LD_Vals            = Off("LD_Vals",          0x20);
        LD_Count           = Off("LD_Count",         0x18);
        BL_Buffer          = Off("BL_Buffer",        0x10);
        BL_Size            = Off("BL_Size",          0x18);

        Obj_Klass          = Off("Obj_Klass",        0x00);
        Klass_Name         = Off("Klass_Name",       0x10);
        Klass_Namespace    = Off("Klass_Namespace",  0x18);
        Klass_Parent       = Off("Klass_Parent",     0x30);

        BN_PrefabID        = Off("BN_PrefabID",      0x18);
        BN_Net             = Off("BN_Net",           0x58);

        BE_Model           = Off("BE_Model");
        BE_Flags           = Off("BE_Flags");
        BE_Transform       = Off("BE_Transform",    0x10);

        BCE_Health         = Off("BCE_Health");
        BCE_MaxHealth      = Off("BCE_MaxHealth");

        BP_DisplayName     = Off("BP_DisplayName");
        BP_PlayerFlags     = Off("BP_PlayerFlags");
        BP_PlayerModel     = Off("BP_PlayerModel");
        BP_Eyes            = Off("BP_Eyes");
        BP_Inventory       = Off("BP_Inventory");
        BP_UserID          = Off("BP_UserID");
        BP_Team            = Off("BP_Team");
        BP_ModelState      = Off("BP_ModelState");
        BP_Metabolism      = Off("BP_Metabolism");
        BP_ActiveItem      = Off("BP_ActiveItem");
        BP_Movement        = Off("BP_Movement");
        BP_Input           = Off("BP_Input");
        BP_MountEntity     = Off("BP_MountEntity");
        BP_SteamID         = Off("BP_SteamID");
        BP_ClientTeam      = Off("BP_ClientTeam");

        PM_Position        = Off("PM_Position");
        PM_Rotation        = Off("PM_Rotation");

        MS_Flags           = Off("MS_Flags");
        MS_Position        = Off("MS_Position");

        PE_BodyRotation    = Off("PE_BodyRotation");
        PE_ViewOffset      = Off("PE_ViewOffset");
        PE_HeadAngles      = Off("PE_HeadAngles");

        PM_Health          = Off("PM_Health");
        PM_Hydration       = Off("PM_Hydration");
        PM_Calories        = Off("PM_Calories");
        PM_Comfort         = Off("PM_Comfort");
        PM_Radiation       = Off("PM_Radiation");
        PM_Bleeding        = Off("PM_Bleeding");

        Cam_ViewMatrix     = Off("Cam_ViewMatrix");
        Cam_FOV            = Off("Cam_FOV");
    }
}


// =============================================================================
// Math
// =============================================================================

struct Vec3 { float x, y, z; };
struct Vec4 { float x, y, z, w; };

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif
#define DEG2RAD(x) ((x) * (float)M_PI / 180.0f)
#define RAD2DEG(x) ((x) * 180.0f / (float)M_PI)

static float Vec3Dist(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

static float Vec2Len(float x, float y) { return sqrtf(x*x + y*y); }

static float QuatToYaw(Vec4 q) {
    float siny = 2.0f * (q.w * q.y - q.z * q.x);
    float cosy = 1.0f - 2.0f * (q.x * q.x + q.y * q.y);
    return RAD2DEG(atan2f(siny, cosy));
}


// =============================================================================
// Entity data
// =============================================================================

struct PlayerData {
    Vec3     position;
    Vec3     headPos;
    float    health, maxHealth;
    float    distance;
    uint64_t teamID;
    char     name[64];
    bool     valid;
    bool     isSleeper;
    bool     isNPC;
    bool     isWounded;
};

static Vec3         g_localPos = {};
static float        g_localYaw = 0;
static float        g_cameraFOV = 90.0f;
static uint64_t     g_localPlayerPtr = 0;
static uint64_t     g_localTeamID = 0;

static PlayerData   g_players[128];
static int          g_playerCount = 0;
static PlayerData   g_allPlayers[200];
static int          g_allPlayerCount = 0;
static std::mutex   g_dataMutex;

static uint64_t     g_gaBase = 0;
static uint64_t     g_unityBase = 0;


// =============================================================================
// IL2CPP class identification
// =============================================================================

// Cache class name lookups to avoid redundant DMA reads
static std::unordered_map<uint64_t, std::string> g_classNameCache;

static std::string GetClassName(uint64_t objPtr) {
    uint64_t klass = rpm<uint64_t>(objPtr + O::Obj_Klass);
    if (klass < 0x10000) return "";

    auto it = g_classNameCache.find(klass);
    if (it != g_classNameCache.end()) return it->second;

    uint64_t namePtr = rpm<uint64_t>(klass + O::Klass_Name);
    std::string name = ReadString(namePtr);
    if (name.size() > 1 && name.size() < 128)
        g_classNameCache[klass] = name;
    return name;
}

static bool InheritsFrom(uint64_t objPtr, const char* parentName) {
    uint64_t klass = rpm<uint64_t>(objPtr + O::Obj_Klass);
    for (int depth = 0; depth < 10 && klass > 0x10000; depth++) {
        uint64_t namePtr = rpm<uint64_t>(klass + O::Klass_Name);
        std::string name = ReadString(namePtr);
        if (name == parentName) return true;
        klass = rpm<uint64_t>(klass + O::Klass_Parent);
    }
    return false;
}


// =============================================================================
// Rust entity reading — walks clientEntities via IL2CPP runtime structures
// =============================================================================

static Vec3 ReadPlayerPosition(uint64_t player) {
    // Try ModelState.position first (client-predicted, most reliable for DMA)
    if (O::BP_ModelState && O::MS_Position) {
        uint64_t ms = rpm<uint64_t>(player + O::BP_ModelState);
        if (ms > 0x10000) {
            Vec3 pos = rpm<Vec3>(ms + O::MS_Position);
            if (pos.x != 0 || pos.y != 0 || pos.z != 0) return pos;
        }
    }

    // Fallback: PlayerModel.newPosition
    if (O::BP_PlayerModel && O::PM_Position) {
        uint64_t pm = rpm<uint64_t>(player + O::BP_PlayerModel);
        if (pm > 0x10000) {
            Vec3 pos = rpm<Vec3>(pm + O::PM_Position);
            if (pos.x != 0 || pos.y != 0 || pos.z != 0) return pos;
        }
    }

    // Fallback: BaseEntity.model.position
    if (O::BE_Model && O::PM_Position) {
        uint64_t model = rpm<uint64_t>(player + O::BE_Model);
        if (model > 0x10000) {
            Vec3 pos = rpm<Vec3>(model + O::PM_Position);
            if (pos.x != 0 || pos.y != 0 || pos.z != 0) return pos;
        }
    }

    return {};
}

static float ReadLocalYaw(uint64_t player) {
    if (!O::BP_Eyes || !O::PE_BodyRotation) return 0;
    uint64_t eyes = rpm<uint64_t>(player + O::BP_Eyes);
    if (eyes < 0x10000) return 0;
    Vec4 rot = rpm<Vec4>(eyes + O::PE_BodyRotation);
    return QuatToYaw(rot);
}

static void ReadPlayers() {
    if (!g_gaBase || !O::ClientEntities) return;

    // Read clientEntities static field
    uint64_t clientEntities = rpm<uint64_t>(g_gaBase + O::ClientEntities);
    if (clientEntities < 0x10000) return;

    // EntityRealm → entityList
    uint64_t entityList = rpm<uint64_t>(clientEntities + O::ER_EntityList);
    if (entityList < 0x10000) return;

    // ListDictionary → vals (BufferList) + count
    uint64_t vals = rpm<uint64_t>(entityList + O::LD_Vals);
    if (vals < 0x10000) return;

    int32_t entityCount = rpm<int32_t>(entityList + O::LD_Count);
    if (entityCount <= 0 || entityCount > 20000) return;

    // BufferList → buffer (array of BaseNetworkable*)
    uint64_t buffer = rpm<uint64_t>(vals + O::BL_Buffer);
    if (buffer < 0x10000) return;
    int32_t bufSize = rpm<int32_t>(vals + O::BL_Size);
    if (bufSize <= 0) bufSize = entityCount + 100;
    if (bufSize > 20000) bufSize = 20000;

    // Find local player
    uint64_t localPlayer = 0;
    if (O::LocalPlayerEnt) {
        localPlayer = rpm<uint64_t>(g_gaBase + O::LocalPlayerEnt);
        if (localPlayer > 0x10000) {
            g_localPlayerPtr = localPlayer;
            g_localPos = ReadPlayerPosition(localPlayer);
            g_localYaw = ReadLocalYaw(localPlayer);

            if (O::BP_Team)
                g_localTeamID = rpm<uint64_t>(localPlayer + O::BP_Team);
            else if (O::BP_ClientTeam)
                g_localTeamID = rpm<uint64_t>(localPlayer + O::BP_ClientTeam);
        }
    }

    int count = 0, allCount = 0;

    // Read entity pointers in chunks (batch DMA reads)
    const int CHUNK = 256;
    // Array starts at +0x20 (array header in IL2CPP managed array)
    uint64_t arrayBase = buffer + 0x20;

    for (int base = 0; base < bufSize && count < 128; base += CHUNK) {
        int batch = (bufSize - base < CHUNK) ? (bufSize - base) : CHUNK;
        uint64_t ptrs[256] = {};
        DmaRead(arrayBase + (uint64_t)base * 8, ptrs, batch * 8);

        for (int i = 0; i < batch && count < 128; i++) {
            uint64_t entity = ptrs[i];
            if (!entity || entity < 0x10000 || entity == localPlayer) continue;

            std::string className = GetClassName(entity);
            if (className.empty()) continue;

            bool isPlayer = (className == "BasePlayer");
            if (!isPlayer) {
                // Check inheritance for derived player classes (NPCPlayer, etc.)
                if (className == "NPCPlayer" || className == "NPCPlayerApex" ||
                    className == "Scientist" || className == "ScientistNPC" ||
                    className == "HTNPlayer" || className == "NPCMurderer" ||
                    className == "HumanNPC" || className == "TunnelDweller" ||
                    className == "UnderwaterDweller" || className == "CustomScientistNpc")
                    isPlayer = true;
            }

            if (!isPlayer) continue;

            Vec3 pos = ReadPlayerPosition(entity);
            if (pos.x == 0 && pos.y == 0 && pos.z == 0) continue;

            float dist = Vec3Dist(g_localPos, pos);
            if (dist > Config::maxRange.load() || dist < 0.5f) continue;

            float hp = 0, maxHp = 100;
            if (O::BCE_Health) hp = rpm<float>(entity + O::BCE_Health);
            if (O::BCE_MaxHealth) maxHp = rpm<float>(entity + O::BCE_MaxHealth);
            if (maxHp <= 0) maxHp = 100;

            // Player flags for sleeper/wounded detection
            int playerFlags = 0;
            if (O::BP_PlayerFlags) playerFlags = rpm<int>(entity + O::BP_PlayerFlags);
            bool isSleeper = (playerFlags & 4) != 0;      // PlayerFlag.Sleeping
            bool isWounded = (playerFlags & 64) != 0;      // PlayerFlag.Wounded

            // Filter sleepers if configured
            if (isSleeper && Config::filterSleepers.load()) continue;
            if (hp <= 0 && !isSleeper) continue;

            // NPC check
            bool isNPC = (className != "BasePlayer");
            if (isNPC && Config::filterNPC.load()) continue;

            // Team
            uint64_t teamID = 0;
            if (O::BP_Team) teamID = rpm<uint64_t>(entity + O::BP_Team);
            else if (O::BP_ClientTeam) teamID = rpm<uint64_t>(entity + O::BP_ClientTeam);

            // Name
            std::string displayName;
            if (O::BP_DisplayName) {
                uint64_t nameStr = rpm<uint64_t>(entity + O::BP_DisplayName);
                displayName = ReadIl2CppString(nameStr);
            }
            if (displayName.empty()) displayName = isNPC ? "NPC" : "Player";

            PlayerData pd = {};
            pd.position = pos;
            pd.headPos = { pos.x, pos.y + 1.6f, pos.z };
            pd.health = hp;
            pd.maxHealth = maxHp;
            pd.distance = dist;
            pd.teamID = teamID;
            pd.isSleeper = isSleeper;
            pd.isNPC = isNPC;
            pd.isWounded = isWounded;
            pd.valid = true;
            strncpy_s(pd.name, displayName.c_str(), 63);

            if (allCount < 200) g_allPlayers[allCount++] = pd;

            // Skip same-team players for enemy list
            if (teamID != 0 && teamID == g_localTeamID) continue;

            g_players[count++] = pd;
        }
    }

    // Add local player to allPlayers
    if (allCount < 200 && localPlayer > 0x10000) {
        PlayerData& lp = g_allPlayers[allCount];
        lp.position = g_localPos;
        lp.headPos = { g_localPos.x, g_localPos.y + 1.6f, g_localPos.z };
        lp.health = O::BCE_Health ? rpm<float>(localPlayer + O::BCE_Health) : 100;
        lp.maxHealth = 100;
        lp.distance = 0;
        lp.teamID = g_localTeamID;
        strcpy_s(lp.name, "You");
        lp.valid = true;
        allCount++;
    }

    g_playerCount = count;
    g_allPlayerCount = allCount;
}


// =============================================================================
// Radar overlay (GDI window on PC2)
// =============================================================================

namespace Radar {
    static HWND hwnd = NULL;
    static std::atomic<bool> running{true};
    static HFONT fontMain = NULL, fontSmall = NULL, fontTitle = NULL;
    static int radarSize = 500;
    static float radarRange = 200.0f;

    static void DrawFilled(HDC hdc, int x, int y, int w, int h, COLORREF c) {
        HBRUSH br = CreateSolidBrush(c);
        RECT r = {x, y, x+w, y+h};
        FillRect(hdc, &r, br); DeleteObject(br);
    }

    static void DrawCircle(HDC hdc, int cx, int cy, int r, COLORREF c, int t = 1) {
        HPEN pen = CreatePen(PS_SOLID, t, c);
        HPEN op = (HPEN)SelectObject(hdc, pen);
        HBRUSH ob = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Ellipse(hdc, cx-r, cy-r, cx+r, cy+r);
        SelectObject(hdc, ob); SelectObject(hdc, op); DeleteObject(pen);
    }

    static void DrawDot(HDC hdc, int cx, int cy, int r, COLORREF c) {
        HBRUSH br = CreateSolidBrush(c);
        HPEN pen = CreatePen(PS_SOLID, 1, c);
        HBRUSH ob = (HBRUSH)SelectObject(hdc, br);
        HPEN op = (HPEN)SelectObject(hdc, pen);
        Ellipse(hdc, cx-r, cy-r, cx+r, cy+r);
        SelectObject(hdc, ob); SelectObject(hdc, op);
        DeleteObject(br); DeleteObject(pen);
    }

    static void DrawLine(HDC hdc, int x1, int y1, int x2, int y2, COLORREF c, int t = 1) {
        HPEN pen = CreatePen(PS_SOLID, t, c);
        HPEN op = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, x1, y1, NULL); LineTo(hdc, x2, y2);
        SelectObject(hdc, op); DeleteObject(pen);
    }

    static void DrawText_(HDC hdc, int x, int y, const char* txt, COLORREF c, HFONT f = NULL) {
        if (f) SelectObject(hdc, f);
        SetTextColor(hdc, c); SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, x, y, txt, (int)strlen(txt));
    }

    static void DrawHealthBar(HDC hdc, int x, int y, int w, int h, float hp) {
        DrawFilled(hdc, x, y, w, h, RGB(40,40,40));
        int fillW = (int)((w-2) * hp);
        if (fillW < 0) fillW = 0;
        int r = (int)(255 * (1-hp)), g = (int)(255 * hp);
        DrawFilled(hdc, x+1, y+1, fillW, h-2, RGB(r,g,0));
    }

    static void WorldToRadar(Vec3 wp, int cx, int cy, int radius, int& ox, int& oy) {
        // Rust uses Y-up, XZ horizontal. Radar: X = right, Z = forward (north)
        float dx = wp.x - g_localPos.x;
        float dz = wp.z - g_localPos.z;
        float a = -DEG2RAD(g_localYaw);
        float rx = dx * cosf(a) - dz * sinf(a);
        float ry = dx * sinf(a) + dz * cosf(a);
        float scale = (float)radius / radarRange;
        ox = cx + (int)(rx * scale);
        oy = cy - (int)(ry * scale);
        float d = Vec2Len((float)(ox - cx), (float)(oy - cy));
        if (d > radius - 4) {
            float ang = atan2f((float)(ox - cx), (float)(cy - oy));
            ox = cx + (int)(sinf(ang) * (radius - 4));
            oy = cy - (int)(cosf(ang) * (radius - 4));
        }
    }

    static void RenderRadar(HDC hdc) {
        int ww = radarSize + 260, wh = radarSize + 60;
        DrawFilled(hdc, 0, 0, ww, wh, RGB(12, 12, 18));

        int cx = 30 + radarSize/2, cy = 30 + radarSize/2, radius = radarSize/2;

        DrawDot(hdc, cx, cy, radius, RGB(20, 25, 20));
        DrawCircle(hdc, cx, cy, radius, RGB(40, 50, 40));
        DrawCircle(hdc, cx, cy, radius*3/4, RGB(30, 40, 30));
        DrawCircle(hdc, cx, cy, radius/2, RGB(30, 40, 30));
        DrawCircle(hdc, cx, cy, radius/4, RGB(30, 40, 30));
        DrawLine(hdc, cx-radius, cy, cx+radius, cy, RGB(35, 45, 35));
        DrawLine(hdc, cx, cy-radius, cx, cy+radius, RGB(35, 45, 35));

        // Compass
        float yawRad = DEG2RAD(g_localYaw);
        const char* dirs[] = {"N","E","S","W"};
        float angles[] = {0,90,180,270};
        for (int i = 0; i < 4; i++) {
            float a = DEG2RAD(angles[i]) - yawRad;
            int lx = cx + (int)(sinf(a)*(radius+12));
            int ly = cy - (int)(cosf(a)*(radius+12));
            DrawText_(hdc, lx-4, ly-6, dirs[i], RGB(100,120,100), fontSmall);
        }

        char rangeBuf[32];
        snprintf(rangeBuf, sizeof(rangeBuf), "%.0fm", radarRange);
        DrawText_(hdc, cx+radius-30, cy+4, rangeBuf, RGB(60,80,60), fontSmall);

        DrawDot(hdc, cx, cy, 5, RGB(0, 200, 255));
        DrawLine(hdc, cx, cy, cx, cy-18, RGB(0, 200, 255), 2);

        std::lock_guard<std::mutex> lock(g_dataMutex);

        for (int i = 0; i < g_playerCount; i++) {
            auto& p = g_players[i];
            if (!p.valid) continue;

            int px, py;
            WorldToRadar(p.position, cx, cy, radius, px, py);

            COLORREF dotCol;
            if (p.isNPC)         dotCol = RGB(200, 150, 50);
            else if (p.isSleeper) dotCol = RGB(100, 100, 100);
            else if (p.isWounded) dotCol = RGB(255, 200, 0);
            else                  dotCol = RGB(255, 50, 50);

            int dotSz = (p.distance < 50.f) ? 6 : (p.distance < 150.f) ? 5 : 4;
            DrawDot(hdc, px, py, dotSz, dotCol);

            char distTxt[16];
            snprintf(distTxt, sizeof(distTxt), "%.0f", p.distance);
            DrawText_(hdc, px+dotSz+2, py-5, distTxt, RGB(180,180,180), fontSmall);
        }

        // Info panel
        int panelX = radarSize + 50, panelY = 20;
        DrawText_(hdc, panelX, panelY, "RUST DMA", RGB(205, 85, 50), fontTitle);
        panelY += 24;

        char status[128];
        snprintf(status, sizeof(status), "Enemies: %d  Range: %.0fm", g_playerCount, radarRange);
        DrawText_(hdc, panelX, panelY, status, RGB(180,180,180), fontMain);
        panelY += 20;
        DrawLine(hdc, panelX, panelY, panelX+210, panelY, RGB(50,50,50));
        panelY += 8;

        for (int i = 0; i < g_playerCount && i < 16; i++) {
            auto& p = g_players[i];
            if (!p.valid) continue;

            COLORREF nameCol;
            if (p.isNPC)         nameCol = RGB(200, 170, 80);
            else if (p.isSleeper) nameCol = RGB(120, 120, 120);
            else if (p.isWounded) nameCol = RGB(255, 200, 80);
            else                  nameCol = RGB(255, 120, 120);

            char line[256];
            const char* tag = p.isSleeper ? " [ZZZ]" : p.isWounded ? " [WOUNDED]" : p.isNPC ? " [NPC]" : "";
            snprintf(line, sizeof(line), "%s  %.0fm%s", p.name, p.distance, tag);
            DrawText_(hdc, panelX, panelY, line, nameCol, fontSmall);
            panelY += 14;
            float hp = (p.maxHealth > 0) ? p.health / p.maxHealth : 1.0f;
            if (hp > 1) hp = 1; if (hp < 0) hp = 0;
            DrawHealthBar(hdc, panelX, panelY, 120, 5, hp);
            panelY += 10;
        }

        panelY = wh - 60;
        DrawText_(hdc, panelX, panelY, "PgUp/PgDn: Range", RGB(80,80,80), fontSmall);
        panelY += 14;
        DrawText_(hdc, panelX, panelY, "F1: Filter sleepers", RGB(80,80,80), fontSmall);
        panelY += 14;
        DrawText_(hdc, panelX, panelY, "END: Exit", RGB(80,80,80), fontSmall);
    }

    LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
        if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
        if (msg == WM_KEYDOWN) {
            if (wp == VK_END)   { running = false; PostQuitMessage(0); return 0; }
            if (wp == VK_PRIOR) { radarRange = min(radarRange+50.f, 800.f); return 0; }
            if (wp == VK_NEXT)  { radarRange = max(radarRange-50.f, 50.f);  return 0; }
            if (wp == VK_F1)    { Config::filterSleepers = !Config::filterSleepers.load(); return 0; }
        }
        return DefWindowProcA(h, msg, wp, lp);
    }

    void Run() {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = "RustDmaRadar";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        RegisterClassExA(&wc);

        int ww = radarSize + 260, wh = radarSize + 60;
        hwnd = CreateWindowExA(WS_EX_TOPMOST, "RustDmaRadar", "Rust DMA Radar",
            WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
            100, 100, ww, wh, NULL, NULL, GetModuleHandle(NULL), NULL);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        fontMain  = CreateFontA(14, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0, CLEARTYPE_QUALITY, 0, "Consolas");
        fontSmall = CreateFontA(11, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0, CLEARTYPE_QUALITY, 0, "Consolas");
        fontTitle = CreateFontA(16, 0,0,0, FW_BOLD,   0,0,0, DEFAULT_CHARSET, 0,0, CLEARTYPE_QUALITY, 0, "Consolas");

        HDC memDC = NULL;
        HBITMAP memBmp = NULL, memOld = NULL;

        MSG msg;
        while (running) {
            while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) { running = false; break; }
                TranslateMessage(&msg); DispatchMessageA(&msg);
            }
            if (!running) break;

            RECT cr; GetClientRect(hwnd, &cr);
            int cw = cr.right, ch = cr.bottom;
            if (cw < 1 || ch < 1) { Sleep(100); continue; }

            HDC hdc = GetDC(hwnd);
            if (!memDC) memDC = CreateCompatibleDC(hdc);
            if (memBmp) { SelectObject(memDC, memOld); DeleteObject(memBmp); }
            memBmp = CreateCompatibleBitmap(hdc, cw, ch);
            memOld = (HBITMAP)SelectObject(memDC, memBmp);

            RenderRadar(memDC);
            BitBlt(hdc, 0, 0, cw, ch, memDC, 0, 0, SRCCOPY);
            ReleaseDC(hwnd, hdc);
            Sleep(16);
        }

        if (memBmp) { SelectObject(memDC, memOld); DeleteObject(memBmp); }
        if (memDC) DeleteDC(memDC);
        if (fontMain) DeleteObject(fontMain);
        if (fontSmall) DeleteObject(fontSmall);
        if (fontTitle) DeleteObject(fontTitle);
        DestroyWindow(hwnd);
        UnregisterClassA("RustDmaRadar", GetModuleHandle(NULL));
    }
}


// =============================================================================
// Web server — compatible with esp_client.exe (/api/gamedata, /api/config)
// =============================================================================

namespace WebRadar {
    static int port = 8888;
    static std::atomic<bool> running{true};

    static std::string BuildGameDataJSON() {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        std::ostringstream js;
        // Format compatible with esp_client.exe
        js << "{\"yaw\":" << g_localYaw
           << ",\"pitch\":0"
           << ",\"fov\":" << g_cameraFOV
           << ",\"lx\":" << g_localPos.x
           << ",\"ly\":" << g_localPos.y
           << ",\"lz\":" << g_localPos.z
           << ",\"p\":[";

        bool first = true;
        for (int i = 0; i < g_allPlayerCount; i++) {
            auto& p = g_allPlayers[i];
            if (!p.valid) continue;
            if (!first) js << ",";
            first = false;
            js << "{\"n\":\"";
            for (const char* c = p.name; *c; c++) {
                if (*c == '"') js << "\\\"";
                else if (*c == '\\') js << "\\\\";
                else js << *c;
            }
            js << "\",\"x\":" << p.position.x
               << ",\"y\":" << p.position.y
               << ",\"z\":" << p.position.z
               << ",\"hx\":" << p.headPos.x
               << ",\"hy\":" << p.headPos.y
               << ",\"hz\":" << p.headPos.z
               << ",\"d\":" << (int)p.distance
               << ",\"hp\":" << (int)p.health
               << ",\"t\":" << (p.isSleeper ? 2 : p.isNPC ? 3 : (p.teamID == g_localTeamID && p.teamID != 0) ? 1 : 0);
            if (p.distance < 0.01f && strcmp(p.name, "You") == 0)
                js << ",\"me\":1,\"yaw\":" << g_localYaw;
            js << "}";
        }
        // Empty arrays for vehicles/zombies/items (keep esp_client happy)
        js << "],\"v\":[],\"z\":[],\"i\":[]}";
        return js.str();
    }

    static std::string BuildConfigJSON() {
        std::ostringstream js;
        js << "{\"radar\":" << (Config::radar?"true":"false")
           << ",\"espBoxes\":" << (Config::espBox?"true":"false")
           << ",\"espNames\":" << (Config::espName?"true":"false")
           << ",\"espHealth\":" << (Config::espHealth?"true":"false")
           << ",\"espDistance\":" << (Config::espDistance?"true":"false")
           << ",\"espSnaplines\":" << (Config::espSnaplines?"true":"false")
           << ",\"filterSleepers\":" << (Config::filterSleepers?"true":"false")
           << ",\"filterNPC\":" << (Config::filterNPC?"true":"false")
           << ",\"showAnimals\":" << (Config::showAnimals?"true":"false")
           << ",\"showTC\":" << (Config::showTC?"true":"false")
           << ",\"maxRange\":" << Config::maxRange.load()
           << ",\"esp\":true,\"aimbot\":false,\"silentAim\":false"
           << ",\"aimbotFOV\":15.0}";
        return js.str();
    }

    static void SendHTTP(SOCKET s, int code, const char* contentType, const std::string& body) {
        const char* statusText = (code == 200) ? "OK" : (code == 404) ? "Not Found" : "Bad Request";
        char header[512];
        int hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n",
            code, statusText, contentType, (int)body.size());
        send(s, header, hlen, 0);
        if (!body.empty()) send(s, body.c_str(), (int)body.size(), 0);
    }

    static void HandleToggle(const char* feature) {
        if (strcmp(feature, "filterSleepers") == 0) Config::filterSleepers = !Config::filterSleepers.load();
        else if (strcmp(feature, "filterNPC") == 0)  Config::filterNPC = !Config::filterNPC.load();
        else if (strcmp(feature, "showAnimals") == 0) Config::showAnimals = !Config::showAnimals.load();
        else if (strcmp(feature, "showTC") == 0)     Config::showTC = !Config::showTC.load();
        else if (strcmp(feature, "radar") == 0)      Config::radar = !Config::radar.load();
        else if (strcmp(feature, "espBoxes") == 0)   Config::espBox = !Config::espBox.load();
        else if (strcmp(feature, "espNames") == 0)   Config::espName = !Config::espName.load();
        else if (strcmp(feature, "espHealth") == 0)  Config::espHealth = !Config::espHealth.load();
        else if (strcmp(feature, "espDistance") == 0) Config::espDistance = !Config::espDistance.load();
        else if (strcmp(feature, "espSnaplines") == 0) Config::espSnaplines = !Config::espSnaplines.load();
    }

    static void HandleSet(const char* feature, const char* value) {
        float fv = (float)atof(value);
        if (strcmp(feature, "maxRange") == 0 && fv >= 50.0f && fv <= 1000.0f)
            Config::maxRange = fv;
    }

    static const char* WEB_PAGE = R"HTML(<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rust DMA Radar</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#ccc;font-family:'Consolas',monospace;overflow:hidden}
#wrap{display:flex;height:100vh}
#radar-box{flex:1;display:flex;align-items:center;justify-content:center}
canvas{border-radius:50%;display:block}
#side{width:280px;padding:14px;overflow-y:auto;background:#0e0e16;border-left:1px solid #1a1a2a}
#hdr{font-size:16px;font-weight:bold;color:#cd5532;margin-bottom:4px}
#sub{font-size:11px;color:#666;margin-bottom:8px}
.sep{height:1px;background:#222;margin:8px 0}
.tb{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}
.tb button{padding:4px 10px;border:1px solid #333;border-radius:4px;background:#14141e;color:#aaa;cursor:pointer;font-family:inherit;font-size:11px}
.tb button.on{border-color:#cd5532;color:#cd5532}
.tb button:hover{border-color:#cd5532}
.pl{font-size:11px;margin-bottom:2px}
.pl .nm{color:#ff9090}
.pl .nm.tm{color:#66cc88}
.pl .nm.npc{color:#c8a632}
.pl .nm.zzz{color:#888}
.pl .dst{color:#888;margin-left:6px}
.hp{height:3px;background:#1a1a1a;margin-bottom:6px;border-radius:2px}
.hp div{height:100%;border-radius:2px}
#plist{max-height:55vh;overflow-y:auto}
@media(max-width:700px){#wrap{flex-direction:column}#side{width:100%;max-height:35vh;border-left:none;border-top:1px solid #1a1a2a}#radar-box{height:65vh}}
</style>
</head><body>
<div id="wrap">
<div id="radar-box"><canvas id="c"></canvas></div>
<div id="side">
<div id="hdr">RUST DMA RADAR</div>
<div id="sub">Waiting for data...</div>
<div class="sep"></div>
<div class="tb" id="toggles"></div>
<div class="sep"></div>
<div id="plist"></div>
</div>
</div>
<script>
const C=document.getElementById('c'),X=C.getContext('2d');
let D={},cfg={};
const TOGGLES=['filterSleepers','filterNPC','showAnimals','showTC','espNames','espDistance'];
function initToggles(){
  const el=document.getElementById('toggles');
  TOGGLES.forEach(k=>{
    const b=document.createElement('button');
    b.textContent=k.replace(/([A-Z])/g,' $1');
    b.id='t_'+k;
    b.onclick=()=>fetch('/api/toggle/'+k,{method:'POST'});
    el.appendChild(b);
  });
}
function updateToggles(){
  TOGGLES.forEach(k=>{
    const b=document.getElementById('t_'+k);
    if(b)b.className=cfg[k]?'on':'';
  });
}
function resize(){
  const b=C.parentElement,sz=Math.min(b.clientWidth,b.clientHeight)-40;
  C.width=C.height=sz;
}
function draw(){
  const sz=C.width,cx=sz/2,cy=sz/2,r=sz/2-10;
  X.fillStyle='#141420';X.fillRect(0,0,sz,sz);
  X.strokeStyle='#283028';X.lineWidth=1;
  [1,.75,.5,.25].forEach(s=>{X.beginPath();X.arc(cx,cy,r*s,0,Math.PI*2);X.stroke()});
  X.beginPath();X.moveTo(cx-r,cy);X.lineTo(cx+r,cy);X.stroke();
  X.beginPath();X.moveTo(cx,cy-r);X.lineTo(cx,cy+r);X.stroke();
  // Compass
  const yr=-(D.local?.yaw||0)*Math.PI/180;
  X.font='11px Consolas';X.textAlign='center';X.fillStyle='#6a8a6a';
  ['N','E','S','W'].forEach((d,i)=>{
    const a=i*Math.PI/2+yr;
    X.fillText(d,cx+Math.sin(a)*(r+12),cy-Math.cos(a)*(r+12)+4);
  });
  // You
  X.fillStyle='#00c8ff';X.beginPath();X.arc(cx,cy,5,0,Math.PI*2);X.fill();
  // Players
  const range=D.range||200,ps=D.players||[];
  ps.forEach(p=>{
    if(p.me)return;
    const dx=p.x-(D.local?.x||0),dz=p.z-(D.local?.z||0);
    const rx=dx*Math.cos(yr)-dz*Math.sin(yr);
    const ry=dx*Math.sin(yr)+dz*Math.cos(yr);
    let px=cx+rx/range*r,py=cy-ry/range*r;
    const dd=Math.hypot(px-cx,py-cy);
    if(dd>r-4){const a=Math.atan2(px-cx,cy-py);px=cx+Math.sin(a)*(r-4);py=cy-Math.cos(a)*(r-4)}
    const col=p.t===1?'#66cc88':p.t===2?'#888':p.t===3?'#c8a632':'#ff3232';
    X.fillStyle=col;X.beginPath();X.arc(px,py,p.d<50?6:p.d<150?5:4,0,Math.PI*2);X.fill();
    X.fillStyle='#b0b0b0';X.font='9px Consolas';X.textAlign='left';
    X.fillText(p.d+'m',px+8,py+3);
  });
  requestAnimationFrame(draw);
}
function updateList(){
  const el=document.getElementById('plist');
  const ps=(D.players||[]).filter(p=>!p.me).sort((a,b)=>a.d-b.d);
  let h='';
  ps.forEach(p=>{
    const cls=p.t===1?'tm':p.t===2?'zzz':p.t===3?'npc':'';
    const hp=Math.max(0,Math.min(100,(p.hp||0)));
    const r=Math.round(255*(1-hp/100)),g=Math.round(255*hp/100);
    const tag=p.t===2?' [ZZZ]':p.t===3?' [NPC]':'';
    h+='<div class="pl"><span class="nm '+cls+'">'+(p.n||'Player')+'</span><span class="dst">'+p.d+'m'+tag+'</span></div>';
    h+='<div class="hp"><div style="width:'+hp+'%;background:rgb('+r+','+g+',0)"></div></div>';
  });
  el.innerHTML=h;
  document.getElementById('sub').textContent='Players: '+ps.length+'  |  Range: '+(D.range||200)+'m';
}
async function poll(){
  try{
    const r=await fetch('/api/data');
    D=await r.json();
  }catch(e){}
  try{
    const r=await fetch('/api/config');
    cfg=await r.json();
    updateToggles();
  }catch(e){}
  updateList();
  setTimeout(poll,120);
}
resize();window.onresize=resize;
initToggles();
draw();poll();
</script>
</body></html>)HTML";

    static void HandleClient(SOCKET client) {
        char buf[4096] = {};
        int received = recv(client, buf, sizeof(buf) - 1, 0);
        if (received <= 0) { closesocket(client); return; }
        buf[received] = 0;

        char method[16] = {}, path[512] = {};
        sscanf(buf, "%15s %511s", method, path);

        if (_stricmp(method, "OPTIONS") == 0) {
            SendHTTP(client, 200, "text/plain", "");
        }
        else if (_stricmp(method, "GET") == 0 && (strcmp(path, "/") == 0 || strcmp(path, "/menu") == 0)) {
            SendHTTP(client, 200, "text/html; charset=utf-8", WEB_PAGE);
        }
        else if (_stricmp(method, "GET") == 0 && (strcmp(path, "/api/data") == 0 || strcmp(path, "/api/gamedata") == 0)) {
            SendHTTP(client, 200, "application/json", BuildGameDataJSON());
        }
        else if (_stricmp(method, "GET") == 0 && strcmp(path, "/api/config") == 0) {
            SendHTTP(client, 200, "application/json", BuildConfigJSON());
        }
        else if (_stricmp(method, "POST") == 0 && strncmp(path, "/api/toggle/", 12) == 0) {
            HandleToggle(path + 12);
            SendHTTP(client, 200, "application/json", "{\"ok\":true}");
        }
        else if (_stricmp(method, "POST") == 0 && strncmp(path, "/api/set/", 9) == 0) {
            char feature[64] = {}, value[32] = {};
            const char* p = path + 9;
            const char* slash = strchr(p, '/');
            if (slash) {
                int flen = (int)(slash - p);
                if (flen > 63) flen = 63;
                memcpy(feature, p, flen);
                strncpy(value, slash + 1, 31);
                HandleSet(feature, value);
            }
            SendHTTP(client, 200, "application/json", "{\"ok\":true}");
        }
        else {
            SendHTTP(client, 404, "text/plain", "Not Found");
        }
        closesocket(client);
    }

    static void ServerLoop() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int opt = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((u_short)port);

        if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            printf("[!] Port %d in use, trying %d...\n", port, port + 1);
            port++;
            addr.sin_port = htons((u_short)port);
            if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
                printf("[!] Web server bind failed\n");
                return;
            }
        }
        listen(listenSock, SOMAXCONN);

        // Print LAN URL
        char hostname[256] = {};
        gethostname(hostname, sizeof(hostname));
        addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET;
        if (getaddrinfo(hostname, NULL, &hints, &result) == 0 && result) {
            char ip[64] = {};
            inet_ntop(AF_INET, &((sockaddr_in*)result->ai_addr)->sin_addr, ip, sizeof(ip));
            printf("[+] Web radar: http://%s:%d\n", ip, port);
            printf("[+] ESP client: esp_client.exe %s %d rust\n", ip, port);
            freeaddrinfo(result);
        }

        while (running) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(listenSock, &readfds);
            timeval tv = { 1, 0 };
            if (select(0, &readfds, NULL, NULL, &tv) > 0 && FD_ISSET(listenSock, &readfds)) {
                SOCKET client = accept(listenSock, NULL, NULL);
                if (client != INVALID_SOCKET)
                    std::thread(HandleClient, client).detach();
            }
        }
        closesocket(listenSock);
    }

    void Start() {
        std::thread(ServerLoop).detach();
    }
}


// =============================================================================
// Main
// =============================================================================

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleTitleA("Rust DMA Radar — PC2");

    printf("=== Rust DMA Radar ===\n");
    printf("Engine: Unity (IL2CPP)\n");
    printf("Runs on PC2 — reads PC1 target via hardware DMA\n\n");

    // Parse args
    int port = 8888;
    std::string iniPath = "rust_offsets.ini";
    std::string cmdLine = lpCmdLine ? lpCmdLine : "";

    auto findArg = [&](const char* key) -> std::string {
        size_t pos = cmdLine.find(key);
        if (pos == std::string::npos) return "";
        pos += strlen(key);
        while (pos < cmdLine.size() && cmdLine[pos] == ' ') pos++;
        size_t end = cmdLine.find(' ', pos);
        return (end == std::string::npos) ? cmdLine.substr(pos) : cmdLine.substr(pos, end - pos);
    };

    std::string portArg = findArg("--port");
    if (!portArg.empty()) port = atoi(portArg.c_str());
    std::string offArg = findArg("--offsets");
    if (!offArg.empty()) iniPath = offArg;

    // Try auto-update from GitHub
    TryAutoUpdate(iniPath);

    // Load offsets
    LoadConfig(iniPath.c_str());
    O::Init();

    // Validate critical offsets
    if (!O::ClientEntities) {
        printf("\n[!] WARNING: ClientEntities offset is 0.\n");
        printf("    Run the dumper against Rust to generate offsets,\n");
        printf("    or push updated rust_offsets.ini to GitHub.\n");
        printf("    The radar will not show players until offsets are set.\n\n");
    }

    // Start web server
    WebRadar::port = port;
    WebRadar::Start();
    printf("[+] Web server on port %d\n", port);

    // Init DMA
    printf("[*] Loading vmm.dll...\n");
    if (!LoadVMM()) return 1;

    printf("[*] Connecting to DMA device...\n");
    LPCSTR args[] = { "", "-device", "fpga" };
    g_vmm = pInit(3, args);
    if (!g_vmm) {
        printf("[-] DMA init failed. Is the FPGA card connected?\n");
        printf("    Web radar still running on port %d\n", port);
        Radar::Run();
        return 1;
    }
    printf("[+] DMA connected\n");

    // Find RustClient.exe
    printf("[*] Searching for RustClient.exe...\n");
    int retries = 0;
    while (!pPidGet(g_vmm, "RustClient.exe", &g_pid) || g_pid == 0) {
        if (retries++ > 120) {
            printf("[-] RustClient.exe not found after 120 tries\n");
            Radar::Run();
            pClose(g_vmm);
            return 1;
        }
        printf("[*] Retry %d/120...\r", retries);
        Sleep(3000);
    }
    printf("[+] RustClient.exe PID: %u\n", g_pid);

    // Get module bases
    g_gaBase = pModBase(g_vmm, g_pid, "GameAssembly.dll");
    g_unityBase = pModBase(g_vmm, g_pid, "UnityPlayer.dll");
    printf("[+] GameAssembly.dll: 0x%llX\n", (unsigned long long)g_gaBase);
    printf("[+] UnityPlayer.dll: 0x%llX\n", (unsigned long long)g_unityBase);

    if (!g_gaBase) {
        printf("[-] GameAssembly.dll not found — is Rust fully loaded?\n");
        Radar::Run();
        pClose(g_vmm);
        return 1;
    }

    printf("\n=== Radar Active ===\n");
    printf("Web:      http://localhost:%d\n", port);
    printf("Controls: PgUp/PgDn = range, F1 = filter sleepers, END = exit\n\n");

    // Read loop in background thread
    std::thread readThread([&]() {
        while (Radar::running) {
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                g_classNameCache.clear();
                ReadPlayers();
            }
            Sleep(15);
        }
    });
    readThread.detach();

    // Run radar window on main thread
    Radar::Run();

    // Cleanup
    pClose(g_vmm);
    printf("Exiting.\n");
    return 0;
}
