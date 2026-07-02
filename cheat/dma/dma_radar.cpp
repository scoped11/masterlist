// Universal DMA Radar — ESP radar via FPGA DMA card
// Works with any game by loading a per-game offset config.
// Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.
// Built-in web radar: share http://<your-ip>:8888 with teammates.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS)
// Build: cl /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS dma_radar.cpp gdi32.lib user32.lib winmm.lib ws2_32.lib /link /SUBSYSTEM:WINDOWS
//
// Usage: dma_radar.exe <game_config.ini>
//        dma_radar.exe --game r6
//        dma_radar.exe --game apex
//        dma_radar.exe --game cs2 --port 9000
//
// Supported game aliases:
//   r6, rust, apex, bf2042, tarkov, pubg, cs2, hunt, valorant,
//   deltaforce, arenabreakout

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
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")


// ═══════════════════════════════════════════════════════════════════════════════
// VMM API (dynamically loaded from vmm.dll)
// ═══════════════════════════════════════════════════════════════════════════════

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
typedef BOOL        (__cdecl *fn_MemWrite)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb);

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
static fn_MemWrite  pMemWrite = nullptr;

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
    pMemWrite = (fn_MemWrite) GetProcAddress(h, "VMMDLL_MemWrite");
    return pInit && pMemRead;
}

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cbRead = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cbRead, 0x0002) && cbRead > 0;
}

template<class T> T rpm(uint64_t addr) { T v{}; DmaRead(addr, &v, sizeof(T)); return v; }

static bool DmaWrite(uint64_t va, void* buf, uint32_t size) {
    if (!pMemWrite) return false;
    return pMemWrite(g_vmm, g_pid, va, (PBYTE)buf, size);
}

template<class T> bool wpm(uint64_t addr, T val) { return DmaWrite(addr, &val, sizeof(T)); }


// ═══════════════════════════════════════════════════════════════════════════════
// Feature config — toggled from web menu
// ═══════════════════════════════════════════════════════════════════════════════

namespace Config {
    // Combat
    inline std::atomic<bool> aimbot{false};
    inline std::atomic<bool> triggerbot{false};
    inline std::atomic<bool> noRecoil{false};
    inline std::atomic<bool> noSpread{false};
    inline std::atomic<bool> rapidFire{false};

    // ESP / Visuals
    inline std::atomic<bool> radar{true};
    inline std::atomic<bool> glow{false};
    inline std::atomic<bool> chams{false};
    inline std::atomic<bool> fovChanger{false};
    inline std::atomic<bool> espBox{false};
    inline std::atomic<bool> espName{false};
    inline std::atomic<bool> espHealth{false};
    inline std::atomic<bool> espDistance{false};
    inline std::atomic<bool> espSkeleton{false};
    inline std::atomic<bool> espSnaplines{false};

    // Misc
    inline std::atomic<bool> noFlash{false};
    inline std::atomic<bool> noSway{false};
    inline std::atomic<bool> infiniteStamina{false};
    inline std::atomic<bool> speedHack{false};
    inline std::atomic<bool> superJump{false};
    inline std::atomic<bool> thirdPerson{false};

    // Values
    inline std::atomic<float> aimbotFOV{15.0f};
    inline std::atomic<float> aimbotSmooth{3.0f};
    inline std::atomic<float> customFOV{120.0f};
    inline std::atomic<float> glowR{1.0f};
    inline std::atomic<float> glowG{0.0f};
    inline std::atomic<float> glowB{0.0f};
    inline std::atomic<float> speedMultiplier{2.0f};
    inline std::atomic<float> jumpMultiplier{2.0f};
    inline std::atomic<float> thirdPersonDist{300.0f};

    // Aimbot state
    inline int aimTargetIndex = -1;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Game config — loaded from ini file
// ═══════════════════════════════════════════════════════════════════════════════

static std::unordered_map<std::string, std::string> g_strConfig;
static std::unordered_map<std::string, uint64_t>    g_offsets;

static void LoadConfig(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        printf("[!] Could not open config: %s\n", path);
        return;
    }
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
    printf("[+] Loaded config: %s\n", path);
}

static std::string Str(const char* key, const char* fallback = "") {
    auto it = g_strConfig.find(key);
    return (it != g_strConfig.end()) ? it->second : fallback;
}

static uint64_t Off(const char* key, uint64_t fallback = 0) {
    auto it = g_offsets.find(key);
    return (it != g_offsets.end()) ? it->second : fallback;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Auto-updater — fetch latest offsets from GitHub on startup
// ═══════════════════════════════════════════════════════════════════════════════

static const char* GITHUB_RAW_BASE =
    "https://raw.githubusercontent.com/scoped11/masterlist/master/cheat/dma/";

static std::string HttpGet(const char* url) {
    HINTERNET hInet = InternetOpenA("DmaRadar/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
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

static bool TryAutoUpdate(const std::string& gameAlias, const std::string& localPath) {
    std::string filename = gameAlias + "_offsets.ini";
    std::string url = std::string(GITHUB_RAW_BASE) + filename;

    printf("[*] Checking for offset updates: %s\n", filename.c_str());

    std::string remote = HttpGet(url.c_str());
    if (remote.empty() || remote.size() < 20) {
        printf("[!] No remote offsets found (offline or not published yet)\n");
        return false;
    }

    // Check if remote starts with a comment or section header (valid ini)
    if (remote[0] != '#' && remote[0] != ';' && remote[0] != '[') {
        printf("[!] Remote response doesn't look like an ini file, skipping\n");
        return false;
    }

    std::string local = ReadFileStr(localPath.c_str());

    // Normalize line endings for comparison
    std::string remoteNorm = remote, localNorm = local;
    remoteNorm.erase(std::remove(remoteNorm.begin(), remoteNorm.end(), '\r'), remoteNorm.end());
    localNorm.erase(std::remove(localNorm.begin(), localNorm.end(), '\r'), localNorm.end());

    if (remoteNorm == localNorm) {
        printf("[+] Offsets are up to date\n");
        return false;
    }

    // Different — save new version
    if (WriteFileStr(localPath.c_str(), remote)) {
        printf("[+] UPDATED offsets from GitHub -> %s\n", localPath.c_str());
        return true;
    } else {
        printf("[!] Failed to write updated offsets to %s\n", localPath.c_str());
        return false;
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Engine abstraction — offsets loaded from config
// ═══════════════════════════════════════════════════════════════════════════════

namespace O {
    uint64_t GWorld, OwningGameInstance, LocalPlayers, PlayerController;
    uint64_t AcknowledgedPawn, PlayerCameraManager, PersistentLevel;
    uint64_t Actors, ActorCount;
    uint64_t RootComponent, ActorMesh, RelativeLocation, ComponentToWorld;
    uint64_t TeamIndex, Health, MaxHealth, bIsDead;
    uint64_t BoneArray, ComponentToWorldMatrix;
    uint64_t CameraLocation, CameraRotation, CameraFOV;
    uint64_t PlayerNamePrivate;

    // Engine-specific chain overrides (e.g. Source 2 EntityList approach)
    uint64_t EntityList, EntityListEntry, EntityListStride;
    uint64_t GameRules, PlayerResource;
    uint64_t Pawn_Health, Pawn_Team, Pawn_Position;

    // Pointer chain style: "ue" | "entitylist" | "unity" | "anvilnext"
    std::string engine;

    // Write-target offsets
    uint64_t GlowEnable, GlowThroughWalls, GlowColor;
    uint64_t ControlRotation, RecoilPitch, RecoilYaw;
    uint64_t ViewAngles, FireRate, SpreadAngle;
    uint64_t ChamsEnable, ChamsThroughWalls, ChamsColor;
    uint64_t FlashAlpha, FlashMaxAlpha, SwayScale;
    uint64_t Stamina, MaxStamina, MovementSpeed, MaxWalkSpeed;
    uint64_t JumpZVelocity, ThirdPersonOffset;
    uint64_t DefaultMaxWalkSpeed, DefaultJumpZ;

    void Init() {
        engine = Str("Engine", "ue");

        GWorld                 = Off("GWorld");
        OwningGameInstance     = Off("OwningGameInstance",      0x1B8);
        LocalPlayers           = Off("LocalPlayers",            0x38);
        PlayerController       = Off("PlayerController",        0x30);
        AcknowledgedPawn       = Off("AcknowledgedPawn",        0x338);
        PlayerCameraManager    = Off("PlayerCameraManager",     0x348);
        PersistentLevel        = Off("PersistentLevel",         0x30);
        Actors                 = Off("Actors",                  0x98);
        ActorCount             = Off("ActorCount",              0xA0);
        RootComponent          = Off("RootComponent",           0x190);
        ActorMesh              = Off("ActorMesh",               0x310);
        RelativeLocation       = Off("RelativeLocation",        0x128);
        ComponentToWorld       = Off("ComponentToWorld",         0x1C0);
        TeamIndex              = Off("TeamIndex",                0x10C);
        Health                 = Off("Health");
        MaxHealth              = Off("MaxHealth");
        bIsDead                = Off("bIsDead");
        BoneArray              = Off("BoneArray",                0x5B0);
        ComponentToWorldMatrix = Off("ComponentToWorldMatrix",   0x1C0);
        CameraLocation         = Off("CameraLocation");
        CameraRotation         = Off("CameraRotation");
        CameraFOV              = Off("CameraFOV");
        PlayerNamePrivate      = Off("PlayerNamePrivate",        0x310);

        EntityList             = Off("EntityList");
        EntityListEntry        = Off("EntityListEntry",          0x78);
        EntityListStride       = Off("EntityListStride",         0x8);
        GameRules              = Off("GameRules");
        PlayerResource         = Off("PlayerResource");
        Pawn_Health            = Off("Pawn_Health");
        Pawn_Team              = Off("Pawn_Team");
        Pawn_Position          = Off("Pawn_Position");

        // Write offsets (for active features)
        GlowEnable             = Off("GlowEnable");
        GlowThroughWalls       = Off("GlowThroughWalls");
        GlowColor              = Off("GlowColor");
        ControlRotation        = Off("ControlRotation");
        RecoilPitch            = Off("RecoilPitch");
        RecoilYaw              = Off("RecoilYaw");
        ViewAngles             = Off("ViewAngles");
        FireRate               = Off("FireRate");
        SpreadAngle            = Off("SpreadAngle");
        // Chams / ESP write offsets
        ChamsEnable            = Off("ChamsEnable");
        ChamsThroughWalls      = Off("ChamsThroughWalls");
        ChamsColor             = Off("ChamsColor");
        // Misc write offsets
        FlashAlpha             = Off("FlashAlpha");
        FlashMaxAlpha          = Off("FlashMaxAlpha");
        SwayScale              = Off("SwayScale");
        Stamina                = Off("Stamina");
        MaxStamina             = Off("MaxStamina");
        MovementSpeed          = Off("MovementSpeed");
        MaxWalkSpeed           = Off("MaxWalkSpeed");
        JumpZVelocity          = Off("JumpZVelocity");
        ThirdPersonOffset      = Off("ThirdPersonOffset");
        DefaultMaxWalkSpeed    = Off("DefaultMaxWalkSpeed");
        DefaultJumpZ           = Off("DefaultJumpZ");
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Math
// ═══════════════════════════════════════════════════════════════════════════════

struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };
struct FRotator { float pitch, yaw, roll; };

struct FTransform {
    float rotation[4];
    Vec3  translation;
    float pad0;
    Vec3  scale3d;
    float pad1;
};

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

static Vec3 GetBoneWorldPos(FTransform bone, FTransform ctw) {
    float bx = bone.translation.x * ctw.scale3d.x;
    float by = bone.translation.y * ctw.scale3d.y;
    float bz = bone.translation.z * ctw.scale3d.z;
    float qx = ctw.rotation[0], qy = ctw.rotation[1];
    float qz = ctw.rotation[2], qw = ctw.rotation[3];
    float ix = qw*bx + qy*bz - qz*by;
    float iy = qw*by + qz*bx - qx*bz;
    float iz = qw*bz + qx*by - qy*bx;
    float iw = -qx*bx - qy*by - qz*bz;
    return {
        ix*qw + iw*-qx + iy*-qz - iz*-qy + ctw.translation.x,
        iy*qw + iw*-qy + iz*-qx - ix*-qz + ctw.translation.y,
        iz*qw + iw*-qz + ix*-qy - iy*-qx + ctw.translation.z
    };
}


// ═══════════════════════════════════════════════════════════════════════════════
// Entity reading — supports UE4/UE5 (GWorld chain) and Source 2 (EntityList)
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t g_base = 0;

struct PlayerData {
    Vec3     origin;
    Vec3     headPos;
    int      health, maxHealth;
    int      team;
    float    distance;
    char     name[64];
    bool     valid;
};

static int          g_localTeam = 0;
static Vec3         g_localPos = {};
static float        g_localYaw = 0;
static float        g_cameraFOV = 90.0f;
static PlayerData   g_players[128];
static int          g_playerCount = 0;
static std::mutex   g_dataMutex;
static float        g_unitScale = 1.0f;  // cm->m conversion (100 for UE, 1 for Source)
static uint64_t     g_actorPtrs[128] = {};
static uint64_t     g_localPawn = 0;
static uint64_t     g_playerController = 0;

static Vec3 GetActorLocation(uint64_t actor) {
    if (O::Pawn_Position) return rpm<Vec3>(actor + O::Pawn_Position);
    uint64_t root = rpm<uint64_t>(actor + O::RootComponent);
    if (!root) return {};
    return rpm<Vec3>(root + O::RelativeLocation);
}

static Vec3 GetBonePos(uint64_t actor, int boneId) {
    uint64_t mesh = rpm<uint64_t>(actor + O::ActorMesh);
    if (!mesh) return {};
    FTransform ctw = rpm<FTransform>(mesh + O::ComponentToWorldMatrix);
    uint64_t boneArr = rpm<uint64_t>(mesh + O::BoneArray);
    if (!boneArr) return {};
    FTransform bone = rpm<FTransform>(boneArr + (uint64_t)boneId * sizeof(FTransform));
    return GetBoneWorldPos(bone, ctw);
}

static bool IsPlayerActor(uint64_t actor) {
    if (!actor) return false;
    if (O::engine == "entitylist") return true;
    uint64_t mesh = rpm<uint64_t>(actor + O::ActorMesh);
    if (!mesh) return false;
    uint64_t root = rpm<uint64_t>(actor + O::RootComponent);
    return root != 0;
}

// UE4/UE5 GWorld chain reader
static void ReadPlayers_UE() {
    uint64_t gworld = rpm<uint64_t>(g_base + O::GWorld);
    if (!gworld) return;

    uint64_t gameInst = rpm<uint64_t>(gworld + O::OwningGameInstance);
    if (!gameInst) return;
    uint64_t lpPtr = rpm<uint64_t>(gameInst + O::LocalPlayers);
    if (!lpPtr) return;
    uint64_t lp = rpm<uint64_t>(lpPtr);
    if (!lp) return;
    uint64_t pc = rpm<uint64_t>(lp + O::PlayerController);
    if (!pc) return;
    g_playerController = pc;
    uint64_t localPawn = rpm<uint64_t>(pc + O::AcknowledgedPawn);
    g_localPawn = localPawn;

    uint64_t camMgr = rpm<uint64_t>(pc + O::PlayerCameraManager);
    if (camMgr && O::CameraLocation && O::CameraRotation) {
        g_localPos = rpm<Vec3>(camMgr + O::CameraLocation);
        FRotator rot = rpm<FRotator>(camMgr + O::CameraRotation);
        g_localYaw = rot.yaw;
        if (O::CameraFOV) g_cameraFOV = rpm<float>(camMgr + O::CameraFOV);
    } else if (localPawn) {
        uint64_t root = rpm<uint64_t>(localPawn + O::RootComponent);
        if (root) g_localPos = rpm<Vec3>(root + O::RelativeLocation);
        g_localPos.z += 70.0f;
    }

    if (localPawn && O::TeamIndex)
        g_localTeam = rpm<int>(localPawn + O::TeamIndex);

    uint64_t level = rpm<uint64_t>(gworld + O::PersistentLevel);
    if (!level) return;
    int32_t actorCount = rpm<int32_t>(level + O::ActorCount);
    uint64_t actorArray = rpm<uint64_t>(level + O::Actors);
    if (!actorArray || actorCount <= 0) return;
    if (actorCount > 10000) actorCount = 10000;

    int count = 0;
    const int CHUNK = 256;
    for (int base = 0; base < actorCount && count < 128; base += CHUNK) {
        int batch = min(actorCount - base, CHUNK);
        uint64_t ptrs[256] = {};
        DmaRead(actorArray + (uint64_t)base * 8, ptrs, batch * 8);

        for (int i = 0; i < batch && count < 128; i++) {
            uint64_t actor = ptrs[i];
            if (!actor || actor == localPawn) continue;
            if (!IsPlayerActor(actor)) continue;

            int team = O::TeamIndex ? rpm<int>(actor + O::TeamIndex) : 0;
            if (team == g_localTeam && team != 0) continue;

            Vec3 origin = GetActorLocation(actor);
            if (origin.x == 0 && origin.y == 0 && origin.z == 0) continue;
            float dist = Vec3Dist(g_localPos, origin) / g_unitScale;
            if (dist > 600.0f || dist < 0.5f) continue;

            bool dead = false;
            if (O::bIsDead) dead = rpm<uint8_t>(actor + O::bIsDead) != 0;
            if (dead) continue;

            PlayerData& p = g_players[count];
            p.origin   = origin;
            p.team     = team;
            p.distance = dist;

            if (O::Health) {
                p.health    = rpm<int>(actor + O::Health);
                p.maxHealth = O::MaxHealth ? rpm<int>(actor + O::MaxHealth) : 100;
            } else { p.health = 100; p.maxHealth = 100; }

            p.headPos = GetBonePos(actor, 6); // BONE_HEAD
            if (p.headPos.x == 0 && p.headPos.y == 0 && p.headPos.z == 0)
                p.headPos = { origin.x, origin.y, origin.z + 70.0f };

            p.name[0] = 0;
            if (O::PlayerNamePrivate) {
                int32_t len = rpm<int32_t>(actor + O::PlayerNamePrivate);
                if (len > 0 && len < 63) {
                    uint64_t dataPtr = rpm<uint64_t>(actor + O::PlayerNamePrivate + 8);
                    if (dataPtr) {
                        wchar_t wbuf[64] = {};
                        DmaRead(dataPtr, wbuf, len * 2);
                        WideCharToMultiByte(CP_ACP, 0, wbuf, len, p.name, 63, NULL, NULL);
                    }
                }
            }

            p.valid = (p.health > 0);
            if (p.valid) { g_actorPtrs[count] = actor; count++; }
        }
    }
    g_playerCount = count;
}

// Source 2 EntityList reader (CS2)
static void ReadPlayers_EntityList() {
    if (!O::EntityList) return;

    uint64_t entityList = rpm<uint64_t>(g_base + O::EntityList);
    if (!entityList) return;

    // Read local player for camera/team
    // Source 2: local controller -> pawn
    if (O::CameraLocation) {
        g_localPos = rpm<Vec3>(g_base + O::CameraLocation);
    }
    if (O::CameraRotation) {
        FRotator rot = rpm<FRotator>(g_base + O::CameraRotation);
        g_localYaw = rot.yaw;
    }

    int count = 0;
    for (int i = 1; i <= 64 && count < 128; i++) {
        uint64_t listEntry = rpm<uint64_t>(entityList + 8 * ((i & 0x7FFF) >> 9) + 16);
        if (!listEntry) continue;
        uint64_t controller = rpm<uint64_t>(listEntry + 120 * (i & 0x1FF));
        if (!controller) continue;

        uint64_t pawnHandle = rpm<uint64_t>(controller + O::AcknowledgedPawn);
        if (!pawnHandle) continue;

        uint64_t listEntry2 = rpm<uint64_t>(entityList + 8 * ((pawnHandle & 0x7FFF) >> 9) + 16);
        if (!listEntry2) continue;
        uint64_t pawn = rpm<uint64_t>(listEntry2 + 120 * (pawnHandle & 0x1FF));
        if (!pawn) continue;

        int team = O::Pawn_Team ? rpm<int>(pawn + O::Pawn_Team) : 0;
        int hp   = O::Pawn_Health ? rpm<int>(pawn + O::Pawn_Health) : 100;
        if (hp <= 0) continue;

        Vec3 origin = O::Pawn_Position ? rpm<Vec3>(pawn + O::Pawn_Position) : Vec3{};
        if (origin.x == 0 && origin.y == 0 && origin.z == 0) continue;
        float dist = Vec3Dist(g_localPos, origin) / g_unitScale;
        if (dist > 600.0f || dist < 0.5f) continue;
        if (team == g_localTeam && team != 0) continue;

        PlayerData& p = g_players[count];
        p.origin   = origin;
        p.team     = team;
        p.distance = dist;
        p.health   = hp;
        p.maxHealth = 100;
        p.headPos  = { origin.x, origin.y, origin.z + 72.0f };
        p.name[0]  = 0;
        p.valid    = true;
        g_actorPtrs[count] = pawn;
        count++;
    }
    g_playerCount = count;
}

// Unity reader (Rust, Tarkov)
static void ReadPlayers_Unity() {
    // Unity games: GOM -> Tagged Objects -> GameObjects -> Components
    // The chain is highly game-specific; this is a skeleton that reads
    // from the offsets provided in the config
    if (!O::GWorld) return;

    uint64_t gom = rpm<uint64_t>(g_base + O::GWorld);
    if (!gom) return;

    uint64_t taggedObjects = rpm<uint64_t>(gom + O::Actors);
    if (!taggedObjects) return;
    int32_t objectCount = rpm<int32_t>(gom + O::ActorCount);
    if (objectCount <= 0 || objectCount > 2000) return;

    if (O::CameraLocation) {
        g_localPos = rpm<Vec3>(g_base + O::CameraLocation);
    }
    if (O::CameraRotation) {
        FRotator rot = rpm<FRotator>(g_base + O::CameraRotation);
        g_localYaw = rot.yaw;
    }

    int count = 0;
    for (int i = 0; i < objectCount && count < 128; i++) {
        uint64_t obj = rpm<uint64_t>(taggedObjects + i * 8);
        if (!obj) continue;

        uint64_t gameObj = rpm<uint64_t>(obj + O::RootComponent);
        if (!gameObj) continue;

        Vec3 pos = O::Pawn_Position
            ? rpm<Vec3>(gameObj + O::Pawn_Position)
            : rpm<Vec3>(gameObj + O::RelativeLocation);
        if (pos.x == 0 && pos.y == 0 && pos.z == 0) continue;

        float dist = Vec3Dist(g_localPos, pos) / g_unitScale;
        if (dist > 600.0f || dist < 0.5f) continue;

        int hp = O::Pawn_Health ? rpm<int>(gameObj + O::Pawn_Health) : 100;
        if (hp <= 0) continue;

        int team = O::Pawn_Team ? rpm<int>(gameObj + O::Pawn_Team) : 0;
        if (team == g_localTeam && team != 0) continue;

        PlayerData& p = g_players[count];
        p.origin   = pos;
        p.team     = team;
        p.distance = dist;
        p.health   = hp;
        p.maxHealth = 100;
        p.headPos  = { pos.x, pos.y, pos.z + 1.7f };
        p.name[0]  = 0;
        p.valid    = true;
        g_actorPtrs[count] = gameObj;
        count++;
    }
    g_playerCount = count;
}

// AnvilNext 2.0 reader (Rainbow Six Siege)
static void ReadPlayers_AnvilNext() {
    uint64_t gmRVA = Off("GameManager");
    if (!gmRVA) return;

    uint64_t gmPtr = rpm<uint64_t>(g_base + gmRVA);
    if (!gmPtr || gmPtr > 0x7FFFFFFFFFFF) return;

    uint64_t entListOff  = Off("EntityList",      0x1C8);
    uint64_t entCountOff = Off("EntityCount",      0x1D0);
    uint64_t headOff     = Off("HeadPosition",     0x6A0);
    uint64_t feetOff     = Off("FeetPosition",     0x700);
    uint64_t replOff     = Off("Replication",      0xC8);
    uint64_t teamIdOff   = Off("TeamID",           0x190);
    uint64_t compChainOff= Off("ComponentChain",   0xD8);
    uint64_t childCompOff= Off("ChildComponent",   0x8);
    uint64_t healthOff   = Off("Health",           0x168);
    uint64_t statusRVA   = Off("StatusManager");
    uint64_t localEntOff = Off("LocalEntity",      0x28);

    uint64_t entityList = rpm<uint64_t>(gmPtr + entListOff);
    if (!entityList || entityList > 0x7FFFFFFFFFFF) return;

    int32_t entityCount = rpm<int32_t>(gmPtr + entCountOff);
    if (entityCount <= 0 || entityCount > 64) return;

    uint64_t localEntity = 0;
    if (statusRVA) {
        uint64_t statusMgr = rpm<uint64_t>(g_base + statusRVA);
        if (statusMgr && statusMgr < 0x7FFFFFFFFFFF)
            localEntity = rpm<uint64_t>(statusMgr + localEntOff);
    }

    uint64_t grRVA = Off("GameRenderer");
    bool hasCam = false;
    if (grRVA) {
        uint64_t gr = rpm<uint64_t>(g_base + grRVA);
        if (gr && gr < 0x7FFFFFFFFFFF) {
            uint64_t engLink = rpm<uint64_t>(gr + Off("EngineLink", 0x120));
            if (engLink) {
                uint64_t eng = rpm<uint64_t>(engLink + Off("CameraEngine", 0x1C8));
                if (eng) {
                    uint64_t cam = rpm<uint64_t>(eng + Off("CameraObject", 0x08));
                    if (cam) {
                        g_localPos = rpm<Vec3>(cam + Off("ViewTranslation", 0x100));
                        Vec3 fwd = rpm<Vec3>(cam + Off("ViewForward", 0xF0));
                        g_localYaw = RAD2DEG(atan2f(fwd.y, fwd.x));
                        hasCam = true;
                    }
                }
            }
        }
    }

    if (localEntity && localEntity < 0x7FFFFFFFFFFF) {
        if (!hasCam) g_localPos = rpm<Vec3>(localEntity + headOff);
        uint64_t repl = rpm<uint64_t>(localEntity + replOff);
        if (repl && repl < 0x7FFFFFFFFFFF) g_localTeam = rpm<int>(repl + teamIdOff);
        g_localPawn = localEntity;
    } else if (!hasCam && entityCount > 0) {
        uint64_t first = rpm<uint64_t>(entityList);
        if (first && first < 0x7FFFFFFFFFFF) {
            g_localPos = rpm<Vec3>(first + headOff);
            localEntity = first;
            g_localPawn = first;
        }
    }

    int count = 0;
    for (int i = 0; i < entityCount && count < 128; i++) {
        uint64_t entity = rpm<uint64_t>(entityList + (uint64_t)i * 8);
        if (!entity || entity > 0x7FFFFFFFFFFF) continue;
        if (entity == localEntity) continue;

        Vec3 headPos = rpm<Vec3>(entity + headOff);
        if (headPos.x == 0.0f && headPos.y == 0.0f && headPos.z == 0.0f) continue;

        int team = 0;
        uint64_t repl = rpm<uint64_t>(entity + replOff);
        if (repl && repl < 0x7FFFFFFFFFFF) team = rpm<int>(repl + teamIdOff);
        if (team == g_localTeam && g_localTeam != 0) continue;

        int hp = 100;
        uint64_t compChain = rpm<uint64_t>(entity + compChainOff);
        if (compChain && compChain < 0x7FFFFFFFFFFF) {
            uint64_t child = rpm<uint64_t>(compChain + childCompOff);
            if (child && child < 0x7FFFFFFFFFFF) {
                float hpf = rpm<float>(child + healthOff);
                if (hpf > 0.0f && hpf <= 200.0f) hp = (int)hpf;
            }
        }
        if (hp <= 0) continue;

        Vec3 feetPos = rpm<Vec3>(entity + feetOff);
        float dist = Vec3Dist(g_localPos, headPos) / g_unitScale;
        if (dist > 600.0f) continue;

        PlayerData& p = g_players[count];
        p.origin  = (feetPos.x != 0.0f || feetPos.y != 0.0f) ? feetPos : headPos;
        p.headPos = headPos;
        p.team    = team;
        p.distance = dist;
        p.health   = hp;
        p.maxHealth = 100;
        p.name[0]  = 0;
        p.valid    = true;
        g_actorPtrs[count] = entity;
        count++;
    }
    g_playerCount = count;
}

static void ReadPlayers() {
    memset(g_actorPtrs, 0, sizeof(g_actorPtrs));
    if (O::engine == "entitylist")       ReadPlayers_EntityList();
    else if (O::engine == "unity")       ReadPlayers_Unity();
    else if (O::engine == "anvilnext")   ReadPlayers_AnvilNext();
    else                                 ReadPlayers_UE();
}

// ═══════════════════════════════════════════════════════════════════════════════
// DMA Write features — aimbot, glow, no-recoil, triggerbot, etc.
// ═══════════════════════════════════════════════════════════════════════════════

static Vec3 CalcAngle(Vec3 src, Vec3 dst) {
    Vec3 delta = { dst.x - src.x, dst.y - src.y, dst.z - src.z };
    float hyp = sqrtf(delta.x*delta.x + delta.y*delta.y);
    Vec3 angles;
    angles.x = -RAD2DEG(atan2f(delta.z, hyp)); // pitch
    angles.y = RAD2DEG(atan2f(delta.y, delta.x)); // yaw
    angles.z = 0;
    return angles;
}

static float AngleFOV(Vec3 viewAngles, Vec3 targetAngles) {
    float dp = targetAngles.x - viewAngles.x;
    float dy = targetAngles.y - viewAngles.y;
    while (dy > 180.f) dy -= 360.f;
    while (dy < -180.f) dy += 360.f;
    return sqrtf(dp*dp + dy*dy);
}

static void ApplyAimbot() {
    if (!Config::aimbot || !g_playerController) return;
    if (!O::ControlRotation && !O::ViewAngles) return;

    Vec3 camPos = g_localPos;
    FRotator camRot = {};
    if (g_playerController && O::CameraRotation) {
        uint64_t camMgr = rpm<uint64_t>(g_playerController + O::PlayerCameraManager);
        if (camMgr) camRot = rpm<FRotator>(camMgr + O::CameraRotation);
    }
    Vec3 viewAngles = { camRot.pitch, camRot.yaw, 0 };

    int bestIdx = -1;
    float bestFov = Config::aimbotFOV.load();

    for (int i = 0; i < g_playerCount; i++) {
        if (!g_players[i].valid) continue;
        Vec3 target = g_players[i].headPos;
        Vec3 angle = CalcAngle(camPos, target);
        float fov = AngleFOV(viewAngles, angle);
        if (fov < bestFov) { bestFov = fov; bestIdx = i; }
    }

    Config::aimTargetIndex = bestIdx;
    if (bestIdx < 0) return;

    if (!(GetAsyncKeyState(VK_RBUTTON) & 0x8000)) return;

    Vec3 target = CalcAngle(camPos, g_players[bestIdx].headPos);
    float smooth = Config::aimbotSmooth.load();
    if (smooth < 1.0f) smooth = 1.0f;

    FRotator newRot;
    newRot.pitch = viewAngles.x + (target.x - viewAngles.x) / smooth;
    newRot.yaw   = viewAngles.y + (target.y - viewAngles.y) / smooth;
    newRot.roll  = 0;

    if (O::ControlRotation && g_playerController)
        wpm(g_playerController + O::ControlRotation, newRot);
    else if (O::ViewAngles)
        wpm(g_base + O::ViewAngles, newRot);
}

static void ApplyGlow() {
    if (!Config::glow || !O::GlowEnable) return;
    for (int i = 0; i < g_playerCount; i++) {
        uint64_t actor = g_actorPtrs[i];
        if (!actor) continue;
        wpm<uint8_t>(actor + O::GlowEnable, 1);
        if (O::GlowThroughWalls)
            wpm<uint8_t>(actor + O::GlowThroughWalls, 1);
        if (O::GlowColor) {
            float color[3] = { Config::glowR, Config::glowG, Config::glowB };
            DmaWrite(actor + O::GlowColor, color, sizeof(color));
        }
    }
}

static void ApplyNoRecoil() {
    if (!Config::noRecoil) return;
    if (!g_localPawn) return;
    if (O::RecoilPitch) wpm<float>(g_localPawn + O::RecoilPitch, 0.0f);
    if (O::RecoilYaw)   wpm<float>(g_localPawn + O::RecoilYaw, 0.0f);
}

static void ApplyNoSpread() {
    if (!Config::noSpread || !O::SpreadAngle) return;
    if (!g_localPawn) return;
    wpm<float>(g_localPawn + O::SpreadAngle, 0.0f);
}

static void ApplyRapidFire() {
    if (!Config::rapidFire || !O::FireRate) return;
    if (!g_localPawn) return;
    wpm<float>(g_localPawn + O::FireRate, 0.0f);
}

static void ApplyFOV() {
    if (!Config::fovChanger || !O::CameraFOV) return;
    if (!g_playerController) return;
    uint64_t camMgr = rpm<uint64_t>(g_playerController + O::PlayerCameraManager);
    if (camMgr) wpm<float>(camMgr + O::CameraFOV, Config::customFOV.load());
}

static void ApplyTriggerbot() {
    if (!Config::triggerbot) return;
    if (Config::aimTargetIndex < 0) return;
    float dist = g_players[Config::aimTargetIndex].distance;
    if (dist > 200.0f) return;
    Vec3 camPos = g_localPos;
    Vec3 target = CalcAngle(camPos, g_players[Config::aimTargetIndex].headPos);
    FRotator camRot = {};
    if (g_playerController) {
        uint64_t camMgr = rpm<uint64_t>(g_playerController + O::PlayerCameraManager);
        if (camMgr && O::CameraRotation) camRot = rpm<FRotator>(camMgr + O::CameraRotation);
    }
    Vec3 view = { camRot.pitch, camRot.yaw, 0 };
    if (AngleFOV(view, target) < 2.0f) {
        INPUT input = {}; input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        SendInput(1, &input, sizeof(INPUT));
        Sleep(30);
        input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
        SendInput(1, &input, sizeof(INPUT));
    }
}

static void ApplyChams() {
    if (!Config::chams || !O::ChamsEnable) return;
    for (int i = 0; i < g_playerCount; i++) {
        uint64_t actor = g_actorPtrs[i];
        if (!actor) continue;
        wpm<uint8_t>(actor + O::ChamsEnable, 1);
        if (O::ChamsThroughWalls) wpm<uint8_t>(actor + O::ChamsThroughWalls, 1);
        if (O::ChamsColor) {
            float color[3] = { Config::glowR, Config::glowG, Config::glowB };
            DmaWrite(actor + O::ChamsColor, color, sizeof(color));
        }
    }
}

static void ApplyNoFlash() {
    if (!Config::noFlash || !g_localPawn) return;
    if (O::FlashAlpha) wpm<float>(g_localPawn + O::FlashAlpha, 0.0f);
    if (O::FlashMaxAlpha) wpm<float>(g_localPawn + O::FlashMaxAlpha, 0.0f);
}

static void ApplyNoSway() {
    if (!Config::noSway || !g_localPawn) return;
    if (O::SwayScale) wpm<float>(g_localPawn + O::SwayScale, 0.0f);
}

static void ApplyInfiniteStamina() {
    if (!Config::infiniteStamina || !g_localPawn) return;
    if (O::Stamina && O::MaxStamina) {
        float maxStam = rpm<float>(g_localPawn + O::MaxStamina);
        if (maxStam > 0) wpm<float>(g_localPawn + O::Stamina, maxStam);
    }
}

static void ApplySpeedHack() {
    if (!g_localPawn) return;
    if (!O::MaxWalkSpeed && !O::MovementSpeed) return;
    if (Config::speedHack) {
        float base = O::DefaultMaxWalkSpeed ? rpm<float>(g_localPawn + O::DefaultMaxWalkSpeed) : 600.0f;
        float target = base * Config::speedMultiplier.load();
        if (O::MaxWalkSpeed) wpm<float>(g_localPawn + O::MaxWalkSpeed, target);
        if (O::MovementSpeed) wpm<float>(g_localPawn + O::MovementSpeed, target);
    }
}

static void ApplySuperJump() {
    if (!Config::superJump || !g_localPawn || !O::JumpZVelocity) return;
    float base = O::DefaultJumpZ ? rpm<float>(g_localPawn + O::DefaultJumpZ) : 420.0f;
    wpm<float>(g_localPawn + O::JumpZVelocity, base * Config::jumpMultiplier.load());
}

static void ApplyThirdPerson() {
    if (!Config::thirdPerson || !g_playerController || !O::ThirdPersonOffset) return;
    uint64_t camMgr = rpm<uint64_t>(g_playerController + O::PlayerCameraManager);
    if (camMgr) wpm<float>(camMgr + O::ThirdPersonOffset, Config::thirdPersonDist.load());
}

static void ApplyFeatures() {
    ApplyAimbot();
    ApplyGlow();
    ApplyChams();
    ApplyNoRecoil();
    ApplyNoSpread();
    ApplyRapidFire();
    ApplyFOV();
    ApplyTriggerbot();
    ApplyNoFlash();
    ApplyNoSway();
    ApplyInfiniteStamina();
    ApplySpeedHack();
    ApplySuperJump();
    ApplyThirdPerson();
}


// ═══════════════════════════════════════════════════════════════════════════════
// Radar overlay
// ═══════════════════════════════════════════════════════════════════════════════

namespace Radar {
    static HWND hwnd = NULL;
    static std::atomic<bool> running{true};
    static HFONT fontMain = NULL, fontSmall = NULL, fontTitle = NULL;
    static int radarSize    = 500;
    static float radarRange = 200.0f;
    static std::string gameName;
    static COLORREF themeColor = RGB(255, 160, 50);

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
        float wx = (wp.x - g_localPos.x) / g_unitScale;
        float wy = (wp.y - g_localPos.y) / g_unitScale;
        float a = -DEG2RAD(g_localYaw);
        float rx = wx * cosf(a) - wy * sinf(a);
        float ry = wx * sinf(a) + wy * cosf(a);
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

        // Local player
        DrawDot(hdc, cx, cy, 5, RGB(0, 200, 255));
        DrawLine(hdc, cx, cy, cx, cy-18, RGB(0, 200, 255), 2);

        std::lock_guard<std::mutex> lock(g_dataMutex);

        for (int i = 0; i < g_playerCount; i++) {
            auto& p = g_players[i];
            if (!p.valid) continue;

            int px, py;
            WorldToRadar(p.origin, cx, cy, radius, px, py);

            float hpPct = (p.maxHealth > 0) ? (float)p.health / p.maxHealth : 1.0f;
            COLORREF dotCol = (hpPct < 0.3f) ? RGB(255,255,0) : RGB(255,50,50);
            int dotSz = (p.distance < 50.f) ? 6 : (p.distance < 150.f) ? 5 : 4;
            DrawDot(hdc, px, py, dotSz, dotCol);

            char distTxt[16];
            snprintf(distTxt, sizeof(distTxt), "%.0f", p.distance);
            DrawText_(hdc, px+dotSz+2, py-5, distTxt, RGB(180,180,180), fontSmall);
        }

        // Info panel
        int panelX = radarSize + 50, panelY = 20;
        char title[64];
        snprintf(title, sizeof(title), "%s DMA", gameName.c_str());
        for (char& c : title) c = (char)toupper((unsigned char)c);
        DrawText_(hdc, panelX, panelY, title, themeColor, fontTitle);
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
            char line[256];
            const char* n = p.name[0] ? p.name : "Enemy";
            snprintf(line, sizeof(line), "%s  %.0fm  %dHP", n, p.distance, p.health);
            DrawText_(hdc, panelX, panelY, line, RGB(255,120,120), fontSmall);
            panelY += 14;
            float hp = (p.maxHealth > 0) ? (float)p.health / p.maxHealth : 1.0f;
            DrawHealthBar(hdc, panelX, panelY, 120, 5, hp);
            panelY += 10;
        }

        panelY = wh - 46;
        DrawText_(hdc, panelX, panelY, "PgUp/PgDn: Range", RGB(80,80,80), fontSmall);
        panelY += 14;
        DrawText_(hdc, panelX, panelY, "END: Exit", RGB(80,80,80), fontSmall);
    }

    LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
        if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
        if (msg == WM_KEYDOWN) {
            if (wp == VK_END)   { running = false; PostQuitMessage(0); return 0; }
            if (wp == VK_PRIOR) { radarRange = min(radarRange+50.f, 800.f); return 0; }
            if (wp == VK_NEXT)  { radarRange = max(radarRange-50.f, 50.f);  return 0; }
        }
        return DefWindowProcA(h, msg, wp, lp);
    }

    void Run() {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = "DmaRadar";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        RegisterClassExA(&wc);

        int ww = radarSize + 260, wh = radarSize + 60;
        char wtitle[128];
        snprintf(wtitle, sizeof(wtitle), "%s DMA Radar", gameName.c_str());

        hwnd = CreateWindowExA(WS_EX_TOPMOST, "DmaRadar", wtitle,
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
        UnregisterClassA("DmaRadar", GetModuleHandle(NULL));
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Web Radar — HTTP server + live canvas radar page
// Share http://<your-ip>:PORT with teammates (phone, tablet, second monitor)
// ═══════════════════════════════════════════════════════════════════════════════

namespace WebRadar {
    static int port = 8888;
    static std::atomic<bool> running{true};

    static std::string BuildJSON() {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        std::ostringstream js;
        js << "{\"game\":\"" << Radar::gameName << "\","
           << "\"count\":" << g_playerCount << ","
           << "\"range\":" << (int)Radar::radarRange << ","
           << "\"local\":{\"x\":" << g_localPos.x << ",\"y\":" << g_localPos.y
           << ",\"z\":" << g_localPos.z << ",\"yaw\":" << g_localYaw
           << ",\"team\":" << g_localTeam << "},"
           << "\"scale\":" << g_unitScale << ","
           << "\"cfg\":{"
           << "\"aimbot\":" << (Config::aimbot?"true":"false") << ","
           << "\"triggerbot\":" << (Config::triggerbot?"true":"false") << ","
           << "\"noRecoil\":" << (Config::noRecoil?"true":"false") << ","
           << "\"noSpread\":" << (Config::noSpread?"true":"false") << ","
           << "\"rapidFire\":" << (Config::rapidFire?"true":"false") << ","
           << "\"glow\":" << (Config::glow?"true":"false") << ","
           << "\"chams\":" << (Config::chams?"true":"false") << ","
           << "\"fovChanger\":" << (Config::fovChanger?"true":"false") << ","
           << "\"radar\":" << (Config::radar?"true":"false") << ","
           << "\"espBox\":" << (Config::espBox?"true":"false") << ","
           << "\"espName\":" << (Config::espName?"true":"false") << ","
           << "\"espHealth\":" << (Config::espHealth?"true":"false") << ","
           << "\"espDistance\":" << (Config::espDistance?"true":"false") << ","
           << "\"espSkeleton\":" << (Config::espSkeleton?"true":"false") << ","
           << "\"espSnaplines\":" << (Config::espSnaplines?"true":"false") << ","
           << "\"noFlash\":" << (Config::noFlash?"true":"false") << ","
           << "\"noSway\":" << (Config::noSway?"true":"false") << ","
           << "\"infiniteStamina\":" << (Config::infiniteStamina?"true":"false") << ","
           << "\"speedHack\":" << (Config::speedHack?"true":"false") << ","
           << "\"superJump\":" << (Config::superJump?"true":"false") << ","
           << "\"thirdPerson\":" << (Config::thirdPerson?"true":"false") << ","
           << "\"aimbotFOV\":" << Config::aimbotFOV.load() << ","
           << "\"aimbotSmooth\":" << Config::aimbotSmooth.load() << ","
           << "\"customFOV\":" << Config::customFOV.load() << ","
           << "\"speedMultiplier\":" << Config::speedMultiplier.load() << ","
           << "\"jumpMultiplier\":" << Config::jumpMultiplier.load() << ","
           << "\"thirdPersonDist\":" << Config::thirdPersonDist.load()
           << "},"
           << "\"players\":[";
        for (int i = 0; i < g_playerCount; i++) {
            auto& p = g_players[i];
            if (!p.valid) continue;
            if (i > 0) js << ",";
            js << "{\"x\":" << p.origin.x << ",\"y\":" << p.origin.y
               << ",\"z\":" << p.origin.z << ",\"hp\":" << p.health
               << ",\"mhp\":" << p.maxHealth << ",\"t\":" << p.team
               << ",\"d\":" << (int)p.distance;
            if (p.name[0]) {
                js << ",\"n\":\"";
                for (const char* c = p.name; *c; c++) {
                    if (*c == '"') js << "\\\"";
                    else if (*c == '\\') js << "\\\\";
                    else js << *c;
                }
                js << "\"";
            }
            js << "}";
        }
        js << "]}";
        return js.str();
    }

    static void HandleToggle(const char* body) {
        auto getVal = [&](const char* key) -> std::string {
            const char* p = strstr(body, key);
            if (!p) return "";
            p += strlen(key);
            if (*p != '=') return "";
            p++;
            const char* end = strchr(p, '&');
            return end ? std::string(p, end) : std::string(p);
        };
        std::string k = getVal("key");
        std::string v = getVal("val");
        if (k.empty()) return;
        bool bv = (v == "true" || v == "1");
        float fv = (float)atof(v.c_str());

        if (k == "aimbot")            Config::aimbot = bv;
        else if (k == "triggerbot")   Config::triggerbot = bv;
        else if (k == "noRecoil")     Config::noRecoil = bv;
        else if (k == "noSpread")     Config::noSpread = bv;
        else if (k == "rapidFire")    Config::rapidFire = bv;
        else if (k == "glow")         Config::glow = bv;
        else if (k == "chams")        Config::chams = bv;
        else if (k == "fovChanger")   Config::fovChanger = bv;
        else if (k == "radar")        Config::radar = bv;
        else if (k == "espBox")       Config::espBox = bv;
        else if (k == "espName")      Config::espName = bv;
        else if (k == "espHealth")    Config::espHealth = bv;
        else if (k == "espDistance")  Config::espDistance = bv;
        else if (k == "espSkeleton")  Config::espSkeleton = bv;
        else if (k == "espSnaplines") Config::espSnaplines = bv;
        else if (k == "noFlash")      Config::noFlash = bv;
        else if (k == "noSway")       Config::noSway = bv;
        else if (k == "infiniteStamina") Config::infiniteStamina = bv;
        else if (k == "speedHack")    Config::speedHack = bv;
        else if (k == "superJump")    Config::superJump = bv;
        else if (k == "thirdPerson")  Config::thirdPerson = bv;
        else if (k == "aimbotFOV")    Config::aimbotFOV = fv;
        else if (k == "aimbotSmooth") Config::aimbotSmooth = fv;
        else if (k == "customFOV")    Config::customFOV = fv;
        else if (k == "speedMultiplier")   Config::speedMultiplier = fv;
        else if (k == "jumpMultiplier")    Config::jumpMultiplier = fv;
        else if (k == "thirdPersonDist")   Config::thirdPersonDist = fv;
    }

    static const char* HTML_PAGE = R"HTML(<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>DMA Cheat</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c12;color:#b4b4b4;font-family:'Consolas','Courier New',monospace;overflow-x:hidden}
#wrap{display:flex;height:100vh;width:100vw}
#radar-box{flex:1;display:flex;align-items:center;justify-content:center;min-width:0}
canvas{display:block;border-radius:50%}
#panel{width:320px;padding:16px;overflow-y:auto;background:#10101a;border-left:1px solid #222}
#title{font-size:18px;font-weight:bold;margin-bottom:4px}
#status{font-size:12px;color:#888;margin-bottom:8px}
.sep{height:1px;background:#333;margin:10px 0}
.cat{font-size:13px;color:#ff9040;font-weight:bold;margin:10px 0 6px 0;text-transform:uppercase;letter-spacing:1px}
.row{display:flex;align-items:center;justify-content:space-between;padding:4px 0}
.row label{font-size:12px;flex:1}
.tog{width:40px;height:20px;border-radius:10px;background:#333;cursor:pointer;position:relative;transition:.2s}
.tog.on{background:#ff4040}
.tog::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#888;transition:.2s}
.tog.on::after{left:22px;background:#fff}
.sld{display:flex;align-items:center;padding:2px 0 6px 0}
.sld label{font-size:11px;width:100px}
.sld input[type=range]{flex:1;accent-color:#ff4040}
.sld .val{font-size:11px;width:40px;text-align:right;color:#ff9040}
.enemy{font-size:11px;color:#ff7878;margin-bottom:2px}
.hpbar{height:3px;background:#282828;margin-bottom:6px;border-radius:2px}
.hpbar div{height:100%;border-radius:2px}
#plist{max-height:200px;overflow-y:auto}
#range-btns{margin:6px 0}
#range-btns button{background:#1a1a2a;color:#aaa;border:1px solid #333;padding:4px 12px;margin:2px;cursor:pointer;font-family:inherit;font-size:11px;border-radius:3px}
#range-btns button:hover{background:#252540;color:#fff}
#conn{font-size:10px;color:#444;margin-top:8px}
@media(max-width:700px){
  #wrap{flex-direction:column}
  #panel{width:100%;max-height:50vh;border-left:none;border-top:1px solid #222}
  #radar-box{height:50vh}
}
</style>
</head><body>
<div id="wrap">
<div id="radar-box"><canvas id="c"></canvas></div>
<div id="panel">
  <div id="title">DMA CHEAT</div>
  <div id="status">Connecting...</div>
  <div class="sep"></div>

  <div class="cat">Combat</div>
  <div class="row"><label>Aimbot</label><div class="tog" data-key="aimbot" onclick="tog(this)"></div></div>
  <div class="sld"><label>Aim FOV</label><input type="range" min="1" max="90" value="15" data-key="aimbotFOV" oninput="sld(this)"><span class="val">15</span></div>
  <div class="sld"><label>Smoothing</label><input type="range" min="1" max="20" value="3" data-key="aimbotSmooth" oninput="sld(this)"><span class="val">3</span></div>
  <div class="row"><label>Triggerbot</label><div class="tog" data-key="triggerbot" onclick="tog(this)"></div></div>
  <div class="row"><label>No Recoil</label><div class="tog" data-key="noRecoil" onclick="tog(this)"></div></div>
  <div class="row"><label>No Spread</label><div class="tog" data-key="noSpread" onclick="tog(this)"></div></div>
  <div class="row"><label>Rapid Fire</label><div class="tog" data-key="rapidFire" onclick="tog(this)"></div></div>

  <div class="cat">ESP</div>
  <div class="row"><label>Box ESP</label><div class="tog" data-key="espBox" onclick="tog(this)"></div></div>
  <div class="row"><label>Name ESP</label><div class="tog" data-key="espName" onclick="tog(this)"></div></div>
  <div class="row"><label>Health Bars</label><div class="tog" data-key="espHealth" onclick="tog(this)"></div></div>
  <div class="row"><label>Distance</label><div class="tog" data-key="espDistance" onclick="tog(this)"></div></div>
  <div class="row"><label>Skeleton</label><div class="tog" data-key="espSkeleton" onclick="tog(this)"></div></div>
  <div class="row"><label>Snaplines</label><div class="tog" data-key="espSnaplines" onclick="tog(this)"></div></div>
  <div class="row"><label>Glow</label><div class="tog" data-key="glow" onclick="tog(this)"></div></div>
  <div class="row"><label>Chams</label><div class="tog" data-key="chams" onclick="tog(this)"></div></div>

  <div class="cat">Visuals</div>
  <div class="row"><label>Radar</label><div class="tog on" data-key="radar" onclick="tog(this)"></div></div>
  <div class="row"><label>FOV Changer</label><div class="tog" data-key="fovChanger" onclick="tog(this)"></div></div>
  <div class="sld"><label>Custom FOV</label><input type="range" min="60" max="160" value="120" data-key="customFOV" oninput="sld(this)"><span class="val">120</span></div>
  <div class="row"><label>Third Person</label><div class="tog" data-key="thirdPerson" onclick="tog(this)"></div></div>
  <div class="sld"><label>TP Distance</label><input type="range" min="100" max="800" value="300" data-key="thirdPersonDist" oninput="sld(this)"><span class="val">300</span></div>

  <div class="cat">Misc</div>
  <div class="row"><label>No Flash</label><div class="tog" data-key="noFlash" onclick="tog(this)"></div></div>
  <div class="row"><label>No Sway</label><div class="tog" data-key="noSway" onclick="tog(this)"></div></div>
  <div class="row"><label>Infinite Stamina</label><div class="tog" data-key="infiniteStamina" onclick="tog(this)"></div></div>
  <div class="row"><label>Speed Hack</label><div class="tog" data-key="speedHack" onclick="tog(this)"></div></div>
  <div class="sld"><label>Speed Multi</label><input type="range" min="1" max="10" value="2" data-key="speedMultiplier" oninput="sld(this)"><span class="val">2</span></div>
  <div class="row"><label>Super Jump</label><div class="tog" data-key="superJump" onclick="tog(this)"></div></div>
  <div class="sld"><label>Jump Multi</label><input type="range" min="1" max="10" value="2" data-key="jumpMultiplier" oninput="sld(this)"><span class="val">2</span></div>

  <div class="sep"></div>
  <div id="range-btns">
    <button onclick="chRange(50)">Range +</button>
    <button onclick="chRange(-50)">Range -</button>
  </div>
  <div class="sep"></div>
  <div id="plist"></div>
  <div id="conn"></div>
</div>
</div>
<script>
const C=document.getElementById('c'),X=C.getContext('2d');
let D={game:'',count:0,range:200,local:{x:0,y:0,z:0,yaw:0,team:0},scale:100,players:[],cfg:{}};
let range=200,fails=0;

function tog(el){
  const on=!el.classList.contains('on');
  el.classList.toggle('on',on);
  fetch('/api/set',{method:'POST',body:'key='+el.dataset.key+'&val='+(on?'true':'false')});
}
function sld(el){
  el.nextElementSibling.textContent=el.value;
  fetch('/api/set',{method:'POST',body:'key='+el.dataset.key+'&val='+el.value});
}
function chRange(d){range=Math.max(50,Math.min(800,range+d))}

function syncUI(cfg){
  if(!cfg)return;
  document.querySelectorAll('.tog').forEach(t=>{
    const v=cfg[t.dataset.key];
    if(v!==undefined)t.classList.toggle('on',v);
  });
  document.querySelectorAll('.sld input[type=range]').forEach(s=>{
    const v=cfg[s.dataset.key];
    if(v!==undefined){s.value=v;s.nextElementSibling.textContent=Math.round(v)}
  });
}

function sz(){
  const b=document.getElementById('radar-box');
  const s=Math.min(b.clientWidth,b.clientHeight)-20;
  const dpr=window.devicePixelRatio||1;
  C.width=s*dpr;C.height=s*dpr;
  C.style.width=s+'px';C.style.height=s+'px';
  X.setTransform(dpr,0,0,dpr,0,0);
  return s;
}
window.addEventListener('resize',()=>sz());
function deg2rad(d){return d*Math.PI/180}

function draw(){
  const s=sz(),cx=s/2,cy=s/2,r=s/2-10;
  X.clearRect(0,0,s,s);
  X.beginPath();X.arc(cx,cy,r,0,Math.PI*2);X.fillStyle='#141a14';X.fill();
  for(let f of[1,.75,.5,.25]){X.beginPath();X.arc(cx,cy,r*f,0,Math.PI*2);X.strokeStyle='#1e281e';X.lineWidth=1;X.stroke()}
  X.beginPath();X.moveTo(cx-r,cy);X.lineTo(cx+r,cy);X.moveTo(cx,cy-r);X.lineTo(cx,cy+r);X.strokeStyle='#232d23';X.stroke();
  const yaw=deg2rad(D.local.yaw||0);
  const dirs=['N','E','S','W'],angs=[0,90,180,270];
  X.font='11px Consolas';X.fillStyle='#647864';X.textAlign='center';X.textBaseline='middle';
  for(let i=0;i<4;i++){const a=deg2rad(angs[i])-yaw;X.fillText(dirs[i],cx+Math.sin(a)*(r+14),cy-Math.cos(a)*(r+14))}
  X.font='10px Consolas';X.fillStyle='#3c503c';X.textAlign='right';X.fillText(range+'m',cx+r-4,cy+14);
  X.beginPath();X.arc(cx,cy,5,0,Math.PI*2);X.fillStyle='#00c8ff';X.fill();
  X.beginPath();X.moveTo(cx,cy);X.lineTo(cx,cy-16);X.strokeStyle='#00c8ff';X.lineWidth=2;X.stroke();
  const sc=D.scale||100;const cfg=D.cfg||{};
  for(const p of D.players){
    let wx=(p.x-D.local.x)/sc,wy=(p.y-D.local.y)/sc;
    const a=-yaw,rx=wx*Math.cos(a)-wy*Math.sin(a),ry=wx*Math.sin(a)+wy*Math.cos(a);
    const scale=r/range;let px=cx+rx*scale,py=cy-ry*scale;
    const dd=Math.sqrt((px-cx)**2+(py-cy)**2);
    if(dd>r-4){const ang=Math.atan2(px-cx,cy-py);px=cx+Math.sin(ang)*(r-4);py=cy-Math.cos(ang)*(r-4)}
    const hpp=p.mhp>0?p.hp/p.mhp:1,col=hpp<.3?'#ffff00':'#ff3232',ds=p.d<50?6:p.d<150?5:4;
    // Snaplines
    if(cfg.espSnaplines){X.beginPath();X.moveTo(cx,cy);X.lineTo(px,py);X.strokeStyle='rgba(255,50,50,0.3)';X.lineWidth=1;X.stroke()}
    // Box ESP
    if(cfg.espBox){const bw=Math.max(8,20-p.d/20),bh=bw*2.2;X.strokeStyle=col;X.lineWidth=1;X.strokeRect(px-bw/2,py-bh/2,bw,bh)}
    // Dot
    X.beginPath();X.arc(px,py,ds,0,Math.PI*2);X.fillStyle=col;X.fill();
    // ESP text
    let ty=py-ds-4;X.font='9px Consolas';X.textAlign='center';X.textBaseline='bottom';
    if(cfg.espName){const nm=p.n||'Enemy';X.fillStyle='#fff';X.fillText(nm,px,ty);ty-=10}
    if(cfg.espHealth){const htxt=p.hp+'/'+p.mhp;X.fillStyle=col;X.fillText(htxt,px,ty);ty-=10}
    if(cfg.espDistance){X.fillStyle='#aaa';X.fillText(Math.round(p.d)+'m',px,ty);ty-=10}
    // Health bar under dot
    if(cfg.espHealth){const bw=Math.max(12,24-p.d/15);X.fillStyle='#333';X.fillRect(px-bw/2,py+ds+2,bw,3);const cr2=Math.round(255*(1-hpp)),cg2=Math.round(255*hpp);X.fillStyle='rgb('+cr2+','+cg2+',0)';X.fillRect(px-bw/2,py+ds+2,bw*hpp,3)}
    // Distance label (always show if no ESP distance toggle)
    if(!cfg.espDistance){X.font='10px Consolas';X.fillStyle='#b4b4b4';X.textAlign='left';X.textBaseline='middle';X.fillText(Math.round(p.d)+'',px+ds+3,py)}
  }
  requestAnimationFrame(draw);
}

async function poll(){
  try{
    const r=await fetch('/api/data');if(!r.ok)throw 0;
    D=await r.json();range=D.range||range;fails=0;
    document.getElementById('title').textContent=(D.game||'DMA')+' CHEAT';
    document.getElementById('status').textContent='Enemies: '+D.count+'  Range: '+range+'m';
    document.getElementById('conn').textContent='Connected';document.getElementById('conn').style.color='#4a4';
    syncUI(D.cfg);
    const pl=document.getElementById('plist');let h='';
    for(const p of D.players.slice(0,16)){
      const nm=p.n||'Enemy',hpp=p.mhp>0?p.hp/p.mhp:1;
      const cr=Math.round(255*(1-hpp)),cg=Math.round(255*hpp);
      h+='<div class="enemy">'+nm+'  '+Math.round(p.d)+'m  '+p.hp+'HP</div>';
      h+='<div class="hpbar"><div style="width:'+Math.round(hpp*100)+'%;background:rgb('+cr+','+cg+',0)"></div></div>';
    }
    pl.innerHTML=h;
  }catch(e){fails++;document.getElementById('conn').textContent='Disconnected ('+fails+')';document.getElementById('conn').style.color='#a44'}
  setTimeout(poll,100);
}
draw();poll();
</script>
</body></html>)HTML";

    static void HandleClient(SOCKET client) {
        char buf[8192];
        int n = recv(client, buf, sizeof(buf)-1, 0);
        if (n <= 0) { closesocket(client); return; }
        buf[n] = 0;

        std::string response;
        if (strstr(buf, "POST /api/set")) {
            char* body = strstr(buf, "\r\n\r\n");
            if (body) { body += 4; HandleToggle(body); }
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                       "Access-Control-Allow-Origin: *\r\nContent-Length: 2\r\n"
                       "Connection: close\r\n\r\nOK";
        } else if (strstr(buf, "GET /api/data")) {
            std::string json = BuildJSON();
            response = "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n"
                       "Access-Control-Allow-Origin: *\r\n"
                       "Cache-Control: no-cache\r\n"
                       "Content-Length: " + std::to_string(json.size()) + "\r\n"
                       "Connection: close\r\n\r\n" + json;
        } else if (strstr(buf, "GET / ") || strstr(buf, "GET / HTTP") ||
                   strstr(buf, "GET /index") || strstr(buf, "GET /radar") ||
                   strstr(buf, "GET /menu")) {
            std::string body = HTML_PAGE;
            response = "HTTP/1.1 200 OK\r\n"
                       "Content-Type: text/html; charset=utf-8\r\n"
                       "Cache-Control: no-cache\r\n"
                       "Content-Length: " + std::to_string(body.size()) + "\r\n"
                       "Connection: close\r\n\r\n" + body;
        } else {
            response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        }
        send(client, response.c_str(), (int)response.size(), 0);
        closesocket(client);
    }

    static void ServerThread() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
        SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (srv == INVALID_SOCKET) { printf("[!] Web: socket() failed\n"); return; }
        int opt = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((u_short)port);
        if (bind(srv, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            port++;
            addr.sin_port = htons((u_short)port);
            if (bind(srv, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
                printf("[!] Web: bind failed\n"); closesocket(srv); return;
            }
        }
        listen(srv, 16);
        char hostname[256]; gethostname(hostname, sizeof(hostname));
        addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
            printf("[+] Web menu URLs:\n");
            for (auto* p = res; p; p = p->ai_next) {
                char ip[64]; inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, ip, sizeof(ip));
                printf("    http://%s:%d\n", ip, port);
            }
            freeaddrinfo(res);
        }
        printf("    http://localhost:%d\n", port);
        fd_set readfds; timeval tv;
        while (running) {
            FD_ZERO(&readfds); FD_SET(srv, &readfds);
            tv.tv_sec = 1; tv.tv_usec = 0;
            if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
                SOCKET client = accept(srv, nullptr, nullptr);
                if (client != INVALID_SOCKET) std::thread(HandleClient, client).detach();
            }
        }
        closesocket(srv); WSACleanup();
    }

    static void Start() { std::thread(ServerThread).detach(); }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Built-in game aliases (generate default config if no ini exists)
// ═══════════════════════════════════════════════════════════════════════════════

struct GameProfile {
    const char* alias;
    const char* displayName;
    const char* processName;
    const char* moduleName;
    const char* engine;        // "ue" | "entitylist" | "unity" | "anvilnext"
    float       unitScale;     // cm->m divisor
    COLORREF    themeColor;
};

static const GameProfile g_profiles[] = {
    {"r6",            "Rainbow Six Siege",     "RainbowSix.exe",                        "RainbowSix.exe",                        "anvilnext",    1.0f, RGB(100,180,255)},
    {"rust",          "Rust",                  "RustClient.exe",                         "GameAssembly.dll",                      "unity",        1.0f, RGB(200,120,50)},
    {"apex",          "Apex Legends",          "r5apex.exe",                             "r5apex.exe",                            "ue",           1.0f, RGB(255,50,50)},
    {"bf2042",        "Battlefield 2042",      "BF2042.exe",                             "BF2042.exe",                            "ue",           1.0f, RGB(80,200,80)},
    {"tarkov",        "Escape From Tarkov",    "EscapeFromTarkov.exe",                   "UnityPlayer.dll",                       "unity",        1.0f, RGB(180,160,100)},
    {"pubg",          "PUBG",                  "TslGame.exe",                            "TslGame.exe",                           "ue",         100.0f, RGB(255,200,0)},
    {"cs2",           "Counter-Strike 2",      "cs2.exe",                                "client.dll",                            "entitylist",   1.0f, RGB(255,180,0)},
    {"hunt",          "Hunt: Showdown",        "HuntGame.exe",                           "HuntGame.exe",                          "ue",           1.0f, RGB(150,80,40)},
    {"valorant",      "Valorant",              "VALORANT-Win64-Shipping.exe",            "VALORANT-Win64-Shipping.exe",           "ue",         100.0f, RGB(255,70,85)},
    {"deltaforce",    "Delta Force",           "DeltaForce.exe",                         "DeltaForce.exe",                        "ue",         100.0f, RGB(255,160,50)},
    {"arenabreakout", "Arena Breakout",        "ArenaBreakoutInfinite-Win64-Shipping.exe","ArenaBreakoutInfinite-Win64-Shipping.exe","ue",      100.0f, RGB(100,200,255)},
    {nullptr}
};

static const GameProfile* FindProfile(const char* alias) {
    for (int i = 0; g_profiles[i].alias; i++)
        if (_stricmp(g_profiles[i].alias, alias) == 0) return &g_profiles[i];
    return nullptr;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    printf("=== Universal DMA Radar ===\n\n");

    std::string configPath;
    std::string gameAlias;
    std::string device = "fpga";
    std::string processOverride;
    int webPort = 8888;
    bool autoUpdate = true;

    // Parse command line
    char* cmd = lpCmdLine;
    while (cmd && *cmd) {
        while (*cmd == ' ') cmd++;
        if (!*cmd) break;

        if (strncmp(cmd, "--game=", 7) == 0 || strncmp(cmd, "--game ", 7) == 0) {
            cmd += 7;
            char* end = strchr(cmd, ' ');
            gameAlias = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--device=", 9) == 0) {
            cmd += 9;
            char* end = strchr(cmd, ' ');
            device = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--port=", 7) == 0 || strncmp(cmd, "--port ", 7) == 0) {
            cmd += 7;
            char* end = strchr(cmd, ' ');
            std::string pv = end ? std::string(cmd, end) : std::string(cmd);
            webPort = atoi(pv.c_str());
            if (webPort < 1 || webPort > 65535) webPort = 8888;
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--no-update", 11) == 0) {
            autoUpdate = false;
            cmd += 11;
        } else if (strncmp(cmd, "--proc=", 7) == 0) {
            cmd += 7;
            char* end = strchr(cmd, ' ');
            processOverride = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (cmd[0] != '-') {
            // Positional arg = config file
            char* end = strchr(cmd, ' ');
            configPath = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else {
            cmd++;
        }
    }

    // Determine game profile
    const GameProfile* profile = nullptr;
    std::string processName, moduleName;

    if (!gameAlias.empty()) {
        profile = FindProfile(gameAlias.c_str());
        if (!profile) {
            printf("[-] Unknown game alias: %s\n", gameAlias.c_str());
            printf("    Available: ");
            for (int i = 0; g_profiles[i].alias; i++)
                printf("%s ", g_profiles[i].alias);
            printf("\n");
            system("pause");
            return 1;
        }
        // Auto-find config: <alias>_offsets.ini
        if (configPath.empty()) {
            configPath = gameAlias + "_offsets.ini";
        }
    }

    // Auto-update offsets from GitHub before loading
    if (autoUpdate && !gameAlias.empty()) {
        std::string updatePath = configPath.empty() ? (gameAlias + "_offsets.ini") : configPath;
        TryAutoUpdate(gameAlias, updatePath);
    }

    // Load config file if it exists
    if (!configPath.empty()) {
        LoadConfig(configPath.c_str());
    }

    // Apply profile defaults where config didn't override
    if (profile) {
        if (g_strConfig.find("ProcessName") == g_strConfig.end())
            g_strConfig["ProcessName"] = profile->processName;
        if (g_strConfig.find("ModuleName") == g_strConfig.end())
            g_strConfig["ModuleName"] = profile->moduleName;
        if (g_strConfig.find("Engine") == g_strConfig.end())
            g_strConfig["Engine"] = profile->engine;
        if (g_strConfig.find("GameName") == g_strConfig.end())
            g_strConfig["GameName"] = profile->displayName;
        if (g_offsets.find("UnitScale") == g_offsets.end())
            g_offsets["UnitScale"] = (uint64_t)profile->unitScale; // close enough for int check
        g_unitScale = profile->unitScale;
        Radar::themeColor = profile->themeColor;
    }

    processName = Str("ProcessName", "UNKNOWN.exe");
    moduleName  = Str("ModuleName", processName.c_str());
    Radar::gameName = Str("GameName", processName.c_str());

    if (!processOverride.empty()) processName = processOverride;

    if (g_offsets.count("UnitScale")) g_unitScale = (float)Off("UnitScale", 100);
    if (g_unitScale < 0.01f) g_unitScale = 1.0f;

    O::Init();

    printf("[*] Game: %s\n", Radar::gameName.c_str());
    printf("[*] Process: %s  Module: %s  Engine: %s\n",
           processName.c_str(), moduleName.c_str(), O::engine.c_str());

    if (!O::GWorld && !O::EntityList && !Off("GameManager")) {
        printf("[!] No GWorld, EntityList, or GameManager offset configured.\n");
        printf("    Run dma_main.exe --offsets to find offsets, then fill in %s\n",
               configPath.empty() ? "<game>_offsets.ini" : configPath.c_str());
    }

    printf("[*] Loading VMM...\n");
    if (!LoadVMM()) return 1;

    printf("[*] Initializing DMA (%s)...\n", device.c_str());
    LPCSTR args[] = { "", "-device", device.c_str(), "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) {
        MessageBoxA(NULL, "DMA init failed.\nCheck FPGA and USB.", "DMA Error", MB_ICONERROR);
        return 1;
    }
    printf("[+] DMA initialized\n");

    printf("[*] Waiting for %s on target...\n", processName.c_str());
    while (!pPidGet(g_vmm, processName.c_str(), &g_pid)) {
        if (GetAsyncKeyState(VK_END) & 1) { pClose(g_vmm); return 0; }
        Sleep(2000);
        printf(".");
    }
    printf("\n[+] %s  PID=%u\n", processName.c_str(), g_pid);

    g_base = pModBase ? pModBase(g_vmm, g_pid, moduleName.c_str()) : 0;
    if (!g_base) {
        printf("[!] Module base not found, using 0x140000000\n");
        g_base = 0x140000000;
    }
    printf("[+] Base: 0x%llX\n", (unsigned long long)g_base);

    // Start web radar server
    WebRadar::port = webPort;
    WebRadar::Start();

    printf("[+] Radar starting  |  PgUp/PgDn = Range  |  END = Exit\n\n");

    std::thread dataThread([&]() {
        while (Radar::running) {
            { std::lock_guard<std::mutex> lock(g_dataMutex); ReadPlayers(); }
            ApplyFeatures();
            Sleep(10 + (GetTickCount() % 5));
        }
    });
    dataThread.detach();

    Radar::Run();

    WebRadar::running = false;
    pClose(g_vmm);
    return 0;
}
