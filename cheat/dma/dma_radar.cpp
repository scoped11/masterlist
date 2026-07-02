// Universal DMA Radar — ESP radar via FPGA DMA card
// Works with any game by loading a per-game offset config.
// Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS)
// Build: cl /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS dma_radar.cpp gdi32.lib user32.lib winmm.lib /link /SUBSYSTEM:WINDOWS
//
// Usage: dma_radar.exe <game_config.ini>
//        dma_radar.exe --game r6
//        dma_radar.exe --game apex
//
// Supported game aliases:
//   r6, rust, apex, bf2042, tarkov, pubg, cs2, hunt, valorant,
//   deltaforce, arenabreakout

#undef UNICODE
#undef _UNICODE
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

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winmm.lib")


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

    // Pointer chain style: "ue" (GWorld chain) or "entitylist" (Source 2 / Frostbite)
    std::string engine;

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
    uint64_t localPawn = rpm<uint64_t>(pc + O::AcknowledgedPawn);

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
            if (p.valid) count++;
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
        count++;
    }
    g_playerCount = count;
}

static void ReadPlayers() {
    if (O::engine == "entitylist")    ReadPlayers_EntityList();
    else if (O::engine == "unity")   ReadPlayers_Unity();
    else                             ReadPlayers_UE();
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
// Built-in game aliases (generate default config if no ini exists)
// ═══════════════════════════════════════════════════════════════════════════════

struct GameProfile {
    const char* alias;
    const char* displayName;
    const char* processName;
    const char* moduleName;
    const char* engine;        // "ue" | "entitylist" | "unity"
    float       unitScale;     // cm->m divisor
    COLORREF    themeColor;
};

static const GameProfile g_profiles[] = {
    {"r6",            "Rainbow Six Siege",     "RainbowSix.exe",                        "RainbowSix.exe",                        "ue",         100.0f, RGB(100,180,255)},
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

    if (!O::GWorld && !O::EntityList) {
        printf("[!] No GWorld or EntityList offset configured.\n");
        printf("    Run dumper_dma.exe to find offsets, then fill in %s\n",
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

    printf("[+] Radar starting  |  PgUp/PgDn = Range  |  END = Exit\n\n");

    std::thread dataThread([&]() {
        while (Radar::running) {
            { std::lock_guard<std::mutex> lock(g_dataMutex); ReadPlayers(); }
            Sleep(10 + (GetTickCount() % 5));
        }
    });
    dataThread.detach();

    Radar::Run();

    pClose(g_vmm);
    return 0;
}
