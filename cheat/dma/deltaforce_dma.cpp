// Delta Force DMA External — ESP radar via FPGA DMA card
// Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.
// Completely invisible to all anti-cheat — reads happen at the PCIe level.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS)
// Build: cl /O2 /EHsc deltaforce_dma.cpp gdi32.lib user32.lib winmm.lib /link /SUBSYSTEM:WINDOWS

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

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winmm.lib")

// ═══════════════════════════════════════════════════════════════════════════════
// VMM API types (dynamically loaded from vmm.dll)
// ═══════════════════════════════════════════════════════════════════════════════

typedef void* VMM_HANDLE;

typedef VMM_HANDLE  (__cdecl *fn_VMMDLL_Initialize)(DWORD argc, LPCSTR argv[]);
typedef VOID        (__cdecl *fn_VMMDLL_Close)(VMM_HANDLE hVMM);
typedef BOOL        (__cdecl *fn_VMMDLL_PidGetFromName)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL        (__cdecl *fn_VMMDLL_MemReadEx)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64     (__cdecl *fn_VMMDLL_ProcessGetModuleBaseU)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef HANDLE      (__cdecl *fn_VMMDLL_Scatter_Initialize)(VMM_HANDLE hVMM, DWORD dwPID, DWORD flags);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Prepare)(HANDLE hS, ULONG64 va, DWORD cb);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Execute)(HANDLE hS);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Read)(HANDLE hS, ULONG64 va, DWORD cb, PBYTE pb, PDWORD pcbRead);
typedef VOID        (__cdecl *fn_VMMDLL_Scatter_CloseHandle)(HANDLE hS);

static VMM_HANDLE g_vmm = nullptr;
static DWORD      g_pid = 0;

static fn_VMMDLL_Initialize             pInitialize = nullptr;
static fn_VMMDLL_Close                  pClose = nullptr;
static fn_VMMDLL_PidGetFromName         pPidGetFromName = nullptr;
static fn_VMMDLL_MemReadEx              pMemReadEx = nullptr;
static fn_VMMDLL_ProcessGetModuleBaseU  pGetModuleBase = nullptr;
static fn_VMMDLL_Scatter_Initialize     pScatterInit = nullptr;
static fn_VMMDLL_Scatter_Prepare        pScatterPrep = nullptr;
static fn_VMMDLL_Scatter_Execute        pScatterExec = nullptr;
static fn_VMMDLL_Scatter_Read           pScatterRead = nullptr;
static fn_VMMDLL_Scatter_CloseHandle    pScatterClose = nullptr;

static bool LoadVMM() {
    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { MessageBoxA(NULL, "vmm.dll not found.\nPlace vmm.dll + leechcore.dll in the same directory.", "DMA Error", MB_ICONERROR); return false; }
    #define LOAD(name) p##name = (fn_VMMDLL_##name)GetProcAddress(h, "VMMDLL_" #name)
    LOAD(Initialize); LOAD(Close); LOAD(PidGetFromName); LOAD(MemReadEx);
    LOAD(ProcessGetModuleBaseU);
    LOAD(Scatter_Initialize); LOAD(Scatter_Prepare); LOAD(Scatter_Execute);
    LOAD(Scatter_Read); LOAD(Scatter_CloseHandle);
    #undef LOAD
    return pInitialize && pMemReadEx;
}

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cbRead = 0;
    return pMemReadEx(g_vmm, g_pid, va, (PBYTE)buf, size, &cbRead, 0x0002) && cbRead > 0;
}

template<class T> T rpm(uint64_t addr) { T v{}; DmaRead(addr, &v, sizeof(T)); return v; }


// ═══════════════════════════════════════════════════════════════════════════════
// Offset config — loaded from df_offsets.ini
// ═══════════════════════════════════════════════════════════════════════════════

static std::unordered_map<std::string, uint64_t> g_offsets;

static void LoadOffsets(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) return;
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
        if (!key.empty()) g_offsets[key] = strtoull(val.c_str(), nullptr, 0);
    }
}

static uint64_t Off(const char* name, uint64_t fallback = 0) {
    auto it = g_offsets.find(name);
    return (it != g_offsets.end()) ? it->second : fallback;
}


// ═══════════════════════════════════════════════════════════════════════════════
// UE5 Offsets
// ═══════════════════════════════════════════════════════════════════════════════

namespace Offsets {
    uint64_t GWorld;
    uint64_t OwningGameInstance;
    uint64_t LocalPlayers;
    uint64_t PlayerController;
    uint64_t AcknowledgedPawn;
    uint64_t PlayerCameraManager;
    uint64_t PersistentLevel;
    uint64_t Actors;
    uint64_t ActorCount;
    uint64_t RootComponent;
    uint64_t ActorMesh;
    uint64_t RelativeLocation;
    uint64_t ComponentToWorld;
    uint64_t TeamIndex;
    uint64_t Health;
    uint64_t MaxHealth;
    uint64_t bIsDead;
    uint64_t BoneArray;
    uint64_t ComponentToWorldMatrix;
    uint64_t CameraLocation;
    uint64_t CameraRotation;
    uint64_t CameraFOV;
    uint64_t PlayerNamePrivate;

    void Init() {
        GWorld                 = Off("GWorld",                  0x0);
        OwningGameInstance     = Off("OwningGameInstance",       0x1B8);
        LocalPlayers           = Off("LocalPlayers",             0x38);
        PlayerController       = Off("PlayerController",         0x30);
        AcknowledgedPawn       = Off("AcknowledgedPawn",         0x338);
        PlayerCameraManager    = Off("PlayerCameraManager",      0x348);
        PersistentLevel        = Off("PersistentLevel",          0x30);
        Actors                 = Off("Actors",                   0x98);
        ActorCount             = Off("ActorCount",               0xA0);
        RootComponent          = Off("RootComponent",            0x190);
        ActorMesh              = Off("ActorMesh",                0x310);
        RelativeLocation       = Off("RelativeLocation",         0x128);
        ComponentToWorld       = Off("ComponentToWorld",          0x1C0);
        TeamIndex              = Off("TeamIndex",                 0x10C);
        Health                 = Off("Health",                    0x0);
        MaxHealth              = Off("MaxHealth",                 0x0);
        bIsDead                = Off("bIsDead",                   0x0);
        BoneArray              = Off("BoneArray",                 0x5B0);
        ComponentToWorldMatrix = Off("ComponentToWorldMatrix",    0x1C0);
        CameraLocation         = Off("CameraLocation",            0x0);
        CameraRotation         = Off("CameraRotation",            0x0);
        CameraFOV              = Off("CameraFOV",                 0x0);
        PlayerNamePrivate      = Off("PlayerNamePrivate",          0x310);
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

static float Vec2Dist(float x1, float y1, float x2, float y2) {
    float dx = x1-x2, dy = y1-y2;
    return sqrtf(dx*dx + dy*dy);
}

static Vec3 GetBoneWorldPos(FTransform bone, FTransform compToWorld) {
    float bx = bone.translation.x * compToWorld.scale3d.x;
    float by = bone.translation.y * compToWorld.scale3d.y;
    float bz = bone.translation.z * compToWorld.scale3d.z;
    float qx = compToWorld.rotation[0], qy = compToWorld.rotation[1];
    float qz = compToWorld.rotation[2], qw = compToWorld.rotation[3];
    float ix = qw*bx + qy*bz - qz*by;
    float iy = qw*by + qz*bx - qx*bz;
    float iz = qw*bz + qx*by - qy*bx;
    float iw = -qx*bx - qy*by - qz*bz;
    return {
        ix*qw + iw*-qx + iy*-qz - iz*-qy + compToWorld.translation.x,
        iy*qw + iw*-qy + iz*-qx - ix*-qz + compToWorld.translation.y,
        iz*qw + iw*-qz + ix*-qy - iy*-qx + compToWorld.translation.z
    };
}


// ═══════════════════════════════════════════════════════════════════════════════
// Entity reading
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t g_base = 0;

struct PlayerData {
    Vec3     origin;
    Vec3     headPos;
    int      health, maxHealth;
    int      team;
    float    distance;
    wchar_t  name[64];
    bool     valid;
};

enum Bones : int {
    BONE_HEAD = 6,
};

static int          g_localTeam = 0;
static Vec3         g_localPos = {};
static float        g_localYaw = 0;
static float        g_cameraFOV = 90.0f;
static PlayerData   g_players[100];
static int          g_playerCount = 0;
static std::mutex   g_dataMutex;

static bool IsPlayerActor(uint64_t actor) {
    if (!actor) return false;
    uint64_t mesh = rpm<uint64_t>(actor + Offsets::ActorMesh);
    if (!mesh) return false;
    uint64_t root = rpm<uint64_t>(actor + Offsets::RootComponent);
    return root != 0;
}

static Vec3 GetActorLocation(uint64_t actor) {
    uint64_t root = rpm<uint64_t>(actor + Offsets::RootComponent);
    if (!root) return {};
    return rpm<Vec3>(root + Offsets::RelativeLocation);
}

static Vec3 GetBonePos(uint64_t actor, int boneId) {
    uint64_t mesh = rpm<uint64_t>(actor + Offsets::ActorMesh);
    if (!mesh) return {};
    FTransform compToWorld = rpm<FTransform>(mesh + Offsets::ComponentToWorldMatrix);
    uint64_t boneArray = rpm<uint64_t>(mesh + Offsets::BoneArray);
    if (!boneArray) return {};
    FTransform bone = rpm<FTransform>(boneArray + (uint64_t)boneId * sizeof(FTransform));
    return GetBoneWorldPos(bone, compToWorld);
}

static void ReadPlayers() {
    uint64_t gworld = rpm<uint64_t>(g_base + Offsets::GWorld);
    if (!gworld) return;

    uint64_t gameInst = rpm<uint64_t>(gworld + Offsets::OwningGameInstance);
    if (!gameInst) return;
    uint64_t localPlayersPtr = rpm<uint64_t>(gameInst + Offsets::LocalPlayers);
    if (!localPlayersPtr) return;
    uint64_t localPlayer = rpm<uint64_t>(localPlayersPtr);
    if (!localPlayer) return;
    uint64_t playerController = rpm<uint64_t>(localPlayer + Offsets::PlayerController);
    if (!playerController) return;
    uint64_t localPawn = rpm<uint64_t>(playerController + Offsets::AcknowledgedPawn);

    uint64_t camMgr = rpm<uint64_t>(playerController + Offsets::PlayerCameraManager);
    if (camMgr && Offsets::CameraLocation && Offsets::CameraRotation) {
        g_localPos = rpm<Vec3>(camMgr + Offsets::CameraLocation);
        FRotator rot = rpm<FRotator>(camMgr + Offsets::CameraRotation);
        g_localYaw = rot.yaw;
        if (Offsets::CameraFOV)
            g_cameraFOV = rpm<float>(camMgr + Offsets::CameraFOV);
    } else if (localPawn) {
        uint64_t root = rpm<uint64_t>(localPawn + Offsets::RootComponent);
        if (root) g_localPos = rpm<Vec3>(root + Offsets::RelativeLocation);
        g_localPos.z += 70.0f;
    }

    if (localPawn && Offsets::TeamIndex)
        g_localTeam = rpm<int>(localPawn + Offsets::TeamIndex);

    uint64_t level = rpm<uint64_t>(gworld + Offsets::PersistentLevel);
    if (!level) return;
    int32_t actorCount = rpm<int32_t>(level + Offsets::ActorCount);
    uint64_t actorArray = rpm<uint64_t>(level + Offsets::Actors);
    if (!actorArray || actorCount <= 0) return;
    if (actorCount > 10000) actorCount = 10000;

    int count = 0;
    const int CHUNK = 256;
    for (int base = 0; base < actorCount && count < 100; base += CHUNK) {
        int batch = (actorCount - base < CHUNK) ? (actorCount - base) : CHUNK;
        uint64_t ptrs[256] = {};
        DmaRead(actorArray + (uint64_t)base * 8, ptrs, batch * 8);

        for (int i = 0; i < batch && count < 100; i++) {
            uint64_t actor = ptrs[i];
            if (!actor || actor == localPawn) continue;
            if (!IsPlayerActor(actor)) continue;

            int team = 0;
            if (Offsets::TeamIndex)
                team = rpm<int>(actor + Offsets::TeamIndex);
            if (team == g_localTeam && team != 0) continue;

            Vec3 origin = GetActorLocation(actor);
            if (origin.x == 0 && origin.y == 0 && origin.z == 0) continue;
            float dist = Vec3Dist(g_localPos, origin) / 100.0f;
            if (dist > 600.0f || dist < 0.5f) continue;

            bool dead = false;
            if (Offsets::bIsDead)
                dead = rpm<uint8_t>(actor + Offsets::bIsDead) != 0;
            if (dead) continue;

            PlayerData& p = g_players[count];
            p.origin   = origin;
            p.team     = team;
            p.distance = dist;

            if (Offsets::Health) {
                p.health    = rpm<int>(actor + Offsets::Health);
                p.maxHealth = Offsets::MaxHealth ? rpm<int>(actor + Offsets::MaxHealth) : 100;
            } else { p.health = 100; p.maxHealth = 100; }

            p.headPos = GetBonePos(actor, BONE_HEAD);
            if (p.headPos.x == 0 && p.headPos.y == 0 && p.headPos.z == 0)
                p.headPos = { origin.x, origin.y, origin.z + 70.0f };

            p.name[0] = 0;
            if (Offsets::PlayerNamePrivate) {
                int32_t len = rpm<int32_t>(actor + Offsets::PlayerNamePrivate);
                if (len > 0 && len < 63) {
                    uint64_t dataPtr = rpm<uint64_t>(actor + Offsets::PlayerNamePrivate + 8);
                    if (dataPtr) DmaRead(dataPtr, p.name, len * 2);
                    p.name[len] = 0;
                }
            }

            p.valid = (p.health > 0);
            if (p.valid) count++;
        }
    }
    g_playerCount = count;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Radar overlay — 2D top-down radar + info panel on PC2
// ═══════════════════════════════════════════════════════════════════════════════

namespace Radar {
    static HWND hwnd = NULL;
    static std::atomic<bool> running{true};
    static HFONT fontMain = NULL;
    static HFONT fontSmall = NULL;
    static HFONT fontTitle = NULL;

    static int radarSize    = 500;
    static float radarRange = 200.0f; // meters

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

    static void DrawFilledCircle(HDC hdc, int cx, int cy, int r, COLORREF c) {
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
        int r = (int)(255 * (1-hp));
        int g = (int)(255 * hp);
        DrawFilled(hdc, x+1, y+1, fillW, h-2, RGB(r,g,0));
    }

    static void RenderRadar(HDC hdc) {
        int ww = radarSize + 260;
        int wh = radarSize + 60;

        // Background
        DrawFilled(hdc, 0, 0, ww, wh, RGB(12, 12, 18));

        int cx = 30 + radarSize / 2;
        int cy = 30 + radarSize / 2;
        int radius = radarSize / 2;

        // Radar background
        DrawFilledCircle(hdc, cx, cy, radius, RGB(20, 25, 20));

        // Range rings
        DrawCircle(hdc, cx, cy, radius, RGB(40, 50, 40));
        DrawCircle(hdc, cx, cy, radius * 3/4, RGB(30, 40, 30));
        DrawCircle(hdc, cx, cy, radius / 2, RGB(30, 40, 30));
        DrawCircle(hdc, cx, cy, radius / 4, RGB(30, 40, 30));

        // Crosshair
        DrawLine(hdc, cx - radius, cy, cx + radius, cy, RGB(35, 45, 35));
        DrawLine(hdc, cx, cy - radius, cx, cy + radius, RGB(35, 45, 35));

        // Compass labels
        float yawRad = DEG2RAD(g_localYaw);
        const char* dirs[] = {"N", "E", "S", "W"};
        float angles[] = {0, 90, 180, 270};
        for (int i = 0; i < 4; i++) {
            float a = DEG2RAD(angles[i]) - yawRad;
            int lx = cx + (int)(sinf(a) * (radius + 12));
            int ly = cy - (int)(cosf(a) * (radius + 12));
            DrawText_(hdc, lx - 4, ly - 6, dirs[i], RGB(100, 120, 100), fontSmall);
        }

        // Range label
        char rangeBuf[32];
        snprintf(rangeBuf, sizeof(rangeBuf), "%.0fm", radarRange);
        DrawText_(hdc, cx + radius - 30, cy + 4, rangeBuf, RGB(60, 80, 60), fontSmall);

        // Local player (center dot)
        DrawFilledCircle(hdc, cx, cy, 5, RGB(0, 200, 255));

        // Direction indicator (line showing where local player faces)
        int dirLen = 18;
        int dx = cx + (int)(sinf(0) * dirLen);  // forward is always up on radar
        int dy = cy - (int)(cosf(0) * dirLen);
        DrawLine(hdc, cx, cy, dx, dy, RGB(0, 200, 255), 2);

        // Enemy dots
        std::lock_guard<std::mutex> lock(g_dataMutex);

        for (int i = 0; i < g_playerCount; i++) {
            auto& p = g_players[i];
            if (!p.valid) continue;

            // World-space delta from local player
            float wx = (p.origin.x - g_localPos.x) / 100.0f; // UE5 cm -> m
            float wy = (p.origin.y - g_localPos.y) / 100.0f;

            // Rotate by negative local yaw so radar is north-up relative to player facing
            float a = -DEG2RAD(g_localYaw);
            float rx = wx * cosf(a) - wy * sinf(a);
            float ry = wx * sinf(a) + wy * cosf(a);

            // Scale to radar pixel space
            float scale = (float)radius / radarRange;
            int px = cx + (int)(rx * scale);
            int py = cy - (int)(ry * scale);

            // Clamp to radar circle
            float distFromCenter = Vec2Dist((float)px, (float)py, (float)cx, (float)cy);
            if (distFromCenter > radius - 4) {
                float ang = atan2f((float)(px - cx), (float)(cy - py));
                px = cx + (int)(sinf(ang) * (radius - 4));
                py = cy - (int)(cosf(ang) * (radius - 4));
            }

            // Color: red for enemy, yellow if low HP
            float hpPct = (p.maxHealth > 0) ? (float)p.health / p.maxHealth : 1.0f;
            COLORREF dotCol = (hpPct < 0.3f) ? RGB(255, 255, 0) : RGB(255, 50, 50);

            int dotSize = (p.distance < 50.0f) ? 6 : (p.distance < 150.0f) ? 5 : 4;
            DrawFilledCircle(hdc, px, py, dotSize, dotCol);

            // Distance label near dot
            char distTxt[16];
            snprintf(distTxt, sizeof(distTxt), "%.0f", p.distance);
            DrawText_(hdc, px + dotSize + 2, py - 5, distTxt, RGB(180, 180, 180), fontSmall);
        }

        // ── Info panel (right side) ──
        int panelX = radarSize + 50;
        int panelY = 20;

        char title[64];
        snprintf(title, sizeof(title), "DELTA FORCE DMA");
        DrawText_(hdc, panelX, panelY, title, RGB(255, 160, 50), fontTitle);
        panelY += 24;

        char status[128];
        snprintf(status, sizeof(status), "Enemies: %d  |  Range: %.0fm", g_playerCount, radarRange);
        DrawText_(hdc, panelX, panelY, status, RGB(180, 180, 180), fontMain);
        panelY += 20;

        DrawLine(hdc, panelX, panelY, panelX + 210, panelY, RGB(50, 50, 50));
        panelY += 8;

        // Player list
        for (int i = 0; i < g_playerCount && i < 16; i++) {
            auto& p = g_players[i];
            if (!p.valid) continue;

            COLORREF nameCol = RGB(255, 100, 100);

            // Name or "Enemy"
            char nameBuf[128] = "Enemy";
            if (p.name[0])
                WideCharToMultiByte(CP_ACP, 0, p.name, -1, nameBuf, 127, NULL, NULL);

            char line[256];
            snprintf(line, sizeof(line), "%s  %.0fm  %dHP", nameBuf, p.distance, p.health);
            DrawText_(hdc, panelX, panelY, line, nameCol, fontSmall);
            panelY += 14;

            // Mini health bar
            float hp = (p.maxHealth > 0) ? (float)p.health / p.maxHealth : 1.0f;
            DrawHealthBar(hdc, panelX, panelY, 120, 6, hp);
            panelY += 12;
        }

        // Controls
        panelY = wh - 60;
        DrawText_(hdc, panelX, panelY, "PgUp/PgDn: Range", RGB(100, 100, 100), fontSmall);
        panelY += 14;
        DrawText_(hdc, panelX, panelY, "END: Exit", RGB(100, 100, 100), fontSmall);
    }

    LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
        if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
        if (msg == WM_KEYDOWN) {
            if (wp == VK_END) { running = false; PostQuitMessage(0); return 0; }
            if (wp == VK_PRIOR) { radarRange = min(radarRange + 50.0f, 800.0f); return 0; }
            if (wp == VK_NEXT) { radarRange = max(radarRange - 50.0f, 50.0f); return 0; }
        }
        return DefWindowProcA(h, msg, wp, lp);
    }

    void Run() {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = "DfDmaRadar";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        RegisterClassExA(&wc);

        int ww = radarSize + 260;
        int wh = radarSize + 60;

        hwnd = CreateWindowExA(
            WS_EX_TOPMOST, "DfDmaRadar", "Delta Force DMA Radar",
            WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
            100, 100, ww, wh,
            NULL, NULL, GetModuleHandle(NULL), NULL);

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        fontMain  = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Consolas");
        fontSmall = CreateFontA(11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Consolas");
        fontTitle = CreateFontA(16, 0, 0, 0, FW_BOLD,   0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Consolas");

        HDC memDC = NULL;
        HBITMAP memBmp = NULL, memOld = NULL;

        MSG msg;
        while (running) {
            while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) { running = false; break; }
                TranslateMessage(&msg); DispatchMessageA(&msg);
            }
            if (!running) break;

            RECT cr;
            GetClientRect(hwnd, &cr);
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

            Sleep(16); // ~60 fps
        }

        if (memBmp) { SelectObject(memDC, memOld); DeleteObject(memBmp); }
        if (memDC) DeleteDC(memDC);
        if (fontMain) DeleteObject(fontMain);
        if (fontSmall) DeleteObject(fontSmall);
        if (fontTitle) DeleteObject(fontTitle);
        DestroyWindow(hwnd);
        UnregisterClassA("DfDmaRadar", GetModuleHandle(NULL));
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    printf("=== Delta Force DMA Radar ===\n\n");

    // Parse command line
    std::string offsetsPath = "df_offsets.ini";
    std::string device = "fpga";
    std::string processName = "DeltaForce.exe";
    std::string moduleName = "DeltaForce.exe";

    // Simple cmdline parse
    char* cmd = lpCmdLine;
    while (cmd && *cmd) {
        while (*cmd == ' ') cmd++;
        if (strncmp(cmd, "--offsets=", 9) == 0) {
            cmd += 9;
            char* end = strchr(cmd, ' ');
            offsetsPath = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--device=", 9) == 0) {
            cmd += 9;
            char* end = strchr(cmd, ' ');
            device = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--proc=", 7) == 0) {
            cmd += 7;
            char* end = strchr(cmd, ' ');
            processName = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else {
            cmd++;
        }
    }

    LoadOffsets(offsetsPath.c_str());

    // Read string overrides from offsets file
    {
        std::ifstream f(offsetsPath);
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            key.erase(key.find_last_not_of(" \t\r\n") + 1);
            key.erase(0, key.find_first_not_of(" \t\r\n"));
            val.erase(val.find_last_not_of(" \t\r\n") + 1);
            val.erase(0, val.find_first_not_of(" \t\r\n"));
            if (key == "ProcessName") processName = val;
            else if (key == "ModuleName") moduleName = val;
        }
    }

    Offsets::Init();

    printf("[*] Loading VMM API...\n");
    if (!LoadVMM()) return 1;

    printf("[*] Initializing DMA (%s)...\n", device.c_str());
    LPCSTR args[] = { "", "-device", device.c_str(), "-v", "-printf", "-waitinitialize" };
    g_vmm = pInitialize(6, args);
    if (!g_vmm) {
        printf("[-] DMA initialization failed. Check FPGA card connection.\n");
        MessageBoxA(NULL, "DMA init failed.\nCheck FPGA card and USB connection.", "DMA Error", MB_ICONERROR);
        return 1;
    }
    printf("[+] DMA initialized\n");

    printf("[*] Waiting for %s on target PC...\n", processName.c_str());
    while (!pPidGetFromName(g_vmm, processName.c_str(), &g_pid)) {
        if (GetAsyncKeyState(VK_END) & 1) { pClose(g_vmm); return 0; }
        Sleep(2000);
        printf(".");
    }
    printf("\n[+] Found %s  PID=%u\n", processName.c_str(), g_pid);

    g_base = pGetModuleBase ? pGetModuleBase(g_vmm, g_pid, moduleName.c_str()) : 0;
    if (!g_base) {
        printf("[!] Module base not found, using default 0x140000000\n");
        g_base = 0x140000000;
    }
    printf("[+] %s base: 0x%llX\n", moduleName.c_str(), (unsigned long long)g_base);

    if (!Offsets::GWorld) {
        printf("[!] GWorld offset is 0 — configure %s with correct offsets.\n", offsetsPath.c_str());
        printf("    Use dumper_dma.exe to find offsets for your game version.\n\n");
    }

    printf("[+] Starting radar overlay\n");
    printf("    PgUp/PgDn = Adjust range\n");
    printf("    END = Exit\n\n");

    // Data read thread
    std::thread dataThread([&]() {
        while (Radar::running) {
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                ReadPlayers();
            }
            Sleep(10 + (GetTickCount() % 5));
        }
    });
    dataThread.detach();

    // Radar runs on main thread (message loop)
    Radar::Run();

    printf("[*] Shutting down...\n");
    pClose(g_vmm);
    return 0;
}
