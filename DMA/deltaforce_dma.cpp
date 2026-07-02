// Delta Force DMA Cheat — Full-feature DMA via FPGA card
// UE5 GWorld chain reader + DMA write features + web menu
// Runs on PC2 (cheat), reads/writes PC1 (target) memory over hardware DMA.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS)
// Build: cl /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS deltaforce_dma.cpp gdi32.lib user32.lib winmm.lib ws2_32.lib /link /SUBSYSTEM:WINDOWS

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
#include <sstream>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ws2_32.lib")


// ═══════════════════════════════════════════════════════════════════════════════
// VMM API (dynamically loaded from vmm.dll)
// ═══════════════════════════════════════════════════════════════════════════════

typedef void* VMM_HANDLE;

typedef VMM_HANDLE  (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID        (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL        (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL        (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64     (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef BOOL        (__cdecl *fn_MemWrite)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb);

static VMM_HANDLE g_vmm = nullptr;
static DWORD      g_pid = 0;

static fn_Init     pInit = nullptr;
static fn_Close    pClose = nullptr;
static fn_PidGet   pPidGet = nullptr;
static fn_MemRead  pMemRead = nullptr;
static fn_ModBase  pModBase = nullptr;
static fn_MemWrite pMemWrite = nullptr;

static bool LoadVMM() {
    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { MessageBoxA(NULL, "vmm.dll not found.\nPlace vmm.dll + leechcore.dll here.", "DMA Error", MB_ICONERROR); return false; }
    pInit     = (fn_Init)    GetProcAddress(h, "VMMDLL_Initialize");
    pClose    = (fn_Close)   GetProcAddress(h, "VMMDLL_Close");
    pPidGet   = (fn_PidGet)  GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead  = (fn_MemRead) GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase  = (fn_ModBase) GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");
    pMemWrite = (fn_MemWrite)GetProcAddress(h, "VMMDLL_MemWrite");
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
    inline std::atomic<float> speedMultiplier{2.0f};
    inline std::atomic<float> jumpMultiplier{2.0f};
    inline std::atomic<float> thirdPersonDist{300.0f};
    inline int aimTargetIndex = -1;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Offset config — loaded from df_offsets.ini
// ═══════════════════════════════════════════════════════════════════════════════

static std::unordered_map<std::string, uint64_t> g_offsets;
static std::unordered_map<std::string, std::string> g_strConfig;

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
    printf("[+] Loaded config: %s\n", path);
}

static std::string Str(const char* key, const char* fb = "") {
    auto it = g_strConfig.find(key); return (it != g_strConfig.end()) ? it->second : fb;
}
static uint64_t Off(const char* key, uint64_t fb = 0) {
    auto it = g_offsets.find(key); return (it != g_offsets.end()) ? it->second : fb;
}


// ═══════════════════════════════════════════════════════════════════════════════
// UE5 Offsets
// ═══════════════════════════════════════════════════════════════════════════════

namespace O {
    uint64_t GWorld, OwningGameInstance, LocalPlayers, PlayerController, AcknowledgedPawn;
    uint64_t PlayerCameraManager, PersistentLevel, Actors, ActorCount;
    uint64_t RootComponent, ActorMesh, RelativeLocation, ComponentToWorldMatrix;
    uint64_t TeamIndex, Health, MaxHealth, bIsDead, BoneArray;
    uint64_t CameraLocation, CameraRotation, CameraFOV, PlayerNamePrivate;
    // Write-target offsets
    uint64_t GlowEnable, GlowThroughWalls, GlowColor;
    uint64_t ControlRotation, RecoilPitch, RecoilYaw, ViewAngles;
    uint64_t FireRate, SpreadAngle;
    uint64_t ChamsEnable, ChamsThroughWalls, ChamsColor;
    uint64_t FlashAlpha, FlashMaxAlpha, SwayScale;
    uint64_t Stamina, MaxStamina, MovementSpeed, MaxWalkSpeed;
    uint64_t JumpZVelocity, ThirdPersonOffset;
    uint64_t DefaultMaxWalkSpeed, DefaultJumpZ;

    void Init() {
        GWorld                 = Off("GWorld", 0x0);
        OwningGameInstance     = Off("OwningGameInstance", 0x1B8);
        LocalPlayers           = Off("LocalPlayers", 0x38);
        PlayerController       = Off("PlayerController", 0x30);
        AcknowledgedPawn       = Off("AcknowledgedPawn", 0x338);
        PlayerCameraManager    = Off("PlayerCameraManager", 0x348);
        PersistentLevel        = Off("PersistentLevel", 0x30);
        Actors                 = Off("Actors", 0x98);
        ActorCount             = Off("ActorCount", 0xA0);
        RootComponent          = Off("RootComponent", 0x190);
        ActorMesh              = Off("ActorMesh", 0x310);
        RelativeLocation       = Off("RelativeLocation", 0x128);
        ComponentToWorldMatrix = Off("ComponentToWorldMatrix", 0x1C0);
        TeamIndex              = Off("TeamIndex", 0x10C);
        Health                 = Off("Health", 0x0);
        MaxHealth              = Off("MaxHealth", 0x0);
        bIsDead                = Off("bIsDead", 0x0);
        BoneArray              = Off("BoneArray", 0x5B0);
        CameraLocation         = Off("CameraLocation", 0x0);
        CameraRotation         = Off("CameraRotation", 0x0);
        CameraFOV              = Off("CameraFOV", 0x0);
        PlayerNamePrivate      = Off("PlayerNamePrivate", 0x0);
        GlowEnable             = Off("GlowEnable", 0x0);
        GlowThroughWalls       = Off("GlowThroughWalls", 0x0);
        GlowColor              = Off("GlowColor", 0x0);
        ControlRotation        = Off("ControlRotation", 0x0);
        RecoilPitch            = Off("RecoilPitch", 0x0);
        RecoilYaw              = Off("RecoilYaw", 0x0);
        ViewAngles             = Off("ViewAngles", 0x0);
        FireRate               = Off("FireRate", 0x0);
        SpreadAngle            = Off("SpreadAngle", 0x0);
        ChamsEnable            = Off("ChamsEnable", 0x0);
        ChamsThroughWalls      = Off("ChamsThroughWalls", 0x0);
        ChamsColor             = Off("ChamsColor", 0x0);
        FlashAlpha             = Off("FlashAlpha", 0x0);
        FlashMaxAlpha          = Off("FlashMaxAlpha", 0x0);
        SwayScale              = Off("SwayScale", 0x0);
        Stamina                = Off("Stamina", 0x0);
        MaxStamina             = Off("MaxStamina", 0x0);
        MovementSpeed          = Off("MovementSpeed", 0x0);
        MaxWalkSpeed           = Off("MaxWalkSpeed", 0x0);
        JumpZVelocity          = Off("JumpZVelocity", 0x0);
        ThirdPersonOffset      = Off("ThirdPersonOffset", 0x0);
        DefaultMaxWalkSpeed    = Off("DefaultMaxWalkSpeed", 0x0);
        DefaultJumpZ           = Off("DefaultJumpZ", 0x0);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Math
// ═══════════════════════════════════════════════════════════════════════════════

struct Vec3 { float x, y, z; };
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
// Entity reading — UE5 GWorld chain
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t g_base = 0;

struct PlayerData {
    Vec3  origin;
    Vec3  headPos;
    int   health, maxHealth;
    int   team;
    float distance;
    char  name[64];
    bool  valid;
};

static int          g_localTeam = 0;
static Vec3         g_localPos = {};
static float        g_localYaw = 0;
static float        g_cameraFOV = 90.0f;
static PlayerData   g_players[128];
static int          g_playerCount = 0;
static std::mutex   g_dataMutex;

static uint64_t g_actorPtrs[128];
static PlayerData g_allPlayers[200];
static int g_allPlayerCount = 0;
static uint64_t g_localPawn = 0;
static uint64_t g_playerController = 0;

static Vec3 GetActorLocation(uint64_t actor) {
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
    uint64_t mesh = rpm<uint64_t>(actor + O::ActorMesh);
    if (!mesh) return false;
    uint64_t root = rpm<uint64_t>(actor + O::RootComponent);
    return root != 0;
}

static void ReadPlayers() {
    memset(g_actorPtrs, 0, sizeof(g_actorPtrs));

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
    int allCount = 0;
    const int CHUNK = 256;
    for (int base = 0; base < actorCount; base += CHUNK) {
        int batch = min(actorCount - base, CHUNK);
        uint64_t ptrs[256] = {};
        DmaRead(actorArray + (uint64_t)base * 8, ptrs, batch * 8);

        for (int i = 0; i < batch; i++) {
            uint64_t actor = ptrs[i];
            if (!actor || actor == localPawn) continue;
            if (!IsPlayerActor(actor)) continue;

            int team = O::TeamIndex ? rpm<int>(actor + O::TeamIndex) : 0;

            Vec3 origin = GetActorLocation(actor);
            if (origin.x == 0 && origin.y == 0 && origin.z == 0) continue;
            float dist = Vec3Dist(g_localPos, origin) / 100.0f;
            if (dist > 600.0f || dist < 0.5f) continue;

            bool dead = false;
            if (O::bIsDead) dead = rpm<uint8_t>(actor + O::bIsDead) != 0;
            if (dead) continue;

            PlayerData pd;
            pd.origin   = origin;
            pd.team     = team;
            pd.distance = dist;

            if (O::Health) {
                pd.health    = rpm<int>(actor + O::Health);
                pd.maxHealth = O::MaxHealth ? rpm<int>(actor + O::MaxHealth) : 100;
            } else { pd.health = 100; pd.maxHealth = 100; }

            pd.headPos = GetBonePos(actor, 6);
            if (pd.headPos.x == 0 && pd.headPos.y == 0 && pd.headPos.z == 0)
                pd.headPos = { origin.x, origin.y, origin.z + 70.0f };

            pd.name[0] = 0;
            if (O::PlayerNamePrivate) {
                int32_t len = rpm<int32_t>(actor + O::PlayerNamePrivate);
                if (len > 0 && len < 63) {
                    uint64_t dataPtr = rpm<uint64_t>(actor + O::PlayerNamePrivate + 8);
                    if (dataPtr) {
                        wchar_t wbuf[64] = {};
                        DmaRead(dataPtr, wbuf, len * 2);
                        WideCharToMultiByte(CP_ACP, 0, wbuf, len, pd.name, 63, NULL, NULL);
                    }
                }
            }

            pd.valid = (pd.health > 0);

            // Store in allPlayers (all teams)
            if (pd.valid && allCount < 200) {
                g_allPlayers[allCount++] = pd;
            }

            // Store in g_players only if enemy
            if (pd.valid && (team != g_localTeam || team == 0) && count < 128) {
                g_players[count] = pd;
                g_actorPtrs[count] = actor;
                count++;
            }
        }
    }
    // Add local player to allPlayers
    if (allCount < 200) {
        PlayerData& lp = g_allPlayers[allCount];
        lp.origin = g_localPos; lp.headPos = {g_localPos.x, g_localPos.y, g_localPos.z + 70.0f};
        lp.health = 100; lp.maxHealth = 100; lp.team = g_localTeam;
        lp.distance = 0; strcpy_s(lp.name, "You"); lp.valid = true; allCount++;
    }
    g_playerCount = count;
    g_allPlayerCount = allCount;
}


// ═══════════════════════════════════════════════════════════════════════════════
// DMA Write features
// ═══════════════════════════════════════════════════════════════════════════════

static Vec3 CalcAngle(Vec3 src, Vec3 dst) {
    Vec3 delta = { dst.x - src.x, dst.y - src.y, dst.z - src.z };
    float hyp = sqrtf(delta.x*delta.x + delta.y*delta.y);
    return { -RAD2DEG(atan2f(delta.z, hyp)), RAD2DEG(atan2f(delta.y, delta.x)), 0 };
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
    uint64_t camMgr = rpm<uint64_t>(g_playerController + O::PlayerCameraManager);
    if (camMgr && O::CameraRotation) camRot = rpm<FRotator>(camMgr + O::CameraRotation);
    Vec3 viewAngles = { camRot.pitch, camRot.yaw, 0 };

    int bestIdx = -1;
    float bestFov = Config::aimbotFOV.load();
    for (int i = 0; i < g_playerCount; i++) {
        if (!g_players[i].valid) continue;
        Vec3 angle = CalcAngle(camPos, g_players[i].headPos);
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
        if (O::GlowThroughWalls) wpm<uint8_t>(actor + O::GlowThroughWalls, 1);
        if (O::GlowColor) {
            float color[3] = { 1.0f, 0.0f, 0.0f };
            DmaWrite(actor + O::GlowColor, color, sizeof(color));
        }
    }
}

static void ApplyNoRecoil() {
    if (!Config::noRecoil || !g_localPawn) return;
    if (O::RecoilPitch) wpm<float>(g_localPawn + O::RecoilPitch, 0.0f);
    if (O::RecoilYaw)   wpm<float>(g_localPawn + O::RecoilYaw, 0.0f);
}

static void ApplyNoSpread() {
    if (!Config::noSpread || !O::SpreadAngle || !g_localPawn) return;
    wpm<float>(g_localPawn + O::SpreadAngle, 0.0f);
}

static void ApplyRapidFire() {
    if (!Config::rapidFire || !O::FireRate || !g_localPawn) return;
    wpm<float>(g_localPawn + O::FireRate, 0.0f);
}

static void ApplyFOV() {
    if (!Config::fovChanger || !O::CameraFOV || !g_playerController) return;
    uint64_t camMgr = rpm<uint64_t>(g_playerController + O::PlayerCameraManager);
    if (camMgr) wpm<float>(camMgr + O::CameraFOV, Config::customFOV.load());
}

static void ApplyTriggerbot() {
    if (!Config::triggerbot || Config::aimTargetIndex < 0) return;
    float dist = g_players[Config::aimTargetIndex].distance;
    if (dist > 200.0f) return;
    Vec3 target = CalcAngle(g_localPos, g_players[Config::aimTargetIndex].headPos);
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
        if (O::ChamsColor) { float c[3]={1,0,0}; DmaWrite(actor+O::ChamsColor,c,12); }
    }
}

static void ApplyNoFlash() {
    if (!Config::noFlash || !g_localPawn) return;
    if (O::FlashAlpha) wpm<float>(g_localPawn + O::FlashAlpha, 0.0f);
    if (O::FlashMaxAlpha) wpm<float>(g_localPawn + O::FlashMaxAlpha, 0.0f);
}

static void ApplyNoSway() {
    if (!Config::noSway || !g_localPawn || !O::SwayScale) return;
    wpm<float>(g_localPawn + O::SwayScale, 0.0f);
}

static void ApplyInfiniteStamina() {
    if (!Config::infiniteStamina || !g_localPawn) return;
    if (O::Stamina && O::MaxStamina) {
        float mx = rpm<float>(g_localPawn + O::MaxStamina);
        if (mx > 0) wpm<float>(g_localPawn + O::Stamina, mx);
    }
}

static void ApplySpeedHack() {
    if (!Config::speedHack || !g_localPawn) return;
    if (!O::MaxWalkSpeed && !O::MovementSpeed) return;
    float base = O::DefaultMaxWalkSpeed ? rpm<float>(g_localPawn + O::DefaultMaxWalkSpeed) : 600.0f;
    float target = base * Config::speedMultiplier.load();
    if (O::MaxWalkSpeed) wpm<float>(g_localPawn + O::MaxWalkSpeed, target);
    if (O::MovementSpeed) wpm<float>(g_localPawn + O::MovementSpeed, target);
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
// Web menu — HTTP server with radar + feature toggles
// ═══════════════════════════════════════════════════════════════════════════════

namespace WebMenu {
    static int port = 8888;
    static std::atomic<bool> running{true};

    static std::string BuildJSON() {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        std::ostringstream js;
        js << "{\"game\":\"Delta Force\","
           << "\"count\":" << g_playerCount << ","
           << "\"range\":200,"
           << "\"local\":{\"x\":" << g_localPos.x << ",\"y\":" << g_localPos.y
           << ",\"z\":" << g_localPos.z << ",\"yaw\":" << g_localYaw
           << ",\"team\":" << g_localTeam << "},"
           << "\"scale\":100,"
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
        bool first = true;
        for (int i = 0; i < g_allPlayerCount; i++) {
            auto& p = g_allPlayers[i];
            if (!p.valid) continue;
            if (!first) js << ",";
            first = false;
            bool isLocal = (p.distance < 0.01f && strcmp(p.name, "You") == 0);
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
            if (isLocal) js << ",\"me\":1,\"yaw\":" << g_localYaw;
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

    static const char* RADAR_PAGE = R"RADAR(<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>Squad Radar</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#ccc;font-family:'Consolas','Courier New',monospace;overflow:hidden}
#ov{position:fixed;inset:0;background:rgba(5,5,12,0.97);z-index:100;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
#ov.h{display:none}
#ov h2{color:#ff6040;margin-bottom:6px;font-size:20px}
#ov p{color:#777;margin-bottom:14px;font-size:12px;text-align:center;max-width:400px}
.tl{font-size:10px;color:#555;text-transform:uppercase;letter-spacing:1px;margin:10px 0 4px;width:100%;text-align:center}
#pg{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;max-width:500px}
.pb{padding:10px 18px;border:1px solid #333;border-radius:8px;background:#14141e;color:#ddd;cursor:pointer;font-family:inherit;font-size:13px;transition:.2s}
.pb:hover{background:#22223a;border-color:#ff6040;transform:scale(1.05)}
.pb.fr{border-left:3px solid #3a8}
.pb.en{border-left:3px solid #c44}
#spb{padding:8px 24px;border:1px solid #333;border-radius:6px;background:transparent;color:#666;cursor:pointer;font-family:inherit;font-size:11px;margin-top:14px}
#spb:hover{color:#aaa;border-color:#555}
#wrap{display:flex;height:100vh;width:100vw}
#radar-box{flex:1;display:flex;align-items:center;justify-content:center;min-width:0}
canvas{display:block;border-radius:50%}
#side{width:280px;padding:14px;overflow-y:auto;background:#0e0e16;border-left:1px solid #1a1a2a}
#hdr{font-size:16px;font-weight:bold;color:#ff6040;margin-bottom:2px}
#sub{font-size:11px;color:#666;margin-bottom:8px}
.sep{height:1px;background:#222;margin:8px 0}
#swb{width:100%;padding:6px;border:1px solid #333;border-radius:4px;background:#14141e;color:#aaa;cursor:pointer;font-family:inherit;font-size:11px;margin-bottom:8px}
#swb:hover{border-color:#ff6040;color:#fff}
.pl{font-size:11px;margin-bottom:2px}
.pl .nm{color:#ff9090}
.pl .nm.fr{color:#66cc88}
.pl .dst{color:#888;margin-left:6px}
.hp{height:3px;background:#1a1a1a;margin-bottom:6px;border-radius:2px}
.hp div{height:100%;border-radius:2px}
#plist{max-height:55vh;overflow-y:auto}
#ft{font-size:9px;color:#333;position:fixed;bottom:6px;right:10px}
@media(max-width:700px){#wrap{flex-direction:column}#side{width:100%;max-height:35vh;border-left:none;border-top:1px solid #1a1a2a}#radar-box{height:65vh}}
</style>
</head><body>
<div id="ov"><h2>SELECT YOUR PLAYER</h2><p>Pick yourself from the list so the radar centers on you and rotates with your movement.</p><div id="pg"></div><button id="spb" onclick="specMode()">Just Spectate (operator view)</button></div>
<div id="wrap">
<div id="radar-box"><canvas id="c"></canvas></div>
<div id="side">
  <div id="hdr">SQUAD RADAR</div>
  <div id="sub">Waiting for data...</div>
  <button id="swb" onclick="showOv()">Switch Player</button>
  <div class="sep"></div>
  <div id="plist"></div>
</div>
</div>
<div id="ft">Squad radar &bull; /radar</div>
<script>
const C=document.getElementById('c'),X=C.getContext('2d');
let D={game:'',count:0,range:200,local:{x:0,y:0,z:0,yaw:0,team:0},scale:100,players:[]};
let sel=localStorage.getItem('rp'),fails=0,spectate=false;
let prev={},cYaw=0,cPos={x:0,y:0,z:0};

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/'/g,'&#39;')}
function showOv(){document.getElementById('ov').classList.remove('h');buildBtns()}
function specMode(){sel=null;spectate=true;localStorage.removeItem('rp');document.getElementById('ov').classList.add('h')}
function pick(n){sel=n;spectate=false;localStorage.setItem('rp',n);document.getElementById('ov').classList.add('h')}

function buildBtns(){
  const g=document.getElementById('pg');if(!D.players||!D.players.length){g.innerHTML='<p style="color:#555">Waiting for player data...</p>';return}
  const lt=D.local?D.local.team:0;
  const fr=D.players.filter(p=>p.t===lt),en=D.players.filter(p=>p.t!==lt);
  let h='';
  if(fr.length){h+='<div class="tl" style="width:100%">Your Team</div>';for(const p of fr)h+='<button class="pb fr" onclick="pick(\''+esc(p.n||'?')+'\')">'+esc(p.n||'Player')+'</button>'}
  if(en.length){h+='<div class="tl" style="width:100%">Enemy Team</div>';for(const p of en)h+='<button class="pb en" onclick="pick(\''+esc(p.n||'?')+'\')">'+esc(p.n||'Enemy')+'</button>'}
  g.innerHTML=h;
}

function estYaw(n,x,y){
  const p=prev[n];
  if(p){const dx=x-p.x,dy=y-p.y,d=Math.sqrt(dx*dx+dy*dy);if(d>3){const ny=Math.atan2(dy,dx)*180/Math.PI;p.yaw=p.yaw*0.6+ny*0.4}p.x=x;p.y=y}
  else prev[n]={x,y,yaw:0};
  return(prev[n]||{}).yaw||0;
}

function sz(){const b=document.getElementById('radar-box'),s=Math.min(b.clientWidth,b.clientHeight)-20,dpr=window.devicePixelRatio||1;C.width=s*dpr;C.height=s*dpr;C.style.width=s+'px';C.style.height=s+'px';X.setTransform(dpr,0,0,dpr,0,0);return s}
window.addEventListener('resize',()=>sz());
function deg2rad(d){return d*Math.PI/180}

function draw(){
  const s=sz(),cx=s/2,cy=s/2,r=s/2-10;
  X.clearRect(0,0,s,s);
  X.beginPath();X.arc(cx,cy,r,0,Math.PI*2);X.fillStyle='#0d140d';X.fill();
  for(let f of[1,.75,.5,.25]){X.beginPath();X.arc(cx,cy,r*f,0,Math.PI*2);X.strokeStyle='#162016';X.lineWidth=1;X.stroke()}
  X.beginPath();X.moveTo(cx-r,cy);X.lineTo(cx+r,cy);X.moveTo(cx,cy-r);X.lineTo(cx,cy+r);X.strokeStyle='#1a281a';X.stroke();
  const yaw=deg2rad(cYaw),range=D.range||200,sc=D.scale||100,lt=D.local?D.local.team:0;
  const dirs=['N','E','S','W'],angs=[0,90,180,270];
  X.font='11px Consolas';X.fillStyle='#4a6a4a';X.textAlign='center';X.textBaseline='middle';
  for(let i=0;i<4;i++){const a=deg2rad(angs[i])-yaw;X.fillText(dirs[i],cx+Math.sin(a)*(r+14),cy-Math.cos(a)*(r+14))}
  X.font='10px Consolas';X.fillStyle='#2a3a2a';X.textAlign='right';X.fillText(range+'m',cx+r-4,cy+14);
  X.beginPath();X.arc(cx,cy,5,0,Math.PI*2);X.fillStyle='#00c8ff';X.fill();
  X.beginPath();X.moveTo(cx,cy);X.lineTo(cx,cy-16);X.strokeStyle='#00c8ff';X.lineWidth=2;X.stroke();
  for(const p of D.players){
    if(p.n===sel&&!spectate)continue;
    let wx=(p.x-cPos.x)/sc,wy=(p.y-cPos.y)/sc;const a=-yaw,rx=wx*Math.cos(a)-wy*Math.sin(a),ry=wx*Math.sin(a)+wy*Math.cos(a);
    const scale=r/range;let px=cx+rx*scale,py=cy-ry*scale;const dd=Math.sqrt((px-cx)**2+(py-cy)**2);
    if(dd>r-4){const ang=Math.atan2(px-cx,cy-py);px=cx+Math.sin(ang)*(r-4);py=cy-Math.cos(ang)*(r-4)}
    const hpp=p.mhp>0?p.hp/p.mhp:1;
    const isF=p.t===lt;const col=isF?'#33dd66':(hpp<.3?'#ffff00':'#ff3232');const ds=p.d<50?7:p.d<150?5:4;
    X.beginPath();X.moveTo(cx,cy);X.lineTo(px,py);X.strokeStyle=isF?'rgba(50,200,80,0.12)':'rgba(255,60,60,0.12)';X.lineWidth=1;X.stroke();
    X.beginPath();X.arc(px,py,ds,0,Math.PI*2);X.fillStyle=col;X.fill();X.strokeStyle='rgba(0,0,0,0.5)';X.lineWidth=1;X.stroke();
    X.font='10px Consolas';X.textAlign='center';X.textBaseline='bottom';
    X.fillStyle='#fff';X.fillText(p.n||'Player',px,py-ds-6);
    X.fillStyle='#aaa';X.fillText(Math.round(p.d)+'m',px,py-ds+2);
    const bw=Math.max(14,28-p.d/12);X.fillStyle='#1a1a1a';X.fillRect(px-bw/2,py+ds+3,bw,3);
    const cr2=Math.round(255*(1-hpp)),cg2=Math.round(255*hpp);X.fillStyle='rgb('+cr2+','+cg2+',0)';X.fillRect(px-bw/2,py+ds+3,bw*hpp,3);
  }
  if(D.items){for(const it of D.items){
    let wx=(it.x-cPos.x)/sc,wy=(it.y-cPos.y)/sc;const a=-yaw,rx=wx*Math.cos(a)-wy*Math.sin(a),ry=wx*Math.sin(a)+wy*Math.cos(a);
    const scale=r/range;let px=cx+rx*scale,py=cy-ry*scale;const dd=Math.sqrt((px-cx)**2+(py-cy)**2);if(dd>r-6)continue;
    X.save();X.translate(px,py);X.rotate(Math.PI/4);X.fillStyle=it.r>=3?'#ffaa00':it.r>=2?'#8888ff':'#88aa88';X.fillRect(-3,-3,6,6);X.restore();
  }}
  requestAnimationFrame(draw);
}

async function poll(){
  try{const r=await fetch('/api/data');if(!r.ok)throw 0;D=await r.json();fails=0;
    const me=D.players.find(p=>p.me);
    if(sel&&!spectate){
      const sp=D.players.find(p=>p.n===sel);
      if(sp){cPos={x:sp.x,y:sp.y,z:sp.z};cYaw=sp.me?sp.yaw:estYaw(sel,sp.x,sp.y)}
      else if(!document.getElementById('ov').classList.contains('h')){}
      else{cPos=D.local||cPos;cYaw=D.local?D.local.yaw:0}
    }else{cPos=D.local||cPos;cYaw=D.local?(D.local.yaw||0):0}
    if(!sel&&!spectate&&D.players.length>0&&!document.getElementById('ov').classList.contains('h'))buildBtns();
    document.getElementById('hdr').textContent=(sel&&!spectate?sel+' RADAR':(D.game||'DMA')+' RADAR');
    document.getElementById('sub').textContent='Players: '+D.players.length+'  Range: '+(D.range||200)+'m';
    const lt=D.local?D.local.team:0;const pl=document.getElementById('plist');let h='';
    for(const p of D.players.slice(0,20)){const nm=p.n||'Player',hpp=p.mhp>0?p.hp/p.mhp:1;const cr=Math.round(255*(1-hpp)),cg=Math.round(255*hpp);const isF=p.t===lt;
      h+='<div class="pl"><span class="nm'+(isF?' fr':'')+'">'+nm+(p.n===sel?' (YOU)':'')+'</span><span class="dst">'+Math.round(p.d)+'m</span> '+p.hp+'/'+p.mhp+'</div>';
      h+='<div class="hp"><div style="width:'+Math.round(hpp*100)+'%;background:rgb('+cr+','+cg+',0)"></div></div>'}
    pl.innerHTML=h;
  }catch(e){fails++;document.getElementById('sub').textContent='Disconnected ('+fails+')'}
  setTimeout(poll,100);
}
if(sel)document.getElementById('ov').classList.add('h');
draw();poll();
</script>
</body></html>)RADAR";

    static const char* HTML_PAGE = R"HTML(<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>Delta Force DMA</title>
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
  <div id="title">DELTA FORCE DMA</div>
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

function syncUI(cfg){
  if(!cfg)return;
  document.querySelectorAll('.tog').forEach(t=>{
    const v=cfg[t.dataset.key];if(v!==undefined)t.classList.toggle('on',v);
  });
  document.querySelectorAll('.sld input[type=range]').forEach(s=>{
    const v=cfg[s.dataset.key];if(v!==undefined){s.value=v;s.nextElementSibling.textContent=Math.round(v)}
  });
}

function sz(){
  const b=document.getElementById('radar-box');
  const s=Math.min(b.clientWidth,b.clientHeight)-20;
  const dpr=window.devicePixelRatio||1;
  C.width=s*dpr;C.height=s*dpr;C.style.width=s+'px';C.style.height=s+'px';
  X.setTransform(dpr,0,0,dpr,0,0);return s;
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
    if(cfg.espSnaplines){X.beginPath();X.moveTo(cx,cy);X.lineTo(px,py);X.strokeStyle='rgba(255,50,50,0.3)';X.lineWidth=1;X.stroke()}
    if(cfg.espBox){const bw=Math.max(8,20-p.d/20),bh=bw*2.2;X.strokeStyle=col;X.lineWidth=1;X.strokeRect(px-bw/2,py-bh/2,bw,bh)}
    X.beginPath();X.arc(px,py,ds,0,Math.PI*2);X.fillStyle=col;X.fill();
    let ty=py-ds-4;X.font='9px Consolas';X.textAlign='center';X.textBaseline='bottom';
    if(cfg.espName){const nm=p.n||'Enemy';X.fillStyle='#fff';X.fillText(nm,px,ty);ty-=10}
    if(cfg.espHealth){X.fillStyle=col;X.fillText(p.hp+'/'+p.mhp,px,ty);ty-=10}
    if(cfg.espDistance){X.fillStyle='#aaa';X.fillText(Math.round(p.d)+'m',px,ty);ty-=10}
    if(cfg.espHealth){const bw=Math.max(12,24-p.d/15);X.fillStyle='#333';X.fillRect(px-bw/2,py+ds+2,bw,3);const cr2=Math.round(255*(1-hpp)),cg2=Math.round(255*hpp);X.fillStyle='rgb('+cr2+','+cg2+',0)';X.fillRect(px-bw/2,py+ds+2,bw*hpp,3)}
    if(!cfg.espDistance){X.font='10px Consolas';X.fillStyle='#b4b4b4';X.textAlign='left';X.textBaseline='middle';X.fillText(Math.round(p.d)+'',px+ds+3,py)}
  }
  requestAnimationFrame(draw);
}

async function poll(){
  try{
    const r=await fetch('/api/data');if(!r.ok)throw 0;
    D=await r.json();range=D.range||range;fails=0;
    document.getElementById('title').textContent=(D.game||'DMA')+' DMA';
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
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                       "Access-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\n"
                       "Content-Length: " + std::to_string(json.size()) + "\r\n"
                       "Connection: close\r\n\r\n" + json;
        } else if (strstr(buf, "GET /radar")) {
            std::string body = RADAR_PAGE;
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                       "Cache-Control: no-cache\r\n"
                       "Content-Length: " + std::to_string(body.size()) + "\r\n"
                       "Connection: close\r\n\r\n" + body;
        } else if (strstr(buf, "GET / ") || strstr(buf, "GET / HTTP") ||
                   strstr(buf, "GET /index") || strstr(buf, "GET /menu")) {
            std::string body = HTML_PAGE;
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
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
        WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
        SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (srv == INVALID_SOCKET) { printf("[!] Web: socket() failed\n"); return; }
        int opt = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        sockaddr_in addr = {}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY;
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
        addrinfo hints = {}, *res = nullptr; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
            printf("[+] Admin panel (you):    http://localhost:%d\n", port);
            printf("[+] Shared radar (squad): http://localhost:%d/radar\n", port);
            printf("[+] LAN URLs:\n");
            for (auto* p = res; p; p = p->ai_next) {
                char ip[64]; inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, ip, sizeof(ip));
                printf("    Admin:  http://%s:%d\n", ip, port);
                printf("    Radar:  http://%s:%d/radar\n", ip, port);
            }
            freeaddrinfo(res);
        } else {
            printf("[+] Admin panel:  http://localhost:%d\n", port);
            printf("[+] Shared radar: http://localhost:%d/radar\n", port);
        }
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
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    printf("=== Delta Force DMA Cheat ===\n\n");

    std::string offsetsPath = "df_offsets.ini";
    std::string device = "fpga";
    std::string processName = "DeltaForce.exe";
    std::string moduleName = "DeltaForce.exe";

    char* cmd = lpCmdLine;
    while (cmd && *cmd) {
        while (*cmd == ' ') cmd++;
        if (strncmp(cmd, "--offsets=", 9) == 0) {
            cmd += 9; char* end = strchr(cmd, ' ');
            offsetsPath = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--device=", 9) == 0) {
            cmd += 9; char* end = strchr(cmd, ' ');
            device = end ? std::string(cmd, end) : std::string(cmd);
            cmd = end ? end : cmd + strlen(cmd);
        } else if (strncmp(cmd, "--port=", 7) == 0) {
            cmd += 7; WebMenu::port = atoi(cmd);
            char* end = strchr(cmd, ' '); cmd = end ? end : cmd + strlen(cmd);
        } else { cmd++; }
    }

    LoadConfig(offsetsPath.c_str());
    auto pn = Str("ProcessName"); if (!pn.empty()) processName = pn;
    auto mn = Str("ModuleName"); if (!mn.empty()) moduleName = mn;
    O::Init();

    printf("[*] Loading VMM API...\n");
    if (!LoadVMM()) return 1;

    printf("[*] Initializing DMA (%s)...\n", device.c_str());
    LPCSTR args[] = { "", "-device", device.c_str(), "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) {
        printf("[-] DMA initialization failed.\n");
        MessageBoxA(NULL, "DMA init failed.\nCheck FPGA card.", "DMA Error", MB_ICONERROR);
        return 1;
    }
    printf("[+] DMA initialized\n");

    printf("[*] Waiting for %s...\n", processName.c_str());
    while (!pPidGet(g_vmm, processName.c_str(), &g_pid)) {
        if (GetAsyncKeyState(VK_END) & 1) { pClose(g_vmm); return 0; }
        Sleep(2000); printf(".");
    }
    printf("\n[+] Found %s  PID=%u\n", processName.c_str(), g_pid);

    g_base = pModBase ? pModBase(g_vmm, g_pid, moduleName.c_str()) : 0;
    if (!g_base) { printf("[!] Module base not found, using 0x140000000\n"); g_base = 0x140000000; }
    printf("[+] %s base: 0x%llX\n", moduleName.c_str(), (unsigned long long)g_base);

    if (!O::GWorld)
        printf("[!] GWorld offset is 0 — configure %s first.\n", offsetsPath.c_str());

    WebMenu::Start();

    printf("[+] Web menu started on port %d\n", WebMenu::port);
    printf("[+] Features controlled via web browser\n");
    printf("    END = Exit\n\n");

    while (!GetAsyncKeyState(VK_END)) {
        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            ReadPlayers();
            ApplyFeatures();
        }
        Sleep(10 + (GetTickCount() % 5));
    }

    printf("[*] Shutting down...\n");
    WebMenu::running = false;
    pClose(g_vmm);
    return 0;
}
