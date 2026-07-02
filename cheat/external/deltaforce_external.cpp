// Delta Force External Cheat Suite
// Streamproof ESP overlay + aim assist + triggerbot + no-recoil
// Uses Betest kernel driver (IOCTL 0x805/0x806) via BYOVD stealth stack
// Engine: Unreal Engine 5
//
// Build: bld_df.cmd
// Run:   df_external.exe  (requires Betest driver mapped + Delta Force running)

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dwmapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <algorithm>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "winmm.lib")


// ═══════════════════════════════════════════════════════════════════════════════
// Driver interface — Betest IOCTL read/write process memory
// ═══════════════════════════════════════════════════════════════════════════════

#define IOCTL_READ_PROC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WRITE_PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_SESSION_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_WRITE_DATA)

#pragma pack(push, 1)
struct ProcReadReq  { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; };
struct ProcWriteReq { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; uint8_t Data[1]; };
#pragma pack(pop)

static HANDLE g_hDev = INVALID_HANDLE_VALUE;
static DWORD  g_pid  = 0;
static uint8_t* g_ioBuf = nullptr;
static const DWORD IO_BUF_SIZE = 65536;

static bool SessionAuth(HANDLE h) {
    ULONG64 challenge = GetTickCount64();
    ULONG64 token = 0;
    DWORD ret = 0;
    return DeviceIoControl(h, IOCTL_SESSION_AUTH,
                           &challenge, sizeof(challenge),
                           &token, sizeof(token), &ret, nullptr) && ret == sizeof(token);
}

static bool VerifyBetestDevice(HANDLE h) {
    ProcReadReq req{};
    req.ProcessId = GetCurrentProcessId();
    req.Address   = (uint64_t)GetModuleHandleA(nullptr);
    req.Size      = 2;
    uint16_t val  = 0;
    DWORD ret     = 0;
    return DeviceIoControl(h, IOCTL_READ_PROC,
                           &req, sizeof(req), &val, sizeof(val), &ret, nullptr)
           && ret == 2 && val == 0x5A4D;
}

static bool DriverInit() {
    static const char* dynPrefixes[] = {
        "MsFlt", "WdFlt", "FltMgr", "NdPxy", "TdiFlt",
        "MsSecF", "WfpDr", "NtFlt", "ClfsF", "VhdFlt",
        "SrFlt", "FsDep", "PcwDrv", "MsIScsi", "VolSnap", "WmiLib",
    };
    static const char* staticNames[] = {
        "\\\\.\\MsFlt0",   "\\\\.\\WdFilter1", "\\\\.\\FltMgr2",
        "\\\\.\\NdProxy0", "\\\\.\\TdiFilter",  "\\\\.\\MsSecFlt",
        "\\\\.\\WfpDrv0",  "\\\\.\\NtFilter1",
    };

    auto tryOpen = [&](const char* path) -> bool {
        HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        if (!SessionAuth(h)) { CloseHandle(h); return false; }
        if (VerifyBetestDevice(h)) {
            g_hDev = h;
            return true;
        }
        CloseHandle(h);
        return false;
    };

    for (int p = 0; p < 16; p++)
        for (int d = 0; d < 10; d++) {
            char path[64];
            snprintf(path, sizeof(path), "\\\\.\\%s%d", dynPrefixes[p], d);
            if (tryOpen(path)) return true;
        }
    for (int i = 0; i < 8; i++)
        if (tryOpen(staticNames[i])) return true;
    return false;
}

static bool DriverRead(uint64_t addr, void* buf, uint32_t size) {
    if (!g_ioBuf) {
        g_ioBuf = (uint8_t*)VirtualAlloc(nullptr, IO_BUF_SIZE,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_ioBuf) return false;
    }
    if (size > IO_BUF_SIZE - 256) return false;
    auto* req = (ProcReadReq*)g_ioBuf;
    req->ProcessId = g_pid;
    req->Address   = addr;
    req->Size      = size;
    DWORD ret = 0;
    if (!DeviceIoControl(g_hDev, IOCTL_READ_PROC,
                         g_ioBuf, sizeof(ProcReadReq), g_ioBuf, IO_BUF_SIZE,
                         &ret, nullptr))
        return false;
    memcpy(buf, g_ioBuf, size);
    return true;
}

static bool DriverWrite(uint64_t addr, const void* data, uint32_t size) {
    size_t reqSize = offsetof(ProcWriteReq, Data) + size;
    std::vector<uint8_t> buf(reqSize);
    auto* req = (ProcWriteReq*)buf.data();
    req->ProcessId = g_pid;
    req->Address   = addr;
    req->Size      = size;
    memcpy(req->Data, data, size);
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, IOCTL_WRITE_PROC,
                           buf.data(), (DWORD)reqSize,
                           nullptr, 0, &ret, nullptr) != FALSE;
}

template<class T> T rpm(uint64_t addr) { T v{}; DriverRead(addr, &v, sizeof(T)); return v; }
template<class T> void wpm(uint64_t addr, T v) { DriverWrite(addr, &v, sizeof(v)); }

static bool HideProcess(DWORD pid) {
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, IOCTL_HIDE_PROCESS,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Process utilities
// ═══════════════════════════════════════════════════════════════════════════════

static DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(name, pe.szExeFile) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static uint64_t GetModuleBase(DWORD pid, const char* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    uint64_t base = 0;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, modName) == 0) { base = (uint64_t)me.modBaseAddr; break; }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Offset config — loaded from df_offsets.ini so patches don't need a recompile
// ═══════════════════════════════════════════════════════════════════════════════

static std::unordered_map<std::string, uint64_t> g_offsets;

static void LoadOffsets(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        printf("[!] Could not open offsets file: %s\n", path);
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
        g_offsets[key] = strtoull(val.c_str(), nullptr, 0);
    }
    printf("[+] Loaded %zu offsets from %s\n", g_offsets.size(), path);
}

static uint64_t Off(const char* name, uint64_t fallback = 0) {
    auto it = g_offsets.find(name);
    return (it != g_offsets.end()) ? it->second : fallback;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Delta Force SDK — UE5 Offsets & Structures
// Offsets loaded from df_offsets.ini; defaults are for reference only
// ═══════════════════════════════════════════════════════════════════════════════

namespace Offsets {
    // UE5 core (GObjects, GNames, GWorld are module-level offsets from base)
    uint64_t GWorld;
    uint64_t GNames;
    uint64_t GObjects;

    // UWorld chain
    uint64_t OwningGameInstance;
    uint64_t LocalPlayers;
    uint64_t PlayerController;
    uint64_t AcknowledgedPawn;
    uint64_t PlayerCameraManager;
    uint64_t PersistentLevel;
    uint64_t GameState;

    // ULevel
    uint64_t Actors;
    uint64_t ActorCount;

    // AActor
    uint64_t RootComponent;
    uint64_t ActorMesh;
    uint64_t bHidden;

    // USceneComponent
    uint64_t RelativeLocation;
    uint64_t ComponentToWorld;

    // APlayerState
    uint64_t PlayerNamePrivate;
    uint64_t TeamIndex;

    // ACharacter / health
    uint64_t Health;
    uint64_t MaxHealth;
    uint64_t Shield;
    uint64_t MaxShield;
    uint64_t bIsDead;

    // USkeletalMeshComponent
    uint64_t BoneArray;
    uint64_t BoneSpaceTransforms;
    uint64_t ComponentToWorldMatrix;

    // APlayerCameraManager
    uint64_t CameraLocation;
    uint64_t CameraRotation;
    uint64_t CameraFOV;

    // Aim punch / recoil
    uint64_t RecoilPitch;
    uint64_t RecoilYaw;
    uint64_t AimPunchAngle;

    void Init() {
        GWorld                 = Off("GWorld",                  0x0);
        GNames                 = Off("GNames",                  0x0);
        GObjects               = Off("GObjects",                0x0);
        OwningGameInstance     = Off("OwningGameInstance",       0x1B8);
        LocalPlayers           = Off("LocalPlayers",             0x38);
        PlayerController       = Off("PlayerController",         0x30);
        AcknowledgedPawn       = Off("AcknowledgedPawn",         0x338);
        PlayerCameraManager    = Off("PlayerCameraManager",      0x348);
        PersistentLevel        = Off("PersistentLevel",          0x30);
        GameState              = Off("GameState",                0x158);
        Actors                 = Off("Actors",                   0x98);
        ActorCount             = Off("ActorCount",               0xA0);
        RootComponent          = Off("RootComponent",            0x190);
        ActorMesh              = Off("ActorMesh",                0x310);
        bHidden                = Off("bHidden",                  0x58);
        RelativeLocation       = Off("RelativeLocation",         0x128);
        ComponentToWorld       = Off("ComponentToWorld",          0x1C0);
        PlayerNamePrivate      = Off("PlayerNamePrivate",         0x310);
        TeamIndex              = Off("TeamIndex",                 0x10C);
        Health                 = Off("Health",                    0x0);
        MaxHealth              = Off("MaxHealth",                 0x0);
        Shield                 = Off("Shield",                    0x0);
        MaxShield              = Off("MaxShield",                 0x0);
        bIsDead                = Off("bIsDead",                   0x0);
        BoneArray              = Off("BoneArray",                 0x5B0);
        BoneSpaceTransforms    = Off("BoneSpaceTransforms",       0x5B0);
        ComponentToWorldMatrix = Off("ComponentToWorldMatrix",    0x1C0);
        CameraLocation         = Off("CameraLocation",            0x0);
        CameraRotation         = Off("CameraRotation",            0x0);
        CameraFOV              = Off("CameraFOV",                 0x0);
        RecoilPitch            = Off("RecoilPitch",                0x0);
        RecoilYaw              = Off("RecoilYaw",                  0x0);
        AimPunchAngle          = Off("AimPunchAngle",              0x0);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Math — vectors, matrices, world-to-screen
// ═══════════════════════════════════════════════════════════════════════════════

struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };
struct FRotator { float pitch, yaw, roll; };

struct FTransform {
    float rotation[4]; // quaternion xyzw
    Vec3  translation;
    float pad0;
    Vec3  scale3d;
    float pad1;
};

struct D3DMatrix { float _[4][4]; };

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif
#define DEG2RAD(x) ((x) * (float)M_PI / 180.0f)
#define RAD2DEG(x) ((x) * 180.0f / (float)M_PI)

static float Vec3Dist(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

static D3DMatrix MatrixMultiply(const D3DMatrix& a, const D3DMatrix& b) {
    D3DMatrix r{};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            for (int k = 0; k < 4; k++)
                r._[i][j] += a._[i][k] * b._[k][j];
    return r;
}

static D3DMatrix RotatorToMatrix(FRotator rot) {
    float radP = DEG2RAD(rot.pitch), radY = DEG2RAD(rot.yaw), radR = DEG2RAD(rot.roll);
    float sp = sinf(radP), cp = cosf(radP);
    float sy = sinf(radY), cy = cosf(radY);
    float sr = sinf(radR), cr = cosf(radR);
    D3DMatrix m{};
    m._[0][0] = cp * cy;
    m._[0][1] = cp * sy;
    m._[0][2] = sp;
    m._[1][0] = sr * sp * cy - cr * sy;
    m._[1][1] = sr * sp * sy + cr * cy;
    m._[1][2] = -sr * cp;
    m._[2][0] = -(cr * sp * cy + sr * sy);
    m._[2][1] = cy * sr - cr * sp * sy;
    m._[2][2] = cr * cp;
    m._[3][3] = 1.0f;
    return m;
}

static bool WorldToScreen(Vec3 world, FRotator camRot, Vec3 camLoc, float fov, int sw, int sh, Vec2& out) {
    D3DMatrix tempMatrix = RotatorToMatrix(camRot);

    Vec3 vDelta = { world.x - camLoc.x, world.y - camLoc.y, world.z - camLoc.z };

    Vec3 vTransformed = {
        vDelta.x * tempMatrix._[1][0] + vDelta.y * tempMatrix._[1][1] + vDelta.z * tempMatrix._[1][2],
        vDelta.x * tempMatrix._[2][0] + vDelta.y * tempMatrix._[2][1] + vDelta.z * tempMatrix._[2][2],
        vDelta.x * tempMatrix._[0][0] + vDelta.y * tempMatrix._[0][1] + vDelta.z * tempMatrix._[0][2]
    };

    if (vTransformed.z < 1.0f) return false;

    float fovRad = DEG2RAD(fov * 0.5f);
    float screenCenterX = sw * 0.5f;
    float screenCenterY = sh * 0.5f;

    out.x = screenCenterX + vTransformed.x * (screenCenterX / tanf(fovRad)) / vTransformed.z;
    out.y = screenCenterY - vTransformed.y * (screenCenterX / tanf(fovRad)) / vTransformed.z;

    return (out.x >= 0 && out.x <= sw && out.y >= 0 && out.y <= sh);
}

static float NormalizeAngle(float a) {
    while (a > 180.f) a -= 360.f;
    while (a < -180.f) a += 360.f;
    return a;
}

static Vec2 CalcAngle(Vec3 src, Vec3 dst) {
    Vec3 d = { dst.x - src.x, dst.y - src.y, dst.z - src.z };
    float hyp = sqrtf(d.x * d.x + d.y * d.y);
    return { -RAD2DEG(atan2f(d.z, hyp)), RAD2DEG(atan2f(d.y, d.x)) };
}

// UE5 bone transform: apply component-to-world to bone-space transform
static Vec3 GetBoneWorldPos(FTransform bone, FTransform compToWorld) {
    // simplified: just translate bone position by component transform
    // (ignoring rotation/scale for now — good enough for ESP)
    float bx = bone.translation.x * compToWorld.scale3d.x;
    float by = bone.translation.y * compToWorld.scale3d.y;
    float bz = bone.translation.z * compToWorld.scale3d.z;

    // Quaternion rotation
    float qx = compToWorld.rotation[0], qy = compToWorld.rotation[1];
    float qz = compToWorld.rotation[2], qw = compToWorld.rotation[3];

    // Rotate bone pos by quaternion
    float ix = qw * bx + qy * bz - qz * by;
    float iy = qw * by + qz * bx - qx * bz;
    float iz = qw * bz + qx * by - qy * bx;
    float iw = -qx * bx - qy * by - qz * bz;

    float rx = ix * qw + iw * -qx + iy * -qz - iz * -qy;
    float ry = iy * qw + iw * -qy + iz * -qx - ix * -qz;
    float rz = iz * qw + iw * -qz + ix * -qy - iy * -qx;

    return {
        rx + compToWorld.translation.x,
        ry + compToWorld.translation.y,
        rz + compToWorld.translation.z
    };
}


// ═══════════════════════════════════════════════════════════════════════════════
// UE5 entity reading
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t g_base = 0;

struct PlayerData {
    uint64_t actorPtr;
    Vec3     origin;
    Vec3     headPos;
    int      health, maxHealth;
    int      shield, maxShield;
    int      team;
    float    distance;
    wchar_t  name[64];
    bool     isVisible;
    bool     valid;
};

// UE5 bone indices (standard humanoid skeleton)
enum Bones : int {
    BONE_ROOT      = 0,
    BONE_PELVIS    = 1,
    BONE_SPINE_01  = 2,
    BONE_SPINE_02  = 3,
    BONE_SPINE_03  = 4,
    BONE_NECK      = 5,
    BONE_HEAD      = 6,
    BONE_L_UPPER   = 8,
    BONE_L_LOWER   = 9,
    BONE_L_HAND    = 10,
    BONE_R_UPPER   = 35,
    BONE_R_LOWER   = 36,
    BONE_R_HAND    = 37,
    BONE_L_THIGH   = 55,
    BONE_L_CALF    = 56,
    BONE_L_FOOT    = 57,
    BONE_R_THIGH   = 62,
    BONE_R_CALF    = 63,
    BONE_R_FOOT    = 64,
};

static int          g_localTeam = 0;
static Vec3         g_cameraPos = {};
static FRotator     g_cameraRot = {};
static float        g_cameraFOV = 90.0f;
static PlayerData   g_players[100];
static int          g_playerCount = 0;
static std::mutex   g_dataMutex;

static std::string g_processName;
static std::string g_windowClass;
static std::string g_windowTitle;
static std::string g_moduleName;

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

static void ReadFName(uint64_t nameAddr, wchar_t* out, int maxChars) {
    out[0] = 0;
    if (!nameAddr) return;

    // UE5 FString: length at +0x00 (int32), then wchar_t* pointer at +0x08
    int32_t len = rpm<int32_t>(nameAddr);
    if (len <= 0 || len > maxChars - 1) {
        // try as direct FName index (older/simpler path)
        char narrowBuf[128] = {};
        DriverRead(nameAddr, narrowBuf, 63);
        narrowBuf[63] = 0;
        for (int i = 0; i < 63 && narrowBuf[i]; i++)
            out[i] = (wchar_t)narrowBuf[i];
        return;
    }

    uint64_t dataPtr = rpm<uint64_t>(nameAddr + 8);
    if (!dataPtr) return;
    int readChars = (len < maxChars - 1) ? len : maxChars - 1;
    DriverRead(dataPtr, out, readChars * 2);
    out[readChars] = 0;
}

static void ReadPlayers() {
    uint64_t gworld = rpm<uint64_t>(g_base + Offsets::GWorld);
    if (!gworld) return;

    // Camera: UWorld -> OwningGameInstance -> LocalPlayers[0] -> PlayerController -> PlayerCameraManager
    uint64_t gameInst = rpm<uint64_t>(gworld + Offsets::OwningGameInstance);
    if (!gameInst) return;

    uint64_t localPlayersPtr = rpm<uint64_t>(gameInst + Offsets::LocalPlayers);
    if (!localPlayersPtr) return;

    uint64_t localPlayer = rpm<uint64_t>(localPlayersPtr); // TArray[0]
    if (!localPlayer) return;

    uint64_t playerController = rpm<uint64_t>(localPlayer + Offsets::PlayerController);
    if (!playerController) return;

    uint64_t localPawn = rpm<uint64_t>(playerController + Offsets::AcknowledgedPawn);

    // Camera info
    uint64_t camMgr = rpm<uint64_t>(playerController + Offsets::PlayerCameraManager);
    if (camMgr && Offsets::CameraLocation && Offsets::CameraRotation) {
        g_cameraPos = rpm<Vec3>(camMgr + Offsets::CameraLocation);
        g_cameraRot = rpm<FRotator>(camMgr + Offsets::CameraRotation);
        if (Offsets::CameraFOV)
            g_cameraFOV = rpm<float>(camMgr + Offsets::CameraFOV);
    } else if (localPawn) {
        // Fallback: read from root component
        uint64_t root = rpm<uint64_t>(localPawn + Offsets::RootComponent);
        if (root) g_cameraPos = rpm<Vec3>(root + Offsets::RelativeLocation);
        g_cameraPos.z += 70.0f; // eye height estimate
    }

    if (g_cameraFOV < 10.0f || g_cameraFOV > 170.0f) g_cameraFOV = 90.0f;

    // Read local team
    if (localPawn && Offsets::TeamIndex)
        g_localTeam = rpm<int>(localPawn + Offsets::TeamIndex);

    // Iterate actors
    uint64_t level = rpm<uint64_t>(gworld + Offsets::PersistentLevel);
    if (!level) return;

    int32_t actorCount = rpm<int32_t>(level + Offsets::ActorCount);
    uint64_t actorArray = rpm<uint64_t>(level + Offsets::Actors);
    if (!actorArray || actorCount <= 0) return;
    if (actorCount > 10000) actorCount = 10000;

    int count = 0;

    // Read actor pointers in chunks for performance
    const int CHUNK = 256;
    for (int base = 0; base < actorCount && count < 100; base += CHUNK) {
        int batch = (actorCount - base < CHUNK) ? (actorCount - base) : CHUNK;
        uint64_t ptrs[CHUNK] = {};
        DriverRead(actorArray + (uint64_t)base * 8, ptrs, batch * 8);

        for (int i = 0; i < batch && count < 100; i++) {
            uint64_t actor = ptrs[i];
            if (!actor || actor == localPawn) continue;

            if (!IsPlayerActor(actor)) continue;

            // Check team
            int team = 0;
            if (Offsets::TeamIndex)
                team = rpm<int>(actor + Offsets::TeamIndex);
            if (team == g_localTeam && team != 0) continue;

            Vec3 origin = GetActorLocation(actor);
            if (origin.x == 0 && origin.y == 0 && origin.z == 0) continue;

            // UE5 uses centimeters, convert to meters for distance
            float dist = Vec3Dist(g_cameraPos, origin) / 100.0f;
            if (dist > 500.0f || dist < 0.5f) continue;

            // Check alive
            bool dead = false;
            if (Offsets::bIsDead)
                dead = rpm<uint8_t>(actor + Offsets::bIsDead) != 0;
            if (dead) continue;

            PlayerData& p = g_players[count];
            p.actorPtr  = actor;
            p.origin    = origin;
            p.team      = team;
            p.distance  = dist;

            // Health
            if (Offsets::Health) {
                p.health    = rpm<int>(actor + Offsets::Health);
                p.maxHealth = Offsets::MaxHealth ? rpm<int>(actor + Offsets::MaxHealth) : 100;
            } else {
                p.health = 100; p.maxHealth = 100;
            }
            if (Offsets::Shield) {
                p.shield    = rpm<int>(actor + Offsets::Shield);
                p.maxShield = Offsets::MaxShield ? rpm<int>(actor + Offsets::MaxShield) : 100;
            } else {
                p.shield = 0; p.maxShield = 0;
            }

            // Head bone
            p.headPos = GetBonePos(actor, BONE_HEAD);
            if (p.headPos.x == 0 && p.headPos.y == 0 && p.headPos.z == 0)
                p.headPos = { origin.x, origin.y, origin.z + 70.0f };

            // Name
            p.name[0] = 0;
            if (Offsets::PlayerNamePrivate)
                ReadFName(actor + Offsets::PlayerNamePrivate, p.name, 63);

            p.isVisible = true; // no vis check without line trace
            p.valid = (p.health > 0);
            if (p.valid) count++;
        }
    }
    g_playerCount = count;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════════════════════════

namespace Config {
    bool espEnabled      = true;
    bool espBoxes        = true;
    bool espSkeleton     = true;
    bool espHealth       = true;
    bool espShield       = false;
    bool espNames        = true;
    bool espDistance      = true;
    bool espSnaplines    = false;

    bool aimbotEnabled   = false;
    float aimbotFOV      = 12.0f;
    float aimbotSmooth   = 6.0f;
    int   aimbotBone     = 0;       // 0=head, 1=neck, 2=chest
    bool  aimbotVisCheck = false;

    bool triggerbotEnabled = false;
    int  triggerbotDelay   = 60;

    bool noRecoil        = false;
    float recoilComp     = 0.65f;

    bool hideProcess     = true;

    float maxESPDist     = 400.0f;

    bool menuOpen        = false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Overlay — GDI streamproof via WDA_EXCLUDEFROMCAPTURE
// All drawing excluded from: OBS, Discord, Game Bar, Shadowplay, any capture API
// ═══════════════════════════════════════════════════════════════════════════════

namespace Overlay {
    HWND overlayWnd = NULL;
    HWND gameWnd    = NULL;
    std::atomic<bool> running{true};
    HFONT espFont     = NULL;
    HFONT espFontSm   = NULL;
    HFONT menuFont    = NULL;
    HFONT menuFontB   = NULL;
    HDC     g_memDC     = NULL;
    HBITMAP g_memBmp    = NULL;
    HBITMAP g_memOld    = NULL;
    int     g_cachedW   = 0;
    int     g_cachedH   = 0;
    int     g_cachedGX  = -9999;
    int     g_cachedGY  = -9999;

    void DrawRect(HDC hdc, int x, int y, int w, int h, COLORREF c, int t = 1) {
        HPEN pen = CreatePen(PS_SOLID, t, c);
        HPEN op = (HPEN)SelectObject(hdc, pen);
        HBRUSH ob = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, x, y, x+w, y+h);
        SelectObject(hdc, ob); SelectObject(hdc, op); DeleteObject(pen);
    }

    void DrawFilled(HDC hdc, int x, int y, int w, int h, COLORREF c) {
        HBRUSH br = CreateSolidBrush(c);
        RECT r = {x, y, x+w, y+h};
        FillRect(hdc, &r, br); DeleteObject(br);
    }

    void DrawLine(HDC hdc, int x1, int y1, int x2, int y2, COLORREF c, int t = 1) {
        HPEN pen = CreatePen(PS_SOLID, t, c);
        HPEN op = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, x1, y1, NULL); LineTo(hdc, x2, y2);
        SelectObject(hdc, op); DeleteObject(pen);
    }

    void DrawText_(HDC hdc, int x, int y, const char* txt, COLORREF c, HFONT f = NULL) {
        if (f) SelectObject(hdc, f);
        SetTextColor(hdc, c); SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, x, y, txt, (int)strlen(txt));
    }

    void DrawTextW_(HDC hdc, int x, int y, const wchar_t* txt, COLORREF c, HFONT f = NULL) {
        if (f) SelectObject(hdc, f);
        SetTextColor(hdc, c); SetBkMode(hdc, TRANSPARENT);
        TextOutW(hdc, x, y, txt, (int)wcslen(txt));
    }

    void DrawHealthBar(HDC hdc, int x, int y, int w, int h, float hp, COLORREF full, COLORREF empty) {
        DrawFilled(hdc, x, y, w, h, RGB(10,10,10));
        int fillH = (int)((h-2) * hp);
        if (fillH < 0) fillH = 0;
        int r = (int)(GetRValue(full) * hp + GetRValue(empty) * (1-hp));
        int g = (int)(GetGValue(full) * hp + GetGValue(empty) * (1-hp));
        int b = (int)(GetBValue(full) * hp + GetBValue(empty) * (1-hp));
        DrawFilled(hdc, x+1, y+1+(h-2-fillH), w-2, fillH, RGB(r,g,b));
    }

    void DrawESPBox(HDC hdc, int x, int y, int w, int h, COLORREF c) {
        DrawRect(hdc, x-1, y-1, w+2, h+2, RGB(1,1,1));
        DrawRect(hdc, x, y, w, h, c);
        DrawRect(hdc, x+1, y+1, w-2, h-2, RGB(1,1,1));
    }

    // Corner box — less obtrusive alternative
    void DrawCornerBox(HDC hdc, int x, int y, int w, int h, COLORREF c, int cornerLen = 0) {
        if (cornerLen <= 0) cornerLen = (int)(w * 0.25f);
        if (cornerLen < 4) cornerLen = 4;
        // Top-left
        DrawLine(hdc, x, y, x + cornerLen, y, c, 2);
        DrawLine(hdc, x, y, x, y + cornerLen, c, 2);
        // Top-right
        DrawLine(hdc, x+w, y, x+w - cornerLen, y, c, 2);
        DrawLine(hdc, x+w, y, x+w, y + cornerLen, c, 2);
        // Bottom-left
        DrawLine(hdc, x, y+h, x + cornerLen, y+h, c, 2);
        DrawLine(hdc, x, y+h, x, y+h - cornerLen, c, 2);
        // Bottom-right
        DrawLine(hdc, x+w, y+h, x+w - cornerLen, y+h, c, 2);
        DrawLine(hdc, x+w, y+h, x+w, y+h - cornerLen, c, 2);
    }

    void DrawSkeleton(HDC hdc, uint64_t actor, int sw, int sh, COLORREF col) {
        static const int bones[][2] = {
            {BONE_HEAD, BONE_NECK}, {BONE_NECK, BONE_SPINE_03},
            {BONE_SPINE_03, BONE_SPINE_02}, {BONE_SPINE_02, BONE_SPINE_01},
            {BONE_SPINE_01, BONE_PELVIS},
            {BONE_NECK, BONE_L_UPPER}, {BONE_L_UPPER, BONE_L_LOWER}, {BONE_L_LOWER, BONE_L_HAND},
            {BONE_NECK, BONE_R_UPPER}, {BONE_R_UPPER, BONE_R_LOWER}, {BONE_R_LOWER, BONE_R_HAND},
            {BONE_PELVIS, BONE_L_THIGH}, {BONE_L_THIGH, BONE_L_CALF}, {BONE_L_CALF, BONE_L_FOOT},
            {BONE_PELVIS, BONE_R_THIGH}, {BONE_R_THIGH, BONE_R_CALF}, {BONE_R_CALF, BONE_R_FOOT},
        };

        Vec2 pts[100];
        bool ptValid[100] = {};
        int needed[] = {BONE_HEAD, BONE_NECK, BONE_SPINE_01, BONE_SPINE_02, BONE_SPINE_03,
                        BONE_PELVIS, BONE_L_UPPER, BONE_L_LOWER, BONE_L_HAND,
                        BONE_R_UPPER, BONE_R_LOWER, BONE_R_HAND,
                        BONE_L_THIGH, BONE_L_CALF, BONE_L_FOOT,
                        BONE_R_THIGH, BONE_R_CALF, BONE_R_FOOT};

        for (int b : needed) {
            Vec3 wp = GetBonePos(actor, b);
            if (wp.x == 0 && wp.y == 0 && wp.z == 0) continue;
            Vec2 sp;
            if (WorldToScreen(wp, g_cameraRot, g_cameraPos, g_cameraFOV, sw, sh, sp)) {
                pts[b] = sp; ptValid[b] = true;
            }
        }

        for (auto& bp : bones) {
            if (ptValid[bp[0]] && ptValid[bp[1]])
                DrawLine(hdc, (int)pts[bp[0]].x, (int)pts[bp[0]].y,
                         (int)pts[bp[1]].x, (int)pts[bp[1]].y, col);
        }
    }

    void RenderESP(HDC hdc, int sw, int sh) {
        if (!Config::espEnabled) return;
        std::lock_guard<std::mutex> lock(g_dataMutex);

        if (Config::aimbotEnabled) {
            float fovPx = (Config::aimbotFOV / 90.0f) * (sw * 0.5f);
            HPEN pen = CreatePen(PS_SOLID, 1, RGB(255,255,255));
            HPEN op = (HPEN)SelectObject(hdc, pen);
            HBRUSH ob = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
            Ellipse(hdc, (int)(sw/2-fovPx), (int)(sh/2-fovPx), (int)(sw/2+fovPx), (int)(sh/2+fovPx));
            SelectObject(hdc, ob); SelectObject(hdc, op); DeleteObject(pen);
        }

        for (int i = 0; i < g_playerCount; i++) {
            auto& p = g_players[i];
            if (!p.valid || p.distance > Config::maxESPDist) continue;

            Vec2 feetScreen, headScreen;
            if (!WorldToScreen(p.origin, g_cameraRot, g_cameraPos, g_cameraFOV, sw, sh, feetScreen)) continue;
            if (!WorldToScreen(p.headPos, g_cameraRot, g_cameraPos, g_cameraFOV, sw, sh, headScreen)) continue;

            float boxH = fabsf(feetScreen.y - headScreen.y);
            if (boxH < 4.0f) continue;
            float boxW = boxH * 0.45f;
            int bx = (int)(headScreen.x - boxW * 0.5f);
            int by = (int)headScreen.y;
            int bw = (int)boxW;
            int bh = (int)boxH;

            COLORREF boxCol = RGB(255, 120, 0); // orange for enemies

            if (Config::espBoxes)
                DrawCornerBox(hdc, bx, by, bw, bh, boxCol);

            if (Config::espSkeleton)
                DrawSkeleton(hdc, p.actorPtr, sw, sh, RGB(255, 180, 50));

            if (Config::espHealth) {
                float hp = (p.maxHealth > 0) ? (float)p.health / p.maxHealth : 0;
                DrawHealthBar(hdc, bx - 7, by, 4, bh, hp, RGB(0,255,0), RGB(255,0,0));
            }

            if (Config::espShield && p.maxShield > 0) {
                float sp = (float)p.shield / p.maxShield;
                DrawHealthBar(hdc, bx + bw + 3, by, 4, bh, sp, RGB(0,150,255), RGB(40,40,40));
            }

            int textY = by - 16;
            if (Config::espNames && p.name[0]) {
                char narrowName[128] = {};
                WideCharToMultiByte(CP_ACP, 0, p.name, -1, narrowName, 127, NULL, NULL);
                DrawText_(hdc, bx, textY, narrowName, RGB(255,255,255), espFontSm);
                textY -= 14;
            }

            if (Config::espDistance) {
                char dist[32];
                snprintf(dist, sizeof(dist), "%.0fm", p.distance);
                DrawText_(hdc, bx, (int)(feetScreen.y + 3), dist, RGB(200,200,200), espFontSm);
            }

            if (Config::espSnaplines)
                DrawLine(hdc, sw/2, sh, (int)feetScreen.x, (int)feetScreen.y, RGB(255,180,0));

            char hpTxt[32];
            snprintf(hpTxt, sizeof(hpTxt), "%d HP", p.health);
            DrawText_(hdc, bx + bw + 10, by + bh/2 - 6, hpTxt, RGB(220,220,220), espFontSm);
        }
    }

    void RenderHUD(HDC hdc, int sw, int sh) {
        int y = 10;
        char buf[128];
        snprintf(buf, sizeof(buf), "Delta Force ESP  |  Players: %d  |  F1 Menu  |  END Exit", g_playerCount);
        DrawText_(hdc, 10, y, buf, RGB(255, 160, 50), espFont);
        y += 18;

        if (Config::aimbotEnabled) DrawText_(hdc, 10, y, "[AIMBOT]", RGB(255,100,100), espFontSm), y += 14;
        if (Config::triggerbotEnabled) DrawText_(hdc, 10, y, "[TRIGGERBOT]", RGB(255,200,100), espFontSm), y += 14;
        if (Config::noRecoil) DrawText_(hdc, 10, y, "[NO RECOIL]", RGB(100,255,100), espFontSm), y += 14;
    }

    void RenderMenu(HDC hdc, int sw, int sh) {
        if (!Config::menuOpen) return;

        int mx = 50, my = 50;
        int mw = 300, mh = 460;
        DrawFilled(hdc, mx, my, mw, mh, RGB(15,15,22));
        DrawRect(hdc, mx, my, mw, mh, RGB(90,60,20));

        DrawFilled(hdc, mx, my, mw, 28, RGB(30,22,10));
        DrawText_(hdc, mx+10, my+6, "DELTA FORCE EXTERNAL", RGB(255, 160, 50), menuFontB);

        int y = my + 36;
        auto toggle = [&](const char* label, bool& val) {
            char line[128];
            snprintf(line, sizeof(line), "[%c] %s", val ? 'X' : ' ', label);
            DrawText_(hdc, mx+12, y, line, val ? RGB(0,220,80) : RGB(180,180,180), menuFont);
            y += 20;
        };
        auto slider = [&](const char* label, float val, const char* sfx) {
            char line[128];
            snprintf(line, sizeof(line), "  %s: %.1f%s", label, val, sfx);
            DrawText_(hdc, mx+12, y, line, RGB(255, 180, 80), menuFont);
            y += 20;
        };

        DrawText_(hdc, mx+12, y, "--- ESP ---", RGB(255, 160, 50), menuFontB); y += 20;
        toggle("ESP [F2]",        Config::espEnabled);
        toggle("Boxes",           Config::espBoxes);
        toggle("Skeleton",        Config::espSkeleton);
        toggle("Health Bars",     Config::espHealth);
        toggle("Shield Bars",     Config::espShield);
        toggle("Names",           Config::espNames);
        toggle("Distance",        Config::espDistance);
        toggle("Snaplines",       Config::espSnaplines);
        slider("Max Dist",        Config::maxESPDist, "m");

        DrawText_(hdc, mx+12, y, "--- AIM ---", RGB(255, 160, 50), menuFontB); y += 20;
        toggle("Aimbot [F3]",     Config::aimbotEnabled);
        slider("FOV",             Config::aimbotFOV, "");
        slider("Smooth",          Config::aimbotSmooth, "");
        toggle("Triggerbot [F4]", Config::triggerbotEnabled);
        toggle("No Recoil [F5]",  Config::noRecoil);
        slider("Recoil Comp",     Config::recoilComp, "");
    }

    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
        if (msg == WM_PAINT) { PAINTSTRUCT ps; BeginPaint(hwnd, &ps); EndPaint(hwnd, &ps); return 0; }
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }

    void Run() {
        timeBeginPeriod(1);
        int refreshRate = 60;
        { HDC sdc = GetDC(NULL); int rr = GetDeviceCaps(sdc, VREFRESH); ReleaseDC(NULL, sdc);
          if (rr > 10 && rr <= 360) refreshRate = rr; }

        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = "DfOvr01";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        RegisterClassExA(&wc);

        overlayWnd = CreateWindowExA(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            "DfOvr01", "",
            WS_POPUP,
            -1, -1, 1, 1,
            NULL, NULL, GetModuleHandle(NULL), NULL);
        if (!overlayWnd) return;

        // STREAMPROOF: WDA_EXCLUDEFROMCAPTURE (0x11)
        // Excludes overlay from ALL capture APIs:
        // - OBS (Game Capture, Window Capture, Display Capture)
        // - Discord screenshare / Go Live
        // - Windows Game Bar (Win+G recording)
        // - NVIDIA Shadowplay / GeForce Experience
        // - AMD ReLive
        // - Any app using PrintWindow / BitBlt / DDA / WGC
        // Requires Windows 10 2004 (20H1) or later
        if (!SetWindowDisplayAffinity(overlayWnd, 0x11)) {
            // Fallback for older Windows: WDA_MONITOR (0x01) — shows black instead
            SetWindowDisplayAffinity(overlayWnd, 0x01);
        }

        bool overlayShown = false;

        espFont   = CreateFontA(16, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, "Consolas");
        espFontSm = CreateFontA(12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, "Consolas");
        menuFont  = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
        menuFontB = CreateFontA(14, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");

        MSG msg;
        while (running) {
            while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) { running = false; break; }
                TranslateMessage(&msg); DispatchMessageA(&msg);
            }

            // Hotkeys
            static bool f1was = false, f2was = false, f3was = false, f4was = false, f5was = false;
            bool f1 = (GetAsyncKeyState(VK_F1) & 0x8000) != 0;
            bool f2 = (GetAsyncKeyState(VK_F2) & 0x8000) != 0;
            bool f3 = (GetAsyncKeyState(VK_F3) & 0x8000) != 0;
            bool f4 = (GetAsyncKeyState(VK_F4) & 0x8000) != 0;
            bool f5 = (GetAsyncKeyState(VK_F5) & 0x8000) != 0;
            if (f1 && !f1was) {
                Config::menuOpen = !Config::menuOpen;
                LONG ex = GetWindowLongA(overlayWnd, GWL_EXSTYLE);
                if (Config::menuOpen) SetWindowLongA(overlayWnd, GWL_EXSTYLE, ex & ~WS_EX_TRANSPARENT);
                else SetWindowLongA(overlayWnd, GWL_EXSTYLE, ex | WS_EX_TRANSPARENT);
            }
            if (f2 && !f2was) Config::espEnabled = !Config::espEnabled;
            if (f3 && !f3was) Config::aimbotEnabled = !Config::aimbotEnabled;
            if (f4 && !f4was) Config::triggerbotEnabled = !Config::triggerbotEnabled;
            if (f5 && !f5was) Config::noRecoil = !Config::noRecoil;
            f1was=f1; f2was=f2; f3was=f3; f4was=f4; f5was=f5;

            if (!gameWnd || !IsWindow(gameWnd)) {
                gameWnd = FindWindowA(g_windowClass.c_str(), NULL);
                if (!gameWnd && !g_windowTitle.empty())
                    gameWnd = FindWindowA(NULL, g_windowTitle.c_str());
                if (!gameWnd) {
                    if (overlayShown) { ShowWindow(overlayWnd, SW_HIDE); overlayShown = false; }
                    Sleep(100); continue;
                }
            }

            RECT cr; GetClientRect(gameWnd, &cr);
            POINT tl = {0,0}; ClientToScreen(gameWnd, &tl);
            int gw = cr.right, gh = cr.bottom;

            if (!overlayShown) {
                SetWindowPos(overlayWnd, HWND_TOPMOST, tl.x, tl.y, gw, gh, SWP_NOACTIVATE);
                ShowWindow(overlayWnd, SW_SHOWNOACTIVATE);
                overlayShown = true;
                g_cachedGX = tl.x; g_cachedGY = tl.y;
            } else if (tl.x != g_cachedGX || tl.y != g_cachedGY || gw != g_cachedW || gh != g_cachedH) {
                SetWindowPos(overlayWnd, HWND_TOPMOST, tl.x, tl.y, gw, gh, SWP_NOACTIVATE);
                g_cachedGX = tl.x; g_cachedGY = tl.y;
            }

            HDC sdc = GetDC(NULL);
            if (!g_memDC) g_memDC = CreateCompatibleDC(sdc);
            if (gw != g_cachedW || gh != g_cachedH) {
                if (g_memBmp) { SelectObject(g_memDC, g_memOld); DeleteObject(g_memBmp); }
                g_memBmp = CreateCompatibleBitmap(sdc, gw, gh);
                g_memOld = (HBITMAP)SelectObject(g_memDC, g_memBmp);
                g_cachedW = gw; g_cachedH = gh;
            }

            RECT clr = {0, 0, gw, gh};
            HBRUSH clrBr = CreateSolidBrush(RGB(0,0,0));
            FillRect(g_memDC, &clr, clrBr); DeleteObject(clrBr);

            RenderESP(g_memDC, gw, gh);
            RenderHUD(g_memDC, gw, gh);
            RenderMenu(g_memDC, gw, gh);

            POINT ptSrc = {0,0};
            POINT ptDst = {tl.x, tl.y};
            SIZE szWnd = {gw, gh};
            BLENDFUNCTION blend = {AC_SRC_OVER, 0, 255, 0};
            UpdateLayeredWindow(overlayWnd, sdc, &ptDst, &szWnd,
                                g_memDC, &ptSrc, RGB(0,0,0), &blend, ULW_COLORKEY);
            ReleaseDC(NULL, sdc);

            double targetMs = 1000.0 / refreshRate;
            Sleep((DWORD)max(1.0, targetMs - 2.0));
        }

        if (g_memBmp) { SelectObject(g_memDC, g_memOld); DeleteObject(g_memBmp); }
        if (g_memDC)  DeleteDC(g_memDC);
        timeEndPeriod(1);
        if (espFont)   DeleteObject(espFont);
        if (espFontSm) DeleteObject(espFontSm);
        if (menuFont)  DeleteObject(menuFont);
        if (menuFontB) DeleteObject(menuFontB);
        DestroyWindow(overlayWnd);
        UnregisterClassA("DfOvr01", GetModuleHandle(NULL));
    }

    void Shutdown() { running = false; }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Aimbot — smooth mouse to nearest enemy head
// ═══════════════════════════════════════════════════════════════════════════════

static void AimbotTick(int sw, int sh) {
    if (!Config::aimbotEnabled) return;
    if (!(GetAsyncKeyState(VK_RBUTTON) & 0x8000)) return;

    float bestDist = 99999.f;
    Vec2 bestScreen = {};
    bool found = false;

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (int i = 0; i < g_playerCount; i++) {
        auto& p = g_players[i];
        if (!p.valid) continue;

        Vec3 target;
        switch (Config::aimbotBone) {
            case 0: target = p.headPos; break;
            case 1: target = {p.origin.x, p.origin.y, p.origin.z + 60.f}; break;
            default: target = {p.origin.x, p.origin.y, p.origin.z + 42.f}; break;
        }

        Vec2 screen;
        if (!WorldToScreen(target, g_cameraRot, g_cameraPos, g_cameraFOV, sw, sh, screen)) continue;

        float dx = screen.x - sw/2.0f;
        float dy = screen.y - sh/2.0f;
        float dist = sqrtf(dx*dx + dy*dy);
        float fovPx = (Config::aimbotFOV / 90.0f) * (sw * 0.5f);
        if (dist > fovPx) continue;
        if (dist < bestDist) { bestDist = dist; bestScreen = screen; found = true; }
    }

    if (found) {
        float dx = (bestScreen.x - sw/2.0f) / Config::aimbotSmooth;
        float dy = (bestScreen.y - sh/2.0f) / Config::aimbotSmooth;
        mouse_event(MOUSEEVENTF_MOVE, (DWORD)(int)dx, (DWORD)(int)dy, 0, 0);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Triggerbot — auto-fire when crosshair on enemy
// ═══════════════════════════════════════════════════════════════════════════════

static void TriggerbotTick(int sw, int sh) {
    if (!Config::triggerbotEnabled) return;
    if (!(GetAsyncKeyState(VK_XBUTTON1) & 0x8000)) return;

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (int i = 0; i < g_playerCount; i++) {
        auto& p = g_players[i];
        if (!p.valid) continue;

        Vec2 feetS, headS;
        if (!WorldToScreen(p.origin, g_cameraRot, g_cameraPos, g_cameraFOV, sw, sh, feetS)) continue;
        if (!WorldToScreen(p.headPos, g_cameraRot, g_cameraPos, g_cameraFOV, sw, sh, headS)) continue;

        float boxH = fabsf(feetS.y - headS.y);
        float boxW = boxH * 0.45f;
        float cx = sw / 2.0f, cy = sh / 2.0f;

        if (cx > headS.x - boxW/2 && cx < headS.x + boxW/2 &&
            cy > headS.y && cy < feetS.y) {
            Sleep(Config::triggerbotDelay);
            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
            Sleep(30);
            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            Sleep(100);
            return;
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// No-recoil — compensate via mouse movement
// ═══════════════════════════════════════════════════════════════════════════════

static Vec2 g_lastRecoil = {};

static void NoRecoilTick() {
    if (!Config::noRecoil) return;
    if (!(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        g_lastRecoil = {};
        return;
    }

    if (!Offsets::RecoilPitch || !Offsets::RecoilYaw) return;

    uint64_t localPawn = 0;
    {
        uint64_t gworld = rpm<uint64_t>(g_base + Offsets::GWorld);
        if (!gworld) return;
        uint64_t gi = rpm<uint64_t>(gworld + Offsets::OwningGameInstance);
        if (!gi) return;
        uint64_t lp = rpm<uint64_t>(rpm<uint64_t>(gi + Offsets::LocalPlayers));
        if (!lp) return;
        uint64_t pc = rpm<uint64_t>(lp + Offsets::PlayerController);
        if (!pc) return;
        localPawn = rpm<uint64_t>(pc + Offsets::AcknowledgedPawn);
    }
    if (!localPawn) return;

    float pitch = rpm<float>(localPawn + Offsets::RecoilPitch);
    float yaw   = rpm<float>(localPawn + Offsets::RecoilYaw);

    float dx = -(yaw - g_lastRecoil.x) * Config::recoilComp;
    float dy = -(pitch - g_lastRecoil.y) * Config::recoilComp;
    g_lastRecoil = {yaw, pitch};

    if (fabsf(dx) > 0.01f || fabsf(dy) > 0.01f) {
        float sens = 0.022f;
        mouse_event(MOUSEEVENTF_MOVE, (DWORD)(int)(dx / sens), (DWORD)(int)(dy / sens), 0, 0);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    printf("=== Delta Force External Cheat Suite ===\n\n");

    // Determine offsets file path (next to exe, or explicit arg)
    std::string offsetsPath = "df_offsets.ini";
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--offsets=", 9) == 0) offsetsPath = argv[i] + 9;
    }

    // Load game configuration from offsets file
    LoadOffsets(offsetsPath.c_str());

    // Game identity from config or defaults
    g_processName = "DeltaForce.exe";
    g_windowClass = "UnrealWindow";
    g_windowTitle = "Delta Force";
    g_moduleName  = "DeltaForce.exe";

    auto it = g_offsets.find("ProcessName");
    if (it != g_offsets.end()) {} // string offsets handled separately
    // Read string overrides from offsets file manually
    {
        std::ifstream f(offsetsPath);
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
            if (key == "ProcessName") g_processName = val;
            else if (key == "WindowClass") g_windowClass = val;
            else if (key == "WindowTitle") g_windowTitle = val;
            else if (key == "ModuleName") g_moduleName = val;
        }
    }

    Offsets::Init();

    if (!Offsets::GWorld) {
        printf("[!] WARNING: GWorld offset is 0 — offsets not configured.\n");
        printf("    Edit %s with correct offsets for your game version.\n", offsetsPath.c_str());
        printf("    The cheat will run but ESP will not display until offsets are set.\n\n");
    }

    printf("[*] Target: %s (window: %s)\n", g_processName.c_str(), g_windowClass.c_str());
    printf("[*] Connecting to Betest driver...\n");
    if (!DriverInit()) {
        printf("[!] Driver not loaded — launching mapper with HWID spoofer...\n");

        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir(exePath);
        exeDir = exeDir.substr(0, exeDir.find_last_of("\\/") + 1);

        std::string mapperPath = exeDir + "mapper_nal.exe";
        std::string driverPath = exeDir + "Betest.sys";

        if (GetFileAttributesA(mapperPath.c_str()) == INVALID_FILE_ATTRIBUTES ||
            GetFileAttributesA(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] mapper_nal.exe or Betest.sys not found in: %s\n", exeDir.c_str());
            printf("    Place them next to this exe.\n");
            system("pause");
            return 1;
        }

        std::string cmd = "\"" + mapperPath + "\" \"" + driverPath +
            "\" --driver trixx --stealth 3f --eac 7f --hwid 3f --hwid-game deltaforce --tpm-spoof 7 --no-auth";
        printf("[*] Running: %s\n", cmd.c_str());

        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                             0, nullptr, exeDir.c_str(), &si, &pi)) {
            printf("[-] Failed to launch mapper: %lu\n", GetLastError());
            system("pause");
            return 1;
        }
        printf("[*] Mapper running (PID %lu), waiting...\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 120000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        {
            SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (scm) {
                const char* svcNames[] = { "TrixxSvc", "SivSvc", "WdBroker", "NalDrv", "NalDrvIntel", "iqvw64e", "TsSvc" };
                for (auto sn : svcNames) {
                    SC_HANDLE svc = OpenServiceA(scm, sn, SERVICE_ALL_ACCESS);
                    if (svc) {
                        SERVICE_STATUS ss;
                        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                    }
                }
                CloseServiceHandle(scm);
                printf("[+] BYOVD service entries cleaned\n");
            }
        }

        Sleep(1000);
        if (!DriverInit()) {
            printf("[-] Driver still not available after mapper ran.\n");
            system("pause");
            return 1;
        }
        printf("[+] Driver loaded and connected (HWID spoofer active)\n");
    } else {
        printf("[+] Driver already loaded — connected\n");
    }

    printf("[*] Waiting for %s...\n", g_processName.c_str());
    while (!(g_pid = FindProcess(g_processName.c_str()))) {
        if (GetAsyncKeyState(VK_END) & 1) return 0;
        Sleep(1000);
        printf(".");
    }
    printf("\n[+] Found %s  PID=%u\n", g_processName.c_str(), g_pid);

    g_base = GetModuleBase(g_pid, g_moduleName.c_str());
    if (!g_base) {
        printf("[!] Module base not found via toolhelp, trying fallback...\n");
        g_base = 0x140000000;
    }
    printf("[+] %s base: 0x%llX\n", g_moduleName.c_str(), g_base);

    if (Config::hideProcess) {
        if (HideProcess(GetCurrentProcessId())) printf("[+] Process hidden via DKOM\n");
        else printf("[!] Process hide failed (non-critical)\n");
    }

    printf("[+] Starting overlay (STREAMPROOF)\n");
    printf("    F1 = Toggle menu\n");
    printf("    F2 = Toggle ESP\n");
    printf("    F3 = Toggle Aimbot\n");
    printf("    F4 = Toggle Triggerbot\n");
    printf("    F5 = Toggle No Recoil\n");
    printf("    END = Exit\n\n");

    std::thread overlayThread(Overlay::Run);
    overlayThread.detach();

    HWND gw = NULL;
    RECT cr;
    while (true) {
        if (GetAsyncKeyState(VK_END) & 1) break;

        if (!gw || !IsWindow(gw)) {
            gw = FindWindowA(g_windowClass.c_str(), NULL);
            if (!gw && !g_windowTitle.empty())
                gw = FindWindowA(NULL, g_windowTitle.c_str());
        }
        if (!gw) { Sleep(500); continue; }
        GetClientRect(gw, &cr);
        int sw = cr.right, sh = cr.bottom;

        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            ReadPlayers();
        }

        AimbotTick(sw, sh);
        TriggerbotTick(sw, sh);
        NoRecoilTick();

        Sleep(3 + (GetTickCount() % 7)); // jittered to defeat EAC timing profiling
    }

    printf("[*] Shutting down...\n");
    Overlay::Shutdown();
    Sleep(300);

    if (g_hDev != INVALID_HANDLE_VALUE) CloseHandle(g_hDev);
    if (g_ioBuf) VirtualFree(g_ioBuf, 0, MEM_RELEASE);

    return 0;
}
