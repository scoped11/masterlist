// CTF Task 96A: Apex Legends External Cheat Suite
// Streamproof ESP overlay + aim assist + triggerbot + no-recoil
// Uses Betest kernel driver (IOCTL 0x805/0x806) via BYOVD stealth stack
//
// Build: bld_apex.cmd
// Run:   apex_external.exe  (requires Betest driver mapped + r5apex.exe running)

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

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "winmm.lib")


// ═══════════════════════════════════════════════════════════════════════════════
// Driver interface — Betest IOCTL read/write process memory
// ═══════════════════════════════════════════════════════════════════════════════

#define IOCTL_READ_PROC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WRITE_PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_SESSION_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_DISABLE_EAC  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_WRITE_DATA)

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

static bool DisableEAC() {
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, IOCTL_DISABLE_EAC,
                           nullptr, 0, nullptr, 0, &ret, nullptr) != FALSE;
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
// Apex Legends SDK — Offsets & Structures
// These offsets are for Season 21+ (may need updating per patch)
// ═══════════════════════════════════════════════════════════════════════════════

namespace Offsets {
    // Core
    uint64_t EntityList      = 0x1F3A258;
    uint64_t LocalPlayer     = 0x2282078;
    uint64_t ViewMatrix      = 0x11A350;
    uint64_t ViewRender      = 0x7540598;
    uint64_t GlobalVars      = 0x16B0B80;
    uint64_t NameList        = 0xD319E58;
    uint64_t LevelName       = 0x16B0E60;

    // CPlayer
    uint64_t Health          = 0x0438;
    uint64_t MaxHealth       = 0x0578;
    uint64_t Shield          = 0x0170;
    uint64_t MaxShield       = 0x0174;
    uint64_t TeamNum         = 0x044C;
    uint64_t LifeState       = 0x0798;
    uint64_t BleedoutState   = 0x2790;
    uint64_t LastVisTime     = 0x19C0;
    uint64_t VecOrigin       = 0x014C;
    uint64_t VecAbsVel       = 0x0140;
    uint64_t ViewAngles      = 0x2564;
    uint64_t BoneMatrix      = 0x0E98;
    uint64_t CameraPos       = 0x1F48;
    uint64_t BreathAngles    = 0x2594;
    uint64_t SignifierName   = 0x0589;
    uint64_t ModelName       = 0x0030;
    uint64_t LastAimedAt     = 0x19A0;
    uint64_t ZoomFOV         = 0x1700;
    uint64_t WeaponIndex     = 0x1A2C;

    // Glow
    uint64_t GlowEnable      = 0x03C8;
    uint64_t GlowThroughWall = 0x03D0;
    uint64_t GlowColor       = 0x01D0;
    uint64_t GlowMode        = 0x02C4;

    // Punch angles (recoil)
    uint64_t AimPunchAngle   = 0x2468;

    // Misc
    uint64_t YawAngle        = 0x224C;
    uint64_t TimeBase        = 0x2098;
    uint64_t ObserverMode    = 0x3534;
    uint64_t SquadID         = 0x0450;

}

// ═══════════════════════════════════════════════════════════════════════════════
// Math — vectors, view matrix, world-to-screen
// ═══════════════════════════════════════════════════════════════════════════════

struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };

struct Matrix4x4 { float m[4][4]; };

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif
#define DEG2RAD(x) ((x) * (float)M_PI / 180.0f)
#define RAD2DEG(x) ((x) * 180.0f / (float)M_PI)

static float Vec3Dist(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

static float Vec3Dist2D(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y;
    return sqrtf(dx*dx + dy*dy);
}

static bool WorldToScreen(const Vec3& world, const Matrix4x4& vm, int w, int h, Vec2& out) {
    float sw = vm.m[0][0]*world.x + vm.m[0][1]*world.y + vm.m[0][2]*world.z + vm.m[0][3];
    float sh = vm.m[1][0]*world.x + vm.m[1][1]*world.y + vm.m[1][2]*world.z + vm.m[1][3];
    float wd = vm.m[3][0]*world.x + vm.m[3][1]*world.y + vm.m[3][2]*world.z + vm.m[3][3];
    if (wd < 0.001f) return false;
    float ndc_x = sw / wd;
    float ndc_y = sh / wd;
    out.x = (w * 0.5f) + (ndc_x * w * 0.5f);
    out.y = (h * 0.5f) - (ndc_y * h * 0.5f);
    return true;
}

static Vec2 CalcAngle(Vec3 src, Vec3 dst) {
    Vec3 d = { dst.x-src.x, dst.y-src.y, dst.z-src.z };
    float hyp = sqrtf(d.x*d.x + d.y*d.y);
    return { -RAD2DEG(atan2f(d.z, hyp)), RAD2DEG(atan2f(d.y, d.x)) };
}

static float NormalizeAngle(float a) {
    while (a > 180.f) a -= 360.f;
    while (a < -180.f) a += 360.f;
    return a;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Apex entity reading
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t g_base = 0; // r5apex.exe base

struct PlayerData {
    uint64_t ptr;
    Vec3     origin;
    Vec3     headPos;
    int      health, maxHealth;
    int      shield, maxShield;
    int      team;
    int      lifeState;
    int      bleedout;
    float    lastVisTime;
    float    distance;
    char     name[64];
    bool     isVisible;
    bool     valid;
};

static int         g_localTeam = 0;
static Vec3        g_localPos = {};
static Vec3        g_localAngles = {};
static Vec3        g_aimPunch = {};
static Matrix4x4   g_viewMatrix = {};
static PlayerData  g_players[64];
static int         g_playerCount = 0;
static std::mutex  g_dataMutex;

static uint64_t GetEntityByIndex(int idx) {
    uint64_t chunk = rpm<uint64_t>(g_base + Offsets::EntityList + ((idx >> 9) * 8));
    if (!chunk) return 0;
    return rpm<uint64_t>(chunk + ((uint64_t)(idx & 0x1FF) * 32));
}

static Vec3 GetBonePos(uint64_t entity, int boneId) {
    uint64_t bonePtr = rpm<uint64_t>(entity + Offsets::BoneMatrix);
    if (!bonePtr) return {};
    struct BoneData { float x, y, z, w; } b;
    DriverRead(bonePtr + (uint64_t)boneId * 48 + 12, &b, sizeof(b));
    Vec3 origin = rpm<Vec3>(entity + Offsets::VecOrigin);
    return { origin.x + b.x, origin.y + b.y, origin.z + b.z };
}

static void ReadPlayers() {
    uint64_t localEnt = rpm<uint64_t>(g_base + Offsets::LocalPlayer);
    if (!localEnt) return;

    g_localTeam   = rpm<int>(localEnt + Offsets::TeamNum);
    g_localPos    = rpm<Vec3>(localEnt + Offsets::CameraPos);
    g_localAngles = rpm<Vec3>(localEnt + Offsets::ViewAngles);
    g_aimPunch    = rpm<Vec3>(localEnt + Offsets::AimPunchAngle);

    DriverRead(g_base + Offsets::ViewMatrix, &g_viewMatrix, sizeof(g_viewMatrix));

    int count = 0;
    for (int i = 0; i < 64 && count < 64; i++) {
        uint64_t ent = GetEntityByIndex(i);
        if (!ent || ent == localEnt) continue;

        int lifeState = rpm<int>(ent + Offsets::LifeState);
        if (lifeState != 0) continue;

        int team = rpm<int>(ent + Offsets::TeamNum);
        if (team == g_localTeam) continue;

        PlayerData& p = g_players[count];
        p.ptr       = ent;
        p.origin    = rpm<Vec3>(ent + Offsets::VecOrigin);
        p.health    = rpm<int>(ent + Offsets::Health);
        p.maxHealth = rpm<int>(ent + Offsets::MaxHealth);
        p.shield    = rpm<int>(ent + Offsets::Shield);
        p.maxShield = rpm<int>(ent + Offsets::MaxShield);
        p.team      = team;
        p.lifeState = lifeState;
        p.bleedout  = rpm<int>(ent + Offsets::BleedoutState);
        p.lastVisTime = rpm<float>(ent + Offsets::LastVisTime);
        p.distance  = Vec3Dist(g_localPos, p.origin) * 0.0254f; // convert units to meters

        p.headPos = GetBonePos(ent, 8); // bone 8 = head
        if (p.headPos.x == 0 && p.headPos.y == 0 && p.headPos.z == 0)
            p.headPos = { p.origin.x, p.origin.y, p.origin.z + 68.0f };

        float curTime = rpm<float>(g_base + Offsets::GlobalVars + 0x10);
        p.isVisible = (curTime - p.lastVisTime < 0.1f);

        DriverRead(ent + Offsets::SignifierName, p.name, 63);
        p.name[63] = 0;

        p.valid = (p.health > 0 && p.distance < 500.f);
        if (p.valid) count++;
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
    bool espShield       = true;
    bool espNames        = true;
    bool espDistance      = true;
    bool espSnaplines    = false;
    bool espGlow         = false;

    bool aimbotEnabled   = false;
    float aimbotFOV      = 15.0f;
    float aimbotSmooth   = 5.0f;
    int   aimbotBone     = 8;       // 0=head, 1=neck, 2=chest
    bool  aimbotVisCheck = true;

    bool triggerbotEnabled = false;
    int  triggerbotDelay   = 50;     // ms

    bool noRecoil        = false;
    float recoilComp     = 0.7f;

    bool hideProcess     = true;
    bool disableEAC      = true;

    float maxESPDist     = 300.0f;

    bool menuOpen        = true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Overlay — GDI, streamproof via WDA_EXCLUDEFROMCAPTURE
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

    void DrawHealthBar(HDC hdc, int x, int y, int w, int h, float hp, COLORREF full, COLORREF empty) {
        DrawFilled(hdc, x, y, w, h, RGB(10,10,10));
        int fillH = (int)((h-2) * hp);
        if (fillH < 0) fillH = 0;
        int r = (int)(GetRValue(full) * hp + GetRValue(empty) * (1-hp));
        int g = (int)(GetGValue(full) * hp + GetGValue(empty) * (1-hp));
        int b = (int)(GetBValue(full) * hp + GetBValue(empty) * (1-hp));
        DrawFilled(hdc, x+1, y+1+(h-2-fillH), w-2, fillH, RGB(r,g,b));
    }

    // Outlined box with dark border
    void DrawESPBox(HDC hdc, int x, int y, int w, int h, COLORREF c) {
        DrawRect(hdc, x-1, y-1, w+2, h+2, RGB(1,1,1));
        DrawRect(hdc, x, y, w, h, c);
        DrawRect(hdc, x+1, y+1, w-2, h-2, RGB(1,1,1));
    }

    // Skeleton: draw bones connecting key joints
    void DrawSkeleton(HDC hdc, uint64_t ent, int sw, int sh, COLORREF col) {
        // Apex bone indices: 0=hip, 1=waist, 2=spine, 4=spine2, 5=neck, 8=head
        // Arms: 9=L_clav, 10=L_upper, 11=L_fore, 12=L_hand, 65=R_clav, 66=R_upper, 67=R_fore, 68=R_hand
        // Legs: 78=L_thigh, 79=L_calf, 80=L_foot, 73=R_thigh, 74=R_calf, 75=R_foot
        static const int bones[][2] = {
            {8,5},{5,4},{4,2},{2,1},{1,0},       // spine
            {5,9},{9,10},{10,11},{11,12},          // left arm
            {5,65},{65,66},{66,67},{67,68},         // right arm
            {0,78},{78,79},{79,80},                 // left leg
            {0,73},{73,74},{74,75},                 // right leg
        };
        Vec2 pts[100];
        bool ptValid[100] = {};
        int neededBones[] = {0,1,2,4,5,8,9,10,11,12,65,66,67,68,73,74,75,78,79,80};
        for (int b : neededBones) {
            Vec3 wp = GetBonePos(ent, b);
            if (wp.x == 0 && wp.y == 0 && wp.z == 0) continue;
            Vec2 sp;
            if (WorldToScreen(wp, g_viewMatrix, sw, sh, sp)) {
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

        // Aimbot FOV circle
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
            if (!WorldToScreen(p.origin, g_viewMatrix, sw, sh, feetScreen)) continue;
            if (!WorldToScreen(p.headPos, g_viewMatrix, sw, sh, headScreen)) continue;

            float boxH = fabsf(feetScreen.y - headScreen.y);
            if (boxH < 4.0f) continue;
            float boxW = boxH * 0.5f;
            int bx = (int)(headScreen.x - boxW * 0.5f);
            int by = (int)headScreen.y;
            int bw = (int)boxW;
            int bh = (int)boxH;

            COLORREF boxCol = p.isVisible ? RGB(0, 255, 0) : RGB(255, 0, 0);

            if (Config::espBoxes)
                DrawESPBox(hdc, bx, by, bw, bh, boxCol);

            if (Config::espSkeleton)
                DrawSkeleton(hdc, p.ptr, sw, sh, p.isVisible ? RGB(0,200,0) : RGB(200,0,0));

            if (Config::espHealth) {
                float hp = (p.maxHealth > 0) ? (float)p.health / p.maxHealth : 0;
                DrawHealthBar(hdc, bx - 7, by, 4, bh, hp, RGB(0,255,0), RGB(255,0,0));
            }

            if (Config::espShield && p.maxShield > 0) {
                float sp = (float)p.shield / p.maxShield;
                COLORREF shieldCol = RGB(0, 150, 255);
                if (p.maxShield >= 100) shieldCol = RGB(200, 50, 200); // purple
                if (p.maxShield >= 125) shieldCol = RGB(255, 0, 0);   // red evo
                DrawHealthBar(hdc, bx + bw + 3, by, 4, bh, sp, shieldCol, RGB(40,40,40));
            }

            int textY = by - 16;
            if (Config::espNames && p.name[0]) {
                DrawText_(hdc, bx, textY, p.name, RGB(255,255,255), espFontSm);
                textY -= 14;
            }

            if (Config::espDistance) {
                char dist[32];
                snprintf(dist, sizeof(dist), "%.0fm", p.distance);
                DrawText_(hdc, bx, (int)(feetScreen.y + 3), dist, RGB(200,200,200), espFontSm);
            }

            if (Config::espSnaplines)
                DrawLine(hdc, sw/2, sh, (int)feetScreen.x, (int)feetScreen.y, RGB(255,255,0));

            // Health + shield text right of box
            char hpTxt[32];
            snprintf(hpTxt, sizeof(hpTxt), "%d/%d", p.health, p.shield);
            DrawText_(hdc, bx + bw + 10, by + bh/2 - 6, hpTxt, RGB(220,220,220), espFontSm);
        }
    }

    // Simple info HUD
    void RenderHUD(HDC hdc, int sw, int sh) {
        int y = 10;
        char buf[128];
        snprintf(buf, sizeof(buf), "Apex ESP  |  Players: %d  |  INS Menu  |  END Exit", g_playerCount);
        DrawText_(hdc, 10, y, buf, RGB(100,200,255), espFont);
        y += 18;

        if (Config::aimbotEnabled) DrawText_(hdc, 10, y, "[AIMBOT]", RGB(255,100,100), espFontSm), y += 14;
        if (Config::triggerbotEnabled) DrawText_(hdc, 10, y, "[TRIGGERBOT]", RGB(255,200,100), espFontSm), y += 14;
        if (Config::noRecoil) DrawText_(hdc, 10, y, "[NO RECOIL]", RGB(100,255,100), espFontSm), y += 14;
    }

    // Menu
    void RenderMenu(HDC hdc, int sw, int sh) {
        if (!Config::menuOpen) return;

        int mx = 50, my = 50;
        int mw = 300, mh = 460;
        DrawFilled(hdc, mx, my, mw, mh, RGB(15,15,22));
        DrawRect(hdc, mx, my, mw, mh, RGB(60,60,100));

        DrawFilled(hdc, mx, my, mw, 28, RGB(25,25,45));
        DrawText_(hdc, mx+10, my+6, "APEX EXTERNAL  |  CTF 96A", RGB(100,180,255), menuFontB);

        int y = my + 36;
        auto toggle = [&](const char* label, bool& val) {
            char line[128];
            snprintf(line, sizeof(line), "[%c] %s", val ? 'X' : ' ', label);
            DrawText_(hdc, mx+12, y, line, val ? RGB(0,220,80) : RGB(180,180,180), menuFont);
            y += 20;
        };
        auto slider = [&](const char* label, float val, float mn, float mx_, const char* sfx) {
            char line[128];
            snprintf(line, sizeof(line), "  %s: %.1f%s", label, val, sfx);
            DrawText_(hdc, mx+12, y, line, RGB(120,180,255), menuFont);
            y += 20;
        };

        DrawText_(hdc, mx+12, y, "--- ESP ---", RGB(100,170,255), menuFontB); y += 20;
        toggle("ESP [F2]",        Config::espEnabled);
        toggle("Boxes",           Config::espBoxes);
        toggle("Skeleton",        Config::espSkeleton);
        toggle("Health Bars",     Config::espHealth);
        toggle("Shield Bars",     Config::espShield);
        toggle("Names",           Config::espNames);
        toggle("Distance",        Config::espDistance);
        toggle("Snaplines",       Config::espSnaplines);
        slider("Max Dist",        Config::maxESPDist, 50, 500, "m");

        DrawText_(hdc, mx+12, y, "--- AIM ---", RGB(100,170,255), menuFontB); y += 20;
        toggle("Aimbot [F3]",     Config::aimbotEnabled);
        slider("FOV",             Config::aimbotFOV, 5, 45, "");
        slider("Smooth",          Config::aimbotSmooth, 1, 15, "");
        toggle("Vis Check",       Config::aimbotVisCheck);
        toggle("Triggerbot [F4]", Config::triggerbotEnabled);
        toggle("No Recoil [F5]",  Config::noRecoil);
        slider("Recoil Comp",     Config::recoilComp, 0.1f, 1.0f, "");

        DrawText_(hdc, mx+12, y, "--- MISC ---", RGB(100,170,255), menuFontB); y += 20;
        toggle("Glow ESP",        Config::espGlow);
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
        wc.lpszClassName = "ApexOvr96A";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        RegisterClassExA(&wc);

        // Start tiny and hidden — only show when game window is found (prevents taskbar vanishing)
        overlayWnd = CreateWindowExA(
            WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            "ApexOvr96A", "",
            WS_POPUP,
            -1, -1, 1, 1,
            NULL, NULL, GetModuleHandle(NULL), NULL);
        if (!overlayWnd) return;

        SetWindowDisplayAffinity(overlayWnd, 0x11); // WDA_EXCLUDEFROMCAPTURE
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
            bool f1 = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
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
                gameWnd = FindWindowA("Respawn001", NULL);
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
        UnregisterClassA("ApexOvr96A", GetModuleHandle(NULL));
    }

    void Shutdown() { running = false; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Aimbot — smooth mouse movement to nearest visible enemy head
// ═══════════════════════════════════════════════════════════════════════════════

static void AimbotTick(int sw, int sh) {
    if (!Config::aimbotEnabled) return;
    if (!(GetAsyncKeyState(VK_RBUTTON) & 0x8000)) return; // hold RMB to aim

    float bestDist = 99999.f;
    Vec2 bestScreen = {};
    bool found = false;

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (int i = 0; i < g_playerCount; i++) {
        auto& p = g_players[i];
        if (!p.valid) continue;
        if (Config::aimbotVisCheck && !p.isVisible) continue;

        Vec3 target = (Config::aimbotBone == 0) ? p.headPos :
                      (Config::aimbotBone == 1) ? Vec3{p.origin.x, p.origin.y, p.origin.z + 60.f} :
                                                   Vec3{p.origin.x, p.origin.y, p.origin.z + 42.f};
        Vec2 screen;
        if (!WorldToScreen(target, g_viewMatrix, sw, sh, screen)) continue;

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
// Triggerbot — auto-fire when crosshair is on enemy
// ═══════════════════════════════════════════════════════════════════════════════

static void TriggerbotTick(int sw, int sh) {
    if (!Config::triggerbotEnabled) return;
    if (!(GetAsyncKeyState(VK_XBUTTON1) & 0x8000)) return; // hold mouse4

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (int i = 0; i < g_playerCount; i++) {
        auto& p = g_players[i];
        if (!p.valid) continue;

        Vec2 feetS, headS;
        if (!WorldToScreen(p.origin, g_viewMatrix, sw, sh, feetS)) continue;
        if (!WorldToScreen(p.headPos, g_viewMatrix, sw, sh, headS)) continue;

        float boxH = fabsf(feetS.y - headS.y);
        float boxW = boxH * 0.5f;
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
// No-recoil — compensate for aim punch via mouse movement
// ═══════════════════════════════════════════════════════════════════════════════

static Vec3 g_lastPunch = {};

static void NoRecoilTick(int sw, int sh) {
    if (!Config::noRecoil) return;
    if (!(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        g_lastPunch = {};
        return;
    }

    Vec3 punch = g_aimPunch;
    float dx = -(punch.y - g_lastPunch.y) * Config::recoilComp;
    float dy = -(punch.x - g_lastPunch.x) * Config::recoilComp;
    g_lastPunch = punch;

    if (fabsf(dx) > 0.01f || fabsf(dy) > 0.01f) {
        float sens = 0.022f;
        int mx = (int)(dx / sens);
        int my = (int)(dy / sens);
        mouse_event(MOUSEEVENTF_MOVE, mx, my, 0, 0);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Glow ESP — write glow structs directly to game memory
// ═══════════════════════════════════════════════════════════════════════════════

static void GlowTick() {
    if (!Config::espGlow) return;

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (int i = 0; i < g_playerCount; i++) {
        auto& p = g_players[i];
        if (!p.valid) continue;

        int glowEnable = 1;
        int glowThrough = 2; // glow through walls
        struct { float r, g, b; } color;
        if (p.isVisible) { color = {0.0f, 1.0f, 0.0f}; }
        else             { color = {1.0f, 0.0f, 0.0f}; }

        wpm<int>(p.ptr + Offsets::GlowEnable, glowEnable);
        wpm<int>(p.ptr + Offsets::GlowThroughWall, glowThrough);
        wpm<float>(p.ptr + Offsets::GlowColor,     color.r);
        wpm<float>(p.ptr + Offsets::GlowColor + 4,  color.g);
        wpm<float>(p.ptr + Offsets::GlowColor + 8,  color.b);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    printf("=== CTF Task 96A: Apex Legends External Cheat Suite ===\n\n");

    printf("[*] Connecting to Betest driver...\n");
    if (!DriverInit()) {
        printf("[!] Driver not loaded — launching mapper with HWID spoofer...\n");

        // Find mapper + driver relative to our exe
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir(exePath);
        exeDir = exeDir.substr(0, exeDir.find_last_of("\\/") + 1);

        std::string mapperPath = exeDir + "mapper_nal.exe";
        std::string driverPath = exeDir + "Betest.sys";

        if (GetFileAttributesA(mapperPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] mapper_nal.exe not found in: %s\n", exeDir.c_str());
            printf("    Place mapper_nal.exe and Betest.sys next to apex_external.exe\n");
            system("pause");
            return 1;
        }
        if (GetFileAttributesA(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] Betest.sys not found in: %s\n", exeDir.c_str());
            system("pause");
            return 1;
        }

        std::string cmd = "\"" + mapperPath + "\" \"" + driverPath +
            "\" --driver trixx --stealth 3f --eac 7f --hwid 3f --hwid-game apex --tpm-spoof 7 --no-auth";
        printf("[*] Running: %s\n", cmd.c_str());

        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                             0, nullptr, exeDir.c_str(), &si, &pi)) {
            printf("[-] Failed to launch mapper: %lu\n", GetLastError());
            printf("    Try running mapper_nal.exe manually as admin.\n");
            system("pause");
            return 1;
        }

        printf("[*] Mapper running (PID %lu), waiting for it to finish...\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 120000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Force-clean BYOVD service entries so EAC/BE don't see them
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
            printf("    Check mapper output for errors.\n");
            system("pause");
            return 1;
        }
        printf("[+] Driver loaded and connected (HWID spoofer active)\n");
    } else {
        printf("[+] Driver already loaded — connected\n");
    }

    // Disable EAC callbacks if available
    if (Config::disableEAC) {
        if (DisableEAC()) printf("[+] EAC callbacks disabled\n");
        else printf("[!] EAC disable failed (non-critical)\n");
    }

    const char* procName = nullptr;
    printf("[*] Waiting for r5apex.exe / r5apex_dx12.exe...\n");
    while (!g_pid) {
        if ((g_pid = FindProcess("r5apex.exe")))      { procName = "r5apex.exe"; break; }
        if ((g_pid = FindProcess("r5apex_dx12.exe")))  { procName = "r5apex_dx12.exe"; break; }
        if (GetAsyncKeyState(VK_END) & 1) return 0;
        Sleep(1000);
        printf(".");
    }
    printf("\n[+] Found %s  PID=%u\n", procName, g_pid);

    // Get module base
    g_base = GetModuleBase(g_pid, procName);
    if (!g_base) {
        printf("[-] Failed to get %s base address\n", procName);
        printf("    Using PEB-based fallback...\n");
        g_base = 0x140000000; // typical base
    }
    printf("[+] %s base: 0x%llX\n", procName, g_base);

    // Hide our process from EAC
    if (Config::hideProcess) {
        if (HideProcess(GetCurrentProcessId())) printf("[+] Process hidden via DKOM\n");
        else printf("[!] Process hide failed (non-critical)\n");
    }

    printf("[+] Starting overlay...\n");
    printf("    INSERT = Toggle menu\n");
    printf("    F2 = Toggle ESP\n");
    printf("    F3 = Toggle Aimbot\n");
    printf("    F4 = Toggle Triggerbot\n");
    printf("    F5 = Toggle No Recoil\n");
    printf("    END = Exit\n\n");

    // Start overlay thread
    std::thread overlayThread(Overlay::Run);
    overlayThread.detach();

    // Main loop: read entities + features
    RECT cr; HWND gw = NULL;
    while (true) {
        if (GetAsyncKeyState(VK_END) & 1) break;

        if (!gw || !IsWindow(gw)) gw = FindWindowA("Respawn001", NULL);
        if (!gw) { Sleep(500); continue; }
        GetClientRect(gw, &cr);
        int sw = cr.right, sh = cr.bottom;

        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            ReadPlayers();
        }

        AimbotTick(sw, sh);
        TriggerbotTick(sw, sh);
        NoRecoilTick(sw, sh);
        GlowTick();

        Sleep(3 + (GetTickCount() % 7)); // jittered ~130-200Hz to defeat EAC timing profiling
    }

    printf("[*] Shutting down...\n");
    Overlay::Shutdown();
    Sleep(300);

    if (g_hDev != INVALID_HANDLE_VALUE) CloseHandle(g_hDev);
    if (g_ioBuf) VirtualFree(g_ioBuf, 0, MEM_RELEASE);

    return 0;
}
