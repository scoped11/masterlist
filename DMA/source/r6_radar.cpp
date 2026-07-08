// R6 DMA Radar — real-time 2D radar overlay
// Reads position buffer from entity at 0x227B172E030 (vtbl +0x115E7F10)
// Positions at stride 0x40 starting at +0x2C0
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_radar.cpp /Fe"../r6_radar.exe" /link user32.lib gdi32.lib

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <algorithm>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static fn_MemRead pMemRead;
static fn_Init pInit;
static fn_Close pClose;
static fn_PidGet pPidGet;
static fn_ModBase pModBase;
static VMM_HANDLE g_vmm;
static DWORD g_pid;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}

struct Vec3 { float x, y, z; };

// Radar config
static const int RADAR_W = 600;
static const int RADAR_H = 600;
static const int RADAR_CX = RADAR_W / 2;
static const int RADAR_CY = RADAR_H / 2;

// Position buffer config
static uint64_t g_entityAddr = 0x227B172E030;
static const int POS_START = 0x2C0;
static const int POS_STRIDE = 0x40;
static const int POS_END = 0x1E00;
static const int NUM_SLOTS = (POS_END - POS_START) / POS_STRIDE;
static const int BUF_SZ = 0x2000;
static const float CLUSTER_RADIUS = 3.0f;
static const int MAX_ENTS = 40;

// Per-slot raw tracking
struct SlotState {
    Vec3 pos;
    Vec3 prevPos;
    int changeCount;
    DWORD lastChange;
};

// Clustered unique entity
struct Entity {
    Vec3 pos;
    int slotCount;
    int totalChanges;
    DWORD lastChange;
    bool isPlayer;
};

static SlotState g_slots[200];
static Entity g_ents[MAX_ENTS];
static int g_entCount = 0;
static uint8_t g_readBuf[BUF_SZ];
static Vec3 g_center = {0, 0, 0};
static bool g_running = true;
static HWND g_hwnd = nullptr;
static HDC g_memDC = nullptr;
static HBITMAP g_memBmp = nullptr;
static HPEN g_gridPen, g_enemyPen, g_playerPen, g_deadPen;
static HBRUSH g_bgBrush, g_enemyBrush, g_playerBrush, g_deadBrush;
static float g_zoomScale = 3.0f;
static int g_playerEnt = -1;

void UpdatePositions() {
    if (!DmaRead(g_entityAddr, g_readBuf, BUF_SZ)) return;

    DWORD now = GetTickCount();

    // Phase 1: update per-slot state
    for (int i = 0; i < NUM_SLOTS; i++) {
        int off = POS_START + i * POS_STRIDE;
        Vec3 cur = *(Vec3*)(g_readBuf + off);

        if (isnan(cur.x) || isnan(cur.y) || isnan(cur.z)) continue;
        if (fabsf(cur.x) > 500.0f || fabsf(cur.y) > 500.0f || fabsf(cur.z) > 500.0f) continue;
        if (fabsf(cur.x) < 0.001f && fabsf(cur.y) < 0.001f) continue;

        float dx = cur.x - g_slots[i].pos.x;
        float dy = cur.y - g_slots[i].pos.y;
        float d = sqrtf(dx*dx + dy*dy);

        if (d > 0.01f) {
            g_slots[i].changeCount++;
            g_slots[i].lastChange = now;
        }

        g_slots[i].prevPos = g_slots[i].pos;
        g_slots[i].pos = cur;
    }

    // Phase 2: cluster slots into unique entities
    g_entCount = 0;
    for (int i = 0; i < NUM_SLOTS; i++) {
        if (g_slots[i].changeCount < 1) continue;
        if (now - g_slots[i].lastChange > 8000) continue;
        Vec3 p = g_slots[i].pos;
        if (fabsf(p.x) < 0.001f && fabsf(p.y) < 0.001f) continue;

        // Find existing cluster this slot belongs to
        int best = -1;
        float bestDist = CLUSTER_RADIUS;
        for (int e = 0; e < g_entCount; e++) {
            float dx = p.x - g_ents[e].pos.x;
            float dy = p.y - g_ents[e].pos.y;
            float d = sqrtf(dx*dx + dy*dy);
            if (d < bestDist) { bestDist = d; best = e; }
        }

        if (best >= 0) {
            // Merge into existing cluster — use position from slot with most changes
            g_ents[best].slotCount++;
            if (g_slots[i].changeCount > g_ents[best].totalChanges) {
                g_ents[best].pos = p;
                g_ents[best].totalChanges = g_slots[i].changeCount;
            }
            if (g_slots[i].lastChange > g_ents[best].lastChange)
                g_ents[best].lastChange = g_slots[i].lastChange;
        } else if (g_entCount < MAX_ENTS) {
            // New cluster
            g_ents[g_entCount].pos = p;
            g_ents[g_entCount].slotCount = 1;
            g_ents[g_entCount].totalChanges = g_slots[i].changeCount;
            g_ents[g_entCount].lastChange = g_slots[i].lastChange;
            g_ents[g_entCount].isPlayer = false;
            g_entCount++;
        }
    }

    // Phase 3: identify player — entity with most total slot changes
    g_playerEnt = -1;
    int maxChanges = 0;
    for (int e = 0; e < g_entCount; e++) {
        if (g_ents[e].totalChanges > maxChanges) {
            maxChanges = g_ents[e].totalChanges;
            g_playerEnt = e;
        }
    }
    if (g_playerEnt >= 0) {
        g_ents[g_playerEnt].isPlayer = true;
        g_center = g_ents[g_playerEnt].pos;
    }
}

void DrawRadar(HDC hdc) {
    RECT rc = {0, 0, RADAR_W, RADAR_H};
    FillRect(g_memDC, &rc, g_bgBrush);

    // Grid circles
    SelectObject(g_memDC, g_gridPen);
    SelectObject(g_memDC, GetStockObject(HOLLOW_BRUSH));
    for (int r = 1; r <= 6; r++) {
        int px = (int)(r * 10 * g_zoomScale);
        Ellipse(g_memDC, RADAR_CX - px, RADAR_CY - px, RADAR_CX + px, RADAR_CY + px);
    }
    MoveToEx(g_memDC, RADAR_CX, 0, NULL);
    LineTo(g_memDC, RADAR_CX, RADAR_H);
    MoveToEx(g_memDC, 0, RADAR_CY, NULL);
    LineTo(g_memDC, RADAR_W, RADAR_CY);

    // Draw clustered entities
    DWORD now = GetTickCount();
    for (int e = 0; e < g_entCount; e++) {
        float rx = (g_ents[e].pos.x - g_center.x) * g_zoomScale;
        float ry = (g_ents[e].pos.y - g_center.y) * g_zoomScale;
        int sx = RADAR_CX + (int)rx;
        int sy = RADAR_CY - (int)ry;

        if (sx < 5 || sx > RADAR_W - 5 || sy < 5 || sy > RADAR_H - 5) continue;

        bool recentlyMoved = (now - g_ents[e].lastChange < 2000);

        if (e == g_playerEnt) {
            SelectObject(g_memDC, g_playerPen);
            SelectObject(g_memDC, g_playerBrush);
            POINT tri[3] = {{sx, sy-8}, {sx-6, sy+6}, {sx+6, sy+6}};
            Polygon(g_memDC, tri, 3);
        } else if (recentlyMoved) {
            SelectObject(g_memDC, g_enemyPen);
            SelectObject(g_memDC, g_enemyBrush);
            Ellipse(g_memDC, sx-6, sy-6, sx+6, sy+6);
        } else {
            SelectObject(g_memDC, g_deadPen);
            SelectObject(g_memDC, g_deadBrush);
            Ellipse(g_memDC, sx-4, sy-4, sx+4, sy+4);
        }
    }

    // HUD
    SetBkMode(g_memDC, TRANSPARENT);
    SetTextColor(g_memDC, RGB(200, 200, 200));
    char txt[256];
    sprintf(txt, "R6 DMA Radar | Entities: %d | Zoom: %.1fx | +/- zoom | R reset | Q quit",
            g_entCount, g_zoomScale);
    TextOutA(g_memDC, 10, 5, txt, (int)strlen(txt));

    sprintf(txt, "Center: (%.1f, %.1f, %.1f)",
            g_center.x, g_center.y, g_center.z);
    TextOutA(g_memDC, 10, 22, txt, (int)strlen(txt));

    BitBlt(hdc, 0, 0, RADAR_W, RADAR_H, g_memDC, 0, 0, SRCCOPY);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        DrawRadar(hdc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_KEYDOWN:
        if (wp == 'Q' || wp == VK_ESCAPE) {
            g_running = false;
            PostQuitMessage(0);
        } else if (wp == VK_OEM_PLUS || wp == VK_ADD) {
            g_zoomScale *= 1.3f;
        } else if (wp == VK_OEM_MINUS || wp == VK_SUBTRACT) {
            g_zoomScale /= 1.3f;
            if (g_zoomScale < 0.5f) g_zoomScale = 0.5f;
        } else if (wp == 'R') {
            for (int i = 0; i < NUM_SLOTS; i++) g_slots[i].changeCount = 0;
            g_playerEnt = -1;
        }
        return 0;
    case WM_DESTROY:
        g_running = false;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 DMA Radar ===\n");
    printf("Controls: +/- zoom, R reset player, Q quit\n\n");

    // Init DMA
    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] VMM init failed\n"); return 1; }
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] PID=%u Base=0x%llX\n", g_pid, (unsigned long long)g_base);

    // Prime slot positions with an initial read so only real movement triggers changes
    memset(g_slots, 0, sizeof(g_slots));
    if (DmaRead(g_entityAddr, g_readBuf, BUF_SZ)) {
        for (int i = 0; i < NUM_SLOTS; i++) {
            int off = POS_START + i * POS_STRIDE;
            g_slots[i].pos = *(Vec3*)(g_readBuf + off);
            g_slots[i].lastChange = 0;
        }
        printf("[+] Primed %d position slots\n", NUM_SLOTS);
    }

    // Create window
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "R6Radar";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    RECT wr = {0, 0, RADAR_W, RADAR_H};
    AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);
    g_hwnd = CreateWindowA("R6Radar", "R6 DMA Radar",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           CW_USEDEFAULT, CW_USEDEFAULT,
                           wr.right - wr.left, wr.bottom - wr.top,
                           NULL, NULL, GetModuleHandle(NULL), NULL);

    // Create GDI resources
    HDC hdc = GetDC(g_hwnd);
    g_memDC = CreateCompatibleDC(hdc);
    g_memBmp = CreateCompatibleBitmap(hdc, RADAR_W, RADAR_H);
    SelectObject(g_memDC, g_memBmp);
    ReleaseDC(g_hwnd, hdc);

    g_gridPen = CreatePen(PS_SOLID, 1, RGB(40, 40, 40));
    g_enemyPen = CreatePen(PS_SOLID, 2, RGB(255, 50, 50));
    g_playerPen = CreatePen(PS_SOLID, 2, RGB(50, 255, 50));
    g_deadPen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
    g_bgBrush = CreateSolidBrush(RGB(15, 15, 20));
    g_enemyBrush = CreateSolidBrush(RGB(255, 50, 50));
    g_playerBrush = CreateSolidBrush(RGB(50, 255, 50));
    g_deadBrush = CreateSolidBrush(RGB(60, 60, 60));

    printf("[+] Radar window created. Reading positions...\n");

    // Main loop
    DWORD lastRead = 0, lastDiag = 0;
    while (g_running) {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { g_running = false; break; }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (!g_running) break;

        DWORD now = GetTickCount();
        if (now - lastRead > 50) {
            UpdatePositions();
            lastRead = now;
            InvalidateRect(g_hwnd, NULL, FALSE);
        }

        if (now - lastDiag > 3000) {
            int valid = 0, changed = 0, recent = 0;
            for (int i = 0; i < NUM_SLOTS; i++) {
                Vec3 p = g_slots[i].pos;
                if (fabsf(p.x) > 0.001f || fabsf(p.y) > 0.001f) valid++;
                if (g_slots[i].changeCount > 0) changed++;
                if (now - g_slots[i].lastChange < 10000) recent++;
            }
            printf("[diag] valid=%d changed=%d recent=%d clustered=%d\n",
                   valid, changed, recent, g_entCount);
            lastDiag = now;
        }

        Sleep(10);
    }

    // Cleanup
    DeleteObject(g_gridPen);
    DeleteObject(g_enemyPen);
    DeleteObject(g_playerPen);
    DeleteObject(g_deadPen);
    DeleteObject(g_bgBrush);
    DeleteObject(g_enemyBrush);
    DeleteObject(g_playerBrush);
    DeleteObject(g_deadBrush);
    DeleteObject(g_memBmp);
    DeleteDC(g_memDC);
    DestroyWindow(g_hwnd);
    pClose(g_vmm);
    printf("Done.\n");
    return 0;
}
