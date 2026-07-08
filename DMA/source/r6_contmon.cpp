// R6 Continuous Monitor — test if NOCACHE gives fresh reads without reinit
// Reads entity 0x227B172E030 positions continuously for 15 seconds
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_contmon.cpp /Fe"../r6_contmon.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>

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
static uint64_t g_base;

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}

struct Vec3 { float x, y, z; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Continuous Position Monitor ===\n");
    printf("=== Testing NOCACHE on entity 0x227B172E030 ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) return 1;
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    const uint64_t TARGET = 0x227B172E030;
    const int BUF_SZ = 0x2000;
    const int POS_START = 0x2C0;
    const int POS_STRIDE = 0x40;
    const int POS_END = 0x1E00;
    const int NUM_SLOTS = (POS_END - POS_START) / POS_STRIDE;

    // Store initial positions
    uint8_t buf[BUF_SZ];
    if (!DmaRead(TARGET, buf, BUF_SZ)) {
        printf("[!] Failed to read entity\n");
        pClose(g_vmm);
        return 1;
    }

    Vec3 initial[200] = {};
    Vec3 last[200] = {};
    int changes[200] = {};

    for (int i = 0; i < NUM_SLOTS; i++) {
        int off = POS_START + i * POS_STRIDE;
        initial[i] = *(Vec3*)(buf + off);
        last[i] = initial[i];
    }

    printf("  Monitoring %d position slots (stride=0x40)\n", NUM_SLOTS);
    printf("  First 5 initial positions:\n");
    for (int i = 0; i < 5 && i < NUM_SLOTS; i++) {
        printf("    Slot[%d] +0x%04X: (%.2f, %.2f, %.2f)\n",
               i, POS_START + i * POS_STRIDE,
               initial[i].x, initial[i].y, initial[i].z);
    }

    printf("\n=== Continuous monitoring for 15 seconds (NO reinit) ===\n");
    DWORD t0 = GetTickCount();
    int iter = 0;

    while (GetTickCount() - t0 < 15000) {
        Sleep(300);
        iter++;

        if (!DmaRead(TARGET, buf, BUF_SZ)) {
            printf("  [%ds] read failed!\n", (GetTickCount() - t0) / 1000);
            continue;
        }

        for (int i = 0; i < NUM_SLOTS; i++) {
            int off = POS_START + i * POS_STRIDE;
            Vec3 cur = *(Vec3*)(buf + off);
            if (isnan(cur.x) || isnan(cur.y) || isnan(cur.z)) continue;

            float dx = cur.x - last[i].x;
            float dy = cur.y - last[i].y;
            float dz = cur.z - last[i].z;
            float d = sqrtf(dx*dx + dy*dy + dz*dz);

            if (d > 0.01f) {
                changes[i]++;
                if (changes[i] <= 2) {
                    printf("  [%ds] Slot[%2d]+0x%04X MOVED: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.2f\n",
                           (GetTickCount() - t0) / 1000, i, off,
                           last[i].x, last[i].y, last[i].z,
                           cur.x, cur.y, cur.z, d);
                }
                last[i] = cur;
            }
        }

        if (iter % 16 == 0) {
            int live = 0;
            for (int i = 0; i < NUM_SLOTS; i++) if (changes[i] > 0) live++;
            printf("  [%ds] %d/%d live slots\n", (GetTickCount() - t0) / 1000, live, NUM_SLOTS);
        }
    }

    // Summary
    printf("\n=== SUMMARY ===\n");
    int liveSlots = 0;
    for (int i = 0; i < NUM_SLOTS; i++) {
        if (changes[i] > 0) {
            liveSlots++;
            float dx = last[i].x - initial[i].x;
            float dy = last[i].y - initial[i].y;
            float dz = last[i].z - initial[i].z;
            printf("  Slot[%2d]+0x%04X: %d changes, totalDelta=%.2f\n",
                   i, POS_START + i * POS_STRIDE, changes[i], sqrtf(dx*dx+dy*dy+dz*dz));
        }
    }
    printf("\n  %d LIVE slots / %d total (continuous reads, NO reinit)\n", liveSlots, NUM_SLOTS);

    if (liveSlots == 0) {
        printf("\n  NOCACHE does NOT give fresh reads without reinit.\n");
        printf("  Page table cache is the bottleneck.\n");
    } else {
        printf("\n  NOCACHE WORKS! Real-time radar is feasible!\n");
    }

    pClose(g_vmm);
    return 0;
}
