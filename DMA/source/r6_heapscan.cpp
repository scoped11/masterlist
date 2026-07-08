// R6 Heap Position Scanner — brute-force scan heap pages for moving world positions
// Scans allocated heap memory for float triples in R6 coordinate range
// Double-read to confirm movement (bots in T-Hunt)
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_heapscan.cpp /Fe"../r6_heapscan.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <map>
#include <algorithm>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static fn_MemRead pMemRead; static fn_Init pInit; static fn_Close pClose;
static fn_PidGet pPidGet; static fn_ModBase pModBase;
static VMM_HANDLE g_vmm; static DWORD g_pid;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Heap Position Scanner ===\n");
    printf("=== Brute-force scan for moving world coordinates ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
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
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    // Phase 1: Find allocated heap pages by scanning in 1MB chunks
    const uint64_t SCAN_START = 0x100000000ULL;  // 4GB
    const uint64_t SCAN_END   = 0x400000000ULL;  // 16GB
    const uint32_t MEGA = 0x100000;              // 1MB

    printf("--- Phase 1: Finding allocated heap pages (%.1f GB range) ---\n",
           (SCAN_END - SCAN_START) / 1073741824.0);

    struct LivePage {
        uint64_t addr;
        int posCount; // positions found in this page
    };
    std::vector<LivePage> livePages;

    uint8_t testBuf[4096];
    int pagesChecked = 0;
    for (uint64_t addr = SCAN_START; addr < SCAN_END; addr += MEGA) {
        // Quick test: can we read the first page of this MB?
        DWORD cb = 0;
        pMemRead(g_vmm, g_pid, addr, testBuf, 4096, &cb, 0x0001 | 0x0002);
        if (cb == 0) continue;

        // This MB is live — scan it for position-like floats
        for (uint64_t page = addr; page < addr + MEGA; page += 0x10000) {
            uint8_t pageBuf[0x10000];
            DWORD pcb = 0;
            pMemRead(g_vmm, g_pid, page, pageBuf, sizeof(pageBuf), &pcb, 0x0001 | 0x0002);
            if (pcb < 0x1000) continue;

            int posCount = 0;
            for (uint32_t i = 0; i + 12 <= pcb; i += 4) {
                float x = *(float*)(pageBuf + i);
                float y = *(float*)(pageBuf + i + 4);
                float z = *(float*)(pageBuf + i + 8);
                if (isnan(x) || isnan(y) || isnan(z)) continue;
                // R6 world coordinates: roughly -100 to +100 for X/Y, 0-15 for Z
                if (fabsf(x) > 3 && fabsf(x) < 200 &&
                    fabsf(y) > 3 && fabsf(y) < 200 &&
                    z > 0.3f && z < 30.0f) {
                    posCount++;
                }
            }
            if (posCount >= 3) {
                livePages.push_back({page, posCount});
            }
        }
        pagesChecked++;
        if (pagesChecked % 500 == 0)
            printf("  0x%llX... %d live pages so far\n",
                   (unsigned long long)addr, (int)livePages.size());
    }
    printf("  Found %d pages with position-like data\n\n", (int)livePages.size());

    // Sort by position count (most positions first)
    std::sort(livePages.begin(), livePages.end(),
              [](const LivePage& a, const LivePage& b) { return a.posCount > b.posCount; });

    // Phase 2: Double-snapshot the top pages to find movement
    printf("--- Phase 2: Double snapshot on top %d pages ---\n",
           (int)(livePages.size() > 200 ? 200 : livePages.size()));

    struct MovingPos {
        uint64_t pageAddr;
        int offset;
        float x1, y1, z1;
        float x2, y2, z2;
        float dist;
        uint64_t vtbl; // vtable at page start (if object)
    };
    std::vector<MovingPos> movers;

    int pagesToCheck = (int)livePages.size();
    if (pagesToCheck > 200) pagesToCheck = 200;

    // Snapshot 1
    struct PageSnap {
        uint64_t addr;
        uint8_t data1[0x10000];
        uint8_t data2[0x10000];
    };
    std::vector<PageSnap> snaps(pagesToCheck);
    for (int i = 0; i < pagesToCheck; i++) {
        snaps[i].addr = livePages[i].addr;
        DmaRead(livePages[i].addr, snaps[i].data1, 0x10000);
    }

    printf("  Snapshot 1 done. Waiting 2 seconds...\n");
    Sleep(2000);

    // Snapshot 2
    for (int i = 0; i < pagesToCheck; i++) {
        DmaRead(snaps[i].addr, snaps[i].data2, 0x10000);
    }
    printf("  Snapshot 2 done. Analyzing...\n\n");

    for (int i = 0; i < pagesToCheck; i++) {
        for (uint32_t off = 0; off + 12 <= 0x10000; off += 4) {
            float x1 = *(float*)(snaps[i].data1 + off);
            float y1 = *(float*)(snaps[i].data1 + off + 4);
            float z1 = *(float*)(snaps[i].data1 + off + 8);
            float x2 = *(float*)(snaps[i].data2 + off);
            float y2 = *(float*)(snaps[i].data2 + off + 4);
            float z2 = *(float*)(snaps[i].data2 + off + 8);

            if (isnan(x1) || isnan(y1) || isnan(z1)) continue;
            if (isnan(x2) || isnan(y2) || isnan(z2)) continue;
            if (fabsf(x1) < 3 || fabsf(x1) > 200) continue;
            if (fabsf(y1) < 3 || fabsf(y1) > 200) continue;
            if (z1 < 0.3f || z1 > 30.0f) continue;

            float dx = x2-x1, dy = y2-y1, dz = z2-z1;
            float d = sqrtf(dx*dx + dy*dy + dz*dz);
            if (d > 0.01f && d < 50.0f) {
                // Find vtable for the object containing this position
                // Walk back to a page-aligned or 0x10-aligned address with a vtable
                uint64_t vtbl = 0;
                int objOff = off & ~0xF;
                while (objOff >= 0) {
                    uint64_t v = *(uint64_t*)(snaps[i].data1 + objOff);
                    if (isModPtr(v)) { vtbl = v; break; }
                    objOff -= 8;
                    if (off - objOff > 0x2000) break; // don't look back too far
                }

                movers.push_back({snaps[i].addr, (int)off,
                                  x1, y1, z1, x2, y2, z2, d, vtbl});
            }
        }
    }

    printf("=== RESULTS: %d moving position triples found ===\n\n", (int)movers.size());

    // Sort by distance
    std::sort(movers.begin(), movers.end(),
              [](const MovingPos& a, const MovingPos& b) { return a.dist > b.dist; });

    // Group by vtable
    std::map<uint64_t, int> vtblMap;
    for (auto& m : movers) vtblMap[m.vtbl]++;
    printf("  By vtable:\n");
    for (auto& kv : vtblMap) {
        if (kv.first) printf("    vtbl=+0x%llX: %d\n", (unsigned long long)(kv.first - g_base), kv.second);
        else printf("    (no vtbl): %d\n", kv.second);
    }

    // Show top 30 movers
    printf("\n  Top movers:\n");
    for (int i = 0; i < (int)movers.size() && i < 30; i++) {
        auto& m = movers[i];
        printf("    0x%llX+0x%04X: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.3f",
               (unsigned long long)m.pageAddr, m.offset,
               m.x1, m.y1, m.z1, m.x2, m.y2, m.z2, m.dist);
        if (m.vtbl) printf(" vtbl=+0x%llX", (unsigned long long)(m.vtbl - g_base));
        printf("\n");
    }

    // For the most common vtable, show the address and position pattern
    if (!movers.empty()) {
        // Find the vtable with the most movers
        uint64_t bestVtbl = 0; int bestN = 0;
        for (auto& kv : vtblMap) {
            if (kv.second > bestN) { bestN = kv.second; bestVtbl = kv.first; }
        }
        if (bestVtbl) {
            printf("\n  Most common vtbl=+0x%llX (%d movers):\n",
                   (unsigned long long)(bestVtbl - g_base), bestN);
            for (auto& m : movers) {
                if (m.vtbl != bestVtbl) continue;
                uint64_t objAddr = m.pageAddr + (m.offset & ~0xF);
                // Walk back to find the exact object start
                while (objAddr > m.pageAddr) {
                    uint64_t vt = rpm<uint64_t>(objAddr);
                    if (vt == bestVtbl) break;
                    objAddr -= 0x10;
                }
                printf("    obj=0x%llX pos_off=+0x%04X (%.2f,%.2f,%.2f) d=%.3f\n",
                       (unsigned long long)objAddr, (int)(m.pageAddr + m.offset - objAddr),
                       m.x1, m.y1, m.z1, m.dist);
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
