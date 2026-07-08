// R6 Position Buffer Probe — drill into entity 0x227B172E030 (vtbl +0x115E7F10)
// Contains multiple bot positions in one object. Map the full layout.
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_posbuffer.cpp /Fe"../r6_posbuffer.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <map>
#include <algorithm>

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
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < g_base || v > g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }

struct Vec3 { float x, y, z; };

void doInit() {
    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) return;
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Position Buffer Probe ===\n");
    printf("=== Target: 0x227B172E030 vtbl=+0x115E7F10 ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    const uint64_t TARGET = 0x227B172E030;
    const int BUF_SZ = 0x2000; // Read 8KB to capture more of the structure

    // SNAPSHOT 1
    printf("--- SNAPSHOT 1 ---\n");
    doInit();
    if (!g_vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n", g_pid, (unsigned long long)g_base);

    uint8_t snap1[BUF_SZ] = {};
    if (!DmaRead(TARGET, snap1, BUF_SZ)) {
        printf("[!] Failed to read target entity\n");
        pClose(g_vmm);
        return 1;
    }

    // Verify vtable
    uint64_t vtbl = *(uint64_t*)snap1;
    printf("[+] vtbl = 0x%llX (+0x%llX)\n\n",
           (unsigned long long)vtbl, (unsigned long long)(vtbl - g_base));

    // Dump ALL Vec3-like positions in the entity
    printf("=== All Vec3 positions in snapshot 1 ===\n");
    struct PosEntry { int off; float x, y, z; };
    std::vector<PosEntry> positions;
    for (int off = 0x10; off + 12 <= BUF_SZ; off += 4) {
        float x = *(float*)(snap1 + off);
        float y = *(float*)(snap1 + off + 4);
        float z = *(float*)(snap1 + off + 8);
        if (!isnan(x) && !isnan(y) && !isnan(z) &&
            fabsf(x) > 1.0f && fabsf(x) < 200.0f &&
            fabsf(y) > 1.0f && fabsf(y) < 200.0f &&
            fabsf(z) > 0.05f && fabsf(z) < 200.0f) {
            positions.push_back({off, x, y, z});
        }
    }
    printf("  Found %d potential Vec3 positions\n\n", (int)positions.size());
    for (auto& p : positions) {
        printf("  +0x%04X: (%.2f, %.2f, %.2f)\n", p.off, p.x, p.y, p.z);
    }

    // Also look for pointer chains from this entity
    printf("\n=== Pointer chains from this entity ===\n");
    for (int off = 0; off + 8 <= 0x400; off += 8) {
        uint64_t ptr = *(uint64_t*)(snap1 + off);
        if (isHeapPtr(ptr)) {
            uint64_t subVt = rpm<uint64_t>(ptr);
            char mark = isModPtr(subVt) ? 'V' : '.';
            printf("  +0x%03X -> 0x%llX [%c]", off, (unsigned long long)ptr, mark);
            if (isModPtr(subVt))
                printf(" vtbl=+0x%llX", (unsigned long long)(subVt - g_base));
            printf("\n");
        }
    }

    // Also follow sub-pointers to find positions through chains
    printf("\n=== Positions through pointer chains ===\n");
    for (int off = 0; off + 8 <= 0x200; off += 8) {
        uint64_t ptr = *(uint64_t*)(snap1 + off);
        if (!isHeapPtr(ptr)) continue;

        uint8_t subBuf[0x800];
        if (!DmaRead(ptr, subBuf, sizeof(subBuf))) continue;

        for (int so = 0x10; so + 12 <= 0x800; so += 4) {
            float x = *(float*)(subBuf + so);
            float y = *(float*)(subBuf + so + 4);
            float z = *(float*)(subBuf + so + 8);
            if (!isnan(x) && !isnan(y) && !isnan(z) &&
                fabsf(x) > 3.0f && fabsf(x) < 200.0f &&
                fabsf(y) > 3.0f && fabsf(y) < 200.0f &&
                fabsf(z) > 0.1f && fabsf(z) < 200.0f) {
                printf("  +0x%03X -> sub+0x%04X: (%.2f, %.2f, %.2f)\n",
                       off, so, x, y, z);
                so += 8;
            }
        }
    }

    pClose(g_vmm); g_vmm = nullptr;

    // Wait
    printf("\n--- Waiting 5 seconds ---\n\n");
    Sleep(5000);

    // SNAPSHOT 2
    printf("--- SNAPSHOT 2 ---\n");
    doInit();
    if (!g_vmm) return 1;

    uint8_t snap2[BUF_SZ] = {};
    DmaRead(TARGET, snap2, BUF_SZ);

    // Compare ALL positions
    printf("\n=== Position changes ===\n");
    int changedPos = 0;
    for (int off = 0x10; off + 12 <= BUF_SZ; off += 4) {
        float x1 = *(float*)(snap1 + off);
        float y1 = *(float*)(snap1 + off + 4);
        float z1 = *(float*)(snap1 + off + 8);
        float x2 = *(float*)(snap2 + off);
        float y2 = *(float*)(snap2 + off + 4);
        float z2 = *(float*)(snap2 + off + 8);

        if (isnan(x1) || isnan(y1) || isnan(z1)) continue;
        if (isnan(x2) || isnan(y2) || isnan(z2)) continue;

        float dx = x2-x1, dy = y2-y1, dz = z2-z1;
        float d = sqrtf(dx*dx + dy*dy + dz*dz);

        if (d > 0.05f && d < 100.0f &&
            fabsf(x1) < 200.0f && fabsf(y1) < 200.0f &&
            fabsf(x2) < 200.0f && fabsf(y2) < 200.0f) {
            changedPos++;
            printf("  +0x%04X: (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f) d=%.2f",
                   off, x1, y1, z1, x2, y2, z2, d);
            if (fabsf(dz) < 0.1f) printf(" [ground]");
            printf("\n");
        }
    }

    // Also do byte-level diff to find ALL changing offsets
    printf("\n=== Byte-level diff summary ===\n");
    int diffCount = 0;
    int firstDiff = -1, lastDiff = -1;
    for (int off = 0; off < BUF_SZ; off += 4) {
        uint32_t v1 = *(uint32_t*)(snap1 + off);
        uint32_t v2 = *(uint32_t*)(snap2 + off);
        if (v1 != v2) {
            diffCount++;
            if (firstDiff < 0) firstDiff = off;
            lastDiff = off;
        }
    }
    printf("  %d dwords changed, range 0x%04X - 0x%04X\n", diffCount, firstDiff, lastDiff);

    // Find consistent position stride by looking at which offsets have Vec3 in snap2
    printf("\n=== Unique positions (snap2, deduplicated) ===\n");
    struct UniquePos { int off; float x, y, z; };
    std::vector<UniquePos> uniq;
    for (int off = 0x10; off + 12 <= BUF_SZ; off += 4) {
        float x = *(float*)(snap2 + off);
        float y = *(float*)(snap2 + off + 4);
        float z = *(float*)(snap2 + off + 8);
        if (isnan(x) || isnan(y) || isnan(z)) continue;
        if (fabsf(x) < 1.0f || fabsf(x) > 200.0f) continue;
        if (fabsf(y) < 1.0f || fabsf(y) > 200.0f) continue;
        if (z < 0.05f || z > 200.0f) continue;

        // Check if duplicate of existing
        bool dup = false;
        for (auto& u : uniq) {
            if (fabsf(u.x - x) < 0.5f && fabsf(u.y - y) < 0.5f && fabsf(u.z - z) < 0.5f) {
                dup = true; break;
            }
        }
        if (!dup) {
            uniq.push_back({off, x, y, z});
            printf("  +0x%04X: (%.2f, %.2f, %.2f)\n", off, x, y, z);
        }
    }
    printf("  %d unique positions in snap2\n", (int)uniq.size());

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
