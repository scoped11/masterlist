// R6 Data Diff — snapshot entire .data section twice, find ALL changing values
// This finds player position, camera, game state globals directly
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_datadiff.cpp /Fe"../r6_datadiff.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cmath>

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

struct InitResult {
    uint64_t base, modEnd, dataBase, dataSize;
    DWORD pid;
};

InitResult doInit() {
    InitResult r = {};
    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) return r;
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    r.pid = g_pid;
    r.base = g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    r.modEnd = g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            r.dataBase = g_base + sec.VirtualAddress;
            r.dataSize = sec.Misc.VirtualSize;
            break;
        }
    }
    return r;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 .data Section Diff ===\n");
    printf("=== Two snapshots, find ALL changing globals ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    // Only scan first 2MB of .data (most globals are early)
    const uint64_t SCAN_SIZE = 2 * 1024 * 1024;

    // SNAPSHOT 1
    printf("--- SNAPSHOT 1 ---\n");
    InitResult r1 = doInit();
    if (!g_vmm) return 1;
    printf("[+] PID=%u Base=0x%llX .data=0x%llX (%.1f MB)\n",
           r1.pid, (unsigned long long)r1.base,
           (unsigned long long)r1.dataBase, r1.dataSize / 1048576.0);

    uint64_t scanBytes = min(SCAN_SIZE, r1.dataSize);
    std::vector<uint8_t> snap1(scanBytes, 0);
    const uint32_t CHUNK = 0x10000;
    int pagesRead1 = 0;
    for (uint64_t off = 0; off < scanBytes; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, scanBytes - off);
        if (DmaRead(r1.dataBase + off, snap1.data() + off, readSz))
            pagesRead1++;
    }
    printf("  Read %d chunks (%.1f MB)\n", pagesRead1, scanBytes / 1048576.0);
    pClose(g_vmm); g_vmm = nullptr;

    printf("\n--- Waiting 5 seconds ---\n");
    Sleep(5000);

    // SNAPSHOT 2
    printf("\n--- SNAPSHOT 2 ---\n");
    InitResult r2 = doInit();
    if (!g_vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n", r2.pid, (unsigned long long)r2.base);

    std::vector<uint8_t> snap2(scanBytes, 0);
    int pagesRead2 = 0;
    for (uint64_t off = 0; off < scanBytes; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, scanBytes - off);
        if (DmaRead(r2.dataBase + off, snap2.data() + off, readSz))
            pagesRead2++;
    }
    printf("  Read %d chunks\n", pagesRead2);

    // DIFF
    printf("\n=== DIFF RESULTS ===\n");

    // Count changed dwords
    int totalChanged = 0;
    for (uint64_t off = 0; off + 4 <= scanBytes; off += 4) {
        uint32_t v1 = *(uint32_t*)(snap1.data() + off);
        uint32_t v2 = *(uint32_t*)(snap2.data() + off);
        if (v1 != v2) totalChanged++;
    }
    printf("  %d dwords changed out of %d total\n\n",
           totalChanged, (int)(scanBytes / 4));

    // Find changed FLOAT values that look like positions
    printf("=== Changed floats that look like world positions ===\n");
    int posCount = 0;
    for (uint64_t off = 0; off + 12 <= scanBytes; off += 4) {
        float x1 = *(float*)(snap1.data() + off);
        float y1 = *(float*)(snap1.data() + off + 4);
        float z1 = *(float*)(snap1.data() + off + 8);
        float x2 = *(float*)(snap2.data() + off);
        float y2 = *(float*)(snap2.data() + off + 4);
        float z2 = *(float*)(snap2.data() + off + 8);

        if (isnan(x1) || isnan(y1) || isnan(z1)) continue;
        if (isnan(x2) || isnan(y2) || isnan(z2)) continue;

        bool ok1 = fabsf(x1) > 1.0f && fabsf(x1) < 50000.0f &&
                   fabsf(y1) > 1.0f && fabsf(y1) < 50000.0f &&
                   fabsf(z1) > 0.1f && fabsf(z1) < 50000.0f;
        bool ok2 = fabsf(x2) > 1.0f && fabsf(x2) < 50000.0f &&
                   fabsf(y2) > 1.0f && fabsf(y2) < 50000.0f &&
                   fabsf(z2) > 0.1f && fabsf(z2) < 50000.0f;
        if (!ok1 || !ok2) continue;

        float dx = x2 - x1, dy = y2 - y1, dz = z2 - z1;
        float d = sqrtf(dx*dx + dy*dy + dz*dz);
        if (d > 0.05f && d < 100.0f) {
            posCount++;
            printf("  .data+0x%06llX: (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f) delta=%.2f\n",
                   (unsigned long long)off, x1, y1, z1, x2, y2, z2, d);
            if (posCount >= 50) { printf("  ... (truncated)\n"); break; }
        }
    }

    // Find changed POINTERS (qwords that look like addresses)
    printf("\n=== Changed pointers in .data ===\n");
    int ptrCount = 0;
    for (uint64_t off = 0; off + 8 <= scanBytes; off += 8) {
        uint64_t v1 = *(uint64_t*)(snap1.data() + off);
        uint64_t v2 = *(uint64_t*)(snap2.data() + off);
        if (v1 == v2) continue;
        bool p1 = v1 > 0x10000 && v1 < 0x7FFFFFFFFFFF;
        bool p2 = v2 > 0x10000 && v2 < 0x7FFFFFFFFFFF;
        if (p1 && p2) {
            ptrCount++;
            if (ptrCount <= 30) {
                printf("  .data+0x%06llX: 0x%llX -> 0x%llX",
                       (unsigned long long)off,
                       (unsigned long long)v1, (unsigned long long)v2);
                if (v1 >= r1.base && v1 < r1.modEnd)
                    printf(" [mod+0x%llX]", (unsigned long long)(v1 - r1.base));
                if (v2 >= r2.base && v2 < r2.modEnd)
                    printf(" [mod+0x%llX]", (unsigned long long)(v2 - r2.base));
                printf("\n");
            }
        }
    }
    printf("  Total changed pointers: %d\n", ptrCount);

    // Find changed 32-bit integers (counters, state, etc)
    printf("\n=== Changed integers (non-float, non-pointer) ===\n");
    int intCount = 0;
    for (uint64_t off = 0; off + 4 <= scanBytes; off += 4) {
        uint32_t v1 = *(uint32_t*)(snap1.data() + off);
        uint32_t v2 = *(uint32_t*)(snap2.data() + off);
        if (v1 == v2) continue;
        float f1 = *(float*)(snap1.data() + off);
        float f2 = *(float*)(snap2.data() + off);
        // Skip if it looks like a float
        if (!isnan(f1) && fabsf(f1) < 1e10 && !isnan(f2) && fabsf(f2) < 1e10) continue;
        // Skip if part of a pointer
        if (off % 8 == 0 || off % 8 == 4) {
            uint64_t q1, q2;
            uint64_t qoff = off & ~7ULL;
            if (qoff + 8 <= scanBytes) {
                q1 = *(uint64_t*)(snap1.data() + qoff);
                q2 = *(uint64_t*)(snap2.data() + qoff);
                if ((q1 > 0x10000 && q1 < 0x7FFFFFFFFFFF) ||
                    (q2 > 0x10000 && q2 < 0x7FFFFFFFFFFF)) continue;
            }
        }
        intCount++;
        if (intCount <= 20)
            printf("  .data+0x%06llX: %u -> %u (0x%X -> 0x%X)\n",
                   (unsigned long long)off, v1, v2, v1, v2);
    }
    printf("  Total changed integers: %d\n", intCount);

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
