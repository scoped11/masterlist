// R6 Live Monitor — reads positions from top candidates every 500ms for 30 seconds
// Detects which positions change = live entities
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_livemon.cpp /Fe"../r6_livemon.exe" /link

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

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_MemRead pMemRead;
static fn_Init pInit;
static fn_Close pClose;
static fn_PidGet pPidGet;
static fn_ModBase pModBase;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && !(v >= g_base && v < g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }

struct WatchTarget {
    uint64_t addr;
    uint64_t posOff;
    Vec3 initial;
    Vec3 current;
    int changeCount;
    const char* label;
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Live Position Monitor ===\n");
    printf("=== MOVE YOUR CHARACTER NOW! Monitoring for 30 seconds ===\n\n");

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
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;

    // Fresh page tables
    pClose(g_vmm); g_vmm = nullptr; Sleep(1500);
    g_vmm = pInit(6, args);
    if (!g_vmm) return 1;
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    dos = rpm<IMAGE_DOS_HEADER>(g_base);
    nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    uint64_t dataBase = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            break;
        }
    }

    // Collect ALL entity positions from top candidates
    std::vector<WatchTarget> targets;

    // Lambda to add targets from a vector
    auto addFromVector = [&](uint64_t obj, uint64_t listOff, uint64_t posOff,
                             uint64_t vtblRVA, const char* label) {
        uint64_t vb = rpm<uint64_t>(obj + listOff);
        uint64_t ve = rpm<uint64_t>(obj + listOff + 8);
        if (!isHeapPtr(vb) || ve <= vb) return;
        int cnt = (int)((ve - vb) / 8);
        int readN = (cnt > 50) ? 50 : cnt;
        std::vector<uint64_t> ptrs(readN);
        DmaRead(vb, ptrs.data(), readN * 8);

        for (int k = 0; k < readN; k++) {
            if (!isHeapPtr(ptrs[k])) continue;
            if (vtblRVA != 0) {
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (!isModPtr(vt) || (vt - g_base) != vtblRVA) continue;
            }
            Vec3 v = rpm<Vec3>(ptrs[k] + posOff);
            if (isnan(v.x) || isnan(v.y) || isnan(v.z)) continue;
            if (fabsf(v.x) < 0.001f && fabsf(v.y) < 0.001f && fabsf(v.z) < 0.001f) continue;
            if (fabsf(v.x) > 100000 || fabsf(v.y) > 100000 || fabsf(v.z) > 100000) continue;

            WatchTarget t;
            t.addr = ptrs[k];
            t.posOff = posOff;
            t.initial = v;
            t.current = v;
            t.changeCount = 0;
            t.label = label;
            targets.push_back(t);
        }
    };

    // Read globals
    uint64_t obj_444BC8 = rpm<uint64_t>(dataBase + 0x444BC8);
    uint64_t obj_13D7AC0 = rpm<uint64_t>(dataBase + 0x13D7AC0);

    // Cand#0: 25 entries vtbl=+0x111B6440, pos@+0x370
    addFromVector(obj_13D7AC0, 0x218, 0x370, 0x111B6440, "C0:+370");

    // Cand#1: 84 entries vtbl=+0x111F6840, pos@+0x50
    addFromVector(obj_444BC8, 0x98, 0x50, 0x111F6840, "C1:+050");

    // Cand#4: 36 entries vtbl=+0x111F6840, pos@+0x50
    addFromVector(obj_444BC8, 0x108, 0x50, 0x111F6840, "C4:+050");

    // Cand#1 also had positions at +0x740
    addFromVector(obj_444BC8, 0x98, 0x740, 0x111F6840, "C1:+740");

    // Also add Cand#0 entities through +0x150 chain for indirect positions
    // Skip this — too slow for continuous monitoring

    printf("Monitoring %d position targets...\n", (int)targets.size());
    printf("Initial positions:\n");
    for (int i = 0; i < (int)targets.size(); i++) {
        auto& t = targets[i];
        printf("  [%2d] %s 0x%llX+0x%llX = (%.2f, %.2f, %.2f)\n",
               i, t.label, (unsigned long long)t.addr, (unsigned long long)t.posOff,
               t.initial.x, t.initial.y, t.initial.z);
    }

    printf("\n=== Monitoring (30 seconds) — MOVE NOW! ===\n");

    DWORD startTime = GetTickCount();
    int iteration = 0;

    while (GetTickCount() - startTime < 30000) {
        Sleep(500);
        iteration++;

        bool anyChanged = false;
        for (auto& t : targets) {
            Vec3 v = rpm<Vec3>(t.addr + t.posOff);
            if (isnan(v.x) || isnan(v.y) || isnan(v.z)) continue;

            float dx = v.x - t.current.x;
            float dy = v.y - t.current.y;
            float dz = v.z - t.current.z;
            float dist = sqrtf(dx*dx + dy*dy + dz*dz);

            if (dist > 0.01f) {
                t.changeCount++;
                if (t.changeCount <= 5) {
                    printf("  [%ds] %s 0x%llX MOVED! (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f) delta=%.3f\n",
                           (GetTickCount() - startTime) / 1000,
                           t.label, (unsigned long long)t.addr,
                           t.current.x, t.current.y, t.current.z,
                           v.x, v.y, v.z, dist);
                }
                t.current = v;
                anyChanged = true;
            }
        }

        if (iteration % 10 == 0) {
            printf("  [%ds] tick — %d targets, no changes yet\n",
                   (GetTickCount() - startTime) / 1000, (int)targets.size());
        }
    }

    // Summary
    printf("\n=== Summary ===\n");
    int moved = 0;
    for (auto& t : targets) {
        if (t.changeCount > 0) {
            moved++;
            float dx = t.current.x - t.initial.x;
            float dy = t.current.y - t.initial.y;
            float dz = t.current.z - t.initial.z;
            float totalDist = sqrtf(dx*dx + dy*dy + dz*dz);
            printf("  MOVED: %s 0x%llX changes=%d totalDelta=%.2f\n",
                   t.label, (unsigned long long)t.addr,
                   t.changeCount, totalDist);
            printf("    start=(%.2f, %.2f, %.2f) end=(%.2f, %.2f, %.2f)\n",
                   t.initial.x, t.initial.y, t.initial.z,
                   t.current.x, t.current.y, t.current.z);
        }
    }
    if (moved == 0)
        printf("  No positions changed in 30 seconds.\n");
    else
        printf("  %d/%d targets moved.\n", moved, (int)targets.size());

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
