// R6 DMA Refresh — forces MemProcFS to re-read page tables then scans
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_refresh.cpp /Fe"../r6_refresh.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <algorithm>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef BOOL       (__cdecl *fn_ConfigSet)(VMM_HANDLE hVMM, ULONG64 fOption, ULONG64 qwValue);
typedef BOOL       (__cdecl *fn_ConfigGet)(VMM_HANDLE hVMM, ULONG64 fOption, PULONG64 pqwValue);

// MemProcFS config options
#define OPT_REFRESH_ALL         0x2001FFFF
#define OPT_REFRESH_FREQ_MEM    0x20010100
#define OPT_REFRESH_FREQ_TLB    0x20010200
#define OPT_REFRESH_FREQ_PROC   0x20010300
#define OPT_PROCESS_DTB         0x200000001ULL

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_MemRead pMemRead;
static fn_ConfigSet pConfigSet;
static fn_ConfigGet pConfigGet;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };
static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }
static bool isHeapPtr(uint64_t v, uint64_t modBase, uint64_t modEnd) {
    return isValidPtr(v) && (v < modBase || v > modEnd);
}
static bool isWorldPos(Vec3 v) {
    return !isnan(v.x) && !isnan(v.y) && !isnan(v.z) &&
           fabsf(v.x) > 0.5f && fabsf(v.x) < 100000.0f &&
           fabsf(v.y) > 0.5f && fabsf(v.y) < 100000.0f &&
           fabsf(v.z) > 0.1f && fabsf(v.z) < 100000.0f;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 DMA Refresh & Scan ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    auto pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    auto pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    auto pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead      = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    auto pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");
    pConfigSet    = (fn_ConfigSet)GetProcAddress(h, "VMMDLL_ConfigSet");
    pConfigGet    = (fn_ConfigGet)GetProcAddress(h, "VMMDLL_ConfigGet");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] DMA init failed\n"); return 1; }

    // === STEP 1: Force full refresh of everything ===
    printf("[*] Forcing full MemProcFS refresh...\n");
    if (pConfigSet) {
        BOOL r1 = pConfigSet(g_vmm, OPT_REFRESH_ALL, 1);
        printf("  REFRESH_ALL: %s\n", r1 ? "OK" : "FAILED");

        // Set TLB refresh to every tick
        pConfigSet(g_vmm, OPT_REFRESH_FREQ_TLB, 1);
        // Set memory refresh to every tick
        pConfigSet(g_vmm, OPT_REFRESH_FREQ_MEM, 1);
        // Set process refresh to every tick
        pConfigSet(g_vmm, OPT_REFRESH_FREQ_PROC, 1);
    }

    Sleep(2000); // Wait for refresh to take effect

    // === STEP 2: Re-enumerate process ===
    printf("\n[*] Re-enumerating processes...\n");
    if (pConfigSet) pConfigSet(g_vmm, OPT_REFRESH_ALL, 1);
    Sleep(1000);

    DWORD newPid = 0;
    if (pPidGet(g_vmm, "RainbowSix.exe", &newPid)) {
        printf("[+] RainbowSix.exe PID=%u %s\n", newPid,
               newPid == 18644 ? "(same)" : "(CHANGED!)");
        g_pid = newPid;
    } else {
        printf("[!] RainbowSix.exe not found after refresh!\n");
        // Try BattlEye launcher
        if (pPidGet(g_vmm, "RainbowSix_BE.exe", &newPid)) {
            printf("[+] Found RainbowSix_BE.exe PID=%u\n", newPid);
        }
        g_pid = 18644; // fallback
    }

    uint64_t base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] Base: 0x%llX\n", (unsigned long long)base);

    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    uint64_t modEnd = base + nt.OptionalHeader.SizeOfImage;
    printf("[+] Module end: 0x%llX\n\n", (unsigned long long)modEnd);

    // === STEP 3: Liveness check after refresh ===
    printf("=== Post-refresh liveness check ===\n");
    uint64_t gmAddr = base + 0x11F0DDF8;
    uint64_t gm1 = rpm<uint64_t>(gmAddr);
    printf("GM global = 0x%llX\n", (unsigned long long)gm1);

    if (isValidPtr(gm1)) {
        uint8_t snap1[256] = {}, snap2[256] = {};
        DmaRead(gm1, snap1, 256);
        printf("Waiting 2 seconds...\n");
        Sleep(2000);

        // Force another refresh before second read
        if (pConfigSet) pConfigSet(g_vmm, OPT_REFRESH_ALL, 1);
        Sleep(500);

        DmaRead(gm1, snap2, 256);
        int diff = 0;
        for (int i = 0; i < 256; i++)
            if (snap1[i] != snap2[i]) diff++;
        printf("GM obj: %d/256 bytes changed %s\n", diff,
               diff > 0 ? "(LIVE!)" : "(still stale)");

        // Show first 0x100 as qwords with changes marked
        printf("\n--- GM object first 0x100 bytes ---\n");
        for (int i = 0; i < 256; i += 8) {
            uint64_t v = *(uint64_t*)(snap2 + i);
            bool changed = memcmp(snap1 + i, snap2 + i, 8) != 0;
            printf("  +0x%03X: 0x%016llX", i, (unsigned long long)v);
            if (isHeapPtr(v, base, modEnd)) printf(" [HEAP]");
            else if (v >= base && v < modEnd) printf(" [MOD]");
            if (changed) printf(" *** CHANGED");
            printf("\n");
        }
    }

    // === STEP 4: Broader scan with fresh page tables ===
    printf("\n=== Entity search with refreshed page tables ===\n");

    // Find .data
    uint64_t secAddr = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    uint64_t dataBase = 0, dataSize = 0;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = base + sec.VirtualAddress;
            dataSize = sec.Misc.VirtualSize;
            break;
        }
    }
    printf(".data: 0x%llX  size: %.1f MB\n\n", (unsigned long long)dataBase, dataSize / 1048576.0);

    // Scan .data for heap ptrs -> objects with std::vector<heap_ptr> cnt 5-50
    // Now with NOCACHE reads after full refresh
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK);
    int hits = 0;

    struct Result {
        uint64_t dataOff;
        uint64_t obj;
        uint64_t listOff;
        int count;
        int heapPtrs;
        int withVtable;
        int withPos;
    };
    std::vector<Result> results;

    for (uint64_t off = 0; off < dataSize && hits < 50; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 8 <= readSz && hits < 50; i += 8) {
            uint64_t globalVal = *(uint64_t*)(buf.data() + i);
            if (!isHeapPtr(globalVal, base, modEnd)) continue;

            for (uint64_t foff = 0x0; foff <= 0x400; foff += 0x8) {
                uint64_t vb = rpm<uint64_t>(globalVal + foff);
                uint64_t ve = rpm<uint64_t>(globalVal + foff + 8);
                uint64_t vc = rpm<uint64_t>(globalVal + foff + 16);
                if (!isHeapPtr(vb, base, modEnd) || ve <= vb || vc < ve) continue;
                uint64_t bytes = ve - vb;
                if (bytes % 8 != 0) continue;
                int cnt = (int)(bytes / 8);
                if (cnt < 5 || cnt > 50) continue;

                int readN = min(cnt, 10);
                uint64_t ptrs[10] = {};
                DmaRead(vb, ptrs, readN * 8);

                int heapCount = 0, withVtable = 0, withPos = 0;
                for (int k = 0; k < readN; k++) {
                    if (isHeapPtr(ptrs[k], base, modEnd)) {
                        heapCount++;
                        uint64_t vt = rpm<uint64_t>(ptrs[k]);
                        if (vt >= base && vt < modEnd) withVtable++;
                        for (uint64_t po = 0; po <= 0x800; po += 4) {
                            Vec3 v = rpm<Vec3>(ptrs[k] + po);
                            if (isWorldPos(v)) { withPos++; break; }
                        }
                    }
                }
                if (heapCount < readN * 3 / 4) continue;

                results.push_back({off + i, globalVal, foff, cnt, heapCount, withVtable, withPos});
                hits++;
            }
        }
    }

    // Sort by quality: vtable + positions first
    std::sort(results.begin(), results.end(), [](auto& a, auto& b) {
        int sa = a.withPos * 100 + a.withVtable * 10 + a.heapPtrs;
        int sb = b.withPos * 100 + b.withVtable * 10 + b.heapPtrs;
        return sa > sb;
    });

    printf("Found %d candidate arrays. Top 15:\n\n", (int)results.size());
    for (int i = 0; i < min((int)results.size(), 15); i++) {
        auto& r = results[i];
        printf("  .data+0x%llX obj=0x%llX +0x%llX cnt=%d heap=%d vtbl=%d pos=%d",
               (unsigned long long)r.dataOff, (unsigned long long)r.obj,
               (unsigned long long)r.listOff, r.count, r.heapPtrs, r.withVtable, r.withPos);
        if (r.withVtable > 0 && r.withPos > 0) printf(" *** STRONG");
        else if (r.withPos > 0) printf(" * has positions");
        printf("\n");

        // Show entries for top 3
        if (i < 3 && r.withPos > 0) {
            uint64_t vb = rpm<uint64_t>(r.obj + r.listOff);
            int readN = min(r.count, 5);
            uint64_t ptrs[5] = {};
            DmaRead(vb, ptrs, readN * 8);
            for (int k = 0; k < readN; k++) {
                printf("    [%d] 0x%llX", k, (unsigned long long)ptrs[k]);
                if (isHeapPtr(ptrs[k], base, modEnd)) {
                    uint64_t vt = rpm<uint64_t>(ptrs[k]);
                    if (vt >= base && vt < modEnd)
                        printf(" vt=0x%llX", (unsigned long long)(vt - base));
                    for (uint64_t po = 0; po <= 0x800; po += 4) {
                        Vec3 v = rpm<Vec3>(ptrs[k] + po);
                        if (isWorldPos(v)) {
                            printf(" pos@+0x%llX=(%.1f,%.1f,%.1f)",
                                   (unsigned long long)po, v.x, v.y, v.z);
                            break;
                        }
                    }
                }
                printf("\n");
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
