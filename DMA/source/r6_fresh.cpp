// R6 Fresh Scan — close and reinit VMM to force fresh page tables
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_fresh.cpp /Fe"../r6_fresh.exe" /link

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

static fn_Init pInit;
static fn_Close pClose;
static fn_PidGet pPidGet;
static fn_MemRead pMemRead;
static fn_ModBase pModBase;

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };
static uint64_t g_base, g_modEnd;
static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }
static bool isHeapPtr(uint64_t v) { return isValidPtr(v) && (v < g_base || v > g_modEnd); }
static bool isWorldPos(Vec3 v) {
    return !isnan(v.x) && !isnan(v.y) && !isnan(v.z) &&
           fabsf(v.x) > 0.5f && fabsf(v.x) < 100000.0f &&
           fabsf(v.y) > 0.5f && fabsf(v.y) < 100000.0f &&
           fabsf(v.z) > 0.1f && fabsf(v.z) < 100000.0f;
}

VMM_HANDLE freshInit() {
    // Close existing handle
    if (g_vmm) {
        printf("[*] Closing previous VMM handle...\n");
        pClose(g_vmm);
        g_vmm = nullptr;
        Sleep(1000);
    }
    printf("[*] Initializing fresh VMM handle...\n");
    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    return pInit(6, args);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Fresh Page Table Scan ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    // Init #1 - just to get process info
    g_vmm = freshInit();
    if (!g_vmm) { printf("[!] Init 1 failed\n"); return 1; }

    // Find R6
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) {
        printf(".");
        Sleep(2000);
    }
    printf("[+] PID=%u\n", g_pid);

    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] Base: 0x%llX\n", (unsigned long long)g_base);

    // Read module size
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;

    // Init #2 - FRESH page tables
    pClose(g_vmm);
    g_vmm = nullptr;
    Sleep(2000);
    printf("\n[*] Re-initializing for fresh page tables...\n");
    g_vmm = freshInit();
    if (!g_vmm) { printf("[!] Init 2 failed\n"); return 1; }

    // Re-find process with fresh enumeration
    g_pid = 0;
    if (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) {
        printf("[!] R6 not found on reinit\n");
        pClose(g_vmm);
        return 1;
    }
    printf("[+] PID=%u (after reinit)\n", g_pid);

    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] Base: 0x%llX\n\n", (unsigned long long)g_base);

    dos = rpm<IMAGE_DOS_HEADER>(g_base);
    nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;

    // === LIVENESS CHECK ===
    printf("=== Liveness check ===\n");
    uint64_t gmAddr = g_base + 0x11F0DDF8;
    uint64_t gm = rpm<uint64_t>(gmAddr);
    printf("GM(0x%llX) = 0x%llX\n", (unsigned long long)gmAddr, (unsigned long long)gm);

    if (isValidPtr(gm)) {
        uint8_t s1[512] = {}, s2[512] = {};
        DmaRead(gm, s1, 512);
        printf("Waiting 2s (move character!)...\n");
        Sleep(2000);
        DmaRead(gm, s2, 512);
        int diff = 0;
        for (int i = 0; i < 512; i++)
            if (s1[i] != s2[i]) diff++;
        printf("Result: %d/512 bytes changed %s\n\n", diff,
               diff > 0 ? "==> DMA IS LIVE!" : "==> still stale");

        // Show the GM object for reference
        printf("--- GM object (first 0x200) ---\n");
        for (int i = 0; i < 512; i += 8) {
            uint64_t v = *(uint64_t*)(s2 + i);
            if (v == 0) continue; // skip nulls for clarity
            printf("  +0x%03X: 0x%016llX", i, (unsigned long long)v);
            if (isHeapPtr(v)) printf(" [HEAP]");
            else if (v >= g_base && v < g_modEnd) printf(" [MOD]");
            printf("\n");
        }
    }

    // === GM FIELD SCAN (wider range 0x0-0x800) ===
    printf("\n=== GM field scan 0x0-0x800 ===\n");
    if (isValidPtr(gm)) {
        for (uint64_t off = 0x0; off <= 0x800; off += 0x8) {
            uint64_t val = rpm<uint64_t>(gm + off);
            if (!isHeapPtr(val)) continue;
            int cnt32 = rpm<int32_t>(gm + off + 8);
            if (cnt32 < 2 || cnt32 > 200) continue;
            uint64_t first = rpm<uint64_t>(val);
            if (!isValidPtr(first)) continue;
            printf("  GM+0x%03llX = 0x%llX cnt=%d first=0x%llX %s\n",
                   (unsigned long long)off, (unsigned long long)val, cnt32,
                   (unsigned long long)first,
                   isHeapPtr(first) ? "[HEAP]" : first >= g_base && first < g_modEnd ? "[MOD]" : "");
        }
    }

    // === ENTITY SEARCH: .data section ===
    printf("\n=== .data entity search ===\n");
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    uint64_t dataBase = 0, dataSize = 0;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            dataSize = sec.Misc.VirtualSize;
            break;
        }
    }
    printf(".data at 0x%llX (%.1f MB)\n\n", (unsigned long long)dataBase, dataSize / 1048576.0);

    // Look for any global pointer -> heap obj -> vector<heap_ptr> with count 5+
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK);
    int hits = 0;

    for (uint64_t off = 0; off < dataSize && hits < 20; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 8 <= readSz && hits < 20; i += 8) {
            uint64_t gv = *(uint64_t*)(buf.data() + i);
            if (!isHeapPtr(gv)) continue;

            for (uint64_t fo = 0x0; fo <= 0x400; fo += 0x8) {
                uint64_t vb = rpm<uint64_t>(gv + fo);
                uint64_t ve = rpm<uint64_t>(gv + fo + 8);
                if (!isHeapPtr(vb) || ve <= vb) continue;
                uint64_t bytes = ve - vb;
                if (bytes % 8 != 0) continue;
                int cnt = (int)(bytes / 8);
                if (cnt < 5 || cnt > 50) continue;

                int readN = min(cnt, 10);
                uint64_t ptrs[10] = {};
                DmaRead(vb, ptrs, readN * 8);

                int hp = 0, vt = 0, wp = 0;
                for (int k = 0; k < readN; k++) {
                    if (!isHeapPtr(ptrs[k])) continue;
                    hp++;
                    uint64_t v0 = rpm<uint64_t>(ptrs[k]);
                    if (v0 >= g_base && v0 < g_modEnd) vt++;
                    for (uint64_t po = 0; po <= 0x800; po += 4) {
                        Vec3 v = rpm<Vec3>(ptrs[k] + po);
                        if (isWorldPos(v)) { wp++; break; }
                    }
                }
                if (hp < readN * 2 / 3) continue;

                printf("  .data+0x%llX obj=0x%llX +0x%llX cnt=%d hp=%d vt=%d pos=%d\n",
                       (unsigned long long)(off + i), (unsigned long long)gv,
                       (unsigned long long)fo, cnt, hp, vt, wp);

                if (wp > 0) {
                    printf("    *** HAS POSITIONS ***\n");
                    for (int k = 0; k < min(readN, 5); k++) {
                        printf("    [%d] 0x%llX\n", k, (unsigned long long)ptrs[k]);
                        if (!isHeapPtr(ptrs[k])) continue;
                        for (uint64_t po = 0; po <= 0x800; po += 4) {
                            Vec3 v = rpm<Vec3>(ptrs[k] + po);
                            if (isWorldPos(v)) {
                                printf("         +0x%llX = (%.1f, %.1f, %.1f)\n",
                                       (unsigned long long)po, v.x, v.y, v.z);
                                break;
                            }
                        }
                    }
                }
                hits++;
            }
        }
    }

    if (hits == 0)
        printf("  No vector-like entity arrays found in .data\n");

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
