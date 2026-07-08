// R6 DMA Liveness Test — checks if memory is actually updating
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_livetest.cpp /Fe"../r6_livetest.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef BOOL       (__cdecl *fn_ConfigSet)(VMM_HANDLE hVMM, ULONG64 fOption, ULONG64 qwValue);

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_MemRead pMemRead;

// NOCACHE flag = 0x0001, ZEROPAD = 0x0002
static bool DmaReadNoCache(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0001 | 0x0002) && cb > 0;
}
static bool DmaReadCached(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaReadNoCache(a, &v, sizeof(T)); return v; }

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 DMA Liveness Test ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    auto pInit = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    auto pClose = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    auto pPidGet = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    auto pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");
    auto pConfigSet = (fn_ConfigSet)GetProcAddress(h, "VMMDLL_ConfigSet");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] DMA init failed\n"); return 1; }

    // Disable cache refresh to force live reads
    // VMMDLL_OPT_CONFIG_CACHE_ENABLE = 0x200000003
    if (pConfigSet) {
        // Try to set cache tick period to 0 (disable periodic refresh)
        pConfigSet(g_vmm, 0x200000003ULL, 0);
    }

    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    printf("[+] PID=%u\n", g_pid);

    uint64_t base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] Base: 0x%llX\n\n", (unsigned long long)base);

    // Test 1: Read the old GM global and check for change
    uint64_t gmAddr = base + 0x11F0DDF8;
    uint64_t gm1 = rpm<uint64_t>(gmAddr);
    printf("[1] GM global (0x%llX) = 0x%llX\n", (unsigned long long)gmAddr, (unsigned long long)gm1);

    // Test 2: If GM is a valid pointer, read some bytes from it
    if (gm1 > 0x10000 && gm1 < 0x7FFFFFFFFFFF) {
        uint8_t snap1[256] = {}, snap2[256] = {};
        DmaReadNoCache(gm1, snap1, 256);

        printf("\n[2] Waiting 3 seconds (move your mouse/character on PC1!)...\n");
        Sleep(3000);

        // Force re-read with NOCACHE
        DmaReadNoCache(gm1, snap2, 256);

        int diff = 0;
        for (int i = 0; i < 256; i++)
            if (snap1[i] != snap2[i]) diff++;
        printf("[2] GM obj: %d/256 bytes changed after 3s %s\n", diff,
               diff > 0 ? "(LIVE!)" : "(STALE - cache issue?)");
    }

    // Test 3: Read a few heap addresses that should be game state
    printf("\n[3] Scanning heap regions for changing data...\n");

    // Try reading multiple heap pages
    uint64_t testAddrs[] = {
        gm1,                    // The GM object
        gm1 + 0x1000,          // Nearby heap
        gm1 + 0x10000,         // Further heap
        base + 0x11C698C8,     // The other .data global
    };

    for (int t = 0; t < 4; t++) {
        uint64_t addr = rpm<uint64_t>(testAddrs[t]);
        if (addr < 0x10000 || addr > 0x7FFFFFFFFFFF) {
            addr = testAddrs[t]; // Use the address directly
        }

        uint8_t s1[4096] = {}, s2[4096] = {};
        DmaReadNoCache(addr, s1, 4096);
        Sleep(1000);
        DmaReadNoCache(addr, s2, 4096);

        int diff = 0;
        for (int i = 0; i < 4096; i++)
            if (s1[i] != s2[i]) diff++;
        printf("  addr=0x%llX: %d/4096 bytes changed %s\n",
               (unsigned long long)addr, diff, diff > 0 ? "(LIVE)" : "(static)");
    }

    // Test 4: Read PEB/TEB or other known-changing OS structures
    printf("\n[4] Testing with broader memory scan...\n");

    // Get the .data section and check if anything changes in it
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
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

    if (dataBase) {
        // Sample 10 random-ish pages from .data
        printf("  .data: 0x%llX (%.1f MB)\n", (unsigned long long)dataBase, dataSize / 1048576.0);
        int totalDiff = 0;
        for (int page = 0; page < 10; page++) {
            uint64_t offset = (dataSize / 10) * page;
            uint8_t p1[4096] = {}, p2[4096] = {};
            DmaReadNoCache(dataBase + offset, p1, 4096);
            Sleep(500);
            DmaReadNoCache(dataBase + offset, p2, 4096);
            int diff = 0;
            for (int i = 0; i < 4096; i++)
                if (p1[i] != p2[i]) diff++;
            if (diff > 0) {
                printf("  .data+0x%llX: %d bytes changed (LIVE)\n",
                       (unsigned long long)offset, diff);
                totalDiff += diff;
            }
        }
        if (totalDiff == 0) printf("  .data: NO changes detected in any sample!\n");
    }

    // Test 5: Try to find and read a timestamp/counter in the game
    printf("\n[5] Looking for frame counter or game clock...\n");

    // Read 3 snapshots of the first 0x800 bytes of the GM object
    if (gm1 > 0x10000 && gm1 < 0x7FFFFFFFFFFF) {
        uint64_t vals1[256] = {}, vals2[256] = {}, vals3[256] = {};
        DmaReadNoCache(gm1, vals1, 2048);
        Sleep(1000);
        DmaReadNoCache(gm1, vals2, 2048);
        Sleep(1000);
        DmaReadNoCache(gm1, vals3, 2048);

        printf("  Fields that changed between 3 reads (1s apart):\n");
        int changes = 0;
        for (int i = 0; i < 256; i++) {
            if (vals1[i] != vals2[i] || vals2[i] != vals3[i]) {
                printf("  GM+0x%03X: 0x%llX -> 0x%llX -> 0x%llX\n",
                       i * 8, (unsigned long long)vals1[i],
                       (unsigned long long)vals2[i], (unsigned long long)vals3[i]);
                changes++;
                if (changes >= 20) break;
            }
        }
        if (changes == 0) printf("  NO fields changed — DMA appears to be reading stale data!\n");
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
