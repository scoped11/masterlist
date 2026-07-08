// R6 TLB Fix — try every MemProcFS cache refresh method to solve stale reads
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_tlbfix.cpp /Fe"../r6_tlbfix.exe" /link

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
typedef BOOL       (__cdecl *fn_ConfigGet)(VMM_HANDLE hVMM, ULONG64 fOption, PULONG64 pqwValue);

// Process info struct
#pragma pack(push, 4)
typedef struct {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    DWORD tpMemoryModel;
    DWORD tpSystem;
    BOOL fUserOnly;
    DWORD dwPID;
    DWORD dwPPID;
    DWORD dwState;
    CHAR szName[16];
    CHAR szNameLong[64];
    ULONG64 paDTB;          // CR3/DTB — THIS IS WHAT WE NEED
    ULONG64 paDTB_UserOpt;
    // ... more fields we don't need
    BYTE padding[512];
} VMMDLL_PROCESS_INFORMATION;
#pragma pack(pop)

typedef BOOL (__cdecl *fn_ProcessGetInfo)(VMM_HANDLE hVMM, DWORD dwPID, PVOID pProcessInformation, PDWORD pcbProcessInformation);

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_MemRead pMemRead;
static fn_ConfigSet pConfigSet;
static fn_ConfigGet pConfigGet;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t size, uint64_t flags = 0x0003) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, flags) && cb > 0;
}

// Physical memory read (PID=0xFFFFFFFF for physical)
static bool PhysRead(uint64_t pa, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, (DWORD)-1, pa, (PBYTE)buf, size, &cb, 0x0001) && cb > 0;
}

template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
struct Vec3 { float x, y, z; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 TLB Fix Test ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    auto pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    auto pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    auto pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead      = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    auto pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");
    pConfigSet    = (fn_ConfigSet)GetProcAddress(h, "VMMDLL_ConfigSet");
    pConfigGet    = (fn_ConfigGet)GetProcAddress(h, "VMMDLL_ConfigGet");
    auto pProcInfo = (fn_ProcessGetInfo)GetProcAddress(h, "VMMDLL_ProcessGetInformation");

    printf("Functions loaded: ConfigSet=%p ConfigGet=%p ProcInfo=%p\n",
           pConfigSet, pConfigGet, pProcInfo);

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] Init failed\n"); return 1; }

    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    // Get process DTB (CR3)
    if (pProcInfo) {
        VMMDLL_PROCESS_INFORMATION pi = {};
        pi.magic = 0xc0ffee663df9301e;
        pi.wVersion = 7;
        pi.wSize = sizeof(pi);
        DWORD cbPi = sizeof(pi);
        if (pProcInfo(g_vmm, g_pid, &pi, &cbPi)) {
            printf("[+] Process DTB (CR3) = 0x%llX\n", (unsigned long long)pi.paDTB);
            printf("[+] Process DTB_User = 0x%llX\n", (unsigned long long)pi.paDTB_UserOpt);
        } else {
            printf("[!] ProcessGetInformation failed\n");
        }
    }

    // Test address: pick one of our known entity positions
    uint64_t dataBase = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) { dataBase = g_base + sec.VirtualAddress; break; }
    }

    uint64_t testObj = rpm<uint64_t>(dataBase + 0x444BC8);
    printf("[+] Test obj (.data+0x444BC8) = 0x%llX\n", (unsigned long long)testObj);

    // Read position from first entity candidate
    uint64_t vb = rpm<uint64_t>(testObj + 0x108);
    uint64_t ve = rpm<uint64_t>(testObj + 0x110);
    int cnt = (ve > vb) ? (int)((ve - vb) / 8) : 0;
    printf("[+] Vector: begin=0x%llX cnt=%d\n", (unsigned long long)vb, cnt);

    uint64_t firstEnt = 0;
    if (cnt > 0) {
        firstEnt = rpm<uint64_t>(vb);
        printf("[+] First entry: 0x%llX\n", (unsigned long long)firstEnt);
    }

    // Test 1: Try all ConfigSet refresh options
    printf("\n=== Testing ConfigSet refresh options ===\n");

    struct { uint64_t opt; const char* name; uint64_t val; } refreshOpts[] = {
        {0x20000001, "REFRESH_TLB", 1},
        {0x20000002, "REFRESH_MEM", 1},
        {0x20000004, "REFRESH_PROC", 1},
        {0x20000008, "REFRESH_READ", 1},
        {0x2001FFFF, "REFRESH_ALL", 1},
        {0x20100000, "FREQ_TLB", 1},      // set TLB refresh frequency to 1
        {0x20200000, "FREQ_MEM", 1},
        {0x20300000, "FREQ_PROC", 1},
        {0x20400000, "FREQ_SLOW", 1},
    };

    for (auto& ro : refreshOpts) {
        if (!pConfigSet) continue;
        BOOL result = pConfigSet(g_vmm, ro.opt, ro.val);
        printf("  ConfigSet(0x%08llX, %s, %llu) = %s\n",
               (unsigned long long)ro.opt, ro.name, (unsigned long long)ro.val,
               result ? "OK" : "FAILED");
    }

    // Test 2: Read with different flag combinations and check for liveness
    printf("\n=== Liveness test with different read flags ===\n");
    printf(">>> MOVE YOUR CHARACTER NOW! <<<\n");

    if (firstEnt) {
        // Read initial position
        Vec3 pos1;
        DmaRead(firstEnt + 0x50, &pos1, sizeof(pos1), 0x0003);
        printf("\nInitial pos@+0x50 = (%.2f, %.2f, %.2f)\n", pos1.x, pos1.y, pos1.z);

        // Read 512 bytes for general liveness check
        uint8_t snap1[512], snap2[512];
        DmaRead(firstEnt, snap1, 512, 0x0003);

        printf("\nWaiting 5 seconds (MOVE NOW!)...\n");
        Sleep(5000);

        // Try TLB refresh again
        if (pConfigSet) {
            pConfigSet(g_vmm, 0x20000001, 1); // TLB refresh
        }

        uint64_t flags[] = {0x0001, 0x0003, 0x0101, 0x0401, 0x0001 | 0x0800};
        const char* flagNames[] = {"NOCACHE", "NOCACHE|ZEROPAD", "NOCACHE|NOCACHEPUT",
                                    "NOCACHE|NOPREDICTIVE", "NOCACHE|FORCECACHE_DIS"};

        for (int f = 0; f < 5; f++) {
            Vec3 pos2;
            DmaRead(firstEnt + 0x50, &pos2, sizeof(pos2), flags[f]);
            DmaRead(firstEnt, snap2, 512, flags[f]);

            int diff = 0;
            for (int b = 0; b < 512; b++)
                if (snap1[b] != snap2[b]) diff++;

            printf("  Flag 0x%04llX (%s): pos=(%.2f,%.2f,%.2f) diff=%d/512\n",
                   (unsigned long long)flags[f], flagNames[f],
                   pos2.x, pos2.y, pos2.z, diff);
        }
    }

    // Test 3: Close and reinit with different flags
    printf("\n=== Reinit with aggressive refresh flags ===\n");
    pClose(g_vmm); g_vmm = nullptr; Sleep(1500);

    // Try with max refresh flags
    LPCSTR args2[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize",
                       "-max" };
    g_vmm = pInit(7, args2);
    if (g_vmm) {
        printf("[+] Reinit with -max succeeded\n");
        pPidGet(g_vmm, "RainbowSix.exe", &g_pid);

        if (firstEnt) {
            Vec3 pos3;
            DmaRead(firstEnt + 0x50, &pos3, sizeof(pos3), 0x0001);
            printf("  pos after reinit = (%.2f, %.2f, %.2f)\n", pos3.x, pos3.y, pos3.z);

            // Check liveness on a broader area — read 4KB
            uint8_t bigSnap1[4096], bigSnap2[4096];
            DmaRead(firstEnt, bigSnap1, 4096, 0x0001);

            // Try TLB refresh
            if (pConfigSet) {
                BOOL r1 = pConfigSet(g_vmm, 0x20000001, 1);
                printf("  TLB refresh after -max init: %s\n", r1 ? "OK" : "FAILED");
            }

            Sleep(2000);
            DmaRead(firstEnt, bigSnap2, 4096, 0x0001);
            int diff = 0;
            for (int b = 0; b < 4096; b++)
                if (bigSnap1[b] != bigSnap2[b]) diff++;
            printf("  4KB liveness: %d/4096 bytes changed\n", diff);
        }

        pClose(g_vmm);
    } else {
        printf("[!] Reinit with -max failed, trying without\n");
    }

    // Test 4: Try physical memory read approach
    printf("\n=== Physical memory test ===\n");
    g_vmm = pInit(6, args);
    if (g_vmm) {
        pPidGet(g_vmm, "RainbowSix.exe", &g_pid);

        // Get DTB again
        uint64_t dtb = 0;
        if (pProcInfo) {
            VMMDLL_PROCESS_INFORMATION pi = {};
            pi.magic = 0xc0ffee663df9301e;
            pi.wVersion = 7;
            pi.wSize = sizeof(pi);
            DWORD cbPi = sizeof(pi);
            if (pProcInfo(g_vmm, g_pid, &pi, &cbPi)) {
                dtb = pi.paDTB;
                printf("[+] DTB = 0x%llX\n", (unsigned long long)dtb);
            }
        }

        // Manual page table walk for the test address
        if (dtb && firstEnt) {
            uint64_t va = firstEnt;
            printf("[+] Walking page tables for VA 0x%llX\n", (unsigned long long)va);

            int pml4i = (va >> 39) & 0x1FF;
            int pdpi  = (va >> 30) & 0x1FF;
            int pdi   = (va >> 21) & 0x1FF;
            int pti   = (va >> 12) & 0x1FF;
            int pageOff = va & 0xFFF;

            printf("  Indices: PML4=%d PDP=%d PD=%d PT=%d offset=0x%X\n",
                   pml4i, pdpi, pdi, pti, pageOff);

            // Read PML4E
            uint64_t pml4e = 0;
            PhysRead((dtb & ~0xFFFULL) + pml4i * 8, &pml4e, 8);
            printf("  PML4E = 0x%llX %s\n", (unsigned long long)pml4e,
                   (pml4e & 1) ? "PRESENT" : "NOT PRESENT");

            if (pml4e & 1) {
                uint64_t pdpe = 0;
                PhysRead((pml4e & 0x000FFFFFFFFFF000ULL) + pdpi * 8, &pdpe, 8);
                printf("  PDPE  = 0x%llX %s%s\n", (unsigned long long)pdpe,
                       (pdpe & 1) ? "PRESENT" : "NOT PRESENT",
                       (pdpe & 0x80) ? " 1GB" : "");

                if ((pdpe & 1) && !(pdpe & 0x80)) {
                    uint64_t pde = 0;
                    PhysRead((pdpe & 0x000FFFFFFFFFF000ULL) + pdi * 8, &pde, 8);
                    printf("  PDE   = 0x%llX %s%s\n", (unsigned long long)pde,
                           (pde & 1) ? "PRESENT" : "NOT PRESENT",
                           (pde & 0x80) ? " 2MB" : "");

                    if ((pde & 1) && !(pde & 0x80)) {
                        uint64_t pte = 0;
                        PhysRead((pde & 0x000FFFFFFFFFF000ULL) + pti * 8, &pte, 8);
                        uint64_t physAddr = (pte & 0x000FFFFFFFFFF000ULL) | pageOff;
                        printf("  PTE   = 0x%llX %s\n", (unsigned long long)pte,
                               (pte & 1) ? "PRESENT" : "NOT PRESENT");
                        printf("  Physical address = 0x%llX\n", (unsigned long long)physAddr);

                        // Read via physical address
                        uint8_t physData[64];
                        if (PhysRead(physAddr, physData, 64)) {
                            Vec3* pv = (Vec3*)(physData + (0x50 & 0x3F));
                            printf("  Physical read pos: (%.2f, %.2f, %.2f)\n",
                                   pv->x, pv->y, pv->z);

                            // Wait and read again
                            printf("  Waiting 3s...\n");
                            Sleep(3000);

                            // Re-walk page tables for fresh PTE
                            pte = 0;
                            PhysRead((pde & 0x000FFFFFFFFFF000ULL) + pti * 8, &pte, 8);
                            physAddr = (pte & 0x000FFFFFFFFFF000ULL) | pageOff;
                            printf("  Re-walked PTE = 0x%llX -> PA = 0x%llX\n",
                                   (unsigned long long)pte, (unsigned long long)physAddr);

                            if (PhysRead(physAddr, physData, 64)) {
                                pv = (Vec3*)(physData + (0x50 & 0x3F));
                                printf("  Physical read pos (fresh): (%.2f, %.2f, %.2f)\n",
                                       pv->x, pv->y, pv->z);
                            }
                        } else {
                            printf("  [!] Physical read failed\n");
                        }
                    } else if (pde & 0x80) {
                        // 2MB page
                        uint64_t physAddr = (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
                        printf("  2MB page -> PA = 0x%llX\n", (unsigned long long)physAddr);
                    }
                }
            }
        }

        pClose(g_vmm);
    }

    printf("\nDone.\n");
    return 0;
}
