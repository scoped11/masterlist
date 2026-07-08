// R6 Deep Probe — examines a specific object found by the monitor
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_probe.cpp /Fe"../r6_probe.exe" /link

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

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_Init pInit; static fn_Close pClose; static fn_PidGet pPidGet;
static fn_MemRead pMemRead; static fn_ModBase pModBase;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };
static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }
static bool isHeapPtr(uint64_t v) { return v > 0x10000000000 && v < 0x7FFFFFFFFFFF; }
static bool isWorldPos(Vec3 v) {
    return !isnan(v.x) && !isnan(v.y) && !isnan(v.z) &&
           fabsf(v.x) > 0.5f && fabsf(v.x) < 100000.0f &&
           fabsf(v.y) > 0.5f && fabsf(v.y) < 100000.0f &&
           fabsf(v.z) > 0.1f && fabsf(v.z) < 100000.0f;
}

void hexdump(uint64_t addr, int size) {
    uint8_t buf[4096] = {};
    if (size > 4096) size = 4096;
    DmaRead(addr, buf, size);
    for (int i = 0; i < size; i += 16) {
        printf("  %04X: ", i);
        for (int j = 0; j < 16 && i+j < size; j++)
            printf("%02X ", buf[i+j]);
        printf(" ");
        for (int j = 0; j < 16 && i+j < size; j++) {
            uint8_t c = buf[i+j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("\n");
    }
}

void dumpQwords(uint64_t addr, int count) {
    for (int i = 0; i < count; i++) {
        uint64_t val = rpm<uint64_t>(addr + i * 8);
        printf("  +0x%03X: 0x%016llX", i * 8, (unsigned long long)val);
        if (isHeapPtr(val)) printf(" (HEAP)");
        else if (isValidPtr(val)) printf(" (MOD?)");
        printf("\n");
    }
}

void probeForPositions(uint64_t addr, const char* label) {
    printf("\n--- Position scan on %s (0x%llX) ---\n", label, (unsigned long long)addr);
    int found = 0;
    for (uint64_t off = 0; off <= 0x1000; off += 4) {
        Vec3 v = rpm<Vec3>(addr + off);
        if (isWorldPos(v)) {
            printf("  +0x%04llX = (%.2f, %.2f, %.2f)\n", (unsigned long long)off, v.x, v.y, v.z);
            if (++found >= 30) break;
        }
    }
    if (!found) printf("  (none found)\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Deep Probe ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] DMA init failed\n"); return 1; }

    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    printf("[+] PID=%u\n", g_pid);

    uint64_t base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] Base: 0x%llX\n\n", (unsigned long long)base);

    uint64_t modEnd = base + 0x19F2C000; // ~415MB from monitor output

    // The object found by monitor
    uint64_t obj = 0x27DB76E0010;
    printf("=== Probing object at 0x%llX ===\n", (unsigned long long)obj);
    printf("\n--- First 0x200 bytes as qwords ---\n");
    dumpQwords(obj, 0x200 / 8);

    // Read the vector at +0xB0
    printf("\n--- Vector at +0xB0 ---\n");
    uint64_t vecB0_begin = rpm<uint64_t>(obj + 0xB0);
    uint64_t vecB0_end = rpm<uint64_t>(obj + 0xB8);
    uint64_t vecB0_cap = rpm<uint64_t>(obj + 0xC0);
    printf("  begin=0x%llX end=0x%llX cap=0x%llX\n",
           (unsigned long long)vecB0_begin, (unsigned long long)vecB0_end, (unsigned long long)vecB0_cap);
    if (vecB0_end > vecB0_begin) {
        uint64_t bytes = vecB0_end - vecB0_begin;
        printf("  size=%llu bytes (%llu qwords)\n", (unsigned long long)bytes, (unsigned long long)(bytes/8));
        printf("\n  Raw data:\n");
        hexdump(vecB0_begin, (int)min(bytes, (uint64_t)512));
    }

    // Read the vector at +0xC8
    printf("\n--- Vector at +0xC8 ---\n");
    uint64_t vecC8_begin = rpm<uint64_t>(obj + 0xC8);
    uint64_t vecC8_end = rpm<uint64_t>(obj + 0xD0);
    uint64_t vecC8_cap = rpm<uint64_t>(obj + 0xD8);
    printf("  begin=0x%llX end=0x%llX cap=0x%llX\n",
           (unsigned long long)vecC8_begin, (unsigned long long)vecC8_end, (unsigned long long)vecC8_cap);
    if (vecC8_end > vecC8_begin) {
        uint64_t bytes = vecC8_end - vecC8_begin;
        printf("  size=%llu bytes (%llu qwords)\n", (unsigned long long)bytes, (unsigned long long)(bytes/8));
        printf("\n  Raw data:\n");
        hexdump(vecC8_begin, (int)min(bytes, (uint64_t)512));
    }

    // Follow every heap pointer in the vectors and scan for positions
    printf("\n=== Following heap pointers ===\n");
    for (int vec = 0; vec < 2; vec++) {
        uint64_t vbegin = (vec == 0) ? vecB0_begin : vecC8_begin;
        uint64_t vend = (vec == 0) ? vecB0_end : vecC8_end;
        const char* vname = (vec == 0) ? "+0xB0" : "+0xC8";
        if (vend <= vbegin) continue;

        uint64_t bytes = vend - vbegin;
        int nq = (int)(bytes / 8);
        if (nq > 50) nq = 50;

        printf("\n--- Vector %s: %d qwords ---\n", vname, nq);
        for (int i = 0; i < nq; i++) {
            uint64_t val = rpm<uint64_t>(vbegin + i * 8);
            if (!isHeapPtr(val)) continue;

            printf("\n  [%d] 0x%llX (HEAP)\n", i, (unsigned long long)val);

            // Check vtable (first qword)
            uint64_t vtable = rpm<uint64_t>(val);
            printf("    vtable? 0x%llX %s\n", (unsigned long long)vtable,
                   (vtable >= base && vtable < modEnd) ? "(IN MODULE)" : "(heap/other)");

            // Scan for positions at this object
            int posFound = 0;
            for (uint64_t off = 0; off <= 0xC00; off += 4) {
                Vec3 v = rpm<Vec3>(val + off);
                if (isWorldPos(v)) {
                    printf("    +0x%04llX = (%.2f, %.2f, %.2f)\n",
                           (unsigned long long)off, v.x, v.y, v.z);
                    if (++posFound >= 10) break;
                }
            }

            // Check 1 level of indirection for positions
            for (uint64_t poff = 0x0; poff <= 0x100; poff += 8) {
                uint64_t sub = rpm<uint64_t>(val + poff);
                if (!isHeapPtr(sub)) continue;
                for (uint64_t soff = 0; soff <= 0x800; soff += 4) {
                    Vec3 v = rpm<Vec3>(sub + soff);
                    if (isWorldPos(v)) {
                        printf("    -> (+0x%llX)0x%llX +0x%04llX = (%.2f, %.2f, %.2f)\n",
                               (unsigned long long)poff, (unsigned long long)sub,
                               (unsigned long long)soff, v.x, v.y, v.z);
                        posFound++;
                        if (posFound >= 5) goto next_entry;
                    }
                }
            }
            next_entry:;
        }
    }

    // Also check the globals from .data
    printf("\n=== Checking .data globals ===\n");
    uint64_t dataBase = base + 0x10D01000; // .data offset from base (approximate)
    uint64_t globalAddr1 = dataBase + 0x1988C8;
    uint64_t globalAddr2 = dataBase + 0x198F58;

    // Actually read the global properly
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    uint64_t secAddr = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = base + sec.VirtualAddress;
            printf("  .data base = 0x%llX\n", (unsigned long long)dataBase);

            uint64_t g1 = rpm<uint64_t>(dataBase + 0x1988C8);
            uint64_t g2 = rpm<uint64_t>(dataBase + 0x198F58);
            printf("  .data+0x1988C8 = 0x%llX %s\n", (unsigned long long)g1,
                   isHeapPtr(g1) ? "(HEAP)" : "");
            printf("  .data+0x198F58 = 0x%llX %s\n", (unsigned long long)g2,
                   isHeapPtr(g2) ? "(HEAP)" : "");

            // These should both point to 0x27DB76E0010
            // Let's get the RVA for the offsets ini
            printf("  RVA for global1: 0x%llX\n", (unsigned long long)(0x1988C8 + sec.VirtualAddress));
            printf("  RVA for global2: 0x%llX\n", (unsigned long long)(0x198F58 + sec.VirtualAddress));
            break;
        }
    }

    // Also scan the OTHER high-density candidates from monitor
    printf("\n=== Checking high-density candidates ===\n");
    // .data+0x18D7D8 => obj=0x27DC667B130 list@+0x168 cnt=16 heap=10
    uint64_t obj2 = rpm<uint64_t>(dataBase + 0x18D7D8);
    printf("  obj2 (.data+0x18D7D8) = 0x%llX\n", (unsigned long long)obj2);
    if (isHeapPtr(obj2)) {
        uint64_t v_begin = rpm<uint64_t>(obj2 + 0x168);
        uint64_t v_end = rpm<uint64_t>(obj2 + 0x170);
        if (v_end > v_begin) {
            int cnt = (int)((v_end - v_begin) / 8);
            printf("  list@+0x168: cnt=%d\n", cnt);
            int readN = min(cnt, 10);
            for (int i = 0; i < readN; i++) {
                uint64_t val = rpm<uint64_t>(v_begin + i * 8);
                printf("    [%d] 0x%llX %s\n", i, (unsigned long long)val,
                       isHeapPtr(val) ? "(HEAP)" : isValidPtr(val) ? "(mod?)" : "");
                if (isHeapPtr(val)) {
                    // Quick position scan
                    for (uint64_t off : {0x3CULL, 0x100ULL, 0x200ULL, 0x400ULL, 0x6A0ULL, 0x700ULL}) {
                        Vec3 v = rpm<Vec3>(val + off);
                        if (isWorldPos(v))
                            printf("       +0x%llX = (%.1f, %.1f, %.1f) <-- POSITION!\n",
                                   (unsigned long long)off, v.x, v.y, v.z);
                    }
                    // Pawn check at +0x20
                    uint64_t pawn = rpm<uint64_t>(val + 0x20);
                    if (isHeapPtr(pawn)) {
                        for (uint64_t off : {0x3CULL, 0x100ULL, 0x6A0ULL, 0x700ULL}) {
                            Vec3 v = rpm<Vec3>(pawn + off);
                            if (isWorldPos(v))
                                printf("       pawn->+0x%llX = (%.1f, %.1f, %.1f) <-- POSITION!\n",
                                       (unsigned long long)off, v.x, v.y, v.z);
                        }
                    }
                }
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
