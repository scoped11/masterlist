// R6 Entity Probe — deep dive on the position-bearing candidates
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_entityprobe.cpp /Fe"../r6_entityprobe.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <set>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_MemRead pMemRead;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };
static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }
static bool isHeapPtr(uint64_t v) { return isValidPtr(v) && (v < g_base || v > g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }
static bool isWorldPos(Vec3 v) {
    return !isnan(v.x) && !isnan(v.y) && !isnan(v.z) &&
           fabsf(v.x) > 0.5f && fabsf(v.x) < 100000.0f &&
           fabsf(v.y) > 0.5f && fabsf(v.y) < 100000.0f &&
           fabsf(v.z) > 0.1f && fabsf(v.z) < 100000.0f;
}

void probeCandidate(uint64_t obj, uint64_t listOff, int expectedCnt, const char* label) {
    printf("\n========================================\n");
    printf("=== %s ===\n", label);
    printf("  obj=0x%llX  list@+0x%llX\n", (unsigned long long)obj, (unsigned long long)listOff);
    printf("========================================\n");

    uint64_t vb = rpm<uint64_t>(obj + listOff);
    uint64_t ve = rpm<uint64_t>(obj + listOff + 8);
    if (ve <= vb) { printf("  [!] Invalid vector\n"); return; }
    int cnt = (int)((ve - vb) / 8);
    printf("  vector: begin=0x%llX end=0x%llX cnt=%d\n\n",
           (unsigned long long)vb, (unsigned long long)ve, cnt);

    int readN = (cnt > 20) ? 20 : cnt;
    uint64_t ptrs[20] = {};
    DmaRead(vb, ptrs, readN * 8);

    // First pass: classify entries
    printf("--- Entry classification ---\n");
    for (int i = 0; i < readN; i++) {
        uint64_t p = ptrs[i];
        printf("  [%2d] 0x%016llX", i, (unsigned long long)p);
        if (isHeapPtr(p)) {
            uint64_t vt = rpm<uint64_t>(p);
            if (isModPtr(vt)) printf(" HEAP vtbl=+0x%llX", (unsigned long long)(vt - g_base));
            else printf(" HEAP (no vtbl)");
        } else if (isModPtr(p)) {
            printf(" MODULE");
        } else if (p == 0) {
            printf(" NULL");
        } else {
            printf(" value=0x%llX", (unsigned long long)p);
        }
        printf("\n");
    }

    // Second pass: for each heap entry with vtable, scan for positions
    printf("\n--- Position scan on heap entries ---\n");
    std::set<uint64_t> vtables;
    int entitiesWithPos = 0;

    for (int i = 0; i < readN; i++) {
        if (!isHeapPtr(ptrs[i])) continue;
        uint64_t vt = rpm<uint64_t>(ptrs[i]);

        // Scan this entry directly for positions
        int found = 0;
        for (uint64_t off = 0; off <= 0xC00; off += 4) {
            Vec3 v = rpm<Vec3>(ptrs[i] + off);
            if (isWorldPos(v)) {
                if (found == 0) {
                    printf("\n  [%d] 0x%llX", i, (unsigned long long)ptrs[i]);
                    if (isModPtr(vt)) {
                        printf(" vtbl=+0x%llX", (unsigned long long)(vt - g_base));
                        vtables.insert(vt);
                    }
                    printf("\n");
                }
                printf("    +0x%04llX = (%.2f, %.2f, %.2f)\n",
                       (unsigned long long)off, v.x, v.y, v.z);
                found++;
                if (found >= 8) break;
            }
        }

        // Also check 1 level of indirection
        if (found == 0) {
            for (uint64_t poff = 0x0; poff <= 0x100; poff += 8) {
                uint64_t sub = rpm<uint64_t>(ptrs[i] + poff);
                if (!isHeapPtr(sub)) continue;
                for (uint64_t soff = 0; soff <= 0x800; soff += 4) {
                    Vec3 v = rpm<Vec3>(sub + soff);
                    if (isWorldPos(v)) {
                        if (found == 0) {
                            printf("\n  [%d] 0x%llX (indirect)\n", i, (unsigned long long)ptrs[i]);
                        }
                        printf("    ->(+0x%llX)0x%llX+0x%04llX = (%.2f, %.2f, %.2f)\n",
                               (unsigned long long)poff, (unsigned long long)sub,
                               (unsigned long long)soff, v.x, v.y, v.z);
                        found++;
                        if (found >= 3) goto done_indirect;
                    }
                }
            }
            done_indirect:;
        }

        if (found > 0) entitiesWithPos++;
    }

    printf("\n  Summary: %d/%d entries have positions, %d unique vtables\n",
           entitiesWithPos, readN, (int)vtables.size());
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Entity Probe ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    auto pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    auto pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    auto pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead      = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    auto pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] DMA init failed\n"); return 1; }

    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    printf("[+] PID=%u\n", g_pid);

    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] Module: 0x%llX - 0x%llX\n", (unsigned long long)g_base, (unsigned long long)g_modEnd);

    // Find .data
    uint64_t dataBase = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            break;
        }
    }
    printf("[+] .data: 0x%llX\n\n", (unsigned long long)dataBase);

    // === Candidate 1: .data+0x18DB20 => obj=0x28128DA1A60, vtable+pos ===
    uint64_t obj1 = rpm<uint64_t>(dataBase + 0x18DB20);
    printf("Candidate 1 global (.data+0x18DB20) = 0x%llX\n", (unsigned long long)obj1);
    if (isHeapPtr(obj1)) {
        probeCandidate(obj1, 0x280, 18, "Candidate 1: .data+0x18DB20 +0x280");
        // Also check other list offsets on this object
        for (uint64_t tryOff = 0x0; tryOff <= 0x400; tryOff += 8) {
            uint64_t tvb = rpm<uint64_t>(obj1 + tryOff);
            uint64_t tve = rpm<uint64_t>(obj1 + tryOff + 8);
            if (!isHeapPtr(tvb) || tve <= tvb) continue;
            int tcnt = (int)((tve - tvb) / 8);
            if (tcnt < 5 || tcnt > 50 || tryOff == 0x280) continue;
            // Quick check: do any entries have positions?
            int treadN = (tcnt > 5) ? 5 : tcnt;
            uint64_t tptrs[5] = {};
            DmaRead(tvb, tptrs, treadN * 8);
            int thp = 0, tvt = 0, twp = 0;
            for (int k = 0; k < treadN; k++) {
                if (!isHeapPtr(tptrs[k])) continue;
                thp++;
                if (isModPtr(rpm<uint64_t>(tptrs[k]))) tvt++;
                for (uint64_t po = 0; po <= 0x800; po += 4) {
                    Vec3 v = rpm<Vec3>(tptrs[k] + po);
                    if (isWorldPos(v)) { twp++; break; }
                }
            }
            if (thp >= 3 && (tvt > 0 || twp > 0))
                printf("\n  Also: obj+0x%llX cnt=%d hp=%d vt=%d pos=%d\n",
                       (unsigned long long)tryOff, tcnt, thp, tvt, twp);
        }
    }

    // === Candidate 2: .data+0x199A08 => obj=0x27DC8B5D750, multi-pos ===
    uint64_t obj2 = rpm<uint64_t>(dataBase + 0x199A08);
    printf("\n\nCandidate 2 global (.data+0x199A08) = 0x%llX\n", (unsigned long long)obj2);
    if (isHeapPtr(obj2)) {
        // Probe multiple offsets that had positions
        probeCandidate(obj2, 0x160, 20, "Candidate 2: +0x160");
        probeCandidate(obj2, 0x230, 20, "Candidate 2: +0x230");
    }

    // === Stability check: read positions twice 2s apart ===
    printf("\n\n=== Position stability check (2s apart) ===\n");
    // Use the known position from candidate 1 entry [4]: 0x27DB5FA2A78 +0x7F0
    // And candidate 1 entry [1]: 0x280DC2286A0 +0x6E8
    uint64_t testAddrs[][2] = {
        {0x280DC2286A0, 0x6E8},
        {0x27DB5FA2A78, 0x7F0},
        {0x27DB5FA2AE4, 0x784},
        {0x27DB5FA2B50, 0x718},
        {0x27DB5F82108, 0x778},
    };
    for (auto& ta : testAddrs) {
        Vec3 v1 = rpm<Vec3>(ta[0] + ta[1]);
        Sleep(500);
        Vec3 v2 = rpm<Vec3>(ta[0] + ta[1]);
        printf("  0x%llX+0x%llX: (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f) %s\n",
               (unsigned long long)ta[0], (unsigned long long)ta[1],
               v1.x, v1.y, v1.z, v2.x, v2.y, v2.z,
               (v1.x == v2.x && v1.y == v2.y && v1.z == v2.z) ? "STABLE" : "CHANGED");
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
