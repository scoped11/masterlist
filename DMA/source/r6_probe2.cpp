// R6 Deep Probe 2 — examine the high-density entity list candidate
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_probe2.cpp /Fe"../r6_probe2.exe" /link

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
static fn_Init pInit; static fn_Close pClose; static fn_PidGet pPidGet;
static fn_MemRead pMemRead; static fn_ModBase pModBase;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0002) && cb > 0;
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

void dumpObj(uint64_t addr, int bytes, const char* label) {
    printf("\n--- %s (0x%llX) ---\n", label, (unsigned long long)addr);
    uint8_t buf[2048] = {};
    if (bytes > 2048) bytes = 2048;
    DmaRead(addr, buf, bytes);
    for (int i = 0; i < bytes; i += 8) {
        uint64_t val = *(uint64_t*)(buf + i);
        printf("  +0x%03X: 0x%016llX", i, (unsigned long long)val);
        if (isModPtr(val)) printf(" [MODULE vtable?]");
        else if (isHeapPtr(val)) printf(" [HEAP]");
        float* f = (float*)(buf + i);
        if (fabsf(f[0]) > 0.5f && fabsf(f[0]) < 100000.0f &&
            fabsf(f[1]) > 0.5f && fabsf(f[1]) < 100000.0f)
            printf(" floats=(%.2f, %.2f)", f[0], f[1]);
        printf("\n");
    }
}

void deepPositionScan(uint64_t addr, const char* label, int depth) {
    // Scan for Vec3 at this object
    int found = 0;
    for (uint64_t off = 0; off <= 0x1000; off += 4) {
        Vec3 v = rpm<Vec3>(addr + off);
        if (isWorldPos(v)) {
            printf("  %s+0x%04llX = (%.2f, %.2f, %.2f)\n",
                   label, (unsigned long long)off, v.x, v.y, v.z);
            if (++found >= 5) break;
        }
    }
    // Follow heap pointers 1 level deep
    if (depth > 0) {
        std::set<uint64_t> visited;
        for (uint64_t off = 0; off <= 0x200; off += 8) {
            uint64_t sub = rpm<uint64_t>(addr + off);
            if (!isHeapPtr(sub) || visited.count(sub)) continue;
            visited.insert(sub);
            char sublabel[128];
            sprintf(sublabel, "%s->(+0x%llX)0x%llX", label, (unsigned long long)off, (unsigned long long)sub);
            int subFound = 0;
            for (uint64_t soff = 0; soff <= 0x800; soff += 4) {
                Vec3 v = rpm<Vec3>(sub + soff);
                if (isWorldPos(v)) {
                    printf("  %s+0x%04llX = (%.2f, %.2f, %.2f)\n",
                           sublabel, (unsigned long long)soff, v.x, v.y, v.z);
                    if (++subFound >= 3) break;
                }
            }
            // Go one more level if depth allows
            if (depth > 1 && subFound == 0) {
                for (uint64_t off2 = 0; off2 <= 0x100; off2 += 8) {
                    uint64_t sub2 = rpm<uint64_t>(sub + off2);
                    if (!isHeapPtr(sub2) || visited.count(sub2)) continue;
                    visited.insert(sub2);
                    for (uint64_t soff2 = 0; soff2 <= 0x800; soff2 += 4) {
                        Vec3 v = rpm<Vec3>(sub2 + soff2);
                        if (isWorldPos(v)) {
                            printf("  %s->(+0x%llX)0x%llX+0x%04llX = (%.2f, %.2f, %.2f)\n",
                                   sublabel, (unsigned long long)off2, (unsigned long long)sub2,
                                   (unsigned long long)soff2, v.x, v.y, v.z);
                            subFound++;
                            if (subFound >= 3) goto next_sub;
                        }
                    }
                }
                next_sub:;
            }
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Deep Probe 2 ===\n\n");

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

    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] Module: 0x%llX - 0x%llX\n\n", (unsigned long long)g_base, (unsigned long long)g_modEnd);

    // Find .data section
    uint64_t dataBase = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            break;
        }
    }

    // === Candidate 1: high-density list from monitor (.data+0x18D7D8) ===
    printf("=== Candidate 1: .data+0x18D7D8 ===\n");
    uint64_t mgr = rpm<uint64_t>(dataBase + 0x18D7D8);
    printf("Manager obj: 0x%llX\n", (unsigned long long)mgr);

    if (isHeapPtr(mgr)) {
        // Dump the manager
        dumpObj(mgr, 0x300, "Manager");

        // Read the list at +0x168
        uint64_t lbegin = rpm<uint64_t>(mgr + 0x168);
        uint64_t lend = rpm<uint64_t>(mgr + 0x170);
        int count = (lend > lbegin) ? (int)((lend - lbegin) / 8) : 0;
        printf("\n--- Entity list at +0x168: %d entries ---\n", count);

        if (count > 0 && count <= 100) {
            int readN = (count > 20) ? 20 : count;
            uint64_t ptrs[20] = {};
            DmaRead(lbegin, ptrs, readN * 8);

            // Get unique entries
            std::set<uint64_t> unique;
            for (int i = 0; i < readN; i++) unique.insert(ptrs[i]);

            printf("  Unique entries: %d (of %d)\n\n", (int)unique.size(), readN);

            int idx = 0;
            for (uint64_t ent : unique) {
                char lbl[64];
                sprintf(lbl, "Ent_%d", idx);
                printf("--- Entity %d: 0x%llX ---\n", idx, (unsigned long long)ent);

                // Dump first 0x100 bytes
                dumpObj(ent, 0x100, lbl);

                // Deep position scan (2 levels of pointer following)
                printf("\n  Position scan:\n");
                deepPositionScan(ent, lbl, 2);

                printf("\n");
                idx++;
                if (idx >= 8) break;
            }
        }
    }

    // === Also scan .data for more entity list candidates ===
    printf("\n=== Broader .data scan for entity lists (heap-only arrays) ===\n");
    printf("  (Looking for std::vector of exclusively heap pointers, count 5-50)\n\n");

    uint64_t dataSize = 0;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) { dataSize = sec.Misc.VirtualSize; break; }
    }

    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK);
    int hits = 0;

    for (uint64_t off = 0; off < dataSize && hits < 30; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 8 <= readSz && hits < 30; i += 8) {
            uint64_t globalVal = *(uint64_t*)(buf.data() + i);
            if (!isHeapPtr(globalVal)) continue;

            // Scan this object for std::vector<heap_ptr> patterns
            for (uint64_t foff = 0x0; foff <= 0x400; foff += 0x8) {
                uint64_t vb = rpm<uint64_t>(globalVal + foff);
                uint64_t ve = rpm<uint64_t>(globalVal + foff + 8);
                uint64_t vc = rpm<uint64_t>(globalVal + foff + 16);
                if (!isHeapPtr(vb) || ve <= vb || vc < ve) continue;
                uint64_t bytes = ve - vb;
                if (bytes % 8 != 0) continue;
                int cnt = (int)(bytes / 8);
                if (cnt < 5 || cnt > 50) continue;

                // ALL entries must be heap pointers (strict filter)
                int readN = (cnt > 10) ? 10 : cnt;
                uint64_t ptrs[10] = {};
                DmaRead(vb, ptrs, readN * 8);
                int heapCount = 0;
                for (int k = 0; k < readN; k++)
                    if (isHeapPtr(ptrs[k])) heapCount++;
                if (heapCount < readN) continue;

                // Check if entries have vtables (first qword in module range)
                int withVtable = 0;
                for (int k = 0; k < readN; k++) {
                    uint64_t vt = rpm<uint64_t>(ptrs[k]);
                    if (isModPtr(vt)) withVtable++;
                }

                // Check if any entry has positions at any level
                int withPos = 0;
                for (int k = 0; k < readN && k < 5; k++) {
                    for (uint64_t posOff = 0; posOff <= 0x800; posOff += 4) {
                        Vec3 v = rpm<Vec3>(ptrs[k] + posOff);
                        if (isWorldPos(v)) { withPos++; break; }
                    }
                }

                printf("  .data+0x%llX => obj=0x%llX  list@+0x%llX cnt=%d vtbl=%d/%d pos=%d/%d\n",
                       (unsigned long long)(off + i), (unsigned long long)globalVal,
                       (unsigned long long)foff, cnt, withVtable, readN, withPos, readN);

                if (withVtable >= readN/2 && withPos > 0) {
                    printf("    ^^^ STRONG CANDIDATE (vtable + positions)\n");
                    for (int k = 0; k < min(readN, 5); k++) {
                        printf("    [%d] 0x%llX vt=0x%llX\n", k, (unsigned long long)ptrs[k],
                               (unsigned long long)rpm<uint64_t>(ptrs[k]));
                    }
                }
                hits++;
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
