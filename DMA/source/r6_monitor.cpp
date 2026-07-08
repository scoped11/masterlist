// R6 Siege Memory Monitor — polls key addresses to detect entity loading
// and brute-force scans heap for entity-like objects.
//
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_monitor.cpp /Fe"../r6_monitor.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <intrin.h>
#include <cmath>
#include <algorithm>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

// VMMDLL_Map_GetVadU for memory map
typedef struct {
    DWORD dwVersion;
    DWORD _Reserved1;
    DWORD cMap;
    DWORD _Filler[5];
} VMMDLL_MAP_VAD;

typedef struct {
    ULONG64 vaStart;
    ULONG64 vaEnd;
    ULONG64 vaVad;
    union {
        struct {
            DWORD VadType : 3;
            DWORD Protection : 5;
            DWORD fImage : 1;
            DWORD fFile : 1;
            DWORD fPageFile : 1;
            DWORD fPrivateMemory : 1;
            DWORD fTeb : 1;
            DWORD fStack : 1;
            DWORD fSpare : 2;
            DWORD HeapNum : 7;
            DWORD fHeap : 1;
            DWORD cwszText : 8;
        };
        DWORD flags;
    };
    DWORD cbPrototypePte;
    ULONG64 vaPrototypePte;
    ULONG64 vaSubsection;
    LPCWSTR wszText;
    DWORD _FutureUse1;
    DWORD _Reserved2;
    ULONG64 vaFileObject;
    DWORD cVadExPages;
    DWORD cVadExPagesBase;
    ULONG64 _Reserved3;
} VMMDLL_MAP_VADENTRY;

typedef BOOL (__cdecl *fn_MapGetVad)(VMM_HANDLE hVMM, DWORD dwPID, PVOID* ppVadMap, DWORD flags);
typedef VOID (__cdecl *fn_MemFree)(PVOID pvMem);

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_Init pInit; static fn_Close pClose; static fn_PidGet pPidGet;
static fn_MemRead pMemRead; static fn_ModBase pModBase;
static fn_MapGetVad pMapGetVad = nullptr;
static fn_MemFree pMemFree = nullptr;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };
static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }
static bool isHeapPtr(uint64_t v, uint64_t modBase, uint64_t modEnd) {
    return isValidPtr(v) && (v < modBase || v > modEnd);
}

// Check if a Vec3 looks like a world position
static bool isWorldPos(Vec3 v) {
    return !isnan(v.x) && !isnan(v.y) && !isnan(v.z) &&
           fabsf(v.x) > 0.5f && fabsf(v.x) < 100000.0f &&
           fabsf(v.y) > 0.5f && fabsf(v.y) < 100000.0f &&
           fabsf(v.z) > 0.1f && fabsf(v.z) < 100000.0f &&
           !(v.x == v.y && v.y == v.z);
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("=== R6 Siege Memory Monitor ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");
    pMapGetVad = (fn_MapGetVad)GetProcAddress(h, "VMMDLL_Map_GetVadU");
    pMemFree = (fn_MemFree)GetProcAddress(h, "VMMDLL_MemFree");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] DMA init failed\n"); return 1; }

    printf("[*] Waiting for RainbowSix.exe...\n");
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    printf("[+] PID=%u\n", g_pid);

    uint64_t base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    printf("[+] Base: 0x%llX\n\n", (unsigned long long)base);

    // Find module end (approximate: base + all sections)
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    uint64_t modEnd = base + nt.OptionalHeader.SizeOfImage;
    printf("[+] Module range: 0x%llX - 0x%llX (%.0f MB)\n\n",
           (unsigned long long)base, (unsigned long long)modEnd,
           (modEnd - base) / 1048576.0);

    // Step 1: Quick liveness check — read a value, wait 2s, read again
    printf("=== DMA Liveness Check ===\n");
    uint64_t testAddr = base + 0x11F0DDF8; // The known global
    uint64_t val1 = rpm<uint64_t>(testAddr);
    Sleep(2000);
    uint64_t val2 = rpm<uint64_t>(testAddr);
    printf("  [0x%llX] t0=0x%llX t1=0x%llX %s\n",
           (unsigned long long)testAddr, (unsigned long long)val1, (unsigned long long)val2,
           val1 == val2 ? "(STATIC)" : "(CHANGED!)");

    // Step 2: Scan .data section for heap pointers that lead to std::vector-like arrays
    printf("\n=== Scanning .data for heap object pointers ===\n");
    printf("  (Looking for global -> heap obj -> array of heap ptrs with count 3+)\n\n");

    // Find .data section
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
    printf("  .data: 0x%llX  size: %.1f MB\n\n",
           (unsigned long long)dataBase, dataSize / 1048576.0);

    if (!dataBase) { printf("[!] .data not found\n"); pClose(g_vmm); return 1; }

    // Scan .data for heap pointers (exclude module-range pointers — those are static)
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK);
    int hits = 0;

    struct EntityListCandidate {
        uint64_t globalAddr;  // address in .data
        uint64_t objAddr;     // heap object
        uint64_t listOff;     // offset within object to the list ptr
        uint64_t listAddr;    // actual list pointer value
        int count;            // entity count
        int heapPtrs;         // how many entries are heap pointers
        int withPos;          // how many have position data
    };
    std::vector<EntityListCandidate> results;

    for (uint64_t off = 0; off < dataSize && hits < 100; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 8 <= readSz && hits < 100; i += 8) {
            uint64_t globalVal = *(uint64_t*)(buf.data() + i);
            if (!isHeapPtr(globalVal, base, modEnd)) continue;

            // This global points to a heap object. Scan its fields.
            // Look for std::vector pattern: {begin, end, capacity} where all 3 are heap ptrs
            // and (end - begin) / 8 gives a count of 3-100
            for (uint64_t foff = 0x0; foff <= 0x400; foff += 0x8) {
                uint64_t vecBegin = rpm<uint64_t>(globalVal + foff);
                uint64_t vecEnd = rpm<uint64_t>(globalVal + foff + 8);
                uint64_t vecCap = rpm<uint64_t>(globalVal + foff + 16);

                if (!isHeapPtr(vecBegin, base, modEnd)) continue;
                if (vecEnd <= vecBegin) continue;
                if (vecCap < vecEnd) continue;

                uint64_t usedBytes = vecEnd - vecBegin;
                if (usedBytes % 8 != 0) continue;
                int count = (int)(usedBytes / 8);
                if (count < 3 || count > 100) continue;

                // Validate: read entries, check how many are heap pointers
                int readN = min(count, 10);
                uint64_t ptrs[10] = {};
                DmaRead(vecBegin, ptrs, readN * 8);

                int heapPtrs = 0;
                for (int k = 0; k < readN; k++)
                    if (isHeapPtr(ptrs[k], base, modEnd)) heapPtrs++;

                if (heapPtrs < 3) continue;

                // Check if any have position-like data
                int withPos = 0;
                for (int k = 0; k < readN && k < 5; k++) {
                    if (!isHeapPtr(ptrs[k], base, modEnd)) continue;
                    // Check multiple offsets for Vec3 position
                    for (uint64_t posOff : {0x20ULL, 0x30ULL, 0x3CULL, 0x40ULL, 0x50ULL, 0x60ULL,
                                            0x80ULL, 0xA0ULL, 0xC0ULL, 0x100ULL, 0x140ULL, 0x180ULL,
                                            0x1C0ULL, 0x200ULL, 0x280ULL, 0x300ULL, 0x400ULL,
                                            0x500ULL, 0x600ULL, 0x6A0ULL, 0x700ULL, 0x780ULL}) {
                        Vec3 v = rpm<Vec3>(ptrs[k] + posOff);
                        if (isWorldPos(v)) { withPos++; break; }
                    }
                    // Also check one level of indirection: entity -> pawn -> position
                    for (uint64_t pawnOff : {0x8ULL, 0x10ULL, 0x18ULL, 0x20ULL, 0x28ULL, 0x30ULL}) {
                        uint64_t pawn = rpm<uint64_t>(ptrs[k] + pawnOff);
                        if (!isHeapPtr(pawn, base, modEnd)) continue;
                        for (uint64_t posOff : {0x3CULL, 0x100ULL, 0x200ULL, 0x400ULL,
                                                0x6A0ULL, 0x700ULL}) {
                            Vec3 v = rpm<Vec3>(pawn + posOff);
                            if (isWorldPos(v)) { withPos++; break; }
                        }
                        if (withPos > 0) break;
                    }
                }

                results.push_back({
                    dataBase + off + i, globalVal, foff, vecBegin,
                    count, heapPtrs, withPos
                });

                if (withPos > 0) {
                    printf("  *** HIT WITH POSITIONS ***\n");
                    printf("      global=.data+0x%llX obj=0x%llX list@+0x%llX cnt=%d heap=%d pos=%d\n",
                           (unsigned long long)(off + i), (unsigned long long)globalVal,
                           (unsigned long long)foff, count, heapPtrs, withPos);

                    // Print detailed entries
                    for (int k = 0; k < min(count, 5); k++) {
                        printf("      [%d] 0x%llX\n", k, (unsigned long long)ptrs[k]);
                        if (!isHeapPtr(ptrs[k], base, modEnd)) continue;

                        // Dump potential positions
                        for (uint64_t posOff : {0x20ULL, 0x3CULL, 0x100ULL, 0x6A0ULL, 0x700ULL}) {
                            Vec3 v = rpm<Vec3>(ptrs[k] + posOff);
                            if (isWorldPos(v))
                                printf("           +0x%llX = (%.1f, %.1f, %.1f)\n",
                                       (unsigned long long)posOff, v.x, v.y, v.z);
                        }
                        // Pawn indirection
                        for (uint64_t pawnOff : {0x20ULL}) {
                            uint64_t pawn = rpm<uint64_t>(ptrs[k] + pawnOff);
                            if (!isHeapPtr(pawn, base, modEnd)) continue;
                            for (uint64_t posOff : {0x3CULL, 0x100ULL, 0x6A0ULL, 0x700ULL}) {
                                Vec3 v = rpm<Vec3>(pawn + posOff);
                                if (isWorldPos(v))
                                    printf("           pawn(+0x%llX)->+0x%llX = (%.1f, %.1f, %.1f)\n",
                                           (unsigned long long)pawnOff,
                                           (unsigned long long)posOff, v.x, v.y, v.z);
                            }
                        }
                    }
                }
                hits++;
            }
        }
    }

    // Summary
    printf("\n=== Summary: %d vector-like arrays found ===\n", (int)results.size());
    int withPos = 0;
    for (auto& r : results) {
        if (r.withPos > 0) withPos++;
    }
    printf("  With position data: %d\n", withPos);

    // Also print top 10 by heap pointer count
    printf("\n--- Top 10 by heap pointer density ---\n");
    std::sort(results.begin(), results.end(), [](auto& a, auto& b) {
        if (a.withPos != b.withPos) return a.withPos > b.withPos;
        return a.heapPtrs > b.heapPtrs;
    });
    for (int i = 0; i < min((int)results.size(), 10); i++) {
        auto& r = results[i];
        printf("  .data+0x%llX => obj=0x%llX list@+0x%llX cnt=%d heap=%d pos=%d\n",
               (unsigned long long)(r.globalAddr - dataBase),
               (unsigned long long)r.objAddr, (unsigned long long)r.listOff,
               r.count, r.heapPtrs, r.withPos);
    }

    printf("\nDone.\n");
    fflush(stdout);
    pClose(g_vmm);
    return 0;
}
