// R6 Movement Scanner — find objects with actively changing position floats
// Double-snapshot approach: read heap objects, wait, read again, find movers
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_movescan.cpp /Fe"../r6_movescan.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <set>
#include <map>
#include <algorithm>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static fn_MemRead pMemRead; static fn_Init pInit; static fn_Close pClose;
static fn_PidGet pPidGet; static fn_ModBase pModBase;
static VMM_HANDLE g_vmm; static DWORD g_pid;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < g_base || v > g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Movement Scanner ===\n");
    printf("=== Finds objects with actively moving position data ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] VMM init failed\n"); return 1; }
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    // Find .data
    uint64_t dataBase = 0, dataSize = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            dataSize = sec.Misc.VirtualSize;
            break;
        }
    }

    // Collect heap pointers from .data
    const uint32_t CHUNK = 0x40000;
    std::vector<uint8_t> readBuf(CHUNK);
    std::set<uint64_t> heapPtrs;
    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= dataSize) ? CHUNK : dataSize - off);
        if (!DmaRead(dataBase + off, readBuf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(readBuf.data() + i);
            if (isHeapPtr(v)) heapPtrs.insert(v);
        }
    }
    printf("[+] %d heap pointers from .data\n", (int)heapPtrs.size());

    // Also follow one level deep: heap object → sub-pointers
    printf("[+] Following 1-level deep pointers...\n");
    std::set<uint64_t> level2Ptrs;
    int scanned = 0;
    for (uint64_t ptr : heapPtrs) {
        scanned++;
        if (scanned % 20000 == 0) printf("    %d/%d...\n", scanned, (int)heapPtrs.size());

        uint8_t head[0x200];
        if (!DmaRead(ptr, head, sizeof(head))) continue;

        // Only follow objects with vtables (likely game objects)
        uint64_t vt = *(uint64_t*)head;
        if (!isModPtr(vt)) continue;

        for (int off = 8; off + 8 <= 0x200; off += 8) {
            uint64_t v = *(uint64_t*)(head + off);
            if (isHeapPtr(v) && !heapPtrs.count(v)) level2Ptrs.insert(v);
        }
    }
    printf("[+] %d additional level-2 pointers\n", (int)level2Ptrs.size());

    // Merge
    for (uint64_t p : level2Ptrs) heapPtrs.insert(p);
    printf("[+] Total unique pointers: %d\n\n", (int)heapPtrs.size());

    // Snapshot 1: read objects that have world-position-like floats
    printf("--- Snapshot 1 ---\n");
    const int OBJ_SZ = 0x2000;
    struct ObjSnap {
        uint64_t addr;
        uint64_t vtblRVA;
        std::vector<uint8_t> snap1;
        std::vector<uint8_t> snap2;
        bool hasWorldPos;
    };
    std::vector<ObjSnap> objs;

    scanned = 0;
    for (uint64_t ptr : heapPtrs) {
        scanned++;
        if (scanned % 50000 == 0) printf("  %d/%d...\n", scanned, (int)heapPtrs.size());

        // Quick check: read first 0x100 to see if it has a vtable
        uint64_t vt = rpm<uint64_t>(ptr);
        if (!isModPtr(vt)) continue;

        // Read full object
        ObjSnap o;
        o.addr = ptr;
        o.vtblRVA = vt - g_base;
        o.snap1.resize(OBJ_SZ);
        if (!DmaRead(ptr, o.snap1.data(), OBJ_SZ)) continue;

        // Check for world-position floats (reasonable range)
        o.hasWorldPos = false;
        for (int off = 0x10; off + 12 <= OBJ_SZ; off += 4) {
            float x = *(float*)(o.snap1.data() + off);
            float y = *(float*)(o.snap1.data() + off + 4);
            float z = *(float*)(o.snap1.data() + off + 8);
            if (!isnan(x) && !isnan(y) && !isnan(z) &&
                fabsf(x) > 5 && fabsf(x) < 5000 &&
                fabsf(y) > 5 && fabsf(y) < 5000 &&
                z > 0.3f && z < 500) {
                o.hasWorldPos = true;
                break;
            }
        }
        if (o.hasWorldPos) objs.push_back(std::move(o));
    }
    printf("  %d objects with world-position floats\n", (int)objs.size());

    // Wait
    printf("\n--- Waiting 3 seconds (bots should move) ---\n\n");
    Sleep(3000);

    // Snapshot 2
    printf("--- Snapshot 2 ---\n");
    for (auto& o : objs) {
        o.snap2.resize(OBJ_SZ);
        DmaRead(o.addr, o.snap2.data(), OBJ_SZ);
    }

    // Find movers
    printf("\n=== MOVERS (objects with changing position floats) ===\n");
    struct Mover {
        uint64_t addr;
        uint64_t vtblRVA;
        int posOff;
        float x1, y1, z1, x2, y2, z2;
        float dist;
        int totalChanged;
    };
    std::vector<Mover> movers;

    for (auto& o : objs) {
        int changed4 = 0;
        for (int off = 0; off < OBJ_SZ; off += 4) {
            if (*(uint32_t*)(o.snap1.data() + off) != *(uint32_t*)(o.snap2.data() + off))
                changed4++;
        }
        if (changed4 == 0) continue;

        // Find the best position-like changed float triple
        float bestDist = 0;
        int bestOff = -1;
        float bx1=0,by1=0,bz1=0,bx2=0,by2=0,bz2=0;

        for (int off = 0; off + 12 <= OBJ_SZ; off += 4) {
            float x1 = *(float*)(o.snap1.data() + off);
            float y1 = *(float*)(o.snap1.data() + off + 4);
            float z1 = *(float*)(o.snap1.data() + off + 8);
            float x2 = *(float*)(o.snap2.data() + off);
            float y2 = *(float*)(o.snap2.data() + off + 4);
            float z2 = *(float*)(o.snap2.data() + off + 8);

            if (isnan(x1) || isnan(y1) || isnan(z1)) continue;
            if (isnan(x2) || isnan(y2) || isnan(z2)) continue;
            if (fabsf(x1) < 5 || fabsf(x1) > 5000) continue;
            if (fabsf(y1) < 5 || fabsf(y1) > 5000) continue;

            float dx = x2-x1, dy = y2-y1, dz = z2-z1;
            float d = sqrtf(dx*dx + dy*dy + dz*dz);
            if (d > 0.01f && d < 50.0f && d > bestDist) {
                bestDist = d; bestOff = off;
                bx1=x1; by1=y1; bz1=z1; bx2=x2; by2=y2; bz2=z2;
            }
        }

        if (bestOff >= 0) {
            movers.push_back({o.addr, o.vtblRVA, bestOff,
                              bx1, by1, bz1, bx2, by2, bz2, bestDist, changed4});
        }
    }

    // Sort by distance (most movement first)
    std::sort(movers.begin(), movers.end(),
              [](const Mover& a, const Mover& b) { return a.dist > b.dist; });

    printf("  %d objects with moving position floats\n\n", (int)movers.size());

    // Group by vtable
    std::map<uint64_t, int> vtblCounts;
    for (auto& m : movers) vtblCounts[m.vtblRVA]++;

    printf("  By vtable:\n");
    for (auto& kv : vtblCounts) {
        printf("    vtbl=+0x%08llX: %d movers\n", (unsigned long long)kv.first, kv.second);
    }

    // Show top 20 movers
    printf("\n  Top movers:\n");
    for (int i = 0; i < (int)movers.size() && i < 20; i++) {
        auto& m = movers[i];
        printf("    0x%llX vtbl=+0x%08llX +0x%04X: (%.1f,%.1f,%.1f)->(%.1f,%.1f,%.1f) d=%.3f [%d dw changed]\n",
               (unsigned long long)m.addr, (unsigned long long)m.vtblRVA, m.posOff,
               m.x1, m.y1, m.z1, m.x2, m.y2, m.z2, m.dist, m.totalChanged);
    }

    // For the most common vtable type among movers, show ALL position offsets
    if (!vtblCounts.empty()) {
        uint64_t bestVtbl = 0; int bestCnt = 0;
        for (auto& kv : vtblCounts) {
            if (kv.second > bestCnt) { bestCnt = kv.second; bestVtbl = kv.first; }
        }
        printf("\n  Most common mover vtbl=+0x%08llX (%d instances):\n",
               (unsigned long long)bestVtbl, bestCnt);

        for (auto& m : movers) {
            if (m.vtblRVA != bestVtbl) continue;
            // Re-read and show ALL changed position offsets
            auto it = std::find_if(objs.begin(), objs.end(),
                                   [&](const ObjSnap& o) { return o.addr == m.addr; });
            if (it == objs.end()) continue;

            printf("    0x%llX positions:\n", (unsigned long long)m.addr);
            for (int off = 0; off + 12 <= OBJ_SZ; off += 4) {
                float x1 = *(float*)(it->snap1.data() + off);
                float y1 = *(float*)(it->snap1.data() + off + 4);
                float z1 = *(float*)(it->snap1.data() + off + 8);
                float x2 = *(float*)(it->snap2.data() + off);
                float y2 = *(float*)(it->snap2.data() + off + 4);
                float z2 = *(float*)(it->snap2.data() + off + 8);
                if (isnan(x1) || isnan(y1)) continue;
                float dx = x2-x1, dy = y2-y1, dz = z2-z1;
                float d = sqrtf(dx*dx + dy*dy + dz*dz);
                if (d > 0.01f && d < 50.0f && fabsf(x1) > 5 && fabsf(x1) < 5000) {
                    printf("      +0x%04X: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.3f\n",
                           off, x1, y1, z1, x2, y2, z2, d);
                }
            }
        }
    }

    // Try to find what .data global points to these movers
    printf("\n--- Tracing movers back to .data globals ---\n");
    for (int i = 0; i < (int)movers.size() && i < 5; i++) {
        uint64_t target = movers[i].addr;
        printf("  Mover 0x%llX:\n", (unsigned long long)target);

        // Direct reference from .data
        for (uint64_t off = 0; off < dataSize; off += CHUNK) {
            uint32_t readSz = (uint32_t)((off + CHUNK <= dataSize) ? CHUNK : dataSize - off);
            if (!DmaRead(dataBase + off, readBuf.data(), readSz)) continue;
            for (uint32_t j = 0; j + 8 <= readSz; j += 8) {
                uint64_t v = *(uint64_t*)(readBuf.data() + j);
                if (v == target) {
                    printf("    .data+0x%llX directly points here\n", (unsigned long long)(off + j));
                }
            }
        }

        // Indirect: .data → obj → ptr == target
        for (uint64_t ptr : heapPtrs) {
            uint64_t vt = rpm<uint64_t>(ptr);
            if (!isModPtr(vt)) continue;

            uint8_t hd[0x200];
            if (!DmaRead(ptr, hd, sizeof(hd))) continue;
            for (int fo = 0; fo + 8 <= 0x200; fo += 8) {
                uint64_t v = *(uint64_t*)(hd + fo);
                if (v == target) {
                    printf("    .data→0x%llX+0x%02X→here (parent vtbl=+0x%llX)\n",
                           (unsigned long long)ptr, fo, (unsigned long long)(vt - g_base));
                }
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
