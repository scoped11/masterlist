// R6 Entity Diff — directly read confirmed live entity + all from its list
// Triple snapshot with full reinit, byte-level diff
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_entdiff.cpp /Fe"../r6_entdiff.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <map>
#include <set>
#include <algorithm>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static fn_MemRead pMemRead;
static fn_Init pInit;
static fn_Close pClose;
static fn_PidGet pPidGet;
static fn_ModBase pModBase;

static VMM_HANDLE g_vmm;
static DWORD g_pid;
static uint64_t g_base, g_modEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
static bool isHeapPtr(uint64_t v) {
    return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < g_base || v > g_modEnd);
}
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }

void doInit() {
    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) return;
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
}

const int ENT_SIZE = 0x1000;

struct EntSnap {
    uint64_t addr;
    uint64_t vtbl;
    uint8_t data[3][ENT_SIZE];
    bool readOk[3];
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Entity Diff (Triple Snapshot) ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    const uint64_t DATA_OFF = 0x86A470;
    const uint64_t CONFIRMED_VTBL_RVA = 0x1192C9E0;

    // SNAPSHOT 1 — discover entities
    printf("--- SNAPSHOT 1 ---\n");
    doInit();
    if (!g_vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n", g_pid, (unsigned long long)g_base);

    // Find .data
    uint64_t dataBase = 0, dataSize = 0;
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            dataSize = sec.Misc.VirtualSize;
            break;
        }
    }

    // Read root object pointer
    uint64_t rootPtr = rpm<uint64_t>(dataBase + DATA_OFF);
    printf("[+] .data+0x%llX = 0x%llX\n",
           (unsigned long long)DATA_OFF, (unsigned long long)rootPtr);

    // Scan root object for ALL vectors, collect ALL entity pointers
    std::vector<EntSnap> ents;
    std::set<uint64_t> seenAddrs;

    if (isHeapPtr(rootPtr)) {
        uint8_t rootBuf[0x800];
        DmaRead(rootPtr, rootBuf, sizeof(rootBuf));

        for (int fo = 0; fo + 16 <= 0x800; fo += 8) {
            uint64_t vb = *(uint64_t*)(rootBuf + fo);
            uint64_t ve = *(uint64_t*)(rootBuf + fo + 8);
            if (!isHeapPtr(vb) || ve <= vb || (ve - vb) % 8 != 0) continue;
            int cnt = (int)((ve - vb) / 8);
            if (cnt < 2 || cnt > 500) continue;

            int readN = min(cnt, 200);
            std::vector<uint64_t> ptrs(readN);
            DmaRead(vb, ptrs.data(), readN * 8);

            int hp = 0;
            for (int k = 0; k < readN; k++) {
                if (isHeapPtr(ptrs[k])) hp++;
            }
            if (hp < 3) continue;

            printf("  Root+0x%03X: vec(%d entries, %d heap)\n", fo, cnt, hp);

            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                if (seenAddrs.count(ptrs[k])) continue;
                seenAddrs.insert(ptrs[k]);

                EntSnap e = {};
                e.addr = ptrs[k];
                e.vtbl = rpm<uint64_t>(ptrs[k]);
                DmaRead(ptrs[k], e.data[0], ENT_SIZE);
                e.readOk[0] = true;
                ents.push_back(e);
            }
        }
    }

    // Also try to reach entities through other .data pointers
    // Scan nearby .data offsets for objects that might contain entity vectors
    printf("\n  Scanning more .data pointers around 0x86A000...\n");
    uint8_t dataBuf[0x2000];
    DmaRead(dataBase + 0x86A000, dataBuf, sizeof(dataBuf));
    for (int di = 0; di + 8 <= 0x2000; di += 8) {
        uint64_t ptr = *(uint64_t*)(dataBuf + di);
        if (!isHeapPtr(ptr)) continue;

        uint8_t objBuf[0x800];
        if (!DmaRead(ptr, objBuf, sizeof(objBuf))) continue;

        for (int fo = 0; fo + 16 <= 0x800; fo += 8) {
            uint64_t vb = *(uint64_t*)(objBuf + fo);
            uint64_t ve = *(uint64_t*)(objBuf + fo + 8);
            if (!isHeapPtr(vb) || ve <= vb || (ve - vb) % 8 != 0) continue;
            int cnt = (int)((ve - vb) / 8);
            if (cnt < 5 || cnt > 500) continue;

            int readN = min(cnt, 10);
            uint64_t ptrs[10] = {};
            DmaRead(vb, ptrs, readN * 8);

            int hp = 0, mvt = 0;
            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                hp++;
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (isModPtr(vt) && (vt - g_base) == CONFIRMED_VTBL_RVA) mvt++;
            }
            if (mvt >= 3) {
                printf("  .data+0x%06X obj=0x%llX +0x%03X: vec(%d) %d matching vtbl!\n",
                       0x86A000 + di, (unsigned long long)ptr, fo, cnt, mvt);
                // Add these entities too
                readN = min(cnt, 200);
                std::vector<uint64_t> allPtrs(readN);
                DmaRead(vb, allPtrs.data(), readN * 8);
                for (int k = 0; k < readN; k++) {
                    if (!isHeapPtr(allPtrs[k]) || seenAddrs.count(allPtrs[k])) continue;
                    seenAddrs.insert(allPtrs[k]);
                    EntSnap e = {};
                    e.addr = allPtrs[k];
                    e.vtbl = rpm<uint64_t>(allPtrs[k]);
                    DmaRead(allPtrs[k], e.data[0], ENT_SIZE);
                    e.readOk[0] = true;
                    ents.push_back(e);
                }
            }
        }
    }

    printf("\n  Total entities captured: %d\n", (int)ents.size());

    // Count by vtable
    std::map<uint64_t, int> vtCounts;
    for (auto& e : ents) {
        if (isModPtr(e.vtbl)) vtCounts[e.vtbl - g_base]++;
    }
    printf("  Vtable distribution:\n");
    for (auto& kv : vtCounts) {
        printf("    +0x%08llX: %d entities%s\n",
               (unsigned long long)kv.first, kv.second,
               kv.first == CONFIRMED_VTBL_RVA ? " <-- CONFIRMED" : "");
    }

    pClose(g_vmm); g_vmm = nullptr;

    // SNAPSHOT 2
    printf("\n--- Waiting 4 seconds ---\n");
    Sleep(4000);
    printf("--- SNAPSHOT 2 ---\n");
    doInit();
    if (!g_vmm) return 1;
    for (auto& e : ents) {
        memset(e.data[1], 0, ENT_SIZE);
        e.readOk[1] = DmaRead(e.addr, e.data[1], ENT_SIZE);
    }
    pClose(g_vmm); g_vmm = nullptr;

    // SNAPSHOT 3
    printf("--- Waiting 4 seconds ---\n");
    Sleep(4000);
    printf("--- SNAPSHOT 3 ---\n");
    doInit();
    if (!g_vmm) return 1;
    for (auto& e : ents) {
        memset(e.data[2], 0, ENT_SIZE);
        e.readOk[2] = DmaRead(e.addr, e.data[2], ENT_SIZE);
    }

    // ANALYSIS
    printf("\n=== ANALYSIS ===\n");

    // For entities with matching vtable, find offsets where float values change
    printf("\n--- Float diffs on CONFIRMED vtable entities ---\n");
    std::map<int, int> floatDiffMap12, floatDiffMap23;
    int confirmedCount = 0;

    for (auto& e : ents) {
        if (!e.readOk[0] || !e.readOk[1] || !e.readOk[2]) continue;
        if (!isModPtr(e.vtbl) || (e.vtbl - g_base) != CONFIRMED_VTBL_RVA) continue;
        confirmedCount++;

        for (int off = 0; off + 4 <= ENT_SIZE; off += 4) {
            float f1 = *(float*)(e.data[0] + off);
            float f2 = *(float*)(e.data[1] + off);
            float f3 = *(float*)(e.data[2] + off);
            if (isnan(f1) || isnan(f2) || isnan(f3)) continue;
            if (f1 != f2) floatDiffMap12[off]++;
            if (f2 != f3) floatDiffMap23[off]++;
        }
    }

    printf("  %d entities with confirmed vtable\n", confirmedCount);
    printf("  Offsets with float changes (snap1→2, 1+ entities):\n");
    for (auto& kv : floatDiffMap12) {
        if (kv.second >= 1) {
            int n23 = floatDiffMap23.count(kv.first) ? floatDiffMap23[kv.first] : 0;
            printf("    +0x%04X: %d s1->s2, %d s2->s3", kv.first, kv.second, n23);
            // Show a sample
            for (auto& e : ents) {
                if (!e.readOk[0] || !isModPtr(e.vtbl) || (e.vtbl - g_base) != CONFIRMED_VTBL_RVA) continue;
                float f1 = *(float*)(e.data[0] + kv.first);
                float f2 = *(float*)(e.data[1] + kv.first);
                float f3 = *(float*)(e.data[2] + kv.first);
                if (f1 != f2 || f2 != f3) {
                    printf(" [%.2f->%.2f->%.2f]", f1, f2, f3);
                    break;
                }
            }
            printf("\n");
        }
    }

    // Also check ALL entities for byte-level changes
    printf("\n--- Entity movement summary (all vtables) ---\n");
    int movedCount = 0;
    for (auto& e : ents) {
        if (!e.readOk[0] || !e.readOk[1] || !e.readOk[2]) continue;
        int diff12 = 0, diff23 = 0;
        for (int off = 0; off < ENT_SIZE; off += 4) {
            if (*(uint32_t*)(e.data[0]+off) != *(uint32_t*)(e.data[1]+off)) diff12++;
            if (*(uint32_t*)(e.data[1]+off) != *(uint32_t*)(e.data[2]+off)) diff23++;
        }
        if (diff12 > 0 || diff23 > 0) {
            movedCount++;
            if (movedCount <= 20) {
                printf("  ent=0x%llX vtbl=+0x%08llX diffs: s1-2=%d s2-3=%d\n",
                       (unsigned long long)e.addr,
                       (unsigned long long)(isModPtr(e.vtbl) ? e.vtbl - g_base : 0),
                       diff12, diff23);
                // Check position at +0x08B0
                float x1 = *(float*)(e.data[0] + 0x8B0);
                float y1 = *(float*)(e.data[0] + 0x8B4);
                float z1 = *(float*)(e.data[0] + 0x8B8);
                float x2 = *(float*)(e.data[1] + 0x8B0);
                float y2 = *(float*)(e.data[1] + 0x8B4);
                float z2 = *(float*)(e.data[1] + 0x8B8);
                float x3 = *(float*)(e.data[2] + 0x8B0);
                float y3 = *(float*)(e.data[2] + 0x8B4);
                float z3 = *(float*)(e.data[2] + 0x8B8);
                printf("    +0x8B0: (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f)\n",
                       x1, y1, z1, x2, y2, z2, x3, y3, z3);
            }
        }
    }
    printf("  Total entities with changes: %d / %d\n", movedCount, (int)ents.size());

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
