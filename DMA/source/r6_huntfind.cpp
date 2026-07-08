// R6 Hunt Finder — fresh scan + live monitoring for moving entities
// For Terrorist Hunt where bots move, detect live positions
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_huntfind.cpp /Fe"../r6_huntfind.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <map>
#include <algorithm>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_MemRead pMemRead;
static fn_Init pInit;
static fn_Close pClose;
static fn_PidGet pPidGet;
static fn_ModBase pModBase;
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
static bool isWorldPos(float x, float y, float z) {
    return !isnan(x) && !isnan(y) && !isnan(z) &&
           fabsf(x) > 1.0f && fabsf(x) < 50000.0f &&
           fabsf(y) > 1.0f && fabsf(y) < 50000.0f &&
           fabsf(z) > 1.0f && fabsf(z) < 50000.0f;
}

struct WatchEntry {
    uint64_t entAddr;
    uint64_t posOff;
    uint64_t dataOff;
    uint64_t listOff;
    uint64_t vtblRVA;
    Vec3 initial;
    Vec3 last;
    int changes;
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Hunt Entity Finder ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    // Init #1 — get base info
    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] Init failed\n"); return 1; }
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) {
        printf(".");
        Sleep(2000);
    }
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;

    // Reinit for fresh page tables
    pClose(g_vmm); g_vmm = nullptr; Sleep(1500);
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] Reinit failed\n"); return 1; }
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    dos = rpm<IMAGE_DOS_HEADER>(g_base);
    nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX Size=0x%llX\n", g_pid,
           (unsigned long long)g_base, (unsigned long long)(g_modEnd - g_base));

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
    printf("[+] .data: 0x%llX (%.1f MB)\n\n", (unsigned long long)dataBase, dataSize / 1048576.0);

    // ==========================================
    // PHASE 1: Fast entity candidate scan
    // ==========================================
    printf("=== Phase 1: Scanning for entity arrays ===\n");

    // Collect heap pointers from .data
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> dataBuf(CHUNK);
    std::map<uint64_t, uint64_t> objToDataOff;

    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, dataBuf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(dataBuf.data() + i);
            if (isHeapPtr(v) && objToDataOff.find(v) == objToDataOff.end())
                objToDataOff[v] = off + i;
        }
    }
    printf("  %d unique heap objects\n", (int)objToDataOff.size());

    // Scan objects for vectors with same-vtable entries that have positions
    struct Cand {
        uint64_t dataOff, obj, listOff, vtbl, posOff;
        int cnt, vtCnt, posCnt;
        float score;
    };
    std::vector<Cand> cands;
    int scanned = 0;
    const int OBJ_SZ = 0x600;
    uint8_t objBuf[OBJ_SZ];

    for (auto& kv : objToDataOff) {
        uint64_t obj = kv.first;
        scanned++;
        if (scanned % 5000 == 0)
            printf("  %d/%d...\n", scanned, (int)objToDataOff.size());

        memset(objBuf, 0, OBJ_SZ);
        if (!DmaRead(obj, objBuf, OBJ_SZ)) continue;

        for (int fo = 0; fo + 16 <= OBJ_SZ; fo += 8) {
            uint64_t vb = *(uint64_t*)(objBuf + fo);
            uint64_t ve = *(uint64_t*)(objBuf + fo + 8);
            if (!isHeapPtr(vb) || ve <= vb) continue;
            if ((ve - vb) % 8 != 0) continue;
            int cnt = (int)((ve - vb) / 8);
            if (cnt < 3 || cnt > 200) continue;

            int readN = min(cnt, 12);
            uint64_t ptrs[12] = {};
            DmaRead(vb, ptrs, readN * 8);

            int hp = 0;
            std::map<uint64_t, int> vtMap;
            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                hp++;
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (isModPtr(vt)) vtMap[vt]++;
            }
            if (hp < 3) continue;

            uint64_t bestVt = 0; int bestVtN = 0;
            for (auto& v : vtMap) {
                if (v.second > bestVtN) { bestVtN = v.second; bestVt = v.first; }
            }
            if (bestVtN < 3) continue;

            // Bulk-read entries with matching vtable, find position offsets
            const int ENT_SZ = 0xA00;
            uint8_t entBuf[ENT_SZ];
            std::map<uint64_t, int> posMap;

            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (vt != bestVt) continue;
                memset(entBuf, 0, ENT_SZ);
                DmaRead(ptrs[k], entBuf, ENT_SZ);
                for (int po = 0x10; po + 12 <= ENT_SZ; po += 4) {
                    float x = *(float*)(entBuf + po);
                    float y = *(float*)(entBuf + po + 4);
                    float z = *(float*)(entBuf + po + 8);
                    if (isWorldPos(x, y, z)) posMap[po]++;
                }
            }

            uint64_t bestPO = 0; int bestPN = 0;
            for (auto& v : posMap) {
                if (v.second > bestPN) { bestPN = v.second; bestPO = v.first; }
            }

            float sc = (float)bestVtN / readN * (bestPN + 1) * min(cnt, 30);
            if (bestVtN >= 3) {
                cands.push_back({kv.second, obj, (uint64_t)fo, bestVt, bestPO,
                                 cnt, bestVtN, bestPN, sc});
            }
        }
    }

    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) { return a.score > b.score; });
    printf("\n  Found %d candidates. Top 15:\n", (int)cands.size());
    for (int i = 0; i < min((int)cands.size(), 15); i++) {
        auto& c = cands[i];
        printf("  [%2d] .data+0x%06llX obj=0x%llX +0x%03llX cnt=%d vt=%d vtbl=+0x%08llX pos=%d @+0x%04llX sc=%.1f\n",
               i, (unsigned long long)c.dataOff, (unsigned long long)c.obj,
               (unsigned long long)c.listOff, c.cnt, c.vtCnt,
               (unsigned long long)(c.vtbl - g_base),
               c.posCnt, (unsigned long long)c.posOff, c.score);
    }

    // ==========================================
    // PHASE 2: Collect watch targets from top candidates
    // ==========================================
    printf("\n=== Phase 2: Collecting position targets ===\n");
    std::vector<WatchEntry> watches;

    for (int ci = 0; ci < min((int)cands.size(), 10); ci++) {
        auto& c = cands[ci];
        if (c.posOff == 0) continue;

        uint64_t vb = rpm<uint64_t>(c.obj + c.listOff);
        uint64_t ve = rpm<uint64_t>(c.obj + c.listOff + 8);
        int cnt = (ve > vb) ? (int)((ve - vb) / 8) : 0;
        int readN = min(cnt, 20);
        uint64_t ptrs[20] = {};
        DmaRead(vb, ptrs, readN * 8);

        for (int k = 0; k < readN; k++) {
            if (!isHeapPtr(ptrs[k])) continue;
            uint64_t vt = rpm<uint64_t>(ptrs[k]);
            if (vt != c.vtbl) continue;

            Vec3 v = rpm<Vec3>(ptrs[k] + c.posOff);
            if (!isWorldPos(v.x, v.y, v.z)) continue;

            WatchEntry w;
            w.entAddr = ptrs[k];
            w.posOff = c.posOff;
            w.dataOff = c.dataOff;
            w.listOff = c.listOff;
            w.vtblRVA = c.vtbl - g_base;
            w.initial = v;
            w.last = v;
            w.changes = 0;
            watches.push_back(w);
        }
    }

    printf("  %d position targets to monitor\n\n", (int)watches.size());

    // ==========================================
    // PHASE 3: Monitor for 20 seconds
    // ==========================================
    printf("=== Phase 3: Live monitoring (20s) ===\n");
    printf("  Bots should be moving — watching for position changes...\n\n");

    DWORD t0 = GetTickCount();
    int iter = 0;
    while (GetTickCount() - t0 < 20000) {
        Sleep(400);
        iter++;

        for (auto& w : watches) {
            Vec3 v = rpm<Vec3>(w.entAddr + w.posOff);
            if (isnan(v.x) || isnan(v.y) || isnan(v.z)) continue;
            float dx = v.x - w.last.x;
            float dy = v.y - w.last.y;
            float dz = v.z - w.last.z;
            float d = sqrtf(dx*dx + dy*dy + dz*dz);
            if (d > 0.01f) {
                w.changes++;
                if (w.changes <= 3) {
                    printf("  >>> LIVE! vtbl=+0x%08llX 0x%llX+0x%llX: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.2f\n",
                           (unsigned long long)w.vtblRVA,
                           (unsigned long long)w.entAddr, (unsigned long long)w.posOff,
                           w.last.x, w.last.y, w.last.z, v.x, v.y, v.z, d);
                }
                w.last = v;
            }
        }

        if (iter % 12 == 0) {
            int live = 0;
            for (auto& w : watches) if (w.changes > 0) live++;
            printf("  [%ds] %d/%d live\n", (GetTickCount() - t0) / 1000, live, (int)watches.size());
        }
    }

    // Summary
    printf("\n=== RESULTS ===\n");
    int liveCount = 0;
    for (auto& w : watches) {
        if (w.changes > 0) {
            liveCount++;
            float dx = w.last.x - w.initial.x;
            float dy = w.last.y - w.initial.y;
            float dz = w.last.z - w.initial.z;
            printf("  LIVE: vtbl=+0x%08llX .data+0x%06llX+0x%03llX ent=0x%llX+0x%llX changes=%d\n",
                   (unsigned long long)w.vtblRVA,
                   (unsigned long long)w.dataOff, (unsigned long long)w.listOff,
                   (unsigned long long)w.entAddr, (unsigned long long)w.posOff, w.changes);
            printf("        start=(%.2f,%.2f,%.2f) end=(%.2f,%.2f,%.2f) totalDelta=%.2f\n",
                   w.initial.x, w.initial.y, w.initial.z,
                   w.last.x, w.last.y, w.last.z,
                   sqrtf(dx*dx + dy*dy + dz*dz));
        }
    }
    if (liveCount == 0) {
        printf("  No live positions detected.\n");
        printf("  Page table cache may be stale. Try moving your character.\n");
    } else {
        printf("\n  %d LIVE entities found!\n", liveCount);
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
