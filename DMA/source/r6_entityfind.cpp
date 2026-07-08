// R6 Entity Finder v2 — bulk-read optimized
// One DMA read per object, local parsing for speed
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_entityfind.cpp /Fe"../r6_entityfind.exe" /link

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

struct Candidate {
    uint64_t dataOff;
    uint64_t obj;
    uint64_t listOff;
    int count;
    int sameVtCount;
    uint64_t commonVtbl;
    int positionsAtBestOff;
    uint64_t bestPosOff;
    float score;
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Entity Finder v2 ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] Init failed\n"); return 1; }
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;

    // Close + reinit for fresh page tables
    pClose(g_vmm); g_vmm = nullptr; Sleep(1500);
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] Reinit failed\n"); return 1; }
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    dos = rpm<IMAGE_DOS_HEADER>(g_base);
    nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX\n", g_pid, (unsigned long long)g_base);

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

    printf("=== Phase 1: Collect globals -> heap objects ===\n");

    // Step 1: Read all of .data, collect unique heap pointers
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> dataBuf(CHUNK);
    std::map<uint64_t, uint64_t> globalToObj; // dataOff -> objAddr

    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, dataBuf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(dataBuf.data() + i);
            if (isHeapPtr(v)) globalToObj[off + i] = v;
        }
    }
    printf("  Found %d globals pointing to heap\n", (int)globalToObj.size());

    // Step 2: Deduplicate by object address (many globals can point to same obj)
    std::map<uint64_t, uint64_t> objToFirstGlobal;
    for (auto& kv : globalToObj) {
        if (objToFirstGlobal.find(kv.second) == objToFirstGlobal.end())
            objToFirstGlobal[kv.second] = kv.first;
    }
    printf("  Unique objects: %d\n\n", (int)objToFirstGlobal.size());

    printf("=== Phase 2: Bulk-read objects, find vectors ===\n");

    std::vector<Candidate> candidates;
    int objsScanned = 0;
    const int OBJ_READ_SIZE = 0x600; // read 1.5KB per object in one shot
    uint8_t objBuf[OBJ_READ_SIZE];

    for (auto& kv : objToFirstGlobal) {
        uint64_t obj = kv.first;
        uint64_t dataOff = kv.second;
        objsScanned++;

        if (objsScanned % 2000 == 0)
            printf("  ... scanned %d/%d objects\n", objsScanned, (int)objToFirstGlobal.size());

        // Bulk-read the object
        memset(objBuf, 0, OBJ_READ_SIZE);
        if (!DmaRead(obj, objBuf, OBJ_READ_SIZE)) continue;

        // Scan for vector<ptr> patterns: {begin, end} where both heap and (end-begin)%8==0
        for (int fo = 0; fo + 16 <= OBJ_READ_SIZE; fo += 8) {
            uint64_t vb = *(uint64_t*)(objBuf + fo);
            uint64_t ve = *(uint64_t*)(objBuf + fo + 8);
            if (!isHeapPtr(vb) || ve <= vb) continue;
            uint64_t bytes = ve - vb;
            if (bytes % 8 != 0) continue;
            int cnt = (int)(bytes / 8);
            if (cnt < 5 || cnt > 100) continue;

            // Read vector entries in one bulk read
            int readN = min(cnt, 15);
            uint64_t ptrs[15] = {};
            DmaRead(vb, ptrs, readN * 8);

            // Count heap entries, find vtable distribution
            int hp = 0;
            std::map<uint64_t, int> vtblMap;
            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                hp++;
                uint64_t vt = rpm<uint64_t>(ptrs[k]); // one read per entry for vtable
                if (isModPtr(vt)) vtblMap[vt]++;
            }
            if (hp < readN / 2) continue;

            // Find dominant vtable
            uint64_t bestVt = 0; int bestVtCnt = 0;
            for (auto& v : vtblMap) {
                if (v.second > bestVtCnt) { bestVtCnt = v.second; bestVt = v.first; }
            }
            if (bestVtCnt < 3) continue;

            // For entries with the dominant vtable, bulk-read each and scan for positions
            const int ENT_READ = 0xA00;
            uint8_t entBuf[ENT_READ];
            std::map<uint64_t, int> posOffMap;

            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (vt != bestVt) continue;

                memset(entBuf, 0, ENT_READ);
                DmaRead(ptrs[k], entBuf, ENT_READ); // one bulk read per entity

                for (int po = 0x10; po + 12 <= ENT_READ; po += 4) {
                    float x = *(float*)(entBuf + po);
                    float y = *(float*)(entBuf + po + 4);
                    float z = *(float*)(entBuf + po + 8);
                    if (isWorldPos(x, y, z)) posOffMap[po]++;
                }
            }

            uint64_t bestPosOff = 0; int bestPosCnt = 0;
            for (auto& v : posOffMap) {
                if (v.second > bestPosCnt) { bestPosCnt = v.second; bestPosOff = v.first; }
            }

            float score = (float)bestVtCnt / readN * (bestPosCnt + 1) * min(cnt, 30);

            Candidate c;
            c.dataOff = dataOff;
            c.obj = obj;
            c.listOff = fo;
            c.count = cnt;
            c.sameVtCount = bestVtCnt;
            c.commonVtbl = bestVt;
            c.positionsAtBestOff = bestPosCnt;
            c.bestPosOff = bestPosOff;
            c.score = score;
            candidates.push_back(c);
        }
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

    printf("\nFound %d candidates. Top 25:\n\n", (int)candidates.size());
    int shown = 0;
    for (auto& c : candidates) {
        if (shown >= 25) break;
        printf("  [%2d] .data+0x%06llX obj=0x%llX +0x%03llX cnt=%2d vt=%2d/%2d vtbl=+0x%08llX pos=%d @+0x%04llX sc=%.1f\n",
               shown, (unsigned long long)c.dataOff, (unsigned long long)c.obj,
               (unsigned long long)c.listOff, c.count, c.sameVtCount, min(c.count,15),
               (unsigned long long)(c.commonVtbl - g_base),
               c.positionsAtBestOff, (unsigned long long)c.bestPosOff, c.score);
        shown++;
    }

    // Phase 3: Deep probe top 5
    printf("\n=== Phase 3: Deep probe ===\n");
    for (int ci = 0; ci < min((int)candidates.size(), 5); ci++) {
        auto& c = candidates[ci];
        printf("\n--- #%d: .data+0x%llX obj=0x%llX +0x%llX cnt=%d vtbl=+0x%llX posOff=+0x%llX ---\n",
               ci, (unsigned long long)c.dataOff, (unsigned long long)c.obj,
               (unsigned long long)c.listOff, c.count,
               (unsigned long long)(c.commonVtbl - g_base),
               (unsigned long long)c.bestPosOff);

        uint64_t vb = rpm<uint64_t>(c.obj + c.listOff);
        int readN = min(c.count, 15);
        uint64_t ptrs[15] = {};
        DmaRead(vb, ptrs, readN * 8);

        int eidx = 0;
        for (int k = 0; k < readN; k++) {
            if (!isHeapPtr(ptrs[k])) continue;
            uint64_t vt = rpm<uint64_t>(ptrs[k]);
            if (vt != c.commonVtbl) continue;

            printf("  e[%d] 0x%llX", eidx, (unsigned long long)ptrs[k]);

            // Read position at best offset
            if (c.bestPosOff > 0) {
                Vec3 v = rpm<Vec3>(ptrs[k] + c.bestPosOff);
                printf("  pos@+0x%llX=(%.2f, %.2f, %.2f)",
                       (unsigned long long)c.bestPosOff, v.x, v.y, v.z);
            }

            // Scan for ALL distinct positions in this entity
            const int ENT_READ = 0xA00;
            uint8_t entBuf[ENT_READ];
            DmaRead(ptrs[k], entBuf, ENT_READ);
            printf("\n");

            int posN = 0;
            for (int po = 0x10; po + 12 <= ENT_READ; po += 4) {
                float x = *(float*)(entBuf + po);
                float y = *(float*)(entBuf + po + 4);
                float z = *(float*)(entBuf + po + 8);
                if (isWorldPos(x, y, z)) {
                    printf("    +0x%04X = (%.2f, %.2f, %.2f)\n", po, x, y, z);
                    posN++;
                    po += 8; // skip overlapping hits
                    if (posN >= 5) break;
                }
            }

            eidx++;
            if (eidx >= 8) break;
        }

        // Stability check on best position offset
        if (c.bestPosOff > 0 && c.positionsAtBestOff >= 2) {
            printf("\n  Stability check (1s apart) at +0x%llX:\n", (unsigned long long)c.bestPosOff);
            for (int k = 0; k < min(readN, 5); k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (vt != c.commonVtbl) continue;
                Vec3 v1 = rpm<Vec3>(ptrs[k] + c.bestPosOff);
                Sleep(500);
                Vec3 v2 = rpm<Vec3>(ptrs[k] + c.bestPosOff);
                printf("    (%.2f,%.2f,%.2f) -> (%.2f,%.2f,%.2f) %s\n",
                       v1.x, v1.y, v1.z, v2.x, v2.y, v2.z,
                       (v1.x==v2.x && v1.y==v2.y && v1.z==v2.z) ? "STABLE" : "CHANGED");
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
