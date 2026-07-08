// R6 Snapshot Diff — two complete reinits, compare ALL candidate positions
// Bypasses ALL caching by fully closing/reopening VMM between reads
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_snapshot.cpp /Fe"../r6_snapshot.exe" /link

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

static fn_MemRead pMemRead;
static fn_Init pInit;
static fn_Close pClose;
static fn_PidGet pPidGet;
static fn_ModBase pModBase;

struct Vec3 { float x, y, z; };

struct Session {
    VMM_HANDLE vmm;
    DWORD pid;
    uint64_t base, modEnd, dataBase, dataSize;
};

static bool DmaRead(Session& s, uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(s.vmm, s.pid, va, (PBYTE)buf, size, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(Session& s, uint64_t a) { T v{}; DmaRead(s, a, &v, sizeof(T)); return v; }

static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }

Session openSession() {
    Session s = {};
    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    s.vmm = pInit(6, args);
    if (!s.vmm) return s;
    pPidGet(s.vmm, "RainbowSix.exe", &s.pid);
    s.base = pModBase(s.vmm, s.pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(s, s.base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(s, s.base + dos.e_lfanew);
    s.modEnd = s.base + nt.OptionalHeader.SizeOfImage;
    uint64_t secAddr = s.base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(s, secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            s.dataBase = s.base + sec.VirtualAddress;
            s.dataSize = sec.Misc.VirtualSize;
            break;
        }
    }
    return s;
}

struct PosTarget {
    uint64_t dataOff;
    uint64_t objAddr;
    uint64_t listOff;
    uint64_t entAddr;
    uint64_t posOff;
    uint64_t vtblRVA;
    Vec3 snap1, snap2;
    float delta;
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Snapshot Diff ===\n");
    printf("=== Takes two snapshots 5s apart with full VMM reinit ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    // ========== SNAPSHOT 1 ==========
    printf("--- SNAPSHOT 1 ---\n");
    Session s1 = openSession();
    if (!s1.vmm) { printf("[!] Init failed\n"); return 1; }
    printf("[+] PID=%u Base=0x%llX .data=0x%llX (%.1f MB)\n",
           s1.pid, (unsigned long long)s1.base,
           (unsigned long long)s1.dataBase, s1.dataSize / 1048576.0);

    // Collect heap pointers from .data
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> dataBuf(CHUNK);
    std::map<uint64_t, uint64_t> objToDataOff;

    for (uint64_t off = 0; off < s1.dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, s1.dataSize - off);
        if (!DmaRead(s1, s1.dataBase + off, dataBuf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(dataBuf.data() + i);
            if (isValidPtr(v) && (v < s1.base || v > s1.modEnd))
                if (objToDataOff.find(v) == objToDataOff.end())
                    objToDataOff[v] = off + i;
        }
    }
    printf("  %d unique heap objects\n", (int)objToDataOff.size());

    // Scan for entity vector candidates + read positions (SNAPSHOT 1)
    std::vector<PosTarget> targets;
    int scanned = 0;
    const int OBJ_SZ = 0x600;
    uint8_t objBuf[OBJ_SZ];

    for (auto& kv : objToDataOff) {
        uint64_t obj = kv.first;
        scanned++;
        if (scanned % 10000 == 0)
            printf("  %d/%d...\n", scanned, (int)objToDataOff.size());

        memset(objBuf, 0, OBJ_SZ);
        if (!DmaRead(s1, obj, objBuf, OBJ_SZ)) continue;

        for (int fo = 0; fo + 16 <= OBJ_SZ; fo += 8) {
            uint64_t vb = *(uint64_t*)(objBuf + fo);
            uint64_t ve = *(uint64_t*)(objBuf + fo + 8);
            if (!isValidPtr(vb) || (vb >= s1.base && vb < s1.modEnd)) continue;
            if (ve <= vb || (ve - vb) % 8 != 0) continue;
            int cnt = (int)((ve - vb) / 8);
            if (cnt < 3 || cnt > 200) continue;

            int readN = min(cnt, 8);
            uint64_t ptrs[8] = {};
            DmaRead(s1, vb, ptrs, readN * 8);

            int hp = 0;
            std::map<uint64_t, int> vtMap;
            for (int k = 0; k < readN; k++) {
                if (!isValidPtr(ptrs[k]) || (ptrs[k] >= s1.base && ptrs[k] < s1.modEnd)) continue;
                hp++;
                uint64_t vt = rpm<uint64_t>(s1, ptrs[k]);
                if (vt >= s1.base && vt < s1.modEnd) vtMap[vt]++;
            }
            if (hp < 3) continue;
            uint64_t bestVt = 0; int bestVtN = 0;
            for (auto& v : vtMap) {
                if (v.second > bestVtN) { bestVtN = v.second; bestVt = v.first; }
            }
            if (bestVtN < 3) continue;

            // Read entities and find positions
            const int ENT_SZ = 0xA00;
            uint8_t entBuf[ENT_SZ];
            for (int k = 0; k < readN; k++) {
                if (!isValidPtr(ptrs[k]) || (ptrs[k] >= s1.base && ptrs[k] < s1.modEnd)) continue;
                uint64_t vt = rpm<uint64_t>(s1, ptrs[k]);
                if (vt != bestVt) continue;
                memset(entBuf, 0, ENT_SZ);
                DmaRead(s1, ptrs[k], entBuf, ENT_SZ);

                for (int po = 0x10; po + 12 <= ENT_SZ; po += 4) {
                    float x = *(float*)(entBuf + po);
                    float y = *(float*)(entBuf + po + 4);
                    float z = *(float*)(entBuf + po + 8);
                    if (!isnan(x) && !isnan(y) && !isnan(z) &&
                        fabsf(x) > 1.0f && fabsf(x) < 50000.0f &&
                        fabsf(y) > 1.0f && fabsf(y) < 50000.0f &&
                        fabsf(z) > 1.0f && fabsf(z) < 50000.0f) {
                        PosTarget t;
                        t.dataOff = kv.second;
                        t.objAddr = obj;
                        t.listOff = fo;
                        t.entAddr = ptrs[k];
                        t.posOff = po;
                        t.vtblRVA = bestVt - s1.base;
                        t.snap1 = {x, y, z};
                        t.snap2 = {0, 0, 0};
                        t.delta = 0;
                        targets.push_back(t);
                        po += 8;
                    }
                }
            }
        }
    }

    printf("  Snapshot 1: %d position targets captured\n", (int)targets.size());
    pClose(s1.vmm);
    s1.vmm = nullptr;

    // ========== WAIT ==========
    printf("\n--- Waiting 5 seconds (bots should move) ---\n");
    Sleep(5000);

    // ========== SNAPSHOT 2 ==========
    printf("\n--- SNAPSHOT 2 ---\n");
    Session s2 = openSession();
    if (!s2.vmm) { printf("[!] Reinit failed\n"); return 1; }
    printf("[+] PID=%u Base=0x%llX\n", s2.pid, (unsigned long long)s2.base);

    if (s2.base != s1.base) {
        printf("[!] Base address changed! 0x%llX -> 0x%llX\n",
               (unsigned long long)s1.base, (unsigned long long)s2.base);
        printf("    Process may have restarted. Aborting.\n");
        pClose(s2.vmm);
        return 1;
    }

    int readOk = 0, changed = 0;
    for (auto& t : targets) {
        Vec3 v = rpm<Vec3>(s2, t.entAddr + t.posOff);
        if (isnan(v.x) || isnan(v.y) || isnan(v.z)) continue;
        readOk++;
        t.snap2 = v;
        float dx = v.x - t.snap1.x;
        float dy = v.y - t.snap1.y;
        float dz = v.z - t.snap1.z;
        t.delta = sqrtf(dx*dx + dy*dy + dz*dz);
        if (t.delta > 0.01f) changed++;
    }
    printf("  Read %d/%d targets, %d CHANGED\n", readOk, (int)targets.size(), changed);

    // Sort by delta descending
    std::sort(targets.begin(), targets.end(),
              [](const PosTarget& a, const PosTarget& b) { return a.delta > b.delta; });

    printf("\n=== RESULTS ===\n");
    if (changed == 0) {
        printf("  No positions changed between snapshots.\n");
        printf("  Possible causes:\n");
        printf("    - Page tables mapping to stale physical addresses\n");
        printf("    - We're reading static data (waypoints/spawn points)\n");
        printf("    - Need to check deeper pointer chains\n");

        // Show a sample of what we read to verify reads work
        printf("\n  Sample positions (first 10):\n");
        for (int i = 0; i < min(10, (int)targets.size()); i++) {
            auto& t = targets[i];
            printf("    ent=0x%llX+0x%04llX vtbl=+0x%08llX snap1=(%.2f,%.2f,%.2f) snap2=(%.2f,%.2f,%.2f)\n",
                   (unsigned long long)t.entAddr, (unsigned long long)t.posOff,
                   (unsigned long long)t.vtblRVA,
                   t.snap1.x, t.snap1.y, t.snap1.z,
                   t.snap2.x, t.snap2.y, t.snap2.z);
        }
    } else {
        printf("  %d LIVE positions found!\n\n", changed);
        int shown = 0;
        for (auto& t : targets) {
            if (t.delta < 0.01f) break;
            shown++;
            printf("  [%d] vtbl=+0x%08llX .data+0x%06llX ent=0x%llX+0x%04llX delta=%.2f\n",
                   shown, (unsigned long long)t.vtblRVA,
                   (unsigned long long)t.dataOff,
                   (unsigned long long)t.entAddr, (unsigned long long)t.posOff, t.delta);
            printf("       snap1=(%.2f,%.2f,%.2f) snap2=(%.2f,%.2f,%.2f)\n",
                   t.snap1.x, t.snap1.y, t.snap1.z,
                   t.snap2.x, t.snap2.y, t.snap2.z);
            if (shown >= 30) break;
        }
    }

    printf("\nDone.\n");
    pClose(s2.vmm);
    return 0;
}
