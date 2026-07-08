// R6 Position Map — dump all positions from top entity candidates
// to identify which is the real entity list
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_posmap.cpp /Fe"../r6_posmap.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
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

void dumpVector(uint64_t obj, uint64_t listOff, uint64_t posOff, uint64_t vtblRVA, const char* label) {
    printf("\n=== %s ===\n", label);
    printf("  obj=0x%llX +0x%llX posOff=+0x%llX vtbl=+0x%llX\n",
           (unsigned long long)obj, (unsigned long long)listOff,
           (unsigned long long)posOff, (unsigned long long)vtblRVA);

    uint64_t vb = rpm<uint64_t>(obj + listOff);
    uint64_t ve = rpm<uint64_t>(obj + listOff + 8);
    if (!isHeapPtr(vb) || ve <= vb) { printf("  [!] Invalid vector\n"); return; }
    int cnt = (int)((ve - vb) / 8);
    printf("  Vector cnt=%d\n\n", cnt);

    int readN = (cnt > 50) ? 50 : cnt;
    std::vector<uint64_t> ptrs(readN);
    DmaRead(vb, ptrs.data(), readN * 8);

    struct PosEntry { int idx; float x, y, z; uint64_t addr; };
    std::vector<PosEntry> positions;
    int nulls = 0, nonHeap = 0, wrongVt = 0;

    for (int i = 0; i < readN; i++) {
        if (ptrs[i] == 0) { nulls++; continue; }
        if (!isHeapPtr(ptrs[i])) { nonHeap++; continue; }

        uint64_t vt = rpm<uint64_t>(ptrs[i]);
        if (vtblRVA != 0 && isModPtr(vt) && (vt - g_base) != vtblRVA) {
            wrongVt++;
            continue;
        }

        Vec3 v = rpm<Vec3>(ptrs[i] + posOff);
        if (!isnan(v.x) && !isnan(v.y) && !isnan(v.z) &&
            (fabsf(v.x) > 0.01f || fabsf(v.y) > 0.01f || fabsf(v.z) > 0.01f)) {
            positions.push_back({i, v.x, v.y, v.z, ptrs[i]});
        }
    }

    printf("  Stats: %d null, %d non-heap, %d wrong-vt, %d with position data\n\n",
           nulls, nonHeap, wrongVt, (int)positions.size());

    // Dump all positions
    for (auto& p : positions) {
        printf("  [%3d] 0x%llX  pos=(%.2f, %.2f, %.2f)\n",
               p.idx, (unsigned long long)p.addr, p.x, p.y, p.z);
    }

    // Statistics on positions
    if (positions.size() >= 3) {
        float minX = 1e9, maxX = -1e9, minY = 1e9, maxY = -1e9, minZ = 1e9, maxZ = -1e9;
        for (auto& p : positions) {
            if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
            if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
            if (p.z < minZ) minZ = p.z; if (p.z > maxZ) maxZ = p.z;
        }
        printf("\n  Range: X[%.1f..%.1f] Y[%.1f..%.1f] Z[%.1f..%.1f]\n",
               minX, maxX, minY, maxY, minZ, maxZ);
        printf("  Spread: X=%.1f Y=%.1f Z=%.1f\n",
               maxX - minX, maxY - minY, maxZ - minZ);

        // Count unique positions
        int unique = 0;
        for (int i = 0; i < (int)positions.size(); i++) {
            bool dup = false;
            for (int j = 0; j < i; j++) {
                if (fabsf(positions[i].x - positions[j].x) < 0.1f &&
                    fabsf(positions[i].y - positions[j].y) < 0.1f &&
                    fabsf(positions[i].z - positions[j].z) < 0.1f) {
                    dup = true; break;
                }
            }
            if (!dup) unique++;
        }
        printf("  Unique positions: %d / %d\n", unique, (int)positions.size());
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Position Map ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) return 1;
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) Sleep(2000);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;

    pClose(g_vmm); g_vmm = nullptr; Sleep(1500);
    g_vmm = pInit(6, args);
    if (!g_vmm) return 1;
    pPidGet(g_vmm, "RainbowSix.exe", &g_pid);
    g_base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    dos = rpm<IMAGE_DOS_HEADER>(g_base);
    nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
    g_modEnd = g_base + nt.OptionalHeader.SizeOfImage;
    printf("[+] PID=%u Base=0x%llX\n", g_pid, (unsigned long long)g_base);

    uint64_t dataBase = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            break;
        }
    }
    printf("[+] .data=0x%llX\n\n", (unsigned long long)dataBase);

    // Read globals for the known candidates
    uint64_t obj_444BC8 = rpm<uint64_t>(dataBase + 0x444BC8);
    uint64_t obj_13D7AC0 = rpm<uint64_t>(dataBase + 0x13D7AC0);
    uint64_t obj_23E1B8 = rpm<uint64_t>(dataBase + 0x23E1B8);
    uint64_t obj_489FA0 = rpm<uint64_t>(dataBase + 0x489FA0);

    // Candidate #0: .data+0x13D7AC0 +0x218 cnt=25 vtbl=+0x111B6440 pos@+0x370
    dumpVector(obj_13D7AC0, 0x218, 0x370, 0x111B6440, "Cand#0: UI/Layout? +0x218 pos@+0x370");

    // Candidate #1: .data+0x444BC8 +0x98 cnt=84 vtbl=+0x111F6840 pos@+0x50
    dumpVector(obj_444BC8, 0x98, 0x50, 0x111F6840, "Cand#1: +0x98 pos@+0x50");

    // Candidate #4: .data+0x444BC8 +0x108 cnt=36 vtbl=+0x111F6840 pos@+0x50
    dumpVector(obj_444BC8, 0x108, 0x50, 0x111F6840, "Cand#4: +0x108 pos@+0x50");

    // Candidate #16: .data+0x23E1B8 +0x350 cnt=12 vtbl=+0x112D6BB0 pos@+0x9E8
    dumpVector(obj_23E1B8, 0x350, 0x9E8, 0x112D6BB0, "Cand#16: +0x350 pos@+0x9E8");

    // Candidate #13: .data+0x489FA0 +0x50 cnt=32 vtbl=+0x1124B260 pos@+0x908
    dumpVector(obj_489FA0, 0x50, 0x908, 0x1124B260, "Cand#13: +0x50 pos@+0x908");

    // Also try candidate #0 through the sub-object chain
    // Entity+0x150 → vtbl=+0x111BD548, follow sub for positions
    printf("\n\n=== Cand#0 entities through +0x150 sub-object chain ===\n");
    if (isHeapPtr(obj_13D7AC0)) {
        uint64_t vb = rpm<uint64_t>(obj_13D7AC0 + 0x218);
        uint64_t ve = rpm<uint64_t>(obj_13D7AC0 + 0x220);
        int cnt = (ve > vb) ? (int)((ve - vb) / 8) : 0;
        int rn = (cnt > 15) ? 15 : cnt;
        uint64_t ptrs[15] = {};
        DmaRead(vb, ptrs, rn * 8);

        for (int i = 0; i < rn; i++) {
            if (!isHeapPtr(ptrs[i])) continue;
            uint64_t vt = rpm<uint64_t>(ptrs[i]);
            if (!isModPtr(vt) || (vt - g_base) != 0x111B6440) continue;

            // Get sub-object at +0x150
            uint64_t sub150 = rpm<uint64_t>(ptrs[i] + 0x150);
            if (!isHeapPtr(sub150)) continue;

            // Read sub-object bulk
            uint8_t subBuf[0xA00];
            DmaRead(sub150, subBuf, sizeof(subBuf));

            // Look for world positions (larger range)
            printf("  e[%d] sub@+0x150=0x%llX", i, (unsigned long long)sub150);
            int found = 0;
            for (int so = 0x10; so + 12 <= 0xA00; so += 4) {
                float x = *(float*)(subBuf + so);
                float y = *(float*)(subBuf + so + 4);
                float z = *(float*)(subBuf + so + 8);
                if (!isnan(x) && !isnan(y) && !isnan(z) &&
                    fabsf(x) > 5 && fabsf(x) < 50000 &&
                    fabsf(y) > 5 && fabsf(y) < 50000 &&
                    fabsf(z) > 5 && fabsf(z) < 50000) {
                    if (found == 0) printf("\n");
                    printf("    +0x%04X = (%.2f, %.2f, %.2f)\n", so, x, y, z);
                    found++;
                    so += 8;
                    if (found >= 4) break;
                }
            }

            // Also follow heap ptrs at +0x0 through +0x100 inside sub for deeper positions
            for (int po = 0; po < 0x100 && found < 6; po += 8) {
                uint64_t sub2 = *(uint64_t*)(subBuf + po);
                if (!isHeapPtr(sub2) || sub2 == sub150 || sub2 == ptrs[i]) continue;
                uint8_t s2[0x800];
                if (!DmaRead(sub2, s2, sizeof(s2))) continue;
                for (int s2o = 0x100; s2o + 12 <= 0x800; s2o += 4) {
                    float x = *(float*)(s2 + s2o);
                    float y = *(float*)(s2 + s2o + 4);
                    float z = *(float*)(s2 + s2o + 8);
                    if (!isnan(x) && !isnan(y) && !isnan(z) &&
                        fabsf(x) > 20 && fabsf(x) < 50000 &&
                        fabsf(y) > 20 && fabsf(y) < 50000 &&
                        fabsf(z) > 5 && fabsf(z) < 50000) {
                        printf("    +0x%02X->sub2+0x%04X = (%.2f, %.2f, %.2f)\n",
                               po, s2o, x, y, z);
                        found++;
                        s2o += 8;
                        if (found >= 6) goto next_ent;
                    }
                }
            }
            next_ent:
            if (found == 0) printf(" (no positions)\n");
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
