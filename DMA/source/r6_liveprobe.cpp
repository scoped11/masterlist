// R6 Live Probe — drill into confirmed live entity list
// vtbl=+0x1192C9E0, .data+0x86A470, pos@+0x08B0
// Two snapshots with full reinit to detect ALL movers
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_liveprobe.cpp /Fe"../r6_liveprobe.exe" /link

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
    uint64_t base, modEnd, dataBase;
};

static bool DmaRead(Session& s, uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(s.vmm, s.pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(Session& s, uint64_t a) { T v{}; DmaRead(s, a, &v, sizeof(T)); return v; }
static bool isHeapPtr(Session& s, uint64_t v) {
    return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < s.base || v > s.modEnd);
}
static bool isModPtr(Session& s, uint64_t v) { return v >= s.base && v < s.modEnd; }

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
            break;
        }
    }
    return s;
}

struct EntInfo {
    uint64_t addr;
    uint64_t vtbl;
    Vec3 pos1, pos2;
    float delta;
    bool valid1, valid2;
    uint8_t raw1[0xC00], raw2[0xC00];
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Live Entity Probe ===\n");
    printf("=== Confirmed: vtbl=+0x1192C9E0 .data+0x86A470 pos@+0x08B0 ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    const uint64_t DATA_OFF = 0x86A470;
    const uint64_t CONFIRMED_VTBL_RVA = 0x1192C9E0;
    const uint64_t POS_OFF = 0x08B0;

    // ========== SNAPSHOT 1 ==========
    printf("--- SNAPSHOT 1 ---\n");
    Session s1 = openSession();
    if (!s1.vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n", s1.pid, (unsigned long long)s1.base);

    // Follow .data+0x86A470 → object → find the entity vector
    uint64_t rootObj = rpm<uint64_t>(s1, s1.dataBase + DATA_OFF);
    printf("[+] Root obj at .data+0x%llX = 0x%llX\n",
           (unsigned long long)DATA_OFF, (unsigned long long)rootObj);

    if (!isHeapPtr(s1, rootObj)) {
        printf("[!] Root obj is not a heap pointer\n");
        pClose(s1.vmm);
        return 1;
    }

    // Read the root object to find ALL vectors
    uint8_t rootBuf[0x600];
    DmaRead(s1, rootObj, rootBuf, sizeof(rootBuf));

    printf("\n=== Scanning root object for ALL entity vectors ===\n");
    struct VecInfo { uint64_t off; uint64_t begin; uint64_t end; int cnt; int matchVt; };
    std::vector<VecInfo> vecs;

    for (int fo = 0; fo + 16 <= 0x600; fo += 8) {
        uint64_t vb = *(uint64_t*)(rootBuf + fo);
        uint64_t ve = *(uint64_t*)(rootBuf + fo + 8);
        if (!isHeapPtr(s1, vb) || ve <= vb || (ve - vb) % 8 != 0) continue;
        int cnt = (int)((ve - vb) / 8);
        if (cnt < 2 || cnt > 500) continue;

        int readN = min(cnt, 6);
        uint64_t ptrs[6] = {};
        DmaRead(s1, vb, ptrs, readN * 8);
        int hp = 0, mvt = 0;
        for (int k = 0; k < readN; k++) {
            if (!isHeapPtr(s1, ptrs[k])) continue;
            hp++;
            uint64_t vt = rpm<uint64_t>(s1, ptrs[k]);
            if (isModPtr(s1, vt) && (vt - s1.base) == CONFIRMED_VTBL_RVA) mvt++;
        }
        if (hp >= 2) {
            vecs.push_back({(uint64_t)fo, vb, ve, cnt, mvt});
            printf("  +0x%03X: vec(%d entries) %d heap, %d matching vtbl\n",
                   fo, cnt, hp, mvt);
        }
    }

    // Find the best vector (most matching vtable entries)
    int bestVecIdx = -1, bestMvt = 0;
    for (int i = 0; i < (int)vecs.size(); i++) {
        if (vecs[i].matchVt > bestMvt) { bestMvt = vecs[i].matchVt; bestVecIdx = i; }
    }

    // Also try ALL vectors with entities
    printf("\n=== Reading ALL entities from ALL vectors ===\n");
    std::vector<EntInfo> ents;

    for (auto& vi : vecs) {
        int readN = min(vi.cnt, 200);
        std::vector<uint64_t> ptrs(readN);
        DmaRead(s1, vi.begin, ptrs.data(), readN * 8);

        for (int k = 0; k < readN; k++) {
            if (!isHeapPtr(s1, ptrs[k])) continue;

            EntInfo e = {};
            e.addr = ptrs[k];
            e.vtbl = rpm<uint64_t>(s1, ptrs[k]);

            DmaRead(s1, ptrs[k], e.raw1, 0xC00);

            // Read position at multiple candidate offsets
            Vec3 p = *(Vec3*)(e.raw1 + POS_OFF);
            if (!isnan(p.x) && !isnan(p.y) && !isnan(p.z) &&
                fabsf(p.x) < 50000 && fabsf(p.y) < 50000 && fabsf(p.z) < 50000) {
                e.pos1 = p;
                e.valid1 = true;
            }
            ents.push_back(e);
        }
    }
    printf("  Total entities found: %d (%d with valid positions)\n",
           (int)ents.size(), (int)std::count_if(ents.begin(), ents.end(),
                                                 [](const EntInfo& e) { return e.valid1; }));

    // Also scan for positions at OTHER offsets to find the real position field
    printf("\n=== Scanning for position offsets across first 10 entities ===\n");
    std::map<int, int> posOffMap;
    int checked = 0;
    for (auto& e : ents) {
        if (!isModPtr(s1, e.vtbl) || (e.vtbl - s1.base) != CONFIRMED_VTBL_RVA) continue;
        if (checked >= 10) break;
        checked++;
        for (int po = 0x10; po + 12 <= 0xC00; po += 4) {
            float x = *(float*)(e.raw1 + po);
            float y = *(float*)(e.raw1 + po + 4);
            float z = *(float*)(e.raw1 + po + 8);
            if (!isnan(x) && !isnan(y) && !isnan(z) &&
                fabsf(x) > 0.5f && fabsf(x) < 50000.0f &&
                fabsf(y) > 0.5f && fabsf(y) < 50000.0f &&
                fabsf(z) > 0.5f && fabsf(z) < 50000.0f) {
                posOffMap[po]++;
            }
        }
    }
    printf("  Position offsets with 3+ hits:\n");
    for (auto& kv : posOffMap) {
        if (kv.second >= 3)
            printf("    +0x%04X: %d/%d entities\n", kv.first, kv.second, checked);
    }

    pClose(s1.vmm);
    s1.vmm = nullptr;

    printf("\n--- Waiting 5 seconds for bots to move ---\n");
    Sleep(5000);

    // ========== SNAPSHOT 2 ==========
    printf("\n--- SNAPSHOT 2 ---\n");
    Session s2 = openSession();
    if (!s2.vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n", s2.pid, (unsigned long long)s2.base);

    int changed = 0;
    for (auto& e : ents) {
        DmaRead(s2, e.addr, e.raw2, 0xC00);

        // Check position at POS_OFF
        Vec3 p2 = *(Vec3*)(e.raw2 + POS_OFF);
        if (!isnan(p2.x) && !isnan(p2.y) && !isnan(p2.z) &&
            fabsf(p2.x) < 50000 && fabsf(p2.y) < 50000 && fabsf(p2.z) < 50000) {
            e.pos2 = p2;
            e.valid2 = true;
        }

        if (e.valid1 && e.valid2) {
            float dx = e.pos2.x - e.pos1.x;
            float dy = e.pos2.y - e.pos1.y;
            float dz = e.pos2.z - e.pos1.z;
            e.delta = sqrtf(dx*dx + dy*dy + dz*dz);
            if (e.delta > 0.01f) changed++;
        }

        // Also check ALL potential position offsets for changes
    }

    printf("\n=== POSITION CHANGES AT +0x%04llX ===\n", (unsigned long long)POS_OFF);
    int shown = 0;
    for (auto& e : ents) {
        if (e.delta > 0.01f) {
            shown++;
            printf("  [%d] vtbl=+0x%08llX ent=0x%llX delta=%.2f\n",
                   shown, (unsigned long long)(e.vtbl - s2.base),
                   (unsigned long long)e.addr, e.delta);
            printf("      snap1=(%.2f,%.2f,%.2f) snap2=(%.2f,%.2f,%.2f)\n",
                   e.pos1.x, e.pos1.y, e.pos1.z,
                   e.pos2.x, e.pos2.y, e.pos2.z);
        }
    }
    if (shown == 0) printf("  No changes at +0x%llX\n", (unsigned long long)POS_OFF);

    // Check ALL offsets for byte-level diffs on matching-vtable entities
    printf("\n=== BYTE-LEVEL DIFF on matching-vtable entities ===\n");
    std::map<int, int> diffMap;
    int diffChecked = 0;
    for (auto& e : ents) {
        if (!isModPtr(s2, e.vtbl) || (e.vtbl - s2.base) != CONFIRMED_VTBL_RVA) continue;
        diffChecked++;
        for (int off = 0; off < 0xC00; off += 4) {
            uint32_t v1 = *(uint32_t*)(e.raw1 + off);
            uint32_t v2 = *(uint32_t*)(e.raw2 + off);
            if (v1 != v2) diffMap[off]++;
        }
    }
    printf("  Checked %d entities with matching vtable\n", diffChecked);
    printf("  Offsets with changes (3+ entities):\n");
    for (auto& kv : diffMap) {
        if (kv.second >= 3) {
            // Show sample values
            printf("    +0x%04X: %d/%d changed", kv.first, kv.second, diffChecked);
            // Check if this looks like a float position
            for (auto& e : ents) {
                if (!isModPtr(s2, e.vtbl) || (e.vtbl - s2.base) != CONFIRMED_VTBL_RVA) continue;
                float f1 = *(float*)(e.raw1 + kv.first);
                float f2 = *(float*)(e.raw2 + kv.first);
                if (fabsf(f1) > 0.1f && fabsf(f1) < 50000.0f &&
                    fabsf(f2) > 0.1f && fabsf(f2) < 50000.0f) {
                    printf(" [%.2f->%.2f]", f1, f2);
                }
                break;
            }
            printf("\n");
        }
    }

    printf("\nDone.\n");
    pClose(s2.vmm);
    return 0;
}
