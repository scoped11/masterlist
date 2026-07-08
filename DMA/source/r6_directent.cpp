// R6 Direct Entity Read — skip .data pointer chains entirely
// Read confirmed entity heap addresses directly + do full scan in one init
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_directent.cpp /Fe"../r6_directent.exe" /link

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

struct Vec3 { float x, y, z; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Direct Entity Reader ===\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) return 1;
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    // ============================================================
    // PHASE 1: Full scan in one init to discover entity addresses
    // ============================================================
    printf("--- PHASE 1: Full entity scan (single init) ---\n");
    doInit();
    if (!g_vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    uint64_t dataBase = 0, dataSize = 0;
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(g_base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(g_base + dos.e_lfanew);
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

    // Collect heap objects from .data
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> dataBuf(CHUNK);
    std::set<uint64_t> heapObjs;

    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, dataSize - off);
        if (!DmaRead(dataBase + off, dataBuf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(dataBuf.data() + i);
            if (isHeapPtr(v)) heapObjs.insert(v);
        }
    }
    printf("  %d unique heap objects in .data\n", (int)heapObjs.size());

    // For each heap object, find vectors and collect all entity addresses
    struct EntAddr {
        uint64_t addr;
        uint64_t vtblRVA;
    };
    std::vector<EntAddr> entityAddrs;
    std::set<uint64_t> seenEnts;
    int scanned = 0;

    for (uint64_t obj : heapObjs) {
        scanned++;
        if (scanned % 10000 == 0) printf("  %d/%d...\n", scanned, (int)heapObjs.size());

        uint8_t objBuf[0x600];
        if (!DmaRead(obj, objBuf, sizeof(objBuf))) continue;

        for (int fo = 0; fo + 16 <= 0x600; fo += 8) {
            uint64_t vb = *(uint64_t*)(objBuf + fo);
            uint64_t ve = *(uint64_t*)(objBuf + fo + 8);
            if (!isHeapPtr(vb) || ve <= vb || (ve - vb) % 8 != 0) continue;
            int cnt = (int)((ve - vb) / 8);
            if (cnt < 5 || cnt > 500) continue;

            int readN = min(cnt, 12);
            uint64_t ptrs[12] = {};
            DmaRead(vb, ptrs, readN * 8);

            std::map<uint64_t, int> vtMap;
            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                uint64_t vt = rpm<uint64_t>(ptrs[k]);
                if (isModPtr(vt)) vtMap[vt - g_base]++;
            }

            uint64_t bestVt = 0; int bestN = 0;
            for (auto& v : vtMap) {
                if (v.second > bestN) { bestN = v.second; bestVt = v.first; }
            }
            if (bestN < 3) continue;

            // Read ALL entries from this vector
            readN = min(cnt, 200);
            std::vector<uint64_t> allPtrs(readN);
            DmaRead(vb, allPtrs.data(), readN * 8);

            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(allPtrs[k]) || seenEnts.count(allPtrs[k])) continue;
                uint64_t vt = rpm<uint64_t>(allPtrs[k]);
                if (!isModPtr(vt)) continue;
                seenEnts.insert(allPtrs[k]);
                entityAddrs.push_back({allPtrs[k], vt - g_base});
            }
        }
    }

    printf("  Discovered %d unique entity addresses\n", (int)entityAddrs.size());

    // Read snapshot 1 of ALL entities
    const int ENT_SIZE = 0x1000;
    struct EntData {
        uint64_t addr;
        uint64_t vtblRVA;
        uint8_t snap1[ENT_SIZE];
        uint8_t snap2[ENT_SIZE];
        bool ok1, ok2;
    };

    // Only keep entities with world-position-like data to limit memory
    std::vector<EntData> entities;
    for (auto& ea : entityAddrs) {
        EntData ed = {};
        ed.addr = ea.addr;
        ed.vtblRVA = ea.vtblRVA;
        ed.ok1 = DmaRead(ea.addr, ed.snap1, ENT_SIZE);
        if (!ed.ok1) continue;

        // Check if this entity has any plausible position data
        bool hasPos = false;
        for (int po = 0x10; po + 12 <= ENT_SIZE; po += 4) {
            float x = *(float*)(ed.snap1 + po);
            float y = *(float*)(ed.snap1 + po + 4);
            float z = *(float*)(ed.snap1 + po + 8);
            if (!isnan(x) && !isnan(y) && !isnan(z) &&
                fabsf(x) > 1.0f && fabsf(x) < 50000.0f &&
                fabsf(y) > 1.0f && fabsf(y) < 50000.0f &&
                fabsf(z) > 0.1f && fabsf(z) < 50000.0f) {
                hasPos = true;
                break;
            }
        }
        if (hasPos) entities.push_back(ed);
    }
    printf("  %d entities with position data captured for snapshot 1\n", (int)entities.size());

    pClose(g_vmm); g_vmm = nullptr;

    // ============================================================
    // PHASE 2: Wait and take snapshot 2
    // ============================================================
    printf("\n--- Waiting 5 seconds (bots should move) ---\n");
    Sleep(5000);

    printf("--- SNAPSHOT 2 ---\n");
    doInit();
    if (!g_vmm) return 1;
    printf("[+] PID=%u Base=0x%llX\n", g_pid, (unsigned long long)g_base);

    int readOk = 0;
    for (auto& e : entities) {
        e.ok2 = DmaRead(e.addr, e.snap2, ENT_SIZE);
        if (e.ok2) readOk++;
    }
    printf("  Read %d/%d entities\n", readOk, (int)entities.size());

    // ============================================================
    // PHASE 3: Diff
    // ============================================================
    printf("\n=== DIFF RESULTS ===\n");

    // Find entities with ANY changed bytes
    int movedTotal = 0;
    std::map<uint64_t, int> movedByVtbl;

    for (auto& e : entities) {
        if (!e.ok1 || !e.ok2) continue;
        int changed = 0;
        for (int off = 0; off < ENT_SIZE; off += 4) {
            if (*(uint32_t*)(e.snap1 + off) != *(uint32_t*)(e.snap2 + off))
                changed++;
        }
        if (changed > 0) {
            movedTotal++;
            movedByVtbl[e.vtblRVA]++;
            if (movedTotal <= 25) {
                printf("  ent=0x%llX vtbl=+0x%08llX %d dwords changed\n",
                       (unsigned long long)e.addr,
                       (unsigned long long)e.vtblRVA, changed);

                // Show changed float offsets that look like positions
                for (int off = 0; off + 12 <= ENT_SIZE; off += 4) {
                    float x1 = *(float*)(e.snap1 + off);
                    float y1 = *(float*)(e.snap1 + off + 4);
                    float z1 = *(float*)(e.snap1 + off + 8);
                    float x2 = *(float*)(e.snap2 + off);
                    float y2 = *(float*)(e.snap2 + off + 4);
                    float z2 = *(float*)(e.snap2 + off + 8);
                    if (isnan(x1) || isnan(y1) || isnan(z1)) continue;
                    if (isnan(x2) || isnan(y2) || isnan(z2)) continue;
                    float dx = x2-x1, dy = y2-y1, dz = z2-z1;
                    float d = sqrtf(dx*dx + dy*dy + dz*dz);
                    if (d > 0.05f && d < 50.0f &&
                        fabsf(x1) < 50000 && fabsf(y1) < 50000 && fabsf(z1) < 50000) {
                        printf("    +0x%04X: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.2f\n",
                               off, x1, y1, z1, x2, y2, z2, d);
                    }
                }
            }
        }
    }

    printf("\n  Total entities with changes: %d / %d\n", movedTotal, (int)entities.size());
    printf("  By vtable:\n");
    for (auto& kv : movedByVtbl) {
        printf("    vtbl=+0x%08llX: %d moved\n",
               (unsigned long long)kv.first, kv.second);
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
