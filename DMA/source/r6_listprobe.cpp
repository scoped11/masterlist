// R6 Entity List Probe — test candidate entity lists for moving positions
// Takes the global pointers found by sigscan2 and probes entities for movement
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_listprobe.cpp /Fe"../r6_listprobe.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
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

struct Vec3 { float x, y, z; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Entity List Probe ===\n\n");

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

    // Candidate globals from sigscan2 (RVA offsets from base)
    struct Candidate {
        const char* name;
        uint64_t globalRVA;
    };
    Candidate candidates[] = {
        {"List170_A",  0x120E7228},
        {"List170_B",  0x120E78B8},
        {"List12_C",   0x120E8860},
        {"List12_D",   0x12150C20},
        {"List12_E",   0x12170428},
        {"List20_F",   0x12170818},
        {"List180_G",  0x12172BA0},
        {"List12_H",   0x12172BA8},
        {"List80_I",   0x1217A3A0},
        {"List20_J",   0x1217ACD0},
        {"List36_K",   0x1217D5A0},
        {"List80_L",   0x1217D9A8},
    };
    int numCands = sizeof(candidates) / sizeof(candidates[0]);

    // For each candidate, read the entity list and check for world positions
    for (int ci = 0; ci < numCands; ci++) {
        auto& c = candidates[ci];
        uint64_t objAddr = rpm<uint64_t>(g_base + c.globalRVA);
        if (!isHeapPtr(objAddr)) { printf("  %-12s: NULL/invalid\n", c.name); continue; }

        uint64_t vt = rpm<uint64_t>(objAddr);
        if (!isModPtr(vt)) continue;

        // Find entity list vector in this object
        uint8_t objBuf[0x400];
        if (!DmaRead(objAddr, objBuf, sizeof(objBuf))) continue;

        // Try all vector-like offset pairs
        for (int vo = 0x10; vo + 16 <= 0x400; vo += 8) {
            uint64_t vBegin = *(uint64_t*)(objBuf + vo);
            uint64_t vEnd   = *(uint64_t*)(objBuf + vo + 8);
            if (!isHeapPtr(vBegin) || vEnd <= vBegin) continue;
            if ((vEnd - vBegin) % 8 != 0) continue;
            int cnt = (int)((vEnd - vBegin) / 8);
            if (cnt < 5 || cnt > 500) continue;

            int readN = (cnt > 50) ? 50 : cnt;
            std::vector<uint64_t> ptrs(readN);
            DmaRead(vBegin, ptrs.data(), readN * 8);

            int validEnts = 0;
            for (int k = 0; k < readN; k++)
                if (isHeapPtr(ptrs[k])) {
                    uint64_t evt = rpm<uint64_t>(ptrs[k]);
                    if (isModPtr(evt)) validEnts++;
                }
            if (validEnts < 3) continue;

            printf("\n=== %-12s Base+0x%llX obj=0x%llX vtbl=+0x%llX ===\n",
                   c.name, (unsigned long long)c.globalRVA, (unsigned long long)objAddr,
                   (unsigned long long)(vt - g_base));
            printf("  Vector at +0x%02X: %d entries, %d valid\n", vo, cnt, validEnts);

            // Snapshot 1: read all entities
            struct EntSnap {
                uint64_t addr;
                uint64_t vtblRVA;
                uint8_t data[0x800];
            };
            std::vector<EntSnap> ents;
            for (int k = 0; k < readN; k++) {
                if (!isHeapPtr(ptrs[k])) continue;
                EntSnap es = {};
                es.addr = ptrs[k];
                uint64_t evt = rpm<uint64_t>(ptrs[k]);
                es.vtblRVA = isModPtr(evt) ? evt - g_base : 0;
                DmaRead(ptrs[k], es.data, sizeof(es.data));
                ents.push_back(es);
            }

            // Count entities with world-position-like floats
            int withWorldPos = 0;
            for (auto& e : ents) {
                for (int off = 0x10; off + 12 <= 0x800; off += 4) {
                    float x = *(float*)(e.data + off);
                    float y = *(float*)(e.data + off + 4);
                    float z = *(float*)(e.data + off + 8);
                    if (!isnan(x) && !isnan(y) && !isnan(z) &&
                        fabsf(x) > 5 && fabsf(x) < 5000 &&
                        fabsf(y) > 5 && fabsf(y) < 5000 &&
                        z > 0.3f && z < 500) {
                        withWorldPos++;
                        break;
                    }
                }
            }
            printf("  Entities with world-pos floats: %d/%d\n", withWorldPos, (int)ents.size());

            if (withWorldPos < 1) continue;

            // Snapshot 2 after delay
            printf("  Taking snapshot 2 (2s delay)...\n");
            Sleep(2000);

            int movers = 0;
            for (auto& e : ents) {
                uint8_t data2[0x800];
                if (!DmaRead(e.addr, data2, sizeof(data2))) continue;

                // Find best moving position triple
                float bestDist = 0;
                int bestOff = -1;
                float bx1=0,by1=0,bz1=0,bx2=0,by2=0,bz2=0;

                for (int off = 0x10; off + 12 <= 0x800; off += 4) {
                    float x1 = *(float*)(e.data + off), y1 = *(float*)(e.data + off+4), z1 = *(float*)(e.data + off+8);
                    float x2 = *(float*)(data2 + off), y2 = *(float*)(data2 + off+4), z2 = *(float*)(data2 + off+8);
                    if (isnan(x1) || isnan(y1) || isnan(x2) || isnan(y2)) continue;
                    if (fabsf(x1) < 5 || fabsf(x1) > 5000) continue;
                    float dx=x2-x1,dy=y2-y1,dz=z2-z1;
                    float d = sqrtf(dx*dx+dy*dy+dz*dz);
                    if (d > 0.01f && d < 50 && d > bestDist) {
                        bestDist=d; bestOff=off;
                        bx1=x1; by1=y1; bz1=z1; bx2=x2; by2=y2; bz2=z2;
                    }
                }

                if (bestOff >= 0) {
                    movers++;
                    if (movers <= 10) {
                        printf("    MOVER: 0x%llX vtbl=+0x%llX +0x%03X: (%.1f,%.1f,%.1f)->(%.1f,%.1f,%.1f) d=%.3f\n",
                               (unsigned long long)e.addr, (unsigned long long)e.vtblRVA, bestOff,
                               bx1, by1, bz1, bx2, by2, bz2, bestDist);
                    }
                }
            }
            printf("  MOVERS: %d/%d entities moved\n", movers, (int)ents.size());

            // Also check sub-objects for movement
            if (movers == 0) {
                printf("  Checking sub-object chains for movement...\n");
                int subMovers = 0;
                for (auto& e : ents) {
                    if (subMovers >= 5) break;
                    for (int poff = 8; poff + 8 <= 0x100; poff += 8) {
                        uint64_t sub = *(uint64_t*)(e.data + poff);
                        if (!isHeapPtr(sub)) continue;

                        uint8_t sb1[0x800], sb2[0x800];
                        if (!DmaRead(sub, sb1, sizeof(sb1))) continue;
                        Sleep(200);
                        if (!DmaRead(sub, sb2, sizeof(sb2))) continue;

                        for (int off = 0x10; off + 12 <= 0x800; off += 4) {
                            float x1 = *(float*)(sb1 + off), y1 = *(float*)(sb1 + off+4), z1 = *(float*)(sb1 + off+8);
                            float x2 = *(float*)(sb2 + off), y2 = *(float*)(sb2 + off+4), z2 = *(float*)(sb2 + off+8);
                            if (isnan(x1) || isnan(y1) || isnan(x2) || isnan(y2)) continue;
                            if (fabsf(x1) < 5 || fabsf(x1) > 5000) continue;
                            float dx=x2-x1,dy=y2-y1,dz=z2-z1;
                            float d = sqrtf(dx*dx+dy*dy+dz*dz);
                            if (d > 0.01f && d < 50) {
                                printf("    SUB-MOVER: ent=0x%llX +0x%02X->sub+0x%03X: (%.1f,%.1f,%.1f) d=%.3f\n",
                                       (unsigned long long)e.addr, poff, off,
                                       x1, y1, z1, d);
                                subMovers++;
                                goto next_ent;
                            }
                        }
                    }
                    next_ent:;
                }
            }

            break; // only check first valid vector per candidate
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
