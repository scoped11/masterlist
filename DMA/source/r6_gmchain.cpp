// R6 GM Chain Probe — drill into GM+0x1C8 → EntityList → Entities
// Also probe GM+0x198 which had vtable entries
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_gmchain.cpp /Fe"../r6_gmchain.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <set>

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

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 GM Chain Probe ===\n\n");

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
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base);

    uint64_t gm = rpm<uint64_t>(g_base + 0x11F0DDF8);
    printf("GM = 0x%llX\n\n", (unsigned long long)gm);

    // ==============================
    // SECTION 1: GM+0x1C8 entity list
    // ==============================
    printf("=== GM+0x1C8 -> Entity List ===\n");
    uint64_t el = rpm<uint64_t>(gm + 0x1C8);
    printf("EntityList obj = 0x%llX\n", (unsigned long long)el);

    if (!isHeapPtr(el)) { printf("[!] EntityList not a heap ptr\n"); goto section2; }

    {
        // Dump the entity list object structure
        uint8_t elBuf[0x400];
        DmaRead(el, elBuf, sizeof(elBuf));

        printf("\nEntityList object dump (first 0x200):\n");
        for (int i = 0; i < 0x200; i += 8) {
            uint64_t v = *(uint64_t*)(elBuf + i);
            if (v == 0) continue;
            printf("  +0x%03X: 0x%016llX", i, (unsigned long long)v);
            if (isModPtr(v)) printf(" [MOD +0x%llX]", (unsigned long long)(v - g_base));
            else if (isHeapPtr(v)) printf(" [HEAP]");
            printf("\n");
        }

        // The vector at +0x180 had 136 entries. Let's read them
        uint64_t vb = *(uint64_t*)(elBuf + 0x180);
        uint64_t ve = *(uint64_t*)(elBuf + 0x188);
        printf("\n+0x180 vector: begin=0x%llX end=0x%llX\n",
               (unsigned long long)vb, (unsigned long long)ve);
        int cnt = 0;
        if (isHeapPtr(vb) && ve > vb) {
            cnt = (int)((ve - vb) / 8);
            printf("  count = %d\n\n", cnt);
        }

        if (cnt > 0 && cnt < 500) {
            int readN = (cnt > 20) ? 20 : cnt;
            uint64_t* ptrs = new uint64_t[readN];
            DmaRead(vb, ptrs, readN * 8);

            printf("First %d entries:\n", readN);
            for (int i = 0; i < readN; i++) {
                printf("  [%3d] 0x%016llX", i, (unsigned long long)ptrs[i]);
                if (isHeapPtr(ptrs[i])) {
                    printf(" [HEAP]");
                    // Read first 0x30 bytes of this entry to understand structure
                    uint8_t entBuf[0x30];
                    DmaRead(ptrs[i], entBuf, sizeof(entBuf));
                    uint64_t w0 = *(uint64_t*)entBuf;
                    uint64_t w1 = *(uint64_t*)(entBuf + 8);
                    uint64_t w2 = *(uint64_t*)(entBuf + 0x10);
                    uint64_t w3 = *(uint64_t*)(entBuf + 0x18);
                    uint64_t w4 = *(uint64_t*)(entBuf + 0x20);
                    uint64_t w5 = *(uint64_t*)(entBuf + 0x28);

                    if (isModPtr(w0)) printf(" vt=+0x%llX", (unsigned long long)(w0 - g_base));

                    // Check if any field is a heap pointer to an entity with vtable
                    for (int fi = 0; fi < 6; fi++) {
                        uint64_t fv = *(uint64_t*)(entBuf + fi * 8);
                        if (fi == 0) continue; // already printed vtbl
                        if (isHeapPtr(fv)) {
                            uint64_t subvt = rpm<uint64_t>(fv);
                            if (isModPtr(subvt)) {
                                printf("\n       +0x%02X->0x%llX vt=+0x%llX",
                                       fi*8, (unsigned long long)fv, (unsigned long long)(subvt - g_base));
                            }
                        }
                    }
                } else if (ptrs[i] == 0) {
                    printf(" NULL");
                } else {
                    printf(" value");
                }
                printf("\n");
            }

            // Deep probe first 3 non-null entries
            printf("\n--- Deep probe entries ---\n");
            int probed = 0;
            for (int i = 0; i < readN && probed < 5; i++) {
                if (!isHeapPtr(ptrs[i])) continue;

                printf("\nEntry[%d] = 0x%llX\n", i, (unsigned long long)ptrs[i]);

                uint8_t bigBuf[0x200];
                DmaRead(ptrs[i], bigBuf, sizeof(bigBuf));

                // Full dump
                for (int off = 0; off < 0x200; off += 8) {
                    uint64_t v = *(uint64_t*)(bigBuf + off);
                    if (v == 0) continue;
                    printf("  +0x%03X: 0x%016llX", off, (unsigned long long)v);
                    if (isModPtr(v)) printf(" [MOD +0x%llX]", (unsigned long long)(v - g_base));
                    else if (isHeapPtr(v)) {
                        printf(" [HEAP]");
                        uint64_t sv = rpm<uint64_t>(v);
                        if (isModPtr(sv)) printf(" ->vt=+0x%llX", (unsigned long long)(sv - g_base));
                    }
                    printf("\n");
                }

                // Follow each heap pointer looking for world positions
                for (int off = 0; off < 0x200; off += 8) {
                    uint64_t v = *(uint64_t*)(bigBuf + off);
                    if (!isHeapPtr(v)) continue;
                    uint8_t subBuf[0xA00];
                    if (!DmaRead(v, subBuf, sizeof(subBuf))) continue;
                    for (int so = 0x10; so + 12 <= 0xA00; so += 4) {
                        float x = *(float*)(subBuf + so);
                        float y = *(float*)(subBuf + so + 4);
                        float z = *(float*)(subBuf + so + 8);
                        if (isWorldPos(x, y, z) && (fabsf(x) > 10 || fabsf(y) > 10 || fabsf(z) > 10)) {
                            printf("  >> +0x%03X -> sub+0x%04X = (%.2f, %.2f, %.2f)\n",
                                   off, so, x, y, z);
                            so += 8;
                        }
                    }
                }

                probed++;
            }

            delete[] ptrs;
        }

        // Also try other vectors in the EntityList object
        printf("\n--- Other vectors in EntityList ---\n");
        for (int off = 0; off < 0x400 - 16; off += 8) {
            if (off == 0x180) continue; // already did this one
            uint64_t tb = *(uint64_t*)(elBuf + off);
            uint64_t te = *(uint64_t*)(elBuf + off + 8);
            if (!isHeapPtr(tb) || te <= tb) continue;
            if ((te - tb) % 8 != 0) continue;
            int tcnt = (int)((te - tb) / 8);
            if (tcnt < 3 || tcnt > 500) continue;

            int trn = (tcnt > 5) ? 5 : tcnt;
            uint64_t tptrs[5] = {};
            DmaRead(tb, tptrs, trn * 8);
            int thp = 0, tvt = 0;
            for (int k = 0; k < trn; k++) {
                if (isHeapPtr(tptrs[k])) {
                    thp++;
                    if (isModPtr(rpm<uint64_t>(tptrs[k]))) tvt++;
                }
            }
            printf("  +0x%03X: cnt=%d hp=%d vt=%d\n", off, tcnt, thp, tvt);
        }
    }

section2:
    // ==============================
    // SECTION 2: GM+0x198 (had vtable entries)
    // ==============================
    printf("\n\n=== GM+0x198 -> Component List ===\n");
    uint64_t c198 = rpm<uint64_t>(gm + 0x198);
    printf("GM+0x198 = 0x%llX\n", (unsigned long long)c198);

    if (isHeapPtr(c198)) {
        uint8_t c198Buf[0x300];
        DmaRead(c198, c198Buf, sizeof(c198Buf));

        // +0x120 had cnt=35 with vtables
        uint64_t cb = *(uint64_t*)(c198Buf + 0x120);
        uint64_t ce = *(uint64_t*)(c198Buf + 0x128);
        if (isHeapPtr(cb) && ce > cb) {
            int ccnt = (int)((ce - cb) / 8);
            printf("+0x120 vector cnt=%d\n", ccnt);

            int crn = (ccnt > 10) ? 10 : ccnt;
            uint64_t cptrs[10] = {};
            DmaRead(cb, cptrs, crn * 8);

            for (int k = 0; k < crn; k++) {
                printf("  [%2d] 0x%016llX", k, (unsigned long long)cptrs[k]);
                if (isHeapPtr(cptrs[k])) {
                    uint64_t cv = rpm<uint64_t>(cptrs[k]);
                    if (isModPtr(cv))
                        printf(" vtbl=+0x%llX", (unsigned long long)(cv - g_base));
                    else
                        printf(" [no vt]");
                } else if (isModPtr(cptrs[k])) {
                    printf(" [MOD]");
                }
                printf("\n");
            }

            // Deep probe entries with vtables, looking for player entity with position
            printf("\n  Deep position search on vtable entries:\n");
            for (int k = 0; k < crn; k++) {
                if (!isHeapPtr(cptrs[k])) continue;
                uint64_t cv = rpm<uint64_t>(cptrs[k]);
                if (!isModPtr(cv)) continue;

                uint8_t eBuf[0xA00];
                if (!DmaRead(cptrs[k], eBuf, sizeof(eBuf))) continue;

                // Direct position scan
                int found = 0;
                for (int so = 0x10; so + 12 <= 0xA00; so += 4) {
                    float x = *(float*)(eBuf + so);
                    float y = *(float*)(eBuf + so + 4);
                    float z = *(float*)(eBuf + so + 8);
                    if (isWorldPos(x, y, z) && (fabsf(x) > 10 || fabsf(y) > 10 || fabsf(z) > 10)) {
                        printf("  [%d] vtbl=+0x%llX +0x%04X = (%.2f, %.2f, %.2f)\n",
                               k, (unsigned long long)(cv - g_base), so, x, y, z);
                        found++;
                        so += 8;
                        if (found >= 3) break;
                    }
                }

                // Indirect: follow heap ptrs at first 0x100 bytes
                for (int po = 0; po < 0x100 && found < 4; po += 8) {
                    uint64_t sub = *(uint64_t*)(eBuf + po);
                    if (!isHeapPtr(sub) || sub == cptrs[k]) continue;
                    uint8_t sBuf[0xA00];
                    if (!DmaRead(sub, sBuf, sizeof(sBuf))) continue;
                    for (int so = 0x10; so + 12 <= 0xA00; so += 4) {
                        float x = *(float*)(sBuf + so);
                        float y = *(float*)(sBuf + so + 4);
                        float z = *(float*)(sBuf + so + 8);
                        if (isWorldPos(x, y, z) && (fabsf(x) > 10 || fabsf(y) > 10 || fabsf(z) > 10)) {
                            printf("  [%d] vtbl=+0x%llX +0x%02X->+0x%04X = (%.2f, %.2f, %.2f)\n",
                                   k, (unsigned long long)(cv - g_base), po, so, x, y, z);
                            found++;
                            so += 8;
                            if (found >= 4) goto next_ent;
                        }
                    }
                }
                next_ent:;
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
