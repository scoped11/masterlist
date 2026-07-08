// R6 Entity Deep Probe — drill into candidate entity list, try multiple position read methods
// Takes the entity list from r6_gmfinder candidate #0
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_entprobe.cpp /Fe"../r6_entprobe.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <set>

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

#define DEC(x) (((x) & 0xFFFFFFFFFFFFULL) ^ (0x100010001ULL * (((x) >> 16) & 0xFFFF)))

struct Vec4 { float x, y, z, w; };

void dumpHex(const uint8_t* data, int len, int baseOff) {
    for (int i = 0; i < len; i += 16) {
        printf("    +%04X:", baseOff + i);
        for (int j = 0; j < 16 && i + j < len; j++) printf(" %02X", data[i + j]);
        printf("  ");
        for (int j = 0; j < 16 && i + j < len; j++) {
            char c = (char)data[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
}

bool tryDecChain(uint64_t startAddr, Vec4& out, const char* label) {
    uint64_t A = rpm<uint64_t>(startAddr);
    uint64_t d1 = DEC(A);
    if (d1 < 0x10000 || d1 > 0x7FFFFFFFFFFF) return false;
    uint64_t B = rpm<uint64_t>(d1);
    uint64_t d2 = DEC(B);
    if (d2 < 0x10000 || d2 > 0x7FFFFFFFFFFF) return false;
    uint64_t C = rpm<uint64_t>(d2);
    uint64_t e1 = DEC(C);
    if (e1 < 0x10000 || e1 > 0x7FFFFFFFFFFF) return false;
    uint64_t E = rpm<uint64_t>(e1);
    uint64_t pp = DEC(E);
    if (pp < 0x10000 || pp > 0x7FFFFFFFFFFF) return false;
    out = rpm<Vec4>(pp);
    if (isnan(out.x) || isnan(out.y) || isnan(out.z)) return false;
    return true;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Entity Deep Probe ===\n\n");

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
    printf("[+] PID=%u Base=0x%llX\n\n", g_pid, (unsigned long long)g_base, (unsigned long long)g_modEnd);

    // Read entity list from candidate #0: obj=0x1B50251FE40 vector at +0x80
    uint64_t gmObj = 0x1B50251FE40;
    uint64_t vBegin = rpm<uint64_t>(gmObj + 0x80);
    uint64_t vEnd   = rpm<uint64_t>(gmObj + 0x88);
    if (!isHeapPtr(vBegin) || vEnd <= vBegin) {
        printf("[!] Vector at +0x80 invalid, trying candidate #1\n");
        gmObj = 0x1B5100D8100;
        vBegin = rpm<uint64_t>(gmObj + 0x1C8);
        vEnd   = rpm<uint64_t>(gmObj + 0x1D0);
    }

    int entCount = (int)((vEnd - vBegin) / 8);
    printf("[+] Entity list: %d entries (0x%llX - 0x%llX)\n",
           entCount, (unsigned long long)vBegin, (unsigned long long)vEnd);

    // Read all entity pointers
    std::vector<uint64_t> entPtrs(entCount);
    DmaRead(vBegin, entPtrs.data(), entCount * 8);

    int validEnts = 0;
    for (int i = 0; i < entCount; i++) {
        if (isHeapPtr(entPtrs[i])) validEnts++;
    }
    printf("[+] Valid pointers: %d/%d\n\n", validEnts, entCount);

    // ============================================================
    // STEP 1: Dump first 3 entities fully
    // ============================================================
    printf("--- Step 1: Dump first 3 valid entities ---\n");
    int dumped = 0;
    for (int i = 0; i < entCount && dumped < 3; i++) {
        if (!isHeapPtr(entPtrs[i])) continue;

        uint8_t entBuf[0x800];
        if (!DmaRead(entPtrs[i], entBuf, sizeof(entBuf))) continue;

        uint64_t vt = *(uint64_t*)entBuf;
        printf("\n  Entity[%d] = 0x%llX vtbl=+0x%llX\n",
               i, (unsigned long long)entPtrs[i],
               (unsigned long long)(isModPtr(vt) ? vt - g_base : 0));

        // Show first 0x100 bytes
        dumpHex(entBuf, 0x100, 0);

        // Show pointer fields
        printf("    Pointer fields:\n");
        for (int off = 0; off + 8 <= 0x800; off += 8) {
            uint64_t v = *(uint64_t*)(entBuf + off);
            if (isHeapPtr(v)) {
                uint64_t svt = rpm<uint64_t>(v);
                printf("      +0x%03X: 0x%llX", off, (unsigned long long)v);
                if (isModPtr(svt)) printf(" vtbl=+0x%llX", (unsigned long long)(svt - g_base));
                printf("\n");
            }
        }

        // Check known offsets
        printf("    Known offset checks:\n");

        // Entity+0x28 = EntityInfo
        uint64_t entInfo = *(uint64_t*)(entBuf + 0x28);
        printf("      +0x28 (EntityInfo?): 0x%llX", (unsigned long long)entInfo);
        if (isHeapPtr(entInfo)) {
            uint64_t eivt = rpm<uint64_t>(entInfo);
            if (isModPtr(eivt)) printf(" vtbl=+0x%llX", (unsigned long long)(eivt - g_base));

            // Read EntityInfo and dump
            uint8_t eiBuf[0x200];
            if (DmaRead(entInfo, eiBuf, sizeof(eiBuf))) {
                printf("\n      EntityInfo dump:\n");
                dumpHex(eiBuf, 0x100, 0);

                // EntityInfo+0xD8 = MainComponent
                uint64_t mainComp = *(uint64_t*)(eiBuf + 0xD8);
                if (isHeapPtr(mainComp)) {
                    printf("      EntityInfo+0xD8 (MainComp): 0x%llX\n", (unsigned long long)mainComp);
                    uint64_t childComp = rpm<uint64_t>(mainComp + 0x8);
                    if (isHeapPtr(childComp)) {
                        float hp = rpm<float>(childComp + 0x168);
                        printf("        ChildComp+0x168 (Health?): %.1f\n", hp);
                    }
                }

                // Try DEC chain from EntityInfo fields
                for (int eoff = 0x10; eoff + 8 <= 0x200; eoff += 8) {
                    uint64_t ev = *(uint64_t*)(eiBuf + eoff);
                    if (!isHeapPtr(ev)) continue;
                    Vec4 pos;
                    if (tryDecChain(ev, pos, "")) {
                        if (fabsf(pos.x) > 1 && fabsf(pos.x) < 5000) {
                            printf("      DEC chain from EI+0x%02X: (%.1f, %.1f, %.1f)\n",
                                   eoff, pos.x, pos.y, pos.z);
                        }
                    }
                }
            }
        }
        printf("\n");

        // Try DEC chain from entity+0x20
        printf("      DEC chain from ent+0x20:\n");
        uint64_t v0val = *(uint64_t*)(entBuf + 0x20);
        printf("        ent+0x20 = 0x%llX\n", (unsigned long long)v0val);
        if (isHeapPtr(v0val)) {
            uint64_t A = rpm<uint64_t>(v0val);
            printf("        *v0 = 0x%llX, DEC = 0x%llX\n", (unsigned long long)A, (unsigned long long)DEC(A));
            uint64_t d1 = DEC(A);
            if (d1 > 0x10000 && d1 < 0x7FFFFFFFFFFF) {
                uint64_t B = rpm<uint64_t>(d1);
                printf("        *d1 = 0x%llX, DEC = 0x%llX\n", (unsigned long long)B, (unsigned long long)DEC(B));
                uint64_t d2 = DEC(B);
                if (d2 > 0x10000 && d2 < 0x7FFFFFFFFFFF) {
                    uint64_t C = rpm<uint64_t>(d2);
                    printf("        *d2 = 0x%llX, DEC = 0x%llX\n", (unsigned long long)C, (unsigned long long)DEC(C));
                    uint64_t e1 = DEC(C);
                    if (e1 > 0x10000 && e1 < 0x7FFFFFFFFFFF) {
                        uint64_t E = rpm<uint64_t>(e1);
                        printf("        *e1 = 0x%llX, DEC = 0x%llX\n", (unsigned long long)E, (unsigned long long)DEC(E));
                        uint64_t pp = DEC(E);
                        if (pp > 0x10000 && pp < 0x7FFFFFFFFFFF) {
                            Vec4 pos = rpm<Vec4>(pp);
                            printf("        *** POS = (%.2f, %.2f, %.2f, %.2f) ***\n",
                                   pos.x, pos.y, pos.z, pos.w);
                        }
                    }
                }
            }
        }

        // Encryption flags
        uint16_t f5E = *(uint16_t*)(entBuf + 0x5E);
        uint16_t f6E = *(uint16_t*)(entBuf + 0x6E);
        printf("      Flags: +0x5E=0x%04X +0x6E=0x%04X (encrypted=%s)\n",
               f5E, f6E, (!f5E || !f6E) ? "YES" : "NO");

        // Unencrypted fallback at +0x50 and +0x60
        Vec4 p50 = *(Vec4*)(entBuf + 0x50);
        Vec4 p60 = *(Vec4*)(entBuf + 0x60);
        printf("      +0x50: (%.2f, %.2f, %.2f, %.2f)\n", p50.x, p50.y, p50.z, p50.w);
        printf("      +0x60: (%.2f, %.2f, %.2f, %.2f)\n", p60.x, p60.y, p60.z, p60.w);

        // Try known position offsets: +0x6A0 (Head), +0x700 (Feet)
        Vec4 head = rpm<Vec4>(entPtrs[i] + 0x6A0);
        Vec4 feet = rpm<Vec4>(entPtrs[i] + 0x700);
        printf("      +0x6A0 (Head?): (%.2f, %.2f, %.2f)\n", head.x, head.y, head.z);
        printf("      +0x700 (Feet?): (%.2f, %.2f, %.2f)\n", feet.x, feet.y, feet.z);

        // Scan ALL floats in the entity for world-position-like values
        printf("      World-position floats:\n");
        for (int off = 0; off + 12 <= 0x800; off += 4) {
            float x = *(float*)(entBuf + off);
            float y = *(float*)(entBuf + off + 4);
            float z = *(float*)(entBuf + off + 8);
            if (!isnan(x) && !isnan(y) && !isnan(z) &&
                fabsf(x) > 5 && fabsf(x) < 5000 &&
                fabsf(y) > 5 && fabsf(y) < 5000 &&
                fabsf(z) > 0.5f && fabsf(z) < 5000) {
                printf("        +0x%03X: (%.2f, %.2f, %.2f)\n", off, x, y, z);
            }
        }

        // Follow pointer chains and look for positions in sub-objects
        printf("      Sub-object position search:\n");
        for (int off = 8; off + 8 <= 0x200; off += 8) {
            uint64_t pv = *(uint64_t*)(entBuf + off);
            if (!isHeapPtr(pv)) continue;

            uint8_t sub[0x800];
            if (!DmaRead(pv, sub, sizeof(sub))) continue;

            for (int so = 0; so + 12 <= 0x800; so += 4) {
                float x = *(float*)(sub + so);
                float y = *(float*)(sub + so + 4);
                float z = *(float*)(sub + so + 8);
                if (!isnan(x) && !isnan(y) && !isnan(z) &&
                    fabsf(x) > 5 && fabsf(x) < 5000 &&
                    fabsf(y) > 5 && fabsf(y) < 5000 &&
                    z > 0.5f && z < 5000) {
                    printf("        +0x%02X->+0x%03X: (%.2f, %.2f, %.2f)\n",
                           off, so, x, y, z);
                    so += 8; // skip adjacent repeats
                }
            }
        }

        dumped++;
    }

    // ============================================================
    // STEP 2: Take 2 snapshots of all entity positions to find movers
    // ============================================================
    printf("\n--- Step 2: Double snapshot to find moving entities ---\n");
    struct EntSnap {
        uint64_t addr;
        uint8_t data1[0x800];
        uint8_t data2[0x800];
    };
    std::vector<EntSnap> snaps;
    for (int i = 0; i < entCount; i++) {
        if (!isHeapPtr(entPtrs[i])) continue;
        EntSnap s = {}; s.addr = entPtrs[i];
        if (DmaRead(entPtrs[i], s.data1, sizeof(s.data1))) snaps.push_back(s);
    }
    printf("  Snapshot 1: %d entities captured\n", (int)snaps.size());

    printf("  Waiting 3 seconds...\n");
    Sleep(3000);

    for (auto& s : snaps) DmaRead(s.addr, s.data2, sizeof(s.data2));
    printf("  Snapshot 2 done. Checking diffs...\n\n");

    for (auto& s : snaps) {
        int changed4 = 0;
        for (int off = 0; off < 0x800; off += 4) {
            if (*(uint32_t*)(s.data1 + off) != *(uint32_t*)(s.data2 + off)) changed4++;
        }
        if (changed4 == 0) continue;

        printf("  Entity 0x%llX: %d dwords changed\n", (unsigned long long)s.addr, changed4);

        // Show which float triples changed (position candidates)
        for (int off = 0; off + 12 <= 0x800; off += 4) {
            float x1 = *(float*)(s.data1 + off), y1 = *(float*)(s.data1 + off+4), z1 = *(float*)(s.data1 + off+8);
            float x2 = *(float*)(s.data2 + off), y2 = *(float*)(s.data2 + off+4), z2 = *(float*)(s.data2 + off+8);
            if (isnan(x1) || isnan(y1) || isnan(x2) || isnan(y2)) continue;
            float dx = x2-x1, dy = y2-y1, dz = z2-z1;
            float d = sqrtf(dx*dx + dy*dy + dz*dz);
            if (d > 0.01f && d < 100.0f && fabsf(x1) < 5000 && fabsf(y1) < 5000) {
                printf("    +0x%03X: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.3f\n",
                       off, x1, y1, z1, x2, y2, z2, d);
            }
        }

        // Also check pointer chain targets for movement
        for (int off = 8; off + 8 <= 0x100; off += 8) {
            uint64_t pv = *(uint64_t*)(s.data2 + off);
            if (!isHeapPtr(pv)) continue;

            // Read sub-object twice
            uint8_t sub1[0x200], sub2[0x200];
            if (!DmaRead(pv, sub1, sizeof(sub1))) continue;
            Sleep(500);
            if (!DmaRead(pv, sub2, sizeof(sub2))) continue;

            for (int so = 0; so + 12 <= 0x200; so += 4) {
                float x1 = *(float*)(sub1 + so), y1 = *(float*)(sub1 + so+4), z1 = *(float*)(sub1 + so+8);
                float x2 = *(float*)(sub2 + so), y2 = *(float*)(sub2 + so+4), z2 = *(float*)(sub2 + so+8);
                if (isnan(x1) || isnan(y1) || isnan(x2) || isnan(y2)) continue;
                float dx = x2-x1, dy = y2-y1, dz = z2-z1;
                float d = sqrtf(dx*dx + dy*dy + dz*dz);
                if (d > 0.01f && d < 100.0f && fabsf(x1) < 5000 && fabsf(y1) < 5000) {
                    printf("    +0x%02X->sub+0x%03X: (%.2f,%.2f,%.2f)->(%.2f,%.2f,%.2f) d=%.3f\n",
                           off, so, x1, y1, z1, x2, y2, z2, d);
                }
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
