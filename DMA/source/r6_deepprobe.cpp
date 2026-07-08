// R6 Deep Entity Probe — follow pointer chains from entity list,
// apply DEC position decryption at each depth, find real world positions
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_deepprobe.cpp /Fe"../r6_deepprobe.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <set>
#include <map>

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

bool tryDecChain(uint64_t objAddr, int startOff, Vec4& out) {
    uint8_t buf[0x80];
    if (!DmaRead(objAddr, buf, sizeof(buf))) return false;
    uint64_t v0 = *(uint64_t*)(buf + startOff);
    if (v0 < 0x10000 || v0 > 0x7FFFFFFFFFFF) return false;
    uint64_t A = rpm<uint64_t>(v0);
    if (A == 0) return false;
    uint64_t d1 = DEC(A);
    if (d1 < 0x10000 || d1 > 0x7FFFFFFFFFFF) return false;
    uint64_t B = rpm<uint64_t>(d1);
    if (B == 0) return false;
    uint64_t d2 = DEC(B);
    if (d2 < 0x10000 || d2 > 0x7FFFFFFFFFFF) return false;
    uint64_t C = rpm<uint64_t>(d2);
    if (C == 0) return false;
    uint64_t e1 = DEC(C);
    if (e1 < 0x10000 || e1 > 0x7FFFFFFFFFFF) return false;
    uint64_t E = rpm<uint64_t>(e1);
    if (E == 0) return false;
    uint64_t pp = DEC(E);
    if (pp < 0x10000 || pp > 0x7FFFFFFFFFFF) return false;
    out = rpm<Vec4>(pp);
    if (isnan(out.x) || isnan(out.y) || isnan(out.z)) return false;
    if (fabsf(out.x) > 10000 || fabsf(out.y) > 10000 || fabsf(out.z) > 10000) return false;
    return true;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Deep Entity Probe ===\n\n");

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

    // Read entity list from List170_A: Base+0x120E7228
    uint64_t listObj = rpm<uint64_t>(g_base + 0x120E7228);
    if (!isHeapPtr(listObj)) { printf("[!] List object invalid\n"); pClose(g_vmm); return 1; }

    uint64_t vBegin = rpm<uint64_t>(listObj + 0x140);
    uint64_t vEnd   = rpm<uint64_t>(listObj + 0x148);
    int entCount = (int)((vEnd - vBegin) / 8);
    printf("[+] Entity list: %d entries\n", entCount);

    int readN = (entCount > 50) ? 50 : entCount;
    std::vector<uint64_t> entPtrs(readN);
    DmaRead(vBegin, entPtrs.data(), readN * 8);

    // Collect valid entities
    struct EntInfo { uint64_t addr; uint64_t vtblRVA; };
    std::vector<EntInfo> ents;
    for (int i = 0; i < readN; i++) {
        if (!isHeapPtr(entPtrs[i])) continue;
        uint64_t vt = rpm<uint64_t>(entPtrs[i]);
        if (!isModPtr(vt)) continue;
        ents.push_back({entPtrs[i], vt - g_base});
    }
    printf("[+] Valid entities: %d\n\n", (int)ents.size());

    // Group by vtable
    std::map<uint64_t, int> vtCounts;
    for (auto& e : ents) vtCounts[e.vtblRVA]++;
    printf("  Vtable distribution:\n");
    for (auto& kv : vtCounts)
        printf("    +0x%llX: %d\n", (unsigned long long)kv.first, kv.second);

    // Per vtable type, probe one entity deep
    std::set<uint64_t> probed;
    for (auto& e : ents) {
        if (probed.count(e.vtblRVA)) continue;
        probed.insert(e.vtblRVA);

        printf("\n  === Entity 0x%llX vtbl=+0x%llX ===\n",
               (unsigned long long)e.addr, (unsigned long long)e.vtblRVA);

        uint8_t entBuf[0x200];
        if (!DmaRead(e.addr, entBuf, sizeof(entBuf))) continue;

        // DEC chain from entity at various offsets
        for (int off = 0x08; off + 8 <= 0x80; off += 8) {
            Vec4 pos;
            if (tryDecChain(e.addr, off, pos) && (pos.x != 0 || pos.y != 0 || pos.z != 0))
                printf("    DEC ent+0x%02X: (%.2f, %.2f, %.2f)\n", off, pos.x, pos.y, pos.z);
        }

        // Depth 1: follow pointer fields
        for (int off = 0x08; off + 8 <= 0x200; off += 8) {
            uint64_t sub = *(uint64_t*)(entBuf + off);
            if (!isHeapPtr(sub)) continue;
            uint64_t svt = rpm<uint64_t>(sub);
            if (!isModPtr(svt)) continue;

            // DEC chain from sub
            for (int doff = 0x10; doff <= 0x48; doff += 8) {
                Vec4 pos;
                if (tryDecChain(sub, doff, pos) && (fabsf(pos.x) > 0.1f || fabsf(pos.z) > 0.1f))
                    printf("    DEC +0x%02X->+0x%02X: (%.2f,%.2f,%.2f) svtbl=+0x%llX\n",
                           off, doff, pos.x, pos.y, pos.z, (unsigned long long)(svt - g_base));
            }

            // Raw pos at sub+0x50, +0x60
            Vec4 p50 = rpm<Vec4>(sub + 0x50);
            if (fabsf(p50.x) > 5 && fabsf(p50.x) < 5000 && fabsf(p50.y) > 5)
                printf("    RAW +0x%02X->+0x50: (%.2f,%.2f,%.2f)\n", off, p50.x, p50.y, p50.z);

            // Depth 2
            uint8_t subBuf[0x200];
            if (!DmaRead(sub, subBuf, sizeof(subBuf))) continue;
            for (int soff = 0x08; soff + 8 <= 0x200; soff += 8) {
                uint64_t sub2 = *(uint64_t*)(subBuf + soff);
                if (!isHeapPtr(sub2)) continue;
                uint64_t s2vt = rpm<uint64_t>(sub2);
                if (!isModPtr(s2vt)) continue;

                for (int doff = 0x10; doff <= 0x48; doff += 8) {
                    Vec4 pos;
                    if (tryDecChain(sub2, doff, pos) && fabsf(pos.x) > 0.5f && fabsf(pos.x) < 5000)
                        printf("    DEC +0x%02X->+0x%02X->+0x%02X: (%.2f,%.2f,%.2f) s2vtbl=+0x%llX\n",
                               off, soff, doff, pos.x, pos.y, pos.z, (unsigned long long)(s2vt - g_base));
                }

                Vec4 dp50 = rpm<Vec4>(sub2 + 0x50);
                if (fabsf(dp50.x) > 5 && fabsf(dp50.x) < 5000 && fabsf(dp50.y) > 5)
                    printf("    RAW +0x%02X->+0x%02X->+0x50: (%.2f,%.2f,%.2f)\n",
                           off, soff, dp50.x, dp50.y, dp50.z);

                // Depth 3
                uint8_t s2Buf[0x100];
                if (!DmaRead(sub2, s2Buf, sizeof(s2Buf))) continue;
                for (int s2off = 0x08; s2off + 8 <= 0x100; s2off += 8) {
                    uint64_t sub3 = *(uint64_t*)(s2Buf + s2off);
                    if (!isHeapPtr(sub3)) continue;
                    uint64_t s3vt = rpm<uint64_t>(sub3);
                    if (!isModPtr(s3vt)) continue;

                    for (int doff : {0x20, 0x28, 0x30}) {
                        Vec4 pos;
                        if (tryDecChain(sub3, doff, pos) && fabsf(pos.x) > 0.5f && fabsf(pos.x) < 5000)
                            printf("    DEC +0x%02X->+0x%02X->+0x%02X->+0x%02X: (%.2f,%.2f,%.2f)\n",
                                   off, soff, s2off, doff, pos.x, pos.y, pos.z);
                    }

                    Vec4 dp = rpm<Vec4>(sub3 + 0x50);
                    if (fabsf(dp.x) > 5 && fabsf(dp.x) < 5000 && fabsf(dp.y) > 5)
                        printf("    RAW +0x%02X->+0x%02X->+0x%02X->+0x50: (%.2f,%.2f,%.2f)\n",
                               off, soff, s2off, dp.x, dp.y, dp.z);
                }
            }
        }
    }

    // ============================================================
    // Also re-find position buffer entity by scanning .data deeply
    // ============================================================
    printf("\n\n--- Searching for position buffer entity (vtbl=+0x115E7F10) ---\n");
    uint64_t targetVtbl = g_base + 0x115E7F10;
    uint64_t dataBase = 0, dataSize = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".data", 5) == 0) { dataBase = g_base + sec.VirtualAddress; dataSize = sec.Misc.VirtualSize; }
    }

    std::set<uint64_t> heapPtrs;
    const uint32_t CHUNK = 0x40000;
    std::vector<uint8_t> buf(CHUNK);
    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= dataSize) ? CHUNK : dataSize - off);
        if (!DmaRead(dataBase + off, buf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(buf.data() + i);
            if (isHeapPtr(v)) heapPtrs.insert(v);
        }
    }
    printf("  %d heap pointers, scanning 2-level deep...\n", (int)heapPtrs.size());

    int found = 0, scanned = 0;
    for (uint64_t ptr : heapPtrs) {
        scanned++;
        if (scanned % 30000 == 0) printf("  %d/%d...\n", scanned, (int)heapPtrs.size());

        uint64_t vt = rpm<uint64_t>(ptr);
        if (vt == targetVtbl) {
            printf("  *** DIRECT: 0x%llX ***\n", (unsigned long long)ptr);
            found++; continue;
        }
        if (!isModPtr(vt)) continue;

        uint8_t hdr[0x200];
        if (!DmaRead(ptr, hdr, sizeof(hdr))) continue;
        for (int off = 8; off + 8 <= 0x200; off += 8) {
            uint64_t sub = *(uint64_t*)(hdr + off);
            if (!isHeapPtr(sub)) continue;
            uint64_t svt = rpm<uint64_t>(sub);
            if (svt == targetVtbl) {
                printf("  *** VIA 0x%llX+0x%02X → 0x%llX (parent vtbl=+0x%llX) ***\n",
                       (unsigned long long)ptr, off, (unsigned long long)sub,
                       (unsigned long long)(vt - g_base));
                found++;
            }
        }
        if (found >= 3) break;
    }
    if (!found) printf("  Not found.\n");

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
