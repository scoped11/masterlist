// R6 Sig Scanner v2 — broader search for global pointers + GameManager decryption
// Scans for MOV reg,[rip+?] instructions that load heap pointers from .data
// Also tries to find GameManager through manager proximity to ProfileManager
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_sigscan2.cpp /Fe"../r6_sigscan2.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <set>
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
static uint64_t g_dataBase, g_dataEnd;

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < g_base || v > g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }
static bool isDataPtr(uint64_t v) { return v >= g_dataBase && v < g_dataEnd; }

#define DEC(x) (((x) & 0xFFFFFFFFFFFFULL) ^ (0x100010001ULL * (((x) >> 16) & 0xFFFF)))

struct Vec4 { float x, y, z, w; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Sig Scanner v2 ===\n\n");

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

    uint64_t textBase = 0, textSize = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".text", 5) == 0) { textBase = g_base + sec.VirtualAddress; textSize = sec.Misc.VirtualSize; }
        if (memcmp(sec.Name, ".data", 5) == 0) { g_dataBase = g_base + sec.VirtualAddress; g_dataEnd = g_dataBase + sec.Misc.VirtualSize; }
    }

    // ============================================================
    // STEP 1: Scan .data around the known encrypted GM global
    // ============================================================
    printf("--- Step 1: Scan .data near GM encrypted ptr for unencrypted copies ---\n");
    // Encrypted GM global at Base+0x12036830
    // ProfileManager at Base+0x1217A840 (value = 0x1B489516BB0)
    uint64_t gmGlobal = g_base + 0x12036830;
    uint64_t pmGlobal = g_base + 0x1217A840;
    printf("  GM encrypted global: 0x%llX (Base+0x12036830)\n", (unsigned long long)gmGlobal);
    printf("  PM global: 0x%llX (Base+0x1217A840)\n", (unsigned long long)pmGlobal);

    // Scan .data in a region around these globals for heap pointers
    // Managers are typically stored in nearby globals
    uint64_t scanStart = gmGlobal - 0x10000;
    if (scanStart < g_dataBase) scanStart = g_dataBase;
    uint64_t scanEnd = pmGlobal + 0x10000;
    if (scanEnd > g_dataEnd) scanEnd = g_dataEnd;

    printf("  Scanning .data range 0x%llX - 0x%llX for heap pointers...\n",
           (unsigned long long)scanStart, (unsigned long long)scanEnd);

    struct GlobalPtr {
        uint64_t addr;      // address in .data
        uint64_t value;     // the value stored there
        uint64_t vtblRVA;   // vtable RVA of the pointed object
        bool hasEntityList;
        int entityCount;
    };
    std::vector<GlobalPtr> globals;

    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK);
    for (uint64_t off = scanStart; off < scanEnd; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= scanEnd) ? CHUNK : scanEnd - off);
        if (!DmaRead(off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(buf.data() + i);
            if (!isHeapPtr(v)) continue;

            uint64_t vt = rpm<uint64_t>(v);
            if (!isModPtr(vt)) continue;

            GlobalPtr gp = {};
            gp.addr = off + i;
            gp.value = v;
            gp.vtblRVA = vt - g_base;

            // Check for entity-list-like vectors in this object
            uint8_t objBuf[0x400];
            if (DmaRead(v, objBuf, sizeof(objBuf))) {
                for (int vo = 0x10; vo + 16 <= 0x400; vo += 8) {
                    uint64_t vBegin = *(uint64_t*)(objBuf + vo);
                    uint64_t vEnd   = *(uint64_t*)(objBuf + vo + 8);
                    if (!isHeapPtr(vBegin) || vEnd <= vBegin) continue;
                    if ((vEnd - vBegin) % 8 != 0) continue;
                    int cnt = (int)((vEnd - vBegin) / 8);
                    if (cnt < 5 || cnt > 200) continue;

                    int readN = (cnt > 20) ? 20 : cnt;
                    uint64_t ptrs[20] = {};
                    DmaRead(vBegin, ptrs, readN * 8);
                    int valid = 0;
                    for (int k = 0; k < readN; k++) {
                        if (isHeapPtr(ptrs[k])) {
                            uint64_t evt = rpm<uint64_t>(ptrs[k]);
                            if (isModPtr(evt)) valid++;
                        }
                    }
                    if (valid >= 3) {
                        gp.hasEntityList = true;
                        gp.entityCount = cnt;
                        break;
                    }
                }
            }

            globals.push_back(gp);
        }
    }

    printf("  Found %d heap-pointing globals in range\n\n", (int)globals.size());

    // Show those with entity lists first
    printf("  Globals with entity-list-like vectors:\n");
    for (auto& g : globals) {
        if (!g.hasEntityList) continue;
        printf("    0x%llX (Base+0x%llX) -> 0x%llX vtbl=+0x%llX entities=%d\n",
               (unsigned long long)g.addr, (unsigned long long)(g.addr - g_base),
               (unsigned long long)g.value, (unsigned long long)g.vtblRVA, g.entityCount);
    }

    // Show all globals grouped by proximity to GM/PM
    printf("\n  All globals near GM encrypted ptr (within +-0x100):\n");
    for (auto& g : globals) {
        int64_t dist = (int64_t)(g.addr - gmGlobal);
        if (dist >= -0x100 && dist <= 0x100) {
            printf("    GM%+5lld: 0x%llX -> 0x%llX vtbl=+0x%llX%s\n",
                   (long long)dist, (unsigned long long)g.addr, (unsigned long long)g.value,
                   (unsigned long long)g.vtblRVA, g.hasEntityList ? " [ENTITY LIST]" : "");
        }
    }

    // ============================================================
    // STEP 2: Flexible GameManager sig — shorter pattern
    // ============================================================
    printf("\n--- Step 2: Shorter GameManager sig (MOV RCX/RAX,[rip+?] → TEST → JE) ---\n");
    printf("  Looking for code that loads from Base+0x12036830 and uses it...\n");

    // The encrypted value is at Base+0x12036830
    // Any code that loads from this address will have a MOV with RIP-relative disp32
    // that resolves to Base+0x12036830
    // Pattern: 48 8B 0D/05 disp32 where [rip+7+disp32] = target

    struct CodeRef {
        uint64_t addr;
        uint8_t ctx[32];
    };
    std::vector<CodeRef> codeRefs;

    for (uint64_t off = 0; off < textSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK + 32 <= textSize) ? CHUNK + 32 : textSize - off);
        if (!DmaRead(textBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 7 <= readSz - 32; i++) {
            // Check for REX.W MOV reg, [rip+disp32]
            // 48 8B 0D dd dd dd dd  -> MOV RCX, [rip+dd]
            // 48 8B 05 dd dd dd dd  -> MOV RAX, [rip+dd]
            // 4C 8B 05 dd dd dd dd  -> MOV R8, [rip+dd]
            // 4C 8B 0D dd dd dd dd  -> MOV R9, [rip+dd]
            uint8_t b0 = buf[i], b1 = buf[i+1], b2 = buf[i+2];
            if ((b0 != 0x48 && b0 != 0x4C) || b1 != 0x8B) continue;
            if (b2 != 0x05 && b2 != 0x0D && b2 != 0x15 && b2 != 0x1D &&
                b2 != 0x25 && b2 != 0x2D && b2 != 0x35 && b2 != 0x3D) continue;

            int32_t disp = *(int32_t*)(buf.data() + i + 3);
            uint64_t target = textBase + off + i + 7 + disp;

            if (target == gmGlobal) {
                CodeRef cr = {};
                cr.addr = textBase + off + i;
                memcpy(cr.ctx, buf.data() + i, 32);
                codeRefs.push_back(cr);
            }
        }
    }

    printf("  Found %d code references to GM global\n", (int)codeRefs.size());
    for (int i = 0; i < (int)codeRefs.size() && i < 15; i++) {
        printf("    0x%llX (Base+0x%llX):",
               (unsigned long long)codeRefs[i].addr,
               (unsigned long long)(codeRefs[i].addr - g_base));
        for (int j = 0; j < 24; j++) printf(" %02X", codeRefs[i].ctx[j]);
        printf("\n");
    }

    // ============================================================
    // STEP 3: Check if GM is stored decrypted somewhere
    // ============================================================
    printf("\n--- Step 3: Search .data for decrypted GM pointer ---\n");
    // We know the encrypted value: 0x8F2A05CA785165DF
    // We need to find what it decrypts to.
    // Strategy: scan .data for heap pointers to objects with entity lists

    printf("  Scanning ALL .data for objects with entity-list vectors...\n");
    uint64_t dataSize = g_dataEnd - g_dataBase;
    int entityListObjs = 0;

    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= dataSize) ? CHUNK : dataSize - off);
        if (!DmaRead(g_dataBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(buf.data() + i);
            if (!isHeapPtr(v)) continue;

            uint64_t vt = rpm<uint64_t>(v);
            if (!isModPtr(vt)) continue;

            // Quick check: read object header for vector-like data at common offsets
            uint8_t hdr[0x200];
            if (!DmaRead(v, hdr, sizeof(hdr))) continue;

            for (int vo = 0xC0; vo <= 0xD0; vo += 8) { // common entity list offsets
                uint64_t vBegin = *(uint64_t*)(hdr + vo);
                uint64_t vEnd   = *(uint64_t*)(hdr + vo + 8);
                if (!isHeapPtr(vBegin) || vEnd <= vBegin) continue;
                if ((vEnd - vBegin) % 8 != 0) continue;
                int cnt = (int)((vEnd - vBegin) / 8);
                if (cnt < 5 || cnt > 200) continue;

                int readN = (cnt > 10) ? 10 : cnt;
                uint64_t ptrs[10] = {};
                DmaRead(vBegin, ptrs, readN * 8);
                int valid = 0;
                for (int k = 0; k < readN; k++) {
                    if (isHeapPtr(ptrs[k])) {
                        uint64_t evt = rpm<uint64_t>(ptrs[k]);
                        if (isModPtr(evt)) valid++;
                    }
                }
                if (valid >= 3) {
                    entityListObjs++;
                    printf("    .data+0x%llX -> 0x%llX vtbl=+0x%llX +0x%02X: %d entries, %d valid\n",
                           (unsigned long long)(off + i), (unsigned long long)v,
                           (unsigned long long)(vt - g_base), vo, cnt, valid);

                    // Show first few entities' vtables
                    for (int k = 0; k < readN && k < 5; k++) {
                        if (!isHeapPtr(ptrs[k])) continue;
                        uint64_t evt = rpm<uint64_t>(ptrs[k]);
                        printf("      ent[%d] 0x%llX vtbl=+0x%llX\n",
                               k, (unsigned long long)ptrs[k],
                               (unsigned long long)(isModPtr(evt) ? evt - g_base : 0));
                    }

                    if (entityListObjs >= 15) goto done_scan;
                }
            }
        }
    }
    done_scan:

    // ============================================================
    // STEP 4: Scan around ProfileManager for nearby managers
    // ============================================================
    printf("\n--- Step 4: Heap objects near ProfileManager ---\n");
    uint64_t pmObj = rpm<uint64_t>(pmGlobal); // 0x1B489516BB0
    printf("  ProfileManager object at 0x%llX\n", (unsigned long long)pmObj);

    // Scan memory pages around PM for other objects with vtables
    uint64_t pmPage = pmObj & ~0xFFFULL;
    for (uint64_t page = pmPage - 0x100000; page < pmPage + 0x100000; page += 0x1000) {
        uint8_t pageBuf[0x1000];
        if (!DmaRead(page, pageBuf, sizeof(pageBuf))) continue;

        for (int off = 0; off + 8 <= 0x1000; off += 8) {
            uint64_t v = *(uint64_t*)(pageBuf + off);
            if (!isModPtr(v)) continue;
            // This could be a vtable at the start of an object
            uint64_t objAddr = page + off;

            // Check if this object has a vector of entity pointers
            uint8_t objBuf[0x200];
            if (!DmaRead(objAddr, objBuf, sizeof(objBuf))) continue;

            for (int vo = 0xC0; vo <= 0xD0; vo += 8) {
                uint64_t vBegin = *(uint64_t*)(objBuf + vo);
                uint64_t vEnd   = *(uint64_t*)(objBuf + vo + 8);
                if (!isHeapPtr(vBegin) || vEnd <= vBegin) continue;
                if ((vEnd - vBegin) % 8 != 0) continue;
                int cnt = (int)((vEnd - vBegin) / 8);
                if (cnt < 5 || cnt > 200) continue;

                int readN = (cnt > 10) ? 10 : cnt;
                uint64_t ptrs[10] = {};
                DmaRead(vBegin, ptrs, readN * 8);
                int valid = 0;
                for (int k = 0; k < readN; k++) {
                    if (isHeapPtr(ptrs[k])) {
                        uint64_t evt = rpm<uint64_t>(ptrs[k]);
                        if (isModPtr(evt)) valid++;
                    }
                }
                if (valid >= 3) {
                    printf("    0x%llX vtbl=+0x%llX +0x%02X: %d entries, %d valid (PM dist=%+lld)\n",
                           (unsigned long long)objAddr, (unsigned long long)(v - g_base),
                           vo, cnt, valid, (long long)(objAddr - pmObj));
                }
            }
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
