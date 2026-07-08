// R6 Class ID Scanner — find GameManager + Entity chain using class IDs
// GameManager class ID: 0xED73CA81
// Entity class ID:      0x409F3D11
// Position decryption:  DEC(x) = ((x & 0xFFFFFFFFFFFF) ^ (0x100010001 * ((x >> 16) & 0xFFFF)))
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_classscan.cpp /Fe"../r6_classscan.exe" /link

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
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < g_base || v > g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }

#define DEC(x) (((x) & 0xFFFFFFFFFFFFULL) ^ (0x100010001ULL * (((x) >> 16) & 0xFFFF)))

struct Vec4 { float x, y, z, w; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Class ID Scanner ===\n");
    printf("GameManager ID: 0xED73CA81\n");
    printf("Entity ID:      0x409F3D11\n\n");

    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found\n"); return 1; }
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
    printf("[+] PID=%u Base=0x%llX End=0x%llX\n\n", g_pid, (unsigned long long)g_base, (unsigned long long)g_modEnd);

    // Find .data section
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
    printf("[+] .data: 0x%llX size=0x%llX (%.1f MB)\n\n",
           (unsigned long long)dataBase, (unsigned long long)dataSize, dataSize / 1048576.0);

    // ============================================================
    // STEP 1: Check known GameManager offsets from public sources
    // ============================================================
    printf("--- Step 1: Try known GameManager offsets ---\n");
    uint64_t knownOffsets[] = { 0x505E3B8, 0x4ECDD40 };
    for (auto off : knownOffsets) {
        if (off >= dataSize) continue;
        uint64_t val = rpm<uint64_t>(g_base + off);
        printf("  Base+0x%llX = 0x%llX", (unsigned long long)off, (unsigned long long)val);
        if (isHeapPtr(val)) {
            uint64_t vt = rpm<uint64_t>(val);
            printf(" [heap, vtbl=0x%llX]", (unsigned long long)vt);
        }
        printf("\n");
    }

    // ============================================================
    // STEP 2: Check our known entity for class ID location
    // ============================================================
    printf("\n--- Step 2: Check known entity for class ID pattern ---\n");
    uint64_t knownEnt = 0x227B172E030;
    uint8_t entBuf[0x100];
    if (DmaRead(knownEnt, entBuf, sizeof(entBuf))) {
        printf("  Known entity at 0x%llX:\n", (unsigned long long)knownEnt);
        // Check for class IDs at various offsets
        for (int off = 0; off + 4 <= 0x100; off += 4) {
            uint32_t v = *(uint32_t*)(entBuf + off);
            if (v == 0x409F3D11 || v == 0xED73CA81) {
                printf("  ** CLASS ID 0x%08X found at +0x%02X! **\n", v, off);
            }
        }
        // Also check vtable area for class ID
        uint64_t vtbl = *(uint64_t*)entBuf;
        if (isModPtr(vtbl)) {
            printf("  vtbl = 0x%llX (+0x%llX)\n", (unsigned long long)vtbl, (unsigned long long)(vtbl - g_base));
            // Read around the vtable for class IDs
            uint8_t vtBuf[0x80];
            DmaRead(vtbl - 0x40, vtBuf, sizeof(vtBuf));
            for (int off = 0; off + 4 <= 0x80; off += 4) {
                uint32_t v = *(uint32_t*)(vtBuf + off);
                if (v == 0x409F3D11 || v == 0xED73CA81) {
                    printf("  ** CLASS ID 0x%08X at vtbl%+d! **\n", v, off - 0x40);
                }
            }
        }
        // Dump first 0x40 bytes
        printf("  First 0x40 bytes:\n  ");
        for (int i = 0; i < 0x40; i++) {
            printf("%02X ", entBuf[i]);
            if ((i & 0xF) == 0xF) printf("\n  ");
        }
    }

    // ============================================================
    // STEP 3: Scan .data for class IDs directly
    // ============================================================
    printf("\n--- Step 3: Scan .data for GameManager class ID 0xED73CA81 ---\n");
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> dataBuf(CHUNK);
    int gmHits = 0, entHits = 0;

    uint64_t scanLimit = (dataSize < 0x600000) ? dataSize : 0x600000; // First 6MB
    for (uint64_t off = 0; off < scanLimit; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= scanLimit) ? CHUNK : scanLimit - off);
        if (!DmaRead(dataBase + off, dataBuf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 4 <= readSz; i += 4) {
            uint32_t v = *(uint32_t*)(dataBuf.data() + i);
            if (v == 0xED73CA81) {
                printf("  .data+0x%06llX: GameManager ID 0xED73CA81\n", (unsigned long long)(off + i));
                gmHits++;
                if (gmHits > 20) { printf("  ... (truncated)\n"); goto done_gm; }
            }
            if (v == 0x409F3D11 && entHits < 5) {
                printf("  .data+0x%06llX: Entity ID 0x409F3D11\n", (unsigned long long)(off + i));
                entHits++;
            }
        }
    }
    done_gm:
    printf("  Found: %d GameManager IDs, %d Entity IDs in .data\n", gmHits, entHits);

    // ============================================================
    // STEP 4: Scan .data pointers -> heap objects -> check for class IDs
    // ============================================================
    printf("\n--- Step 4: Scan heap objects for class IDs ---\n");
    std::set<uint64_t> heapPtrs;
    for (uint64_t off = 0; off < scanLimit; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= scanLimit) ? CHUNK : scanLimit - off);
        if (!DmaRead(dataBase + off, dataBuf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(dataBuf.data() + i);
            if (isHeapPtr(v)) heapPtrs.insert(v);
        }
    }
    printf("  %d unique heap pointers in .data\n", (int)heapPtrs.size());

    int scanned = 0, gmFound = 0;
    struct GMCandidate { uint64_t addr; uint64_t dataOff; int classIdOff; };
    std::vector<GMCandidate> gmCandidates;

    for (uint64_t ptr : heapPtrs) {
        scanned++;
        if (scanned % 10000 == 0) printf("  scanning %d/%d...\n", scanned, (int)heapPtrs.size());

        uint8_t objBuf[0x200];
        if (!DmaRead(ptr, objBuf, sizeof(objBuf))) continue;

        for (int off = 0; off + 4 <= 0x200; off += 4) {
            uint32_t v = *(uint32_t*)(objBuf + off);
            if (v == 0xED73CA81) {
                printf("  ** GAMEMANAGER found at heap 0x%llX +0x%02X **\n",
                       (unsigned long long)ptr, off);
                gmCandidates.push_back({ptr, 0, off});
                gmFound++;
                if (gmFound >= 10) goto done_heap;
                break;
            }
        }
    }
    done_heap:

    // ============================================================
    // STEP 5: For each GM candidate, try reading EntityList at +0xC8
    // ============================================================
    printf("\n--- Step 5: Try EntityList chain on GameManager candidates ---\n");
    for (auto& gm : gmCandidates) {
        printf("\n  GM at 0x%llX (classID at +0x%02X):\n", (unsigned long long)gm.addr, gm.classIdOff);

        // The GameManager object might start before the class ID
        // Try different base offsets
        for (int baseOff = 0; baseOff <= gm.classIdOff; baseOff += 8) {
            uint64_t gmBase = gm.addr + baseOff - gm.classIdOff;
            uint64_t entListVal = rpm<uint64_t>(gmBase + 0xC8);

            if (!isHeapPtr(entListVal)) continue;

            // Try reading as entity pointer array
            uint64_t entPtrs[20] = {};
            if (!DmaRead(entListVal, entPtrs, sizeof(entPtrs))) continue;

            int validEnts = 0;
            for (int k = 0; k < 20; k++) {
                if (isHeapPtr(entPtrs[k])) validEnts++;
            }

            if (validEnts < 2) continue;

            printf("    gmBase=0x%llX +0xC8 -> 0x%llX (%d valid ptrs)\n",
                   (unsigned long long)gmBase, (unsigned long long)entListVal, validEnts);

            // Check first few entities for Entity class ID and positions
            for (int k = 0; k < validEnts && k < 10; k++) {
                if (!isHeapPtr(entPtrs[k])) continue;

                uint8_t eBuf[0x100];
                if (!DmaRead(entPtrs[k], eBuf, sizeof(eBuf))) continue;

                // Search for Entity class ID
                bool hasEntId = false;
                int entIdOff = -1;
                for (int eo = 0; eo + 4 <= 0x100; eo += 4) {
                    if (*(uint32_t*)(eBuf + eo) == 0x409F3D11) {
                        hasEntId = true;
                        entIdOff = eo;
                        break;
                    }
                }

                printf("      ent[%d] 0x%llX", k, (unsigned long long)entPtrs[k]);
                if (hasEntId) printf(" classID=0x409F3D11@+0x%02X", entIdOff);

                // Try encrypted position chain from entity+0x20
                uint64_t v0 = *(uint64_t*)(eBuf + 0x20);
                if (isHeapPtr(v0)) {
                    uint64_t A = rpm<uint64_t>(v0);
                    uint64_t d1 = DEC(A);
                    if (d1 > 0x10000 && d1 < 0x7FFFFFFFFFFF) {
                        uint64_t B = rpm<uint64_t>(d1);
                        uint64_t d2 = DEC(B);
                        if (d2 > 0x10000 && d2 < 0x7FFFFFFFFFFF) {
                            uint64_t C = rpm<uint64_t>(d2);
                            uint64_t enc1 = DEC(C);
                            if (enc1 > 0x10000 && enc1 < 0x7FFFFFFFFFFF) {
                                uint64_t E = rpm<uint64_t>(enc1);
                                uint64_t pos_ptr = DEC(E);
                                if (pos_ptr > 0x10000 && pos_ptr < 0x7FFFFFFFFFFF) {
                                    Vec4 pos = rpm<Vec4>(pos_ptr);
                                    if (!isnan(pos.x) && fabsf(pos.x) < 5000 && fabsf(pos.z) < 5000) {
                                        printf(" POS=(%.1f,%.1f,%.1f)", pos.x, pos.y, pos.z);
                                    }
                                }
                            }
                        }
                    }
                }

                // Also try unencrypted position at +0x50 and +0x60
                Vec4 p50 = *(Vec4*)(eBuf + 0x50);
                Vec4 p60 = *(Vec4*)(eBuf + 0x60);
                if (!isnan(p50.x) && fabsf(p50.x) > 1 && fabsf(p50.x) < 5000)
                    printf(" p50=(%.1f,%.1f,%.1f)", p50.x, p50.y, p50.z);
                if (!isnan(p60.x) && fabsf(p60.x) > 1 && fabsf(p60.x) < 5000)
                    printf(" p60=(%.1f,%.1f,%.1f)", p60.x, p60.y, p60.z);

                printf("\n");
            }
        }
    }

    // ============================================================
    // STEP 6: Also scan .text section for the class ID pattern
    // ============================================================
    printf("\n--- Step 6: Scan .text for class ID references ---\n");
    uint64_t textBase = 0, textSize = 0;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".text", 5) == 0) {
            textBase = g_base + sec.VirtualAddress;
            textSize = sec.Misc.VirtualSize;
            break;
        }
    }

    // Search for mov reg, 0xED73CA81 pattern in first 2MB of .text
    int textHits = 0;
    uint64_t textScanLimit = (textSize < 0x200000) ? textSize : 0x200000;
    for (uint64_t off = 0; off < textScanLimit; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= textScanLimit) ? CHUNK : textScanLimit - off);
        if (!DmaRead(textBase + off, dataBuf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 4 <= readSz; i++) {
            if (*(uint32_t*)(dataBuf.data() + i) == 0xED73CA81) {
                printf("  .text+0x%06llX: ref to 0xED73CA81\n", (unsigned long long)(off + i));
                textHits++;
                if (textHits >= 10) goto done_text;
            }
        }
    }
    done_text:
    printf("  %d references in .text\n", textHits);

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
