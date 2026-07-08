// R6 Class ID Scanner v2 — vtable metadata, type descriptors, string search
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_classscan2.cpp /Fe"../r6_classscan2.exe" /link
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

static bool DmaRead(uint64_t va, void* buf, uint32_t sz) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, sz, &cb, 0x0001 | 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v < g_base || v > g_modEnd); }
static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }
static bool isAnyPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }

#define DEC(x) (((x) & 0xFFFFFFFFFFFFULL) ^ (0x100010001ULL * (((x) >> 16) & 0xFFFF)))

struct Vec4 { float x, y, z, w; };

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Class ID Scanner v2 ===\n\n");

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
    printf("[+] PID=%u Base=0x%llX End=0x%llX ImageSize=0x%X\n\n",
           g_pid, (unsigned long long)g_base, (unsigned long long)g_modEnd,
           nt.OptionalHeader.SizeOfImage);

    // ============================================================
    // STEP 1: Try known GameManager pointer offsets (from community)
    // ============================================================
    printf("--- Step 1: Known GameManager pointer offsets ---\n");
    uint64_t offsets[] = { 0x505E3B8, 0x4ECDD40, 0x505E3A0, 0x505E3A8, 0x505E3B0, 0x505E3C0 };
    for (auto off : offsets) {
        uint64_t addr = g_base + off;
        if (addr >= g_modEnd) continue;
        uint64_t val = rpm<uint64_t>(addr);
        printf("  Base+0x%llX (0x%llX) = 0x%llX",
               (unsigned long long)off, (unsigned long long)addr, (unsigned long long)val);
        if (isHeapPtr(val)) {
            uint64_t vt = rpm<uint64_t>(val);
            printf(" [heap]");
            if (isModPtr(vt)) printf(" vtbl=+0x%llX", (unsigned long long)(vt - g_base));

            // Check if this has an entity list at +0xC8
            uint64_t entList = rpm<uint64_t>(val + 0xC8);
            if (isHeapPtr(entList)) {
                printf(" +0xC8=0x%llX", (unsigned long long)entList);
                // Try reading as pointer array
                uint64_t ptrs[5] = {};
                DmaRead(entList, ptrs, sizeof(ptrs));
                int valid = 0;
                for (int k = 0; k < 5; k++) if (isHeapPtr(ptrs[k])) valid++;
                if (valid > 0) printf(" [%d valid ptrs]", valid);
            }
        } else if (val == 0) {
            printf(" [NULL]");
        }
        printf("\n");
    }

    // ============================================================
    // STEP 2: Deep vtable metadata analysis of known entity
    // ============================================================
    printf("\n--- Step 2: Deep vtable analysis of known entity ---\n");
    uint64_t knownEnt = 0x227B172E030;
    uint8_t entBuf[0x100];
    if (DmaRead(knownEnt, entBuf, sizeof(entBuf))) {
        uint64_t vtbl = *(uint64_t*)entBuf;
        printf("  Entity 0x%llX, vtbl=0x%llX (+0x%llX)\n",
               (unsigned long long)knownEnt, (unsigned long long)vtbl, (unsigned long long)(vtbl - g_base));

        // Read extended vtable area: vtbl-0x80 to vtbl+0x80
        uint8_t vtArea[0x200];
        uint64_t vtStart = vtbl - 0x100;
        if (DmaRead(vtStart, vtArea, sizeof(vtArea))) {
            printf("  Vtable area (vtbl-0x100 to vtbl+0x100):\n");
            printf("  Pointers and values before vtable:\n");
            for (int i = 0; i < 0x100; i += 8) {
                uint64_t v = *(uint64_t*)(vtArea + i);
                int relOff = i - 0x100;
                if (v == 0) continue;
                printf("    vtbl%+4d: 0x%016llX", relOff, (unsigned long long)v);
                if (isModPtr(v)) {
                    printf(" [mod +0x%llX]", (unsigned long long)(v - g_base));
                } else if (isHeapPtr(v)) {
                    printf(" [heap]");
                } else if (v < 0x100000) {
                    printf(" [small=%llu]", (unsigned long long)v);
                }
                // Check if it's a class ID candidate
                uint32_t lo = (uint32_t)v;
                uint32_t hi = (uint32_t)(v >> 32);
                if (lo == 0xED73CA81 || lo == 0x409F3D11)
                    printf(" *** CLASS ID ***");
                if (hi == 0xED73CA81 || hi == 0x409F3D11)
                    printf(" *** CLASS ID (hi) ***");
                printf("\n");
            }

            // Follow pre-vtable pointers to find TypeInfo structures
            printf("\n  Following pre-vtable pointers:\n");
            for (int i = 0; i < 0x100; i += 8) {
                uint64_t v = *(uint64_t*)(vtArea + i);
                int relOff = i - 0x100;
                if (!isModPtr(v) && !isHeapPtr(v)) continue;

                uint8_t subBuf[0x100];
                if (!DmaRead(v, subBuf, sizeof(subBuf))) continue;

                // Search for class IDs in this target
                for (int j = 0; j + 4 <= 0x100; j += 4) {
                    uint32_t sv = *(uint32_t*)(subBuf + j);
                    if (sv == 0x409F3D11 || sv == 0xED73CA81) {
                        printf("    vtbl%+4d -> 0x%llX +0x%02X: CLASS ID 0x%08X!\n",
                               relOff, (unsigned long long)v, j, sv);
                    }
                }

                // Also look for ASCII strings ("Entity", "GameManager")
                for (int j = 0; j + 6 <= 0x100; j++) {
                    if (memcmp(subBuf + j, "Entity", 6) == 0 || memcmp(subBuf + j, "Game", 4) == 0) {
                        char str[64] = {};
                        int slen = 0;
                        for (int k = j; k < 0x100 && subBuf[k] >= 0x20 && subBuf[k] < 0x7F && slen < 63; k++)
                            str[slen++] = (char)subBuf[k];
                        printf("    vtbl%+4d -> 0x%llX +0x%02X: STRING \"%s\"\n",
                               relOff, (unsigned long long)v, j, str);
                    }
                }
            }
        }

        // Also check object fields for type info pointers
        printf("\n  Object fields with type info:\n");
        for (int off = 8; off + 8 <= 0x100; off += 8) {
            uint64_t v = *(uint64_t*)(entBuf + off);
            if (!isHeapPtr(v)) continue;

            uint8_t subBuf[0x100];
            if (!DmaRead(v, subBuf, sizeof(subBuf))) continue;

            for (int j = 0; j + 4 <= 0x100; j += 4) {
                uint32_t sv = *(uint32_t*)(subBuf + j);
                if (sv == 0x409F3D11 || sv == 0xED73CA81) {
                    printf("    ent+0x%02X -> 0x%llX +0x%02X: CLASS ID 0x%08X!\n",
                           off, (unsigned long long)v, j, sv);
                }
            }
        }
    }

    // ============================================================
    // STEP 3: Search for "GameManager" and "Entity" strings in .rdata
    // ============================================================
    printf("\n--- Step 3: String search in module ---\n");
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    struct Section { uint64_t base; uint32_t size; char name[9]; };
    std::vector<Section> sections;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        Section s;
        s.base = g_base + sec.VirtualAddress;
        s.size = sec.Misc.VirtualSize;
        memcpy(s.name, sec.Name, 8); s.name[8] = 0;
        sections.push_back(s);
        printf("  Section %-8s: 0x%llX size=0x%08X (%.1f MB)\n",
               s.name, (unsigned long long)s.base, s.size, s.size / 1048576.0);
    }

    const char* searchStrs[] = { "GameManager", "EntityList", "m_Origin", "m_Position" };
    const uint32_t CHUNK = 0x40000;
    std::vector<uint8_t> buf(CHUNK);

    for (auto& sec : sections) {
        if (sec.name[0] == '.' && (sec.name[1] == 'r' || sec.name[1] == 'd')) {
            // Scan .rdata and .data for strings
            uint64_t limit = (sec.size < 0x2000000) ? sec.size : 0x2000000;
            for (uint64_t off = 0; off < limit; off += CHUNK) {
                uint32_t readSz = (uint32_t)((off + CHUNK <= limit) ? CHUNK : limit - off);
                if (!DmaRead(sec.base + off, buf.data(), readSz)) continue;

                for (uint32_t i = 0; i + 12 <= readSz; i++) {
                    for (auto str : searchStrs) {
                        int slen = (int)strlen(str);
                        if (i + slen <= readSz && memcmp(buf.data() + i, str, slen) == 0) {
                            char ctx[80] = {};
                            int clen = 0;
                            for (int k = (int)i; k < (int)readSz && buf[k] >= 0x20 && buf[k] < 0x7F && clen < 79; k++)
                                ctx[clen++] = (char)buf[k];
                            printf("  %s +0x%llX: \"%s\"\n",
                                   sec.name, (unsigned long long)(off + i), ctx);
                        }
                    }
                }
            }
        }
    }

    // ============================================================
    // STEP 4: FULL .text scan for class ID immediates
    // ============================================================
    printf("\n--- Step 4: Full .text scan for class ID immediates ---\n");
    for (auto& sec : sections) {
        if (memcmp(sec.name, ".text", 5) != 0) continue;

        printf("  Scanning .text (%.1f MB)...\n", sec.size / 1048576.0);
        int hits = 0;
        for (uint64_t off = 0; off < sec.size; off += CHUNK) {
            uint32_t readSz = (uint32_t)((off + CHUNK <= sec.size) ? CHUNK : sec.size - off);
            if (!DmaRead(sec.base + off, buf.data(), readSz)) continue;

            for (uint32_t i = 0; i + 4 <= readSz; i++) {
                uint32_t v = *(uint32_t*)(buf.data() + i);
                if (v == 0xED73CA81 || v == 0x409F3D11) {
                    printf("    .text+0x%08llX: 0x%08X", (unsigned long long)(off + i), v);
                    // Show context bytes for instruction decoding
                    printf(" ctx:");
                    int start = (i >= 4) ? (int)i - 4 : 0;
                    int end = (i + 12 <= readSz) ? (int)i + 12 : readSz;
                    for (int k = start; k < end; k++) printf(" %02X", buf[k]);
                    printf("\n");
                    hits++;
                    if (hits >= 30) goto done_text;
                }
            }
        }
        done_text:
        printf("  Total .text hits: %d\n", hits);
    }

    // ============================================================
    // STEP 5: Full .rdata scan for class IDs
    // ============================================================
    printf("\n--- Step 5: Full .rdata scan for class IDs ---\n");
    for (auto& sec : sections) {
        if (sec.name[0] != '.' || sec.name[1] != 'r') continue;

        printf("  Scanning %s (%.1f MB)...\n", sec.name, sec.size / 1048576.0);
        int hits = 0;
        uint64_t limit = sec.size;
        for (uint64_t off = 0; off < limit; off += CHUNK) {
            uint32_t readSz = (uint32_t)((off + CHUNK <= limit) ? CHUNK : limit - off);
            if (!DmaRead(sec.base + off, buf.data(), readSz)) continue;

            for (uint32_t i = 0; i + 4 <= readSz; i += 4) {
                uint32_t v = *(uint32_t*)(buf.data() + i);
                if (v == 0xED73CA81 || v == 0x409F3D11) {
                    printf("    %s+0x%08llX: 0x%08X", sec.name, (unsigned long long)(off + i), v);
                    // Show surrounding qwords for context
                    int base = (i >= 16) ? (int)i - 16 : 0;
                    printf("  nearby:");
                    for (int k = base; k < (int)i + 16 && k + 8 <= (int)readSz; k += 8) {
                        uint64_t qv = *(uint64_t*)(buf.data() + k);
                        if (k == (int)i) printf(" [");
                        printf(" %016llX", (unsigned long long)qv);
                        if (k == (int)i) printf("]");
                    }
                    printf("\n");
                    hits++;
                    if (hits >= 30) goto done_rdata;
                }
            }
        }
        done_rdata:
        printf("  Total %s hits: %d\n", sec.name, hits);
    }

    // ============================================================
    // STEP 6: Try the encrypted GameManager pointer approach
    // ============================================================
    printf("\n--- Step 6: Try encrypted GameManager pointer (XOR+ROL) ---\n");
    // In some R6 builds, the GameManager pointer is at a known offset but encrypted
    // The encryption is: ptr = ROR(stored ^ key, rotation)
    // Try different key derivation patterns around known offsets
    for (auto off : offsets) {
        uint64_t addr = g_base + off;
        if (addr >= g_modEnd) continue;

        // Read a block around the offset
        uint8_t area[0x40];
        if (!DmaRead(addr - 0x10, area, sizeof(area))) continue;

        uint64_t stored = *(uint64_t*)(area + 0x10); // The value at the offset
        if (stored == 0) continue;

        printf("  Offset 0x%llX stored=0x%llX\n", (unsigned long long)off, (unsigned long long)stored);

        // Try DEC decryption
        uint64_t dec = DEC(stored);
        printf("    DEC(stored) = 0x%llX", (unsigned long long)dec);
        if (isHeapPtr(dec)) {
            printf(" [VALID HEAP!]");
            uint64_t vt = rpm<uint64_t>(dec);
            if (isModPtr(vt))
                printf(" vtbl=+0x%llX", (unsigned long long)(vt - g_base));
        }
        printf("\n");

        // Try XOR with various keys near the address
        for (int ki = 0; ki < 0x40; ki += 8) {
            uint64_t key = *(uint64_t*)(area + ki);
            if (key == 0 || key == stored) continue;
            uint64_t dec2 = stored ^ key;
            if (isHeapPtr(dec2)) {
                uint64_t vt = rpm<uint64_t>(dec2);
                if (isModPtr(vt)) {
                    printf("    XOR(key@-%d) = 0x%llX vtbl=+0x%llX\n",
                           0x10 - ki, (unsigned long long)dec2, (unsigned long long)(vt - g_base));
                }
            }
        }

        // Try ROL/ROR with common rotations
        for (int rot = 1; rot <= 63; rot++) {
            uint64_t ror_val = (stored >> rot) | (stored << (64 - rot));
            if (isHeapPtr(ror_val)) {
                uint64_t vt = rpm<uint64_t>(ror_val);
                if (isModPtr(vt)) {
                    printf("    ROR(%d) = 0x%llX vtbl=+0x%llX\n",
                           rot, (unsigned long long)ror_val, (unsigned long long)(vt - g_base));
                }
            }
        }
    }

    // ============================================================
    // STEP 7: Try position reading on known entity using DEC chain
    // ============================================================
    printf("\n--- Step 7: Try DEC position chain on known entity ---\n");
    if (DmaRead(knownEnt, entBuf, 0x100)) {
        // Check encryption flags
        uint16_t flag5E = *(uint16_t*)(entBuf + 0x5E);
        uint16_t flag6E = *(uint16_t*)(entBuf + 0x6E);
        printf("  Entity 0x%llX: flag@0x5E=0x%04X flag@0x6E=0x%04X\n",
               (unsigned long long)knownEnt, flag5E, flag6E);
        printf("  Encrypted: %s (enc5E=%d enc6E=%d)\n",
               (!flag5E || !flag6E) ? "YES" : "NO", !flag5E, !flag6E);

        // Try encrypted path: entity+0x20 -> chain
        uint64_t v0 = *(uint64_t*)(entBuf + 0x20);
        printf("  ent+0x20 = 0x%llX", (unsigned long long)v0);
        if (isAnyPtr(v0)) {
            printf(" [ptr]");
            uint64_t A = rpm<uint64_t>(v0);
            uint64_t d1 = DEC(A);
            printf("\n    A=0x%llX DEC(A)=0x%llX", (unsigned long long)A, (unsigned long long)d1);
            if (isAnyPtr(d1)) {
                uint64_t B = rpm<uint64_t>(d1);
                uint64_t d2 = DEC(B);
                printf("\n    B=0x%llX DEC(B)=0x%llX", (unsigned long long)B, (unsigned long long)d2);
                if (isAnyPtr(d2)) {
                    uint64_t C = rpm<uint64_t>(d2);
                    uint64_t enc1 = DEC(C);
                    printf("\n    C=0x%llX DEC(C)=0x%llX", (unsigned long long)C, (unsigned long long)enc1);
                    if (isAnyPtr(enc1)) {
                        uint64_t E = rpm<uint64_t>(enc1);
                        uint64_t pos_ptr = DEC(E);
                        printf("\n    E=0x%llX DEC(E)=0x%llX", (unsigned long long)E, (unsigned long long)pos_ptr);
                        if (isAnyPtr(pos_ptr)) {
                            Vec4 pos = rpm<Vec4>(pos_ptr);
                            printf("\n    *** POSITION: (%.2f, %.2f, %.2f, %.2f) ***",
                                   pos.x, pos.y, pos.z, pos.w);
                        }
                    }
                }
            }
        }
        printf("\n");

        // Try unencrypted paths
        Vec4 p50 = *(Vec4*)(entBuf + 0x50);
        Vec4 p60 = *(Vec4*)(entBuf + 0x60);
        printf("  ent+0x50: (%.2f, %.2f, %.2f, %.2f)\n", p50.x, p50.y, p50.z, p50.w);
        printf("  ent+0x60: (%.2f, %.2f, %.2f, %.2f)\n", p60.x, p60.y, p60.z, p60.w);

        // Dump first 0x80 bytes with labels
        printf("\n  Raw hex dump:\n");
        for (int i = 0; i < 0x80; i += 16) {
            printf("    +%02X:", i);
            for (int j = 0; j < 16; j++) printf(" %02X", entBuf[i + j]);
            printf("  ");
            for (int j = 0; j < 16; j++) {
                char c = (char)entBuf[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
            printf("\n");
        }
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
