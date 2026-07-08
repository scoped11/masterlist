// R6 GameManager Finder — behavioral analysis + UBX type registry scan
// Finds GM by: global ptr → object with entity vector → entities with positions
// Also scans UBX sections for type registry and class IDs
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_gmfinder.cpp /Fe"../r6_gmfinder.exe" /link
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

#define DEC(x) (((x) & 0xFFFFFFFFFFFFULL) ^ (0x100010001ULL * (((x) >> 16) & 0xFFFF)))

struct Vec4 { float x, y, z, w; };

struct Section { uint64_t base; uint32_t size; char name[9]; };
std::vector<Section> g_sections;

bool tryDecPosition(uint64_t entAddr, Vec4& out) {
    uint8_t eb[0x80];
    if (!DmaRead(entAddr, eb, sizeof(eb))) return false;

    uint16_t f5E = *(uint16_t*)(eb + 0x5E);
    uint16_t f6E = *(uint16_t*)(eb + 0x6E);
    bool encrypted = (!f5E || !f6E);

    if (encrypted) {
        uint64_t v0 = *(uint64_t*)(eb + 0x20);
        if (v0 < 0x10000 || v0 > 0x7FFFFFFFFFFF) return false;
        uint64_t A = rpm<uint64_t>(v0);
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
    } else {
        Vec4 p50 = *(Vec4*)(eb + 0x50);
        if (p50.x != 0.f || p50.y != 0.f || p50.z != 0.f) { out = p50; }
        else { out = *(Vec4*)(eb + 0x60); }
    }

    if (isnan(out.x) || isnan(out.y) || isnan(out.z)) return false;
    if (fabsf(out.x) > 10000 || fabsf(out.y) > 10000 || fabsf(out.z) > 10000) return false;
    if (out.x == 0.f && out.y == 0.f && out.z == 0.f) return false;
    return true;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 GameManager Finder ===\n\n");

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
    printf("[+] PID=%u Base=0x%llX End=0x%llX\n\n", g_pid,
           (unsigned long long)g_base, (unsigned long long)g_modEnd);

    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    uint64_t dataBase = 0, dataSize = 0;
    uint64_t rdataBase = 0, rdataSize = 0;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        Section s; s.base = g_base + sec.VirtualAddress; s.size = sec.Misc.VirtualSize;
        memcpy(s.name, sec.Name, 8); s.name[8] = 0;
        g_sections.push_back(s);
        if (memcmp(sec.Name, ".data", 5) == 0) { dataBase = s.base; dataSize = s.size; }
        if (memcmp(sec.Name, ".rdata", 6) == 0) { rdataBase = s.base; rdataSize = s.size; }
    }

    // ============================================================
    // STEP 1: Broad string search for GameManager in .rdata
    // ============================================================
    printf("--- Step 1: Search .rdata for GameManager/Entity strings ---\n");
    const uint32_t CHUNK = 0x40000;
    std::vector<uint8_t> buf(CHUNK);
    std::vector<uint64_t> gmStringAddrs;

    for (uint64_t off = 0; off < rdataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= rdataSize) ? CHUNK : rdataSize - off);
        if (!DmaRead(rdataBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i + 4 <= readSz; i++) {
            bool match = false;
            const char* what = "";
            if (i + 11 <= readSz && memcmp(buf.data() + i, "GameManager", 11) == 0) {
                match = true; what = "GameManager";
            } else if (i + 6 <= readSz && memcmp(buf.data() + i, "Entity", 6) == 0) {
                match = true; what = "Entity";
            } else if (i + 10 <= readSz && memcmp(buf.data() + i, "m_Position", 10) == 0) {
                match = true; what = "m_Position";
            } else if (i + 8 <= readSz && memcmp(buf.data() + i, "m_Origin", 8) == 0) {
                match = true; what = "m_Origin";
            } else if (i + 10 <= readSz && memcmp(buf.data() + i, "m_pManager", 10) == 0) {
                match = true; what = "m_pManager";
            }
            if (!match) continue;

            char ctx[80] = {};
            int cl = 0;
            for (uint32_t k = i; k < readSz && buf[k] >= 0x20 && buf[k] < 0x7F && cl < 79; k++)
                ctx[cl++] = (char)buf[k];
            uint64_t strAddr = rdataBase + off + i;
            printf("  0x%llX (.rdata+0x%llX): \"%s\"\n",
                   (unsigned long long)strAddr, (unsigned long long)(off + i), ctx);
            if (strncmp(what, "GameManager", 11) == 0 && strlen(ctx) < 20)
                gmStringAddrs.push_back(strAddr);
        }
    }

    // ============================================================
    // STEP 2: XREF — find what references the "GameManager" string
    // ============================================================
    printf("\n--- Step 2: XREF for GameManager string addresses ---\n");
    for (uint64_t strAddr : gmStringAddrs) {
        printf("  Searching for references to 0x%llX...\n", (unsigned long long)strAddr);
        // Search .rdata and .data for pointers to this string
        for (auto& sec : g_sections) {
            if (sec.name[0] != '.' || (sec.name[1] != 'r' && sec.name[1] != 'd' && sec.name[1] != 'U')) continue;
            uint64_t limit = (sec.size < 0x2000000) ? sec.size : 0x2000000;
            for (uint64_t off = 0; off < limit; off += CHUNK) {
                uint32_t readSz = (uint32_t)((off + CHUNK <= limit) ? CHUNK : limit - off);
                if (!DmaRead(sec.base + off, buf.data(), readSz)) continue;
                for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
                    uint64_t v = *(uint64_t*)(buf.data() + i);
                    if (v == strAddr) {
                        printf("    XREF: %s+0x%llX (abs 0x%llX)\n",
                               sec.name, (unsigned long long)(off + i),
                               (unsigned long long)(sec.base + off + i));
                        // Dump surrounding data for context
                        int dumpStart = (i >= 0x40) ? (int)(i - 0x40) : 0;
                        int dumpEnd = (i + 0x80 <= readSz) ? (int)(i + 0x80) : readSz;
                        printf("    Context (qwords around XREF):\n");
                        for (int j = dumpStart; j + 8 <= dumpEnd; j += 8) {
                            uint64_t qv = *(uint64_t*)(buf.data() + j);
                            printf("      %s+0x%llX: 0x%016llX",
                                   sec.name, (unsigned long long)(off + j), (unsigned long long)qv);
                            if (j == (int)i) printf(" <-- XREF");
                            if (isModPtr(qv)) printf(" [mod]");
                            if (isHeapPtr(qv)) printf(" [heap]");
                            if ((qv & 0xFFFFFFFF00000000ULL) == 0 && qv > 0 && qv < 0x1000)
                                printf(" [small=%llu]", (unsigned long long)qv);
                            printf("\n");
                        }
                    }
                }
            }
        }

        // Also search .text for LEA references (RIP-relative)
        // LEA reg, [rip+disp32] = 48 8D xx yy yy yy yy
        printf("  Searching .text for LEA refs...\n");
        for (auto& sec : g_sections) {
            if (memcmp(sec.name, ".text", 5) != 0) continue;
            int leaHits = 0;
            for (uint64_t off = 0; off < sec.size; off += CHUNK) {
                uint32_t readSz = (uint32_t)((off + CHUNK <= sec.size) ? CHUNK : sec.size - off);
                if (!DmaRead(sec.base + off, buf.data(), readSz)) continue;
                for (uint32_t i = 0; i + 7 <= readSz; i++) {
                    if (buf[i] != 0x48 && buf[i] != 0x4C) continue;
                    if (buf[i+1] != 0x8D) continue;
                    int32_t disp = *(int32_t*)(buf.data() + i + 3);
                    uint64_t target = sec.base + off + i + 7 + disp;
                    if (target == strAddr) {
                        printf("    LEA XREF: .text+0x%llX (abs 0x%llX)\n",
                               (unsigned long long)(off + i),
                               (unsigned long long)(sec.base + off + i));
                        leaHits++;
                        if (leaHits >= 5) goto next_str;
                    }
                }
            }
            next_str:;
        }
    }

    // ============================================================
    // STEP 3: Scan .data for objects with entity-list-like vectors
    // ============================================================
    printf("\n--- Step 3: Find entity lists in .data heap objects ---\n");
    std::set<uint64_t> heapPtrs;
    for (uint64_t off = 0; off < dataSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)((off + CHUNK <= dataSize) ? CHUNK : dataSize - off);
        if (!DmaRead(dataBase + off, buf.data(), readSz)) continue;
        for (uint32_t i = 0; i + 8 <= readSz; i += 8) {
            uint64_t v = *(uint64_t*)(buf.data() + i);
            if (isHeapPtr(v)) heapPtrs.insert(v);
        }
    }
    printf("  %d heap pointers in .data\n", (int)heapPtrs.size());

    struct GMCandidate {
        uint64_t dataOff;     // offset in .data where ptr lives
        uint64_t objAddr;     // the heap object
        int vectorOff;        // offset within obj where the vector is
        int entCount;         // entities in the vector
        int withPos;          // entities that have position data
    };
    std::vector<GMCandidate> candidates;

    int scanned = 0;
    for (uint64_t ptr : heapPtrs) {
        scanned++;
        if (scanned % 5000 == 0) printf("  scanning %d/%d...\n", scanned, (int)heapPtrs.size());

        uint8_t objBuf[0x200];
        if (!DmaRead(ptr, objBuf, sizeof(objBuf))) continue;

        // Check if this object has a vtable (first qword is module pointer)
        uint64_t vt = *(uint64_t*)objBuf;
        if (!isModPtr(vt)) continue;

        // Look for vector<Entity*> patterns: begin/end pointer pairs
        for (int vo = 0; vo + 16 <= 0x200; vo += 8) {
            uint64_t vBegin = *(uint64_t*)(objBuf + vo);
            uint64_t vEnd   = *(uint64_t*)(objBuf + vo + 8);
            if (!isHeapPtr(vBegin) || vEnd <= vBegin) continue;
            if ((vEnd - vBegin) % 8 != 0) continue;
            int cnt = (int)((vEnd - vBegin) / 8);
            if (cnt < 3 || cnt > 200) continue;

            // Read the pointer array
            int readN = (cnt > 30) ? 30 : cnt;
            uint64_t entPtrs[30] = {};
            if (!DmaRead(vBegin, entPtrs, readN * 8)) continue;

            // Count valid entity-like pointers
            int validEnts = 0;
            for (int k = 0; k < readN; k++) {
                if (isHeapPtr(entPtrs[k])) {
                    uint64_t evtbl = rpm<uint64_t>(entPtrs[k]);
                    if (isModPtr(evtbl)) validEnts++;
                }
            }
            if (validEnts < 3) continue;

            // Try reading positions from these entities
            int withPos = 0;
            for (int k = 0; k < readN && k < 10; k++) {
                if (!isHeapPtr(entPtrs[k])) continue;
                Vec4 pos;
                if (tryDecPosition(entPtrs[k], pos)) withPos++;
            }

            if (withPos >= 1) {
                candidates.push_back({0, ptr, vo, cnt, withPos});
                if (candidates.size() >= 30) goto done_scan;
            }
        }
    }
    done_scan:

    printf("  Found %d candidate entity lists\n\n", (int)candidates.size());

    // Sort by position count descending
    std::sort(candidates.begin(), candidates.end(),
              [](const GMCandidate& a, const GMCandidate& b) { return a.withPos > b.withPos; });

    for (int ci = 0; ci < (int)candidates.size() && ci < 10; ci++) {
        auto& c = candidates[ci];
        uint64_t vt = rpm<uint64_t>(c.objAddr);
        printf("  === Candidate #%d ===\n", ci);
        printf("    Object: 0x%llX vtbl=+0x%llX\n",
               (unsigned long long)c.objAddr, (unsigned long long)(vt - g_base));
        printf("    Vector at +0x%02X: %d entries, %d with DEC positions\n",
               c.vectorOff, c.entCount, c.withPos);

        // Read full entity list and show positions
        int readN = (c.entCount > 50) ? 50 : c.entCount;
        std::vector<uint64_t> entPtrs(readN);
        uint64_t vBegin = rpm<uint64_t>(c.objAddr + c.vectorOff);
        DmaRead(vBegin, entPtrs.data(), readN * 8);

        int posCount = 0;
        for (int k = 0; k < readN; k++) {
            if (!isHeapPtr(entPtrs[k])) continue;
            uint64_t evtbl = rpm<uint64_t>(entPtrs[k]);
            Vec4 pos;
            bool hasPos = tryDecPosition(entPtrs[k], pos);
            if (hasPos) {
                posCount++;
                printf("      ent[%2d] 0x%llX vtbl=+0x%llX pos=(%.1f, %.1f, %.1f)\n",
                       k, (unsigned long long)entPtrs[k],
                       (unsigned long long)(isModPtr(evtbl) ? evtbl - g_base : 0),
                       pos.x, pos.y, pos.z);
            }
        }
        printf("    Total with positions: %d/%d\n\n", posCount, readN);
    }

    // ============================================================
    // STEP 4: Scan UBX sections for type registry
    // ============================================================
    printf("--- Step 4: Scan .UBX0 for class IDs and type descriptors ---\n");
    for (auto& sec : g_sections) {
        if (memcmp(sec.name, ".UBX0", 5) != 0) continue;
        printf("  Scanning %s (%.1f MB)...\n", sec.name, sec.size / 1048576.0);

        // Search for "GameManager" and "Entity" strings in UBX
        for (uint64_t off = 0; off < sec.size; off += CHUNK) {
            uint32_t readSz = (uint32_t)((off + CHUNK <= sec.size) ? CHUNK : sec.size - off);
            if (!DmaRead(sec.base + off, buf.data(), readSz)) continue;

            for (uint32_t i = 0; i + 11 <= readSz; i++) {
                if (memcmp(buf.data() + i, "GameManager", 11) == 0 ||
                    (i + 6 <= readSz && memcmp(buf.data() + i, "Entity", 6) == 0 && buf[i+6] == 0) ||
                    (i + 14 <= readSz && memcmp(buf.data() + i, "ProfileManager", 14) == 0)) {
                    char ctx[80] = {};
                    int cl = 0;
                    for (uint32_t k = i; k < readSz && buf[k] >= 0x20 && buf[k] < 0x7F && cl < 79; k++)
                        ctx[cl++] = (char)buf[k];
                    printf("    %s+0x%06llX: \"%s\"\n",
                           sec.name, (unsigned long long)(off + i), ctx);
                }
            }
        }
    }

    // ============================================================
    // STEP 5: Alternative — find position buffer entity again
    // ============================================================
    printf("\n--- Step 5: Re-find position buffer entity (vtbl scan) ---\n");
    // The old entity was at 0x227B172E030 with vtbl=+0x115E7F10
    // After restart, the vtbl RVA should be the same but base changed
    // New vtbl absolute = new_base + 0x115E7F10
    uint64_t targetVtbl = g_base + 0x115E7F10;
    printf("  Looking for objects with vtbl=0x%llX (+0x115E7F10)...\n",
           (unsigned long long)targetVtbl);

    int vtblHits = 0;
    for (uint64_t ptr : heapPtrs) {
        uint64_t vt = rpm<uint64_t>(ptr);
        if (vt == targetVtbl) {
            printf("    FOUND: 0x%llX\n", (unsigned long long)ptr);
            vtblHits++;

            // Read position data from this entity
            uint8_t eb[0x2000];
            if (DmaRead(ptr, eb, sizeof(eb))) {
                int posCount = 0;
                for (int off = 0x2C0; off + 12 <= 0x1E00; off += 0x40) {
                    float x = *(float*)(eb + off);
                    float y = *(float*)(eb + off + 4);
                    float z = *(float*)(eb + off + 8);
                    if (!isnan(x) && fabsf(x) > 1 && fabsf(x) < 5000) posCount++;
                }
                printf("      Position slots with data: %d\n", posCount);
            }
            if (vtblHits >= 5) break;
        }
    }
    if (vtblHits == 0) printf("    Not found via .data pointers. May need deeper scan.\n");

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
