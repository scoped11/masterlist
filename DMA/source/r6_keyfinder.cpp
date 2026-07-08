// R6 Siege Encryption Key Finder
// Scans R6's .text section via DMA to find the GameManager decryption key + rotation.
// Also validates the full entity chain with found/manual offsets.
//
// Build: cl /O2 /EHsc /std:c++17 r6_keyfinder.cpp /Fe"../r6_keyfinder.exe" /link
// Usage: r6_keyfinder.exe [--gm=0xRVA]

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <intrin.h>
#include <conio.h>

typedef void* VMM_HANDLE;
typedef VMM_HANDLE (__cdecl *fn_Init)(DWORD argc, LPCSTR argv[]);
typedef VOID       (__cdecl *fn_Close)(VMM_HANDLE hVMM);
typedef BOOL       (__cdecl *fn_PidGet)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL       (__cdecl *fn_MemRead)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef ULONG64    (__cdecl *fn_ModBase)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);

static VMM_HANDLE g_vmm = nullptr;
static DWORD g_pid = 0;
static fn_Init pInit; static fn_Close pClose; static fn_PidGet pPidGet;
static fn_MemRead pMemRead; static fn_ModBase pModBase;

static bool DmaRead(uint64_t va, void* buf, uint32_t size) {
    DWORD cb = 0;
    return pMemRead(g_vmm, g_pid, va, (PBYTE)buf, size, &cb, 0x0002) && cb > 0;
}
template<class T> T rpm(uint64_t a) { T v{}; DmaRead(a, &v, sizeof(T)); return v; }

struct Vec3 { float x, y, z; };

// Offsets from research (AnvilNext 2.0 standard)
static uint64_t OFF_GM           = 0x11F0DDF8; // GameManager RVA (from ini)
static uint64_t OFF_ENTITY_LIST  = 0x1C8;       // GM + this = entity list ptr
static uint64_t OFF_ENTITY_COUNT = 0x1D0;       // GM + this = entity count
static uint64_t OFF_ENTITY_PAWN  = 0x20;        // Entity + this = Pawn ptr
static uint64_t OFF_PAWN_FEET    = 0x700;       // Pawn + this = feet Vec3
static uint64_t OFF_PAWN_HEAD    = 0x6A0;       // Pawn + this = head Vec3
static uint64_t OFF_REPLICATION  = 0xC8;        // Entity + this = replication
static uint64_t OFF_REPL_TEAM   = 0x190;       // Replication + this = team ID

static uint64_t g_decryptKey = 0;
static int g_decryptRot = 0;

static uint64_t Decrypt(uint64_t enc) {
    if (!g_decryptKey && !g_decryptRot) return enc;
    uint64_t v = enc ^ g_decryptKey;
    if (g_decryptRot > 0) v = _rotl64(v, g_decryptRot);
    else if (g_decryptRot < 0) v = _rotr64(v, -g_decryptRot);
    return v;
}

struct SectionInfo { uint64_t va; uint64_t size; char name[9]; };

static void FindSections(uint64_t base, std::vector<SectionInfo>& sections) {
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    uint64_t secAddr = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        SectionInfo si;
        si.va = base + sec.VirtualAddress;
        si.size = sec.Misc.VirtualSize;
        memcpy(si.name, sec.Name, 8); si.name[8] = 0;
        sections.push_back(si);
    }
}

static void FindTextSection(uint64_t base, uint64_t& textBase, uint64_t& textSize) {
    std::vector<SectionInfo> secs;
    FindSections(base, secs);
    textBase = 0; textSize = 0;
    for (auto& s : secs) {
        if (memcmp(s.name, ".text", 5) == 0) {
            textBase = s.va; textSize = s.size; return;
        }
    }
    textBase = base + 0x1000;
    IMAGE_DOS_HEADER dos = rpm<IMAGE_DOS_HEADER>(base);
    IMAGE_NT_HEADERS64 nt = rpm<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    textSize = nt.OptionalHeader.SizeOfCode;
}

static bool isValidPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }

// Sig scan for a byte pattern with ?? wildcards. Returns RVA of the resolved RIP-relative target.
static uint64_t SigScan(uint64_t textBase, uint64_t textSize, const uint8_t* pat, const uint8_t* mask, int patLen, int ripOffset) {
    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK + patLen + 16);
    for (uint64_t off = 0; off < textSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)(CHUNK + patLen + 16), textSize - off);
        if (!DmaRead(textBase + off, buf.data(), readSz)) continue;
        for (uint32_t i = 0; i < readSz - patLen; i++) {
            bool match = true;
            for (int j = 0; j < patLen && match; j++)
                if (mask[j] && buf[i+j] != pat[j]) match = false;
            if (!match) continue;
            uint64_t instrAddr = textBase + off + i;
            int32_t disp = *(int32_t*)(buf.data() + i + ripOffset);
            uint64_t resolved = instrAddr + ripOffset + 4 + disp;
            return resolved;
        }
    }
    return 0;
}

static bool ParsePattern(const char* hex, uint8_t* pat, uint8_t* mask, int* outLen) {
    int len = 0;
    const char* p = hex;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') { pat[len] = 0; mask[len] = 0; len++; p += 2; }
        else { pat[len] = (uint8_t)strtoul(p, nullptr, 16); mask[len] = 1; len++; p += 2; }
    }
    *outLen = len;
    return len > 0;
}

// Find real GameManager via sig scanning
static uint64_t FindGameManager(uint64_t textBase, uint64_t textSize, uint64_t base) {
    printf("[*] Sig scanning for GameManager...\n");
    const char* patterns[] = {
        "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48",           // mov rax,[rip+?]; test rax,rax; jz; mov rcx,[rax+?]
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8",           // mov rcx,[rip+?]; call; mov rbx,rax
        "48 8D 0D ?? ?? ?? ?? 48 89 4C 24",                       // lea rcx,[rip+?]; mov [rsp+?],rcx
        "48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B",  // mov rax,[rip+?]; test rax,rax; jz far
    };
    const int ripOffsets[] = {3, 3, 3, 3};
    const char* names[] = {"GM_pat1", "GM_pat2", "GM_pat3", "GM_pat4"};

    struct Candidate { uint64_t addr; int entityCount; uint64_t entityListPtr; int patIdx; };
    std::vector<Candidate> candidates;

    for (int p = 0; p < 4; p++) {
        uint8_t pat[64], mask[64]; int patLen;
        ParsePattern(patterns[p], pat, mask, &patLen);

        // Find ALL matches for this pattern
        const uint32_t CHUNK = 0x10000;
        std::vector<uint8_t> buf(CHUNK + patLen + 16);
        int found = 0;
        for (uint64_t off = 0; off < textSize && found < 50; off += CHUNK) {
            uint32_t readSz = (uint32_t)min((uint64_t)(CHUNK + patLen + 16), textSize - off);
            if (!DmaRead(textBase + off, buf.data(), readSz)) continue;
            for (uint32_t i = 0; i < readSz - patLen && found < 50; i++) {
                bool match = true;
                for (int j = 0; j < patLen && match; j++)
                    if (mask[j] && buf[i+j] != pat[j]) match = false;
                if (!match) continue;

                uint64_t instrAddr = textBase + off + i;
                int32_t disp = *(int32_t*)(buf.data() + i + ripOffsets[p]);
                uint64_t resolved = instrAddr + ripOffsets[p] + 4 + disp;

                // Read the global — should be a valid pointer
                uint64_t gmPtr = rpm<uint64_t>(resolved);
                if (!isValidPtr(gmPtr)) continue;

                // Check if this looks like a GameManager: scan for entity list at common offsets
                for (uint64_t listOff : {0x1C8ULL, 0x130ULL, 0x198ULL, 0x1A0ULL, 0x1B0ULL, 0x1B8ULL,
                                          0xC8ULL, 0xD0ULL, 0xD8ULL, 0xE0ULL, 0xE8ULL, 0xF0ULL,
                                          0x100ULL, 0x108ULL, 0x110ULL, 0x118ULL, 0x120ULL, 0x128ULL,
                                          0x138ULL, 0x140ULL, 0x148ULL, 0x150ULL, 0x158ULL, 0x160ULL,
                                          0x168ULL, 0x170ULL, 0x178ULL, 0x180ULL, 0x188ULL, 0x190ULL}) {
                    uint64_t listPtr = rpm<uint64_t>(gmPtr + listOff);
                    if (!isValidPtr(listPtr)) continue;
                    int cnt = rpm<int32_t>(gmPtr + listOff + 8);
                    if (cnt < 2 || cnt > 100) continue;
                    // Check if first entry in the list is a valid pointer
                    uint64_t first = rpm<uint64_t>(listPtr);
                    if (!isValidPtr(first)) continue;

                    candidates.push_back({resolved, cnt, listPtr, p});
                    printf("  [%s] global=0x%llX obj=0x%llX  list@+0x%llX cnt=%d first=0x%llX\n",
                           names[p], (unsigned long long)(resolved - base),
                           (unsigned long long)gmPtr, (unsigned long long)listOff, cnt,
                           (unsigned long long)first);
                    found++;
                }
            }
        }
    }

    if (candidates.empty()) {
        printf("[!] No GameManager candidates found via sig scan\n");
        printf("[*] Brute-force scanning .data section for entity-like arrays...\n");

        std::vector<SectionInfo> secs;
        FindSections(base, secs);
        for (auto& sec : secs) {
            bool isData = (memcmp(sec.name, ".data", 5) == 0 || memcmp(sec.name, ".rdata", 6) == 0);
            if (!isData) continue;
            printf("  Scanning %s (0x%llX, %.1f MB)...\n", sec.name,
                   (unsigned long long)sec.va, sec.size / 1048576.0);

            const uint32_t CHUNK = 0x10000;
            std::vector<uint8_t> buf(CHUNK);
            int hits = 0;
            for (uint64_t off = 0; off < sec.size && hits < 20; off += CHUNK) {
                uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, sec.size - off);
                if (!DmaRead(sec.va + off, buf.data(), readSz)) continue;
                for (uint32_t i = 0; i + 8 <= readSz && hits < 20; i += 8) {
                    uint64_t globalVal = *(uint64_t*)(buf.data() + i);
                    if (!isValidPtr(globalVal)) continue;
                    // globalVal is an object pointer — scan its fields for ptr+count
                    for (uint64_t foff = 0x0; foff <= 0x300; foff += 0x8) {
                        uint64_t listPtr = rpm<uint64_t>(globalVal + foff);
                        if (!isValidPtr(listPtr)) continue;
                        int cnt = rpm<int32_t>(globalVal + foff + 8);
                        if (cnt < 3 || cnt > 100) continue;
                        // Validate: first 3 entries should be valid pointers
                        uint64_t arr[3] = {};
                        DmaRead(listPtr, arr, 24);
                        int validPtrs = 0;
                        for (int k = 0; k < min(cnt, 3); k++)
                            if (isValidPtr(arr[k])) validPtrs++;
                        if (validPtrs < 2) continue;

                        uint64_t globalRVA = sec.va + off + i - base;
                        printf("  HIT! %s+0x%llX => obj=0x%llX  list@+0x%llX cnt=%d\n",
                               sec.name, (unsigned long long)(off + i),
                               (unsigned long long)globalVal, (unsigned long long)foff, cnt);
                        printf("       first3: 0x%llX 0x%llX 0x%llX\n",
                               (unsigned long long)arr[0], (unsigned long long)arr[1], (unsigned long long)arr[2]);

                        candidates.push_back({sec.va + off + i, cnt, listPtr, -1});
                        hits++;
                    }
                }
            }
        }
    }

    if (candidates.empty()) {
        printf("[!] Still no candidates — game may not be fully loaded into match\n");
        return 0;
    }

    // Pick the best candidate: highest entity count with valid pointer chain
    int bestIdx = 0;
    for (int i = 1; i < (int)candidates.size(); i++) {
        if (candidates[i].entityCount > candidates[bestIdx].entityCount)
            bestIdx = i;
    }

    printf("\n[+] Best candidate: global RVA=0x%llX count=%d\n",
           (unsigned long long)(candidates[bestIdx].addr - base), candidates[bestIdx].entityCount);
    return candidates[bestIdx].addr;
}

// Scan for xrefs to GameManager global, then look for XOR + ROL/ROR nearby
static bool ScanForKey(uint64_t textBase, uint64_t textSize, uint64_t gmGlobal) {
    printf("[*] Scanning .text (0x%llX, %llu MB) for xrefs to GM global 0x%llX...\n",
           (unsigned long long)textBase, (unsigned long long)(textSize / 1048576), (unsigned long long)gmGlobal);

    const uint32_t CHUNK = 0x10000;
    std::vector<uint8_t> buf(CHUNK + 64);
    int xrefs = 0;

    for (uint64_t off = 0; off < textSize; off += CHUNK) {
        uint32_t readSz = (uint32_t)min((uint64_t)(CHUNK + 64), textSize - off);
        if (!DmaRead(textBase + off, buf.data(), readSz)) continue;

        for (uint32_t i = 0; i < readSz - 32; i++) {
            // Look for RIP-relative MOV/LEA: 48 8B/8D XX [rip+disp32]
            if (buf[i] != 0x48 && buf[i] != 0x4C) continue;
            if (buf[i+1] != 0x8B && buf[i+1] != 0x8D) continue;
            uint8_t modrm = buf[i+2];
            if ((modrm & 0xC7) != 0x05) continue;

            int32_t disp = *(int32_t*)(buf.data() + i + 3);
            uint64_t instrAddr = textBase + off + i;
            uint64_t resolved = instrAddr + 7 + disp;

            if (resolved != gmGlobal) continue;
            xrefs++;
            printf("\n[+] Xref #%d at 0x%llX\n", xrefs, (unsigned long long)instrAddr);

            // Read a window around this xref
            uint8_t window[300] = {};
            uint64_t winStart = (instrAddr > 16) ? instrAddr - 16 : instrAddr;
            DmaRead(winStart, window, 300);
            int base_off = (int)(instrAddr - winStart);

            uint64_t candKey = 0;
            int candRot = 0;
            bool sawXOR = false, sawROT = false;

            for (int j = base_off; j < 260; j++) {
                // MOVABS r64, imm64: 48/49 B8-BF + 8 bytes
                if ((window[j] == 0x48 || window[j] == 0x49) &&
                    window[j+1] >= 0xB8 && window[j+1] <= 0xBF) {
                    uint64_t imm = *(uint64_t*)(window + j + 2);
                    if (imm > 0xFFFF && imm != 0xFFFFFFFFFFFFFFFF) {
                        candKey = imm;
                        printf("    [KEY] MOV r64, 0x%llX at offset +%d\n",
                               (unsigned long long)imm, j - base_off);
                    }
                    j += 9;
                    continue;
                }
                // XOR r64,r64: 48/49/4C 31/33 XX
                if ((window[j] == 0x48 || window[j] == 0x49 || window[j] == 0x4C) &&
                    (window[j+1] == 0x31 || window[j+1] == 0x33)) {
                    sawXOR = true;
                    printf("    [XOR] at offset +%d (opcode: %02X %02X %02X)\n",
                           j - base_off, window[j], window[j+1], window[j+2]);
                }
                // ROL/ROR r64, imm8: 48/49 C1 C0-CF XX
                if ((window[j] == 0x48 || window[j] == 0x49) && window[j+1] == 0xC1) {
                    uint8_t rm = window[j+2];
                    if (rm >= 0xC0 && rm <= 0xC7) {
                        candRot = (int)window[j+3];
                        sawROT = true;
                        printf("    [ROL] ROL by %d at offset +%d\n", candRot, j - base_off);
                    } else if (rm >= 0xC8 && rm <= 0xCF) {
                        candRot = -(int)window[j+3];
                        sawROT = true;
                        printf("    [ROR] ROR by %d at offset +%d\n", (int)window[j+3], j - base_off);
                    }
                }
            }

            if (candKey && sawXOR) {
                printf("\n========================================\n");
                printf("  ENCRYPTION KEY FOUND!\n");
                printf("  XOR Key:    0x%llX\n", (unsigned long long)candKey);
                printf("  Rotation:   %d (%s)\n", abs(candRot),
                       candRot > 0 ? "ROL" : candRot < 0 ? "ROR" : "none");
                printf("========================================\n\n");
                printf("Add to r6_offsets.ini:\n");
                printf("  DecryptKey=0x%llX\n", (unsigned long long)candKey);
                printf("  DecryptRotation=%d\n", candRot);
                printf("========================================\n");
                g_decryptKey = candKey;
                g_decryptRot = candRot;
                return true;
            }

            if (xrefs >= 30) break;
        }
        if (xrefs >= 30) break;
    }

    printf("\n[*] Scanned %d xrefs — ", xrefs);
    if (xrefs == 0)
        printf("GameManager RVA 0x%llX may be wrong for this version\n", (unsigned long long)(gmGlobal - textBase + 0x1000));
    else
        printf("no encryption pattern found, pointers may be plaintext\n");
    return false;
}

static uint64_t TryDecrypt(uint64_t enc, uint64_t key, int rot) {
    if (!key && !rot) return enc;
    uint64_t v = enc ^ key;
    if (rot > 0) v = _rotl64(v, rot);
    else if (rot < 0) v = _rotr64(v, -rot);
    return v;
}

struct DecryptConfig {
    uint64_t key;
    int rot;
    char label[64];
};

static bool TestEntityChain(uint64_t gm, uint64_t key, int rot, const char* label) {
    uint64_t entList = rpm<uint64_t>(gm + OFF_ENTITY_LIST);
    int entCount = rpm<int32_t>(gm + OFF_ENTITY_COUNT);
    if (!isValidPtr(entList) || entCount <= 0 || entCount > 200) return false;

    uint64_t ptrs[10] = {};
    int readN = min(entCount, 10);
    DmaRead(entList, ptrs, readN * 8);

    int validEnts = 0, validPawns = 0, validPos = 0;
    for (int i = 0; i < readN; i++) {
        if (!ptrs[i]) continue;
        uint64_t ent = TryDecrypt(ptrs[i], key, rot);
        if (!isValidPtr(ent)) continue;
        validEnts++;
        uint64_t pawnRaw = rpm<uint64_t>(ent + OFF_ENTITY_PAWN);
        if (!pawnRaw) continue;
        uint64_t pawn = TryDecrypt(pawnRaw, key, rot);
        if (!isValidPtr(pawn)) continue;
        validPawns++;
        Vec3 feet = rpm<Vec3>(pawn + OFF_PAWN_FEET);
        if (fabsf(feet.x) > 0.5f || fabsf(feet.y) > 0.5f || fabsf(feet.z) > 0.5f)
            validPos++;
    }
    printf("  [%s] key=0x%llX rot=%d  ents=%d/%d pawns=%d pos=%d\n",
           label, (unsigned long long)key, rot, validEnts, readN, validPawns, validPos);
    return validPos > 0;
}

// Validate the entity chain
static void ValidateChain(uint64_t base, uint64_t* candKeys, int nKeys) {
    printf("\n=== Entity Chain Validation ===\n");

    uint64_t gmRaw = rpm<uint64_t>(base + OFF_GM);
    printf("GameManager global:    0x%llX\n", (unsigned long long)(base + OFF_GM));
    printf("GameManager raw ptr:   0x%llX %s\n", (unsigned long long)gmRaw,
           isValidPtr(gmRaw) ? "(VALID - not encrypted)" : "(INVALID)");

    if (!isValidPtr(gmRaw)) {
        printf("[!] GameManager pointer invalid — RVA 0x%llX may be wrong\n", (unsigned long long)OFF_GM);
        printf("[*] Scanning for GM pointer near expected offset...\n");
        for (int64_t delta = -0x100; delta <= 0x100; delta += 8) {
            uint64_t tryAddr = base + OFF_GM + delta;
            uint64_t tryVal = rpm<uint64_t>(tryAddr);
            if (isValidPtr(tryVal)) {
                printf("    RVA 0x%llX => 0x%llX (valid ptr)\n",
                       (unsigned long long)(OFF_GM + delta), (unsigned long long)tryVal);
            }
        }
        return;
    }

    uint64_t gm = gmRaw;

    // Broad scan of GM fields for entity list candidates (ptr + count pairs)
    printf("\n--- GM field scan (0x0-0x400) looking for ptr+count pairs ---\n");
    printf("    (Filtering: count 2-100, ptr valid, first entry valid)\n\n");
    int candidates = 0;
    for (uint64_t off = 0x0; off <= 0x400; off += 0x8) {
        uint64_t val = rpm<uint64_t>(gm + off);
        if (!isValidPtr(val)) continue;
        // Check +8 for 32-bit count, also +8 for 64-bit count
        int cnt32 = rpm<int32_t>(gm + off + 0x8);
        int cnt64lo = (int)(rpm<uint64_t>(gm + off + 0x8) & 0xFFFFFFFF);
        int cnt = (cnt32 > 0 && cnt32 <= 200) ? cnt32 : 0;
        if (cnt <= 0) continue;

        // Read first pointer in the array
        uint64_t first = rpm<uint64_t>(val);
        // Also check if it's an inline array (pointers at val, val+8, val+16...)
        bool firstValid = isValidPtr(first);
        bool firstIsAscii = (first < 0x7FFFFFFFFFFF && first > 0) &&
                            ((first & 0xFF) >= 0x20 && (first & 0xFF) <= 0x7E);
        printf("  GM+0x%03llX = 0x%llX  cnt=%d  first=0x%llX %s%s\n",
               (unsigned long long)off, (unsigned long long)val, cnt,
               (unsigned long long)first,
               firstValid ? "(valid ptr)" : "(not ptr)",
               firstIsAscii ? " [looks like ASCII]" : "");
        if (firstValid && cnt >= 2) {
            candidates++;
            // Read a few more entries
            uint64_t arr[5] = {};
            int readN = min(cnt, 5);
            DmaRead(val, arr, readN * 8);
            for (int i = 0; i < readN; i++) {
                printf("       [%d] 0x%llX %s\n", i, (unsigned long long)arr[i],
                       isValidPtr(arr[i]) ? "OK" : arr[i] ? "bad" : "NULL");
            }
        }
    }
    if (!candidates) printf("  (no ptr+count pairs with count>=2 found — are you in a match?)\n");

    // Try to find entity list dynamically if default gives bad results
    uint64_t entList = rpm<uint64_t>(gm + OFF_ENTITY_LIST);
    int entCount = rpm<int32_t>(gm + OFF_ENTITY_COUNT);
    printf("\nEntityList default (GM+0x%llX): 0x%llX count=%d\n",
           (unsigned long long)OFF_ENTITY_LIST, (unsigned long long)entList, entCount);

    if (!isValidPtr(entList) || entCount < 2) {
        printf("[*] Default offset didn't find entities, scanning all GM fields...\n");
        uint64_t bestList = 0; int bestCount = 0; uint64_t bestOff = 0;
        for (uint64_t off = 0x0; off <= 0x400; off += 0x8) {
            uint64_t ptr = rpm<uint64_t>(gm + off);
            if (!isValidPtr(ptr)) continue;
            int cnt = rpm<int32_t>(gm + off + 0x8);
            if (cnt < 2 || cnt > 200) continue;
            uint64_t first = rpm<uint64_t>(ptr);
            if (!isValidPtr(first)) continue;
            if (cnt > bestCount) { bestCount = cnt; bestList = ptr; bestOff = off; }
        }
        if (bestCount >= 2) {
            OFF_ENTITY_LIST = bestOff;
            OFF_ENTITY_COUNT = bestOff + 8;
            entList = bestList;
            entCount = bestCount;
            printf("[+] Found entity list at GM+0x%llX count=%d\n",
                   (unsigned long long)bestOff, bestCount);
        }
    }

    if (!isValidPtr(entList) || entCount < 2) {
        printf("[!] No entity list found — are you fully loaded into a match?\n");
        return;
    }
    if (entCount > 200) entCount = 200;

    // Read raw entity pointers
    printf("\n--- Raw entity pointers (first 5) ---\n");
    uint64_t ptrs[10] = {};
    int readN = min(entCount, 10);
    DmaRead(entList, ptrs, readN * 8);
    for (int i = 0; i < min(readN, 5); i++) {
        printf("  [%d] 0x%llX %s\n", i, (unsigned long long)ptrs[i],
               isValidPtr(ptrs[i]) ? "(valid range)" : ptrs[i] ? "(out of range)" : "(NULL)");
    }

    // Test different decrypt configurations
    printf("\n--- Testing decryption modes ---\n");
    DecryptConfig configs[20];
    int nConfigs = 0;
    configs[nConfigs] = {0, 0, {}};
    strcpy(configs[nConfigs].label, "plaintext");
    nConfigs++;
    for (int k = 0; k < nKeys && nConfigs < 18; k++) {
        configs[nConfigs] = {candKeys[k], 0, {}};
        sprintf(configs[nConfigs].label, "xor_%d", k);
        nConfigs++;
        for (int r : {3, 5, 7, 13, 16, 19, 23, 29, 31, 37, 43, 47}) {
            if (nConfigs >= 18) break;
            configs[nConfigs] = {candKeys[k], r, {}};
            sprintf(configs[nConfigs].label, "xor_%d_rol%d", k, r);
            nConfigs++;
        }
    }

    int bestIdx = -1;
    for (int c = 0; c < nConfigs; c++) {
        if (TestEntityChain(gm, configs[c].key, configs[c].rot, configs[c].label)) {
            if (bestIdx < 0) bestIdx = c;
        }
    }

    // Use the best config for detailed output
    uint64_t useKey = bestIdx >= 0 ? configs[bestIdx].key : g_decryptKey;
    int useRot = bestIdx >= 0 ? configs[bestIdx].rot : g_decryptRot;
    if (bestIdx >= 0) {
        printf("\n========================================\n");
        printf("  BEST DECRYPTION: %s\n", configs[bestIdx].label);
        printf("  Key: 0x%llX  Rotation: %d\n", (unsigned long long)useKey, useRot);
        printf("========================================\n");
    } else {
        printf("\n[!] No decryption config yielded valid positions\n");
        printf("[*] Trying plaintext chain with detailed dump...\n");
        useKey = 0; useRot = 0;
    }

    printf("\n--- Detailed entity dump (key=0x%llX rot=%d) ---\n",
           (unsigned long long)useKey, useRot);
    for (int i = 0; i < min(readN, 5); i++) {
        uint64_t raw = ptrs[i];
        if (!raw) { printf("  [%d] NULL\n", i); continue; }

        uint64_t ent = TryDecrypt(raw, useKey, useRot);
        printf("  [%d] raw=0x%llX dec=0x%llX", i, (unsigned long long)raw, (unsigned long long)ent);

        if (!isValidPtr(ent)) { printf(" (INVALID)\n"); continue; }

        uint64_t pawnRaw = rpm<uint64_t>(ent + OFF_ENTITY_PAWN);
        uint64_t pawn = TryDecrypt(pawnRaw, useKey, useRot);
        printf(" pawn_raw=0x%llX pawn=0x%llX", (unsigned long long)pawnRaw, (unsigned long long)pawn);

        if (isValidPtr(pawn)) {
            Vec3 feet = rpm<Vec3>(pawn + OFF_PAWN_FEET);
            Vec3 head = rpm<Vec3>(pawn + OFF_PAWN_HEAD);
            printf("\n       feet=(%.1f, %.1f, %.1f)  head=(%.1f, %.1f, %.1f)",
                   feet.x, feet.y, feet.z, head.x, head.y, head.z);
            if (feet.x != 0 || feet.y != 0 || feet.z != 0)
                printf("  <-- HAS POSITION");
        } else if (pawnRaw) {
            // Try plaintext pawn even with encrypted entity
            uint64_t pawnPlain = pawnRaw;
            if (isValidPtr(pawnPlain)) {
                printf(" (pawn plaintext works)");
                Vec3 feet = rpm<Vec3>(pawnPlain + OFF_PAWN_FEET);
                printf("\n       feet=(%.1f, %.1f, %.1f)", feet.x, feet.y, feet.z);
            }
        }

        uint64_t repl = rpm<uint64_t>(ent + OFF_REPLICATION);
        if (isValidPtr(repl)) {
            int team = rpm<int>(repl + OFF_REPL_TEAM);
            printf("\n       team=%d", team);
        }
        printf("\n");
    }

    // Pawn field scan for first valid entity
    for (int i = 0; i < readN; i++) {
        if (!ptrs[i]) continue;
        uint64_t ent = TryDecrypt(ptrs[i], useKey, useRot);
        if (!isValidPtr(ent)) continue;
        uint64_t pawnRaw = rpm<uint64_t>(ent + OFF_ENTITY_PAWN);
        uint64_t pawn = TryDecrypt(pawnRaw, useKey, useRot);
        if (!isValidPtr(pawn)) pawn = pawnRaw;
        if (!isValidPtr(pawn)) continue;

        printf("\n--- Pawn field scan (entity %d, pawn=0x%llX) ---\n", i, (unsigned long long)pawn);
        int found = 0;
        for (uint64_t off = 0; off <= 0x800; off += 0x4) {
            Vec3 v = rpm<Vec3>(pawn + off);
            if (fabsf(v.x) > 1.0f && fabsf(v.x) < 50000.0f &&
                fabsf(v.y) > 1.0f && fabsf(v.y) < 50000.0f &&
                fabsf(v.z) > 0.1f && fabsf(v.z) < 50000.0f &&
                v.x != v.y && v.y != v.z) {
                printf("  Pawn+0x%03llX = (%.2f, %.2f, %.2f)\n",
                       (unsigned long long)off, v.x, v.y, v.z);
                if (++found >= 20) break;
            }
        }
        if (!found) printf("  (no position-like floats found)\n");
        break;
    }

    printf("\n=== Done ===\n");
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("=== R6 Siege Encryption Key Finder ===\n");
    printf("    Scans game memory via DMA for decryption parameters\n\n");

    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--gm=", 5) == 0)
            OFF_GM = strtoull(argv[i] + 5, nullptr, 16);
        if (strncmp(argv[i], "--list=", 7) == 0)
            OFF_ENTITY_LIST = strtoull(argv[i] + 7, nullptr, 16);
        if (strncmp(argv[i], "--count=", 8) == 0)
            OFF_ENTITY_COUNT = strtoull(argv[i] + 8, nullptr, 16);
    }

    printf("Config:\n");
    printf("  GameManager RVA:  0x%llX\n", (unsigned long long)OFF_GM);
    printf("  EntityList off:   0x%llX\n", (unsigned long long)OFF_ENTITY_LIST);
    printf("  EntityCount off:  0x%llX\n", (unsigned long long)OFF_ENTITY_COUNT);
    printf("  EntityPawn off:   0x%llX\n", (unsigned long long)OFF_ENTITY_PAWN);
    printf("  PawnFeet off:     0x%llX\n", (unsigned long long)OFF_PAWN_FEET);
    printf("  PawnHead off:     0x%llX\n\n", (unsigned long long)OFF_PAWN_HEAD);

    // Load VMM
    HMODULE h = LoadLibraryA("vmm.dll");
    if (!h) { printf("[!] vmm.dll not found. Place in same directory.\n"); return 1; }
    pInit    = (fn_Init)GetProcAddress(h, "VMMDLL_Initialize");
    pClose   = (fn_Close)GetProcAddress(h, "VMMDLL_Close");
    pPidGet  = (fn_PidGet)GetProcAddress(h, "VMMDLL_PidGetFromName");
    pMemRead = (fn_MemRead)GetProcAddress(h, "VMMDLL_MemReadEx");
    pModBase = (fn_ModBase)GetProcAddress(h, "VMMDLL_ProcessGetModuleBaseU");

    LPCSTR args[] = { "", "-device", "fpga", "-v", "-printf", "-waitinitialize" };
    g_vmm = pInit(6, args);
    if (!g_vmm) { printf("[!] DMA init failed\n"); return 1; }
    printf("[+] DMA initialized\n");

    printf("[*] Waiting for RainbowSix.exe...\n");
    int retries = 0;
    while (!pPidGet(g_vmm, "RainbowSix.exe", &g_pid)) {
        if (++retries > 60) { printf("[!] R6 not found after 60 attempts\n"); pClose(g_vmm); return 1; }
        printf(".");
        Sleep(2000);
    }
    printf("\n[+] RainbowSix.exe PID=%u\n", g_pid);

    uint64_t base = pModBase(g_vmm, g_pid, "RainbowSix.exe");
    if (!base) { base = 0x140000000; printf("[!] Module base not found, using default\n"); }
    printf("[+] Base: 0x%llX\n\n", (unsigned long long)base);

    // Step 1: Find .text section
    uint64_t textBase, textSize;
    FindTextSection(base, textBase, textSize);
    printf("[+] .text: 0x%llX  size: 0x%llX (%.1f MB)\n\n",
           (unsigned long long)textBase, (unsigned long long)textSize, textSize / 1048576.0);

    // Step 2: Sig scan for real GameManager (the hardcoded RVA may be wrong)
    uint64_t realGmGlobal = FindGameManager(textBase, textSize, base);
    if (realGmGlobal) {
        uint64_t oldRVA = OFF_GM;
        OFF_GM = realGmGlobal - base;
        printf("[+] Updated GameManager RVA: 0x%llX (was 0x%llX)\n\n",
               (unsigned long long)OFF_GM, (unsigned long long)oldRVA);
    } else {
        printf("[*] Using hardcoded GM RVA 0x%llX\n\n", (unsigned long long)OFF_GM);
    }

    // Step 3: Scan for encryption key using the (possibly updated) GM address
    bool foundKey = ScanForKey(textBase, textSize, base + OFF_GM);

    // Collect candidate keys
    uint64_t candKeys[4] = {};
    int nKeys = 0;
    if (g_decryptKey) candKeys[nKeys++] = g_decryptKey;

    // Step 4: Validate entity chain (GM ptr is plaintext, entities may be encrypted)
    ValidateChain(base, candKeys, nKeys);

    printf("\nDone. Closing DMA.\n");
    fflush(stdout);
    pClose(g_vmm);
    return 0;
}
