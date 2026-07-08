// R6 Signature Scanner — find GameManager, Camera, Actor offsets via byte patterns
// Patterns from UC community (v3/v4 sig finder)
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_sigscan.cpp /Fe"../r6_sigscan.exe" /link
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>

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

struct Sig {
    const char* name;
    const char* pattern;
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;
    int ripOffset;  // offset within pattern where RIP-relative disp32 starts (-1 = no RIP)
    int ripInsnLen; // total instruction length for RIP calculation
};

void parseSig(Sig& s) {
    const char* p = s.pattern;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            s.bytes.push_back(0);
            s.mask.push_back(false);
            while (*p == '?') p++;
        } else {
            char hex[3] = {p[0], p[1], 0};
            s.bytes.push_back((uint8_t)strtol(hex, nullptr, 16));
            s.mask.push_back(true);
            p += 2;
        }
    }
}

bool matchSig(const uint8_t* data, const Sig& s) {
    for (int i = 0; i < (int)s.bytes.size(); i++) {
        if (s.mask[i] && data[i] != s.bytes[i]) return false;
    }
    return true;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 Signature Scanner ===\n\n");

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
    printf("[+] PID=%u Base=0x%llX End=0x%llX\n\n",
           g_pid, (unsigned long long)g_base, (unsigned long long)g_modEnd);

    // Find .text section
    uint64_t textBase = 0, textSize = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".text", 5) == 0) {
            textBase = g_base + sec.VirtualAddress;
            textSize = sec.Misc.VirtualSize;
            break;
        }
    }
    printf("[+] .text: 0x%llX size=0x%llX (%.1f MB)\n\n",
           (unsigned long long)textBase, (unsigned long long)textSize, textSize / 1048576.0);

    // Define signatures
    // ripOffset = byte index where the 4-byte RIP displacement starts
    // ripInsnLen = total bytes in the instruction containing the RIP ref
    Sig sigs[] = {
        // GameManager: MOV RCX,[rip+?] ; TEST RCX,RCX ; JE ; MOV RAX,[RCX] ; CALL [RAX+0x90]
        {"GameManager",
         "48 8B 0D ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 01 FF 90 90 00 00 00",
         {}, {}, 3, 7},

        // GameManager alt: MOV RCX,[rip+?] ; AND EAX,? ; ADD RAX,R10 ; SUB RAX,RSP ; ADD RAX,?
        {"GameManager_alt",
         "48 8B 0D ? ? ? ? 25 ? ? ? ? 4C 01 D0 48 29 E0 48 05 ? ? ? ?",
         {}, {}, 3, 7},

        // NetworkManager: MOV RAX,[rip+?] ; TEST RAX,RAX ; JE ; CMP R8D,...
        {"NetworkManager",
         "48 8B 05 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 41 83",
         {}, {}, 3, 7},

        // ProfileManager: MOV RAX,[rip+?] ; MOV RAX,[RAX+0x110] ; MOV RAX,[RAX] ; TEST RAX,RAX
        {"ProfileManager",
         "48 8B 05 ? ? ? ? 48 8B 80 10 01 00 00 48 8B 00 48 85 C0",
         {}, {}, 3, 7},

        // GlowManager: MOV RCX,[rip+?] ; TEST RCX,RCX ; JE 08 ; MOV RDX,RDI ; CALL
        {"GlowManager",
         "48 8B 0D ? ? ? ? 48 85 C9 74 08 48 89 FA E8",
         {}, {}, 3, 7},

        // RoundManager: MOV RAX,[rip+?]
        {"RoundManager",
         "48 8B 05 ? ? ? ? 48 C7 44 24 28 00 00 00 00 F0 41 FF",
         {}, {}, 3, 7},

        // Camera: MOV R9,[rip+?] ; XOR RDX,? ; LEA RDX,[RDX+RDX*2] ; SUB RDX,RSP ; ADD RDX,?
        {"Camera",
         "4C 8B 0D ? ? ? ? 48 81 F2 ? ? ? ? 4A 8D 14 52 48 29 E2 48 81 C2 ? ? ? ?",
         {}, {}, 3, 7},

        // EngineSpeed: MOVSS XMM0,[rip+?] ; MOVSS [rip+?],XMM0 ; RET
        {"EngineSpeed",
         "F3 0F 10 05 ? ? ? ? F3 0F 11 05 ? ? ? ? C3 CC",
         {}, {}, 4, 8},

        // ActorPosition: MOVUPS [RDI+0x50],XMM3 ; MOV RDX,[RDI+0x38] ; TEST EDX,...
        {"ActorPosition",
         "0F 11 5F 50 48 8B 57 38 F7 C2",
         {}, {}, -1, 0},

        // ActorDirection: MOVSS [RDX+0x30],XMM13
        {"ActorDirection",
         "F3 44 0F 11 6A 30 48 8B 54 24",
         {}, {}, -1, 0},

        // ActorFilterByte
        {"ActorFilterByte",
         "49 89 B8 B0 00 00 00 E9 BA 01",
         {}, {}, -1, 0},

        // ActorBoundsMax
        {"ActorBoundsMax",
         "42 0F 11 9C 84 90 00 00 00 F3",
         {}, {}, -1, 0},

        // ViewMatrix: MOVAPS XMM9,[RBP+0x390]
        {"ViewMatrix",
         "44 0F 28 8D 90 03 00 00 0F 57",
         {}, {}, -1, 0},
    };

    int numSigs = sizeof(sigs) / sizeof(sigs[0]);
    for (int i = 0; i < numSigs; i++) parseSig(sigs[i]);

    // Scan .text for all signatures
    printf("--- Scanning .text for %d signatures ---\n\n", numSigs);
    const uint32_t CHUNK = 0x100000; // 1MB chunks
    const uint32_t OVERLAP = 256;
    std::vector<uint8_t> buf(CHUNK + OVERLAP);

    for (int si = 0; si < numSigs; si++) {
        Sig& s = sigs[si];
        int sigLen = (int)s.bytes.size();
        bool found = false;

        for (uint64_t off = 0; off < textSize && !found; off += CHUNK) {
            uint32_t readSz = (uint32_t)((off + CHUNK + OVERLAP <= textSize) ? CHUNK + OVERLAP : textSize - off);
            if (!DmaRead(textBase + off, buf.data(), readSz)) continue;

            for (uint32_t i = 0; i + sigLen <= readSz; i++) {
                if (!matchSig(buf.data() + i, s)) continue;

                uint64_t matchAddr = textBase + off + i;
                uint64_t matchRVA = matchAddr - g_base;
                printf("  [FOUND] %-20s at 0x%llX (Base+0x%llX)\n",
                       s.name, (unsigned long long)matchAddr, (unsigned long long)matchRVA);

                // Show matched bytes
                printf("    Bytes:");
                for (int j = 0; j < sigLen; j++) printf(" %02X", buf[i + j]);
                printf("\n");

                // If this has a RIP-relative reference, resolve it
                if (s.ripOffset >= 0) {
                    int32_t disp = *(int32_t*)(buf.data() + i + s.ripOffset);
                    uint64_t targetAddr = matchAddr + s.ripInsnLen + disp;
                    uint64_t targetRVA = targetAddr - g_base;
                    printf("    RIP target: 0x%llX (Base+0x%llX)\n",
                           (unsigned long long)targetAddr, (unsigned long long)targetRVA);

                    // Read the value at the target
                    uint64_t val = rpm<uint64_t>(targetAddr);
                    printf("    Value at target: 0x%llX\n", (unsigned long long)val);

                    if (isHeapPtr(val)) {
                        printf("    -> VALID HEAP POINTER!\n");
                        uint64_t vt = rpm<uint64_t>(val);
                        if (isModPtr(vt))
                            printf("    -> vtbl = +0x%llX\n", (unsigned long long)(vt - g_base));

                        // If this is GameManager, try reading entity list
                        if (strncmp(s.name, "GameManager", 11) == 0) {
                            printf("\n    === GameManager Analysis ===\n");
                            printf("    GM object at 0x%llX\n", (unsigned long long)val);

                            // Dump first 0x200 bytes
                            uint8_t gmBuf[0x200];
                            if (DmaRead(val, gmBuf, sizeof(gmBuf))) {
                                printf("    First 0x100 bytes:\n");
                                for (int r = 0; r < 0x100; r += 16) {
                                    printf("      +%03X:", r);
                                    for (int c = 0; c < 16; c++) printf(" %02X", gmBuf[r+c]);
                                    printf("\n");
                                }

                                // Check common entity list offsets
                                printf("\n    Checking entity list offsets:\n");
                                int offsets[] = {0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8,
                                                 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8, 0x100, 0x108,
                                                 0x110, 0x118, 0x120, 0x128, 0x130, 0x138, 0x140,
                                                 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
                                                 0x180, 0x188, 0x190, 0x198, 0x1A0, 0x1A8, 0x1B0,
                                                 0x1B8, 0x1C0, 0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8};
                                for (int eo : offsets) {
                                    if (eo + 16 > 0x200) continue;
                                    uint64_t begin = *(uint64_t*)(gmBuf + eo);
                                    uint64_t end   = *(uint64_t*)(gmBuf + eo + 8);
                                    if (!isHeapPtr(begin) || end <= begin) continue;
                                    if ((end - begin) % 8 != 0) continue;
                                    int cnt = (int)((end - begin) / 8);
                                    if (cnt < 2 || cnt > 500) continue;

                                    // Read first entries
                                    int readN = (cnt > 20) ? 20 : cnt;
                                    uint64_t ptrs[20] = {};
                                    DmaRead(begin, ptrs, readN * 8);
                                    int valid = 0;
                                    for (int k = 0; k < readN; k++)
                                        if (isHeapPtr(ptrs[k])) valid++;

                                    if (valid < 2) continue;
                                    printf("      +0x%02X: vector, %d entries, %d valid ptrs\n",
                                           eo, cnt, valid);

                                    // Check if entries have vtables
                                    int withVt = 0;
                                    uint64_t commonVt = 0;
                                    for (int k = 0; k < readN; k++) {
                                        if (!isHeapPtr(ptrs[k])) continue;
                                        uint64_t evt = rpm<uint64_t>(ptrs[k]);
                                        if (isModPtr(evt)) {
                                            withVt++;
                                            if (!commonVt) commonVt = evt;
                                        }
                                    }
                                    if (withVt > 0)
                                        printf("        %d with vtables, first=+0x%llX\n",
                                               withVt, (unsigned long long)(commonVt - g_base));
                                }
                            }
                        }
                    } else if (val != 0) {
                        // Might be encrypted pointer
                        printf("    -> Not a direct heap ptr. Trying DEC decryption...\n");
                        uint64_t dec = DEC(val);
                        printf("    -> DEC(val) = 0x%llX", (unsigned long long)dec);
                        if (isHeapPtr(dec)) {
                            printf(" [VALID HEAP!]");
                            uint64_t vt = rpm<uint64_t>(dec);
                            if (isModPtr(vt))
                                printf(" vtbl=+0x%llX", (unsigned long long)(vt - g_base));
                        }
                        printf("\n");

                        // Try XOR with nearby values
                        uint8_t area[0x40];
                        DmaRead(targetAddr - 0x10, area, sizeof(area));
                        for (int ki = 0; ki < 0x40; ki += 8) {
                            if (ki == 0x10) continue; // skip self
                            uint64_t key = *(uint64_t*)(area + ki);
                            if (key == 0 || key == val) continue;
                            uint64_t xored = val ^ key;
                            if (isHeapPtr(xored)) {
                                uint64_t xvt = rpm<uint64_t>(xored);
                                if (isModPtr(xvt))
                                    printf("    -> XOR(nearby@%+d) = 0x%llX vtbl=+0x%llX\n",
                                           ki - 0x10, (unsigned long long)xored,
                                           (unsigned long long)(xvt - g_base));
                            }
                        }
                    } else {
                        printf("    -> NULL (manager not initialized?)\n");
                    }
                }
                printf("\n");
                found = true;
                break;
            }
        }

        if (!found) printf("  [MISS]  %-20s not found\n\n", s.name);
    }

    printf("Done.\n");
    pClose(g_vmm);
    return 0;
}
