// R6 RTTI Scanner — find GameManager and entity classes via MSVC RTTI strings
// Build: cl /O2 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS r6_rtti.cpp /Fe"../r6_rtti.exe" /link

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>

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

static bool isModPtr(uint64_t v) { return v >= g_base && v < g_modEnd; }
static bool isHeapPtr(uint64_t v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && !isModPtr(v); }

// MSVC RTTI TypeDescriptor layout:
// +0x00: pVFTable (pointer to type_info vtable)
// +0x08: spare (0)
// +0x10: name[] — decorated name string like ".?AVGameManager@@"

struct RTTIHit {
    uint64_t addr;       // address of TypeDescriptor
    uint64_t vtblAddr;   // address of the vtable (if found)
    char name[128];
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== R6 RTTI Scanner ===\n\n");

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
    printf("[+] PID=%u Base=0x%llX End=0x%llX\n", g_pid,
           (unsigned long long)g_base, (unsigned long long)g_modEnd);

    // Find .rdata section
    uint64_t rdataBase = 0, rdataSize = 0;
    uint64_t dataBase = 0, dataSize = 0;
    uint64_t secAddr = g_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = rpm<IMAGE_SECTION_HEADER>(secAddr + i * sizeof(IMAGE_SECTION_HEADER));
        if (memcmp(sec.Name, ".rdata", 6) == 0) {
            rdataBase = g_base + sec.VirtualAddress;
            rdataSize = sec.Misc.VirtualSize;
        }
        if (memcmp(sec.Name, ".data", 5) == 0) {
            dataBase = g_base + sec.VirtualAddress;
            dataSize = sec.Misc.VirtualSize;
        }
    }
    printf("[+] .rdata: 0x%llX (%.1f MB)\n", (unsigned long long)rdataBase, rdataSize / 1048576.0);
    printf("[+] .data: 0x%llX (%.1f MB)\n\n", (unsigned long long)dataBase, dataSize / 1048576.0);

    // Search strings in .rdata for entity/manager related RTTI names
    const char* searches[] = {
        "Manager",
        "Entity",
        "Player",
        "Pawn",
        "Actor",
        "Character",
        "Operator",
        "NetworkReplicat",
        "ProfileManager",
        "GameManager",
        "RoundManager",
        "MatchManager",
        "WorldManager",
    };
    int nSearches = sizeof(searches) / sizeof(searches[0]);

    printf("=== Scanning .rdata for RTTI class names ===\n\n");

    const uint32_t CHUNK = 0x40000;
    std::vector<uint8_t> buf(CHUNK);
    std::vector<RTTIHit> hits;

    for (uint64_t off = 0; off < rdataSize; off += CHUNK - 256) {
        uint32_t readSz = (uint32_t)min((uint64_t)CHUNK, rdataSize - off);
        if (!DmaRead(rdataBase + off, buf.data(), readSz)) continue;

        // Look for ".?AV" prefix (MSVC RTTI decorated name)
        for (uint32_t i = 0; i + 32 < readSz; i++) {
            if (buf[i] != '.' || buf[i+1] != '?' || buf[i+2] != 'A' || buf[i+3] != 'V')
                continue;

            // Extract the class name
            char name[128] = {};
            int ni = 0;
            for (uint32_t j = i; j < readSz && j < i + 127 && buf[j] != 0; j++)
                name[ni++] = buf[j];
            name[ni] = 0;

            // Check if this matches any of our search terms
            bool match = false;
            for (int s = 0; s < nSearches; s++) {
                if (strstr(name, searches[s])) { match = true; break; }
            }
            if (!match) continue;

            // This is the TypeDescriptor name at offset +0x10 from TypeDescriptor start
            uint64_t typeDescAddr = rdataBase + off + i - 0x10;

            RTTIHit hit;
            hit.addr = typeDescAddr;
            hit.vtblAddr = 0;
            strncpy(hit.name, name, 127);
            hits.push_back(hit);
        }
    }

    // Sort and deduplicate
    std::sort(hits.begin(), hits.end(), [](const RTTIHit& a, const RTTIHit& b) {
        return strcmp(a.name, b.name) < 0;
    });

    printf("Found %d RTTI class names:\n\n", (int)hits.size());
    for (auto& h : hits) {
        printf("  0x%llX: %s\n", (unsigned long long)h.addr, h.name);
    }

    // For the most interesting ones, try to find their vtable
    // MSVC RTTI: vtable[-1] = RTTI Complete Object Locator
    // COL+0x0C = offset to TypeDescriptor (RVA from module base)
    // So scan .rdata for pointers that reference each TypeDescriptor

    printf("\n\n=== Searching for vtables of key classes ===\n");

    // Key classes to find vtables for
    const char* keyClasses[] = {
        "GameManager",
        "Manager",
        "Entity",
        "Player",
        "Pawn",
        "Actor",
        "Replicat",
        "Profile",
    };

    for (auto& hit : hits) {
        bool isKey = false;
        for (auto& kc : keyClasses) {
            if (strstr(hit.name, kc)) { isKey = true; break; }
        }
        if (!isKey) continue;

        // The TypeDescriptor RVA (offset from module base)
        uint32_t tdRVA = (uint32_t)(hit.addr - g_base);

        // Scan .rdata for CompleteObjectLocator referencing this TypeDescriptor
        // COL layout: +0x00 = signature (1 for 64-bit), +0x04 = offset, +0x08 = cdOffset,
        //             +0x0C = pTypeDescriptor (RVA), +0x10 = pClassHierarchy (RVA), +0x14 = pSelf (RVA)
        for (uint64_t roff = 0; roff < rdataSize; roff += CHUNK - 256) {
            uint32_t rReadSz = (uint32_t)min((uint64_t)CHUNK, rdataSize - roff);
            if (!DmaRead(rdataBase + roff, buf.data(), rReadSz)) continue;

            for (uint32_t ri = 0; ri + 24 < rReadSz; ri += 4) {
                uint32_t sig = *(uint32_t*)(buf.data() + ri);
                if (sig != 1) continue; // 64-bit RTTI signature
                uint32_t pTD = *(uint32_t*)(buf.data() + ri + 0x0C);
                if (pTD != tdRVA) continue;

                // Found a COL pointing to our TypeDescriptor!
                uint64_t colAddr = rdataBase + roff + ri;

                // Now find the vtable: scan for a pointer to colAddr
                // vtable[-1] (i.e., vtable_addr - 8) points to COL
                // So we need to find colAddr stored as a pointer in .rdata
                for (uint64_t voff = 0; voff < rdataSize; voff += CHUNK - 256) {
                    uint32_t vReadSz = (uint32_t)min((uint64_t)CHUNK, rdataSize - voff);
                    if (!DmaRead(rdataBase + voff, buf.data(), vReadSz)) continue;

                    for (uint32_t vi = 0; vi + 8 < vReadSz; vi += 8) {
                        uint64_t ptrVal = *(uint64_t*)(buf.data() + vi);
                        if (ptrVal == colAddr) {
                            // vtable[-1] = COL, so vtable = this_addr + 8
                            uint64_t vtblAddr = rdataBase + voff + vi + 8;
                            printf("  %s\n", hit.name);
                            printf("    TypeDesc=0x%llX COL=0x%llX vtbl=0x%llX (+0x%llX)\n",
                                   (unsigned long long)hit.addr,
                                   (unsigned long long)colAddr,
                                   (unsigned long long)vtblAddr,
                                   (unsigned long long)(vtblAddr - g_base));

                            // Check if any .data global points to a heap object with this vtable
                            // Quick scan: check first 1MB of .data
                            uint8_t dataBuf[0x10000];
                            int scanLimit = (int)min(dataSize, (uint64_t)0x200000);
                            for (uint64_t doff = 0; doff < (uint64_t)scanLimit; doff += 0x10000) {
                                uint32_t drs = (uint32_t)min((uint64_t)0x10000, dataSize - doff);
                                if (!DmaRead(dataBase + doff, dataBuf, drs)) continue;
                                for (uint32_t di = 0; di + 8 <= drs; di += 8) {
                                    uint64_t gv = *(uint64_t*)(dataBuf + di);
                                    if (!isHeapPtr(gv)) continue;
                                    uint64_t objVt = rpm<uint64_t>(gv);
                                    if (objVt == vtblAddr) {
                                        printf("    >>> INSTANCE at .data+0x%llX -> 0x%llX\n",
                                               (unsigned long long)(doff + di), (unsigned long long)gv);
                                    }
                                }
                            }
                            hit.vtblAddr = vtblAddr;
                            goto found_vtbl;
                        }
                    }
                }
                found_vtbl:;
                goto next_hit;
            }
        }
        next_hit:;
    }

    printf("\nDone.\n");
    pClose(g_vmm);
    return 0;
}
