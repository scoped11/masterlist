// DMA Dumper — reads game memory via FPGA DMA card using MemProcFS/VMM API
// Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.
// Completely invisible to all anti-cheat — reads happen at the hardware level.
//
// Requirements: vmm.dll + leechcore.dll in same directory (from MemProcFS release)
// Usage: dumper_dma.exe <game> [options]
//
// Build: cl /O2 /EHsc dumper_dma.cpp /link /SUBSYSTEM:CONSOLE

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

// ── VMM API types (dynamically loaded from vmm.dll) ────────────────────────────

typedef void* VMM_HANDLE;

#pragma pack(push, 8)

typedef struct {
    ULONG64 vaBase;
    ULONG64 vaEntry;
    DWORD   cbImageSize;
    BOOL    fWoW64;
    CHAR    uszText[260];
    CHAR    uszFullName[260];
    DWORD   tp;
    DWORD   cbFileSizeRaw;
    DWORD   cSection;
    DWORD   cEAT;
    DWORD   cIAT;
    DWORD   _Reserved2;
    ULONG64 _Reserved3[3];
} VMMDLL_MAP_MODULEENTRY_V1;

typedef struct {
    DWORD   dwVersion;
    DWORD   _Reserved1[5];
    PBYTE   pbMultiText;
    DWORD   cbMultiText;
    DWORD   cMap;
    // pMap[] follows — variable-length array
} VMMDLL_MAP_MODULE_HDR;

typedef struct {
    ULONG64 vaBase;
    ULONG64 cbImageSize;
    CHAR    uszText[260];
} VMMDLL_MAP_MODULEENTRY_SIMPLE;

typedef struct {
    ULONG64 magic;
    WORD    wVersion;
    WORD    wSize;
    DWORD   tpMemoryModel;
    DWORD   tpSystem;
    BOOL    fAbort;
    DWORD   dwPID;
    DWORD   dwPPID;
    DWORD   dwState;
    CHAR    szName[16];
    CHAR    szNameLong[64];
    ULONG64 paDTB;
    ULONG64 paDTB_UserOpt;
    // ... more fields exist but we only need the above
} VMMDLL_PROCESS_INFORMATION;

#pragma pack(pop)

// VMM function pointers
typedef VMM_HANDLE  (__cdecl *fn_VMMDLL_Initialize)(DWORD argc, LPCSTR argv[]);
typedef VOID        (__cdecl *fn_VMMDLL_Close)(VMM_HANDLE hVMM);
typedef VOID        (__cdecl *fn_VMMDLL_CloseAll)();
typedef BOOL        (__cdecl *fn_VMMDLL_PidGetFromName)(VMM_HANDLE hVMM, LPCSTR szProcName, PDWORD pdwPID);
typedef BOOL        (__cdecl *fn_VMMDLL_PidList)(VMM_HANDLE hVMM, PDWORD pPIDs, PULONG64 pcPIDs);
typedef BOOL        (__cdecl *fn_VMMDLL_MemReadEx)(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags);
typedef BOOL        (__cdecl *fn_VMMDLL_ProcessGetInformationString)(VMM_HANDLE hVMM, DWORD dwPID, DWORD fOptionString, LPSTR *pszStr);
typedef VOID        (__cdecl *fn_VMMDLL_MemFree)(PVOID pv);

// Scatter read API for efficient bulk reads
typedef HANDLE      (__cdecl *fn_VMMDLL_Scatter_Initialize)(VMM_HANDLE hVMM, DWORD dwPID, DWORD flags);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Prepare)(HANDLE hS, ULONG64 va, DWORD cb);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Execute)(HANDLE hS);
typedef BOOL        (__cdecl *fn_VMMDLL_Scatter_Read)(HANDLE hS, ULONG64 va, DWORD cb, PBYTE pb, PDWORD pcbRead);
typedef VOID        (__cdecl *fn_VMMDLL_Scatter_CloseHandle)(HANDLE hS);

// Module enumeration via ProcessGetInformation
typedef ULONG64     (__cdecl *fn_VMMDLL_ProcessGetModuleBaseU)(VMM_HANDLE hVMM, DWORD dwPID, LPCSTR uszModuleName);
typedef BOOL        (__cdecl *fn_VMMDLL_ProcessGetInformation)(VMM_HANDLE hVMM, DWORD dwPID, PVOID pProcessInformation, PSIZE_T pcbProcessInformation);
typedef BOOL        (__cdecl *fn_VMMDLL_Map_GetModuleU)(VMM_HANDLE hVMM, DWORD dwPID, PVOID *ppModuleMap, DWORD flags);

// ── Global state ───────────────────────────────────────────────────────────────

static HMODULE g_hVMM = nullptr;
static VMM_HANDLE g_hVmmHandle = nullptr;

static fn_VMMDLL_Initialize             pVMMDLL_Initialize = nullptr;
static fn_VMMDLL_Close                  pVMMDLL_Close = nullptr;
static fn_VMMDLL_PidGetFromName         pVMMDLL_PidGetFromName = nullptr;
static fn_VMMDLL_PidList                pVMMDLL_PidList = nullptr;
static fn_VMMDLL_MemReadEx              pVMMDLL_MemReadEx = nullptr;
static fn_VMMDLL_ProcessGetInformationString pVMMDLL_ProcessGetInformationString = nullptr;
static fn_VMMDLL_MemFree               pVMMDLL_MemFree = nullptr;
static fn_VMMDLL_Scatter_Initialize     pVMMDLL_Scatter_Initialize = nullptr;
static fn_VMMDLL_Scatter_Prepare        pVMMDLL_Scatter_Prepare = nullptr;
static fn_VMMDLL_Scatter_Execute        pVMMDLL_Scatter_Execute = nullptr;
static fn_VMMDLL_Scatter_Read           pVMMDLL_Scatter_Read = nullptr;
static fn_VMMDLL_Scatter_CloseHandle    pVMMDLL_Scatter_CloseHandle = nullptr;
static fn_VMMDLL_ProcessGetModuleBaseU  pVMMDLL_ProcessGetModuleBaseU = nullptr;
static fn_VMMDLL_ProcessGetInformation  pVMMDLL_ProcessGetInformation = nullptr;
static fn_VMMDLL_Map_GetModuleU         pVMMDLL_Map_GetModuleU = nullptr;

// ── VMM loader ─────────────────────────────────────────────────────────────────

static bool LoadVMM() {
    g_hVMM = LoadLibraryA("vmm.dll");
    if (!g_hVMM) {
        printf("[-] vmm.dll not found. Place vmm.dll + leechcore.dll in the same directory.\n");
        printf("    Download MemProcFS from: https://github.com/ufrisk/MemProcFS/releases\n");
        return false;
    }

    #define LOAD(name) p##name = (fn_##name)GetProcAddress(g_hVMM, #name)
    LOAD(VMMDLL_Initialize);
    LOAD(VMMDLL_Close);
    LOAD(VMMDLL_PidGetFromName);
    LOAD(VMMDLL_PidList);
    LOAD(VMMDLL_MemReadEx);
    LOAD(VMMDLL_ProcessGetInformationString);
    LOAD(VMMDLL_MemFree);
    LOAD(VMMDLL_Scatter_Initialize);
    LOAD(VMMDLL_Scatter_Prepare);
    LOAD(VMMDLL_Scatter_Execute);
    LOAD(VMMDLL_Scatter_Read);
    LOAD(VMMDLL_Scatter_CloseHandle);
    LOAD(VMMDLL_ProcessGetModuleBaseU);
    LOAD(VMMDLL_ProcessGetInformation);
    LOAD(VMMDLL_Map_GetModuleU);
    #undef LOAD

    if (!pVMMDLL_Initialize || !pVMMDLL_MemReadEx) {
        printf("[-] Failed to resolve VMM API functions. Version mismatch?\n");
        return false;
    }

    return true;
}

// ── DMA memory read wrappers ───────────────────────────────────────────────────

static bool DmaRead(DWORD pid, uint64_t va, void* buf, size_t size) {
    DWORD cbRead = 0;
    // VMMDLL_FLAG_NOCACHE = 0x0001, VMMDLL_FLAG_ZEROPAD_ON_FAIL = 0x0002
    return pVMMDLL_MemReadEx(g_hVmmHandle, pid, va, (PBYTE)buf, (DWORD)size, &cbRead, 0x0002) && cbRead > 0;
}

static bool DmaReadChunked(DWORD pid, uint64_t va, void* buf, size_t totalSize) {
    const size_t CHUNK = 0x1000; // 4KB pages
    uint8_t* dst = (uint8_t*)buf;
    size_t remaining = totalSize;
    size_t offset = 0;

    while (remaining > 0) {
        size_t toRead = min(remaining, CHUNK);
        DWORD cbRead = 0;
        pVMMDLL_MemReadEx(g_hVmmHandle, pid, va + offset, dst + offset, (DWORD)toRead, &cbRead, 0x0002);
        offset += toRead;
        remaining -= toRead;
    }
    return true;
}

// ── PE parsing helpers ─────────────────────────────────────────────────────────

struct ModuleInfo {
    std::string name;
    uint64_t    base;
    uint32_t    size;
};

struct SectionInfo {
    char name[9];
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawSize;
    uint32_t rawOffset;
    uint32_t flags;
};

struct ExportEntry {
    std::string name;
    uint32_t    rva;
};

static bool ReadPEHeaders(DWORD pid, uint64_t base, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt) {
    if (!DmaRead(pid, base, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!DmaRead(pid, base + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    return true;
}

static std::vector<SectionInfo> ReadSections(DWORD pid, uint64_t base, const IMAGE_DOS_HEADER& dos, const IMAGE_NT_HEADERS64& nt) {
    std::vector<SectionInfo> sections;
    uint64_t secAddr = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec{};
        if (!DmaRead(pid, secAddr + i * sizeof(sec), &sec, sizeof(sec))) continue;

        SectionInfo si{};
        memcpy(si.name, sec.Name, 8);
        si.name[8] = 0;
        si.virtualAddress = sec.VirtualAddress;
        si.virtualSize = sec.Misc.VirtualSize;
        si.rawSize = sec.SizeOfRawData;
        si.rawOffset = sec.PointerToRawData;
        si.flags = sec.Characteristics;
        sections.push_back(si);
    }
    return sections;
}

static std::vector<ExportEntry> ReadExports(DWORD pid, uint64_t base, const IMAGE_NT_HEADERS64& nt) {
    std::vector<ExportEntry> exports;
    auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return exports;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!DmaRead(pid, base + dir.VirtualAddress, &exp, sizeof(exp))) return exports;

    std::vector<DWORD> funcs(exp.NumberOfFunctions);
    std::vector<DWORD> names(exp.NumberOfNames);
    std::vector<WORD>  ords(exp.NumberOfNames);

    if (exp.NumberOfFunctions)
        DmaRead(pid, base + exp.AddressOfFunctions, funcs.data(), exp.NumberOfFunctions * sizeof(DWORD));
    if (exp.NumberOfNames) {
        DmaRead(pid, base + exp.AddressOfNames, names.data(), exp.NumberOfNames * sizeof(DWORD));
        DmaRead(pid, base + exp.AddressOfNameOrdinals, ords.data(), exp.NumberOfNames * sizeof(WORD));
    }

    for (DWORD i = 0; i < exp.NumberOfNames && i < 1000; i++) {
        char nameBuf[256]{};
        if (DmaRead(pid, base + names[i], nameBuf, sizeof(nameBuf) - 1)) {
            ExportEntry e;
            e.name = nameBuf;
            e.rva = (ords[i] < funcs.size()) ? funcs[ords[i]] : 0;
            exports.push_back(e);
        }
    }
    return exports;
}

static std::vector<std::string> ReadImports(DWORD pid, uint64_t base, const IMAGE_NT_HEADERS64& nt) {
    std::vector<std::string> dlls;
    auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return dlls;

    for (int i = 0; i < 256; i++) {
        IMAGE_IMPORT_DESCRIPTOR imp{};
        if (!DmaRead(pid, base + dir.VirtualAddress + i * sizeof(imp), &imp, sizeof(imp))) break;
        if (!imp.Name) break;

        char dllName[128]{};
        if (DmaRead(pid, base + imp.Name, dllName, sizeof(dllName) - 1))
            dlls.push_back(dllName);
    }
    return dlls;
}

// ── Module enumeration via VMM API ─────────────────────────────────────────────

static std::vector<ModuleInfo> EnumerateModulesDirect(DWORD pid) {
    std::vector<ModuleInfo> modules;

    // Try VMMDLL_Map_GetModuleU first (returns full module map)
    if (pVMMDLL_Map_GetModuleU) {
        PVOID pModMap = nullptr;
        if (pVMMDLL_Map_GetModuleU(g_hVmmHandle, pid, &pModMap, 0) && pModMap) {
            auto* hdr = (VMMDLL_MAP_MODULE_HDR*)pModMap;
            uint8_t* raw = (uint8_t*)pModMap;

            // Module entries start after the header
            // Structure layout varies by MemProcFS version, so we parse carefully
            uint8_t* entryBase = raw + sizeof(VMMDLL_MAP_MODULE_HDR);

            // Try to detect entry size by reading first entry's base address
            // Entry layout: vaBase(8) vaEntry(8) cbImageSize(4) fWoW64(4) uszText(ptr/inline)...
            // This varies between versions, so we try common sizes

            for (DWORD i = 0; i < hdr->cMap; i++) {
                // Try reading entry at offset assuming largest common struct size
                // MemProcFS v5.8+: entries are ~0x180 bytes each
                // MemProcFS v5.0-5.7: entries are ~0x130 bytes each
                // We try both by checking if vaBase looks valid

                for (int entrySize : {0x180, 0x130, 0x100, 0x200}) {
                    uint8_t* ep = entryBase + i * entrySize;
                    if (ep + 24 > raw + hdr->cbMultiText + sizeof(VMMDLL_MAP_MODULE_HDR) + hdr->cMap * 0x200)
                        break;

                    uint64_t vaBase = *(uint64_t*)(ep + 0);
                    uint64_t vaEntry = *(uint64_t*)(ep + 8);
                    uint32_t cbImage = *(uint32_t*)(ep + 16);

                    // Sanity check: base should be in user/kernel space
                    if (vaBase > 0x10000 && vaBase < 0xFFFFFFFFFFFF0000ULL && cbImage > 0 && cbImage < 0x80000000) {
                        // This entry size works — read all entries with it
                        modules.clear();
                        for (DWORD j = 0; j < hdr->cMap; j++) {
                            uint8_t* p = entryBase + j * entrySize;
                            uint64_t b = *(uint64_t*)(p + 0);
                            uint32_t sz = *(uint32_t*)(p + 16);

                            if (b < 0x10000 || sz == 0) continue;

                            // Try to find the module name — it's either inline or a pointer to multitext
                            ModuleInfo mi;
                            mi.base = b;
                            mi.size = sz;

                            // Read the name from the module's PE headers instead (more reliable)
                            char modName[260]{};
                            bool gotName = false;

                            // Check offset 20 (after fWoW64) for inline string
                            char* nameCandidate = (char*)(p + 24);
                            if (nameCandidate[0] >= 0x20 && nameCandidate[0] < 0x7F && strlen(nameCandidate) > 2 && strlen(nameCandidate) < 256) {
                                mi.name = nameCandidate;
                                gotName = true;
                            }

                            if (!gotName) {
                                // Fall back to PE header export name
                                IMAGE_DOS_HEADER dos{};
                                IMAGE_NT_HEADERS64 nt{};
                                if (ReadPEHeaders(pid, b, dos, nt)) {
                                    auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                                    if (expDir.VirtualAddress) {
                                        IMAGE_EXPORT_DIRECTORY ed{};
                                        if (DmaRead(pid, b + expDir.VirtualAddress, &ed, sizeof(ed))) {
                                            if (ed.Name)
                                                DmaRead(pid, b + ed.Name, modName, sizeof(modName) - 1);
                                        }
                                    }
                                }
                                mi.name = modName[0] ? modName : ("module_" + std::to_string(j));
                            }

                            modules.push_back(mi);
                        }
                        goto done;
                    }
                }
            }
            done:
            if (pVMMDLL_MemFree) pVMMDLL_MemFree(pModMap);
            if (!modules.empty()) return modules;
        }
    }

    // Fallback: walk PEB ourselves via DMA
    printf("[*] Falling back to manual PEB walk via DMA...\n");

    // Read process PEB address from process info
    VMMDLL_PROCESS_INFORMATION info{};
    SIZE_T cbInfo = sizeof(info);
    info.magic = 0x6372705f6d6d7663ULL; // "cvmm_prc"
    info.wVersion = 6;
    info.wSize = sizeof(info);

    if (pVMMDLL_ProcessGetInformation &&
        pVMMDLL_ProcessGetInformation(g_hVmmHandle, pid, &info, &cbInfo)) {
        printf("[+] Process DTB: 0x%llX\n", (unsigned long long)info.paDTB);
    }

    // Try known module names for common games
    const char* commonModules[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "RainbowSix.exe", "r5apex_dx12.exe", "r5apex.exe", "RustClient.exe",
        "cs2.exe", "Unturned.exe", "DeltaForceClient-Win64-Shipping.exe",
        "stalzone.exe", "STALZONE.exe",
        "BEClient_x64.dll", "EasyAntiCheat_EOS.sys",
        "d3d11.dll", "d3d12.dll", "dxgi.dll",
        "UnityPlayer.dll", "GameAssembly.dll",
        "client.dll", "engine2.dll", "server.dll",
        nullptr
    };

    if (pVMMDLL_ProcessGetModuleBaseU) {
        for (int i = 0; commonModules[i]; i++) {
            uint64_t base = pVMMDLL_ProcessGetModuleBaseU(g_hVmmHandle, pid, commonModules[i]);
            if (base) {
                IMAGE_DOS_HEADER dos{};
                IMAGE_NT_HEADERS64 nt{};
                if (ReadPEHeaders(pid, base, dos, nt)) {
                    ModuleInfo mi;
                    mi.name = commonModules[i];
                    mi.base = base;
                    mi.size = nt.OptionalHeader.SizeOfImage;
                    modules.push_back(mi);
                }
            }
        }
    }

    return modules;
}

// ── Dump a single module ───────────────────────────────────────────────────────

static bool DumpModule(DWORD pid, const ModuleInfo& mod, const std::string& outDir) {
    printf("\n=== %s ===\n", mod.name.c_str());
    printf("  Base: 0x%llX  Size: %u KB\n", (unsigned long long)mod.base, mod.size / 1024);

    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(pid, mod.base, dos, nt)) {
        printf("  [-] Failed to read PE headers\n");
        return false;
    }

    printf("  Image Base: 0x%llX  Sections: %d\n",
           (unsigned long long)nt.OptionalHeader.ImageBase,
           nt.FileHeader.NumberOfSections);

    // Read sections
    auto sections = ReadSections(pid, mod.base, dos, nt);
    printf("\n  Sections:\n");
    printf("  %-10s %-12s %-12s %-10s\n", "Name", "VirtAddr", "VirtSize", "Flags");
    for (auto& sec : sections) {
        printf("  %-10s 0x%08X   0x%08X   0x%08X", sec.name, sec.virtualAddress, sec.virtualSize, sec.flags);
        if (sec.flags & 0x20000000) printf(" X");
        if (sec.flags & 0x40000000) printf(" R");
        if (sec.flags & 0x80000000) printf(" W");
        printf("\n");
    }

    // Read exports
    auto exports = ReadExports(pid, mod.base, nt);
    if (!exports.empty()) {
        printf("\n  Exports (%zu):\n", exports.size());
        int shown = 0;
        for (auto& e : exports) {
            if (shown < 30)
                printf("    0x%08X  %s\n", e.rva, e.name.c_str());
            shown++;
        }
        if (shown > 30) printf("    ... and %d more\n", shown - 30);
    }

    // Read imports
    auto imports = ReadImports(pid, mod.base, nt);
    if (!imports.empty()) {
        printf("\n  Imports (%zu DLLs):\n", imports.size());
        for (auto& dll : imports)
            printf("    %s\n", dll.c_str());
    }

    // Dump memory to file
    std::string outFile = outDir + "\\" + mod.name + ".dma_dump";
    uint32_t dumpSize = nt.OptionalHeader.SizeOfImage;
    if (dumpSize > 512 * 1024 * 1024) {
        printf("  [!] Module too large (%u MB), capping at 512MB\n", dumpSize / (1024*1024));
        dumpSize = 512 * 1024 * 1024;
    }

    printf("\n  [*] Dumping %u KB via DMA...\n", dumpSize / 1024);

    std::vector<uint8_t> buffer(dumpSize, 0);

    // Use scatter reads for efficiency (reads multiple pages in one DMA transaction)
    if (pVMMDLL_Scatter_Initialize) {
        HANDLE hScatter = pVMMDLL_Scatter_Initialize(g_hVmmHandle, pid, 0x0002);
        if (hScatter) {
            // Prepare all pages
            for (uint32_t off = 0; off < dumpSize; off += 0x1000) {
                uint32_t readSz = min((uint32_t)0x1000, dumpSize - off);
                pVMMDLL_Scatter_Prepare(hScatter, mod.base + off, readSz);
            }

            // Execute all reads in one DMA transaction
            pVMMDLL_Scatter_Execute(hScatter);

            // Collect results
            for (uint32_t off = 0; off < dumpSize; off += 0x1000) {
                uint32_t readSz = min((uint32_t)0x1000, dumpSize - off);
                DWORD cbRead = 0;
                pVMMDLL_Scatter_Read(hScatter, mod.base + off, readSz, buffer.data() + off, &cbRead);
            }

            pVMMDLL_Scatter_CloseHandle(hScatter);
        } else {
            DmaReadChunked(pid, mod.base, buffer.data(), dumpSize);
        }
    } else {
        DmaReadChunked(pid, mod.base, buffer.data(), dumpSize);
    }

    // Write dump file
    FILE* f = fopen(outFile.c_str(), "wb");
    if (f) {
        fwrite(buffer.data(), 1, dumpSize, f);
        fclose(f);
        printf("  [+] Wrote %s (%u KB)\n", outFile.c_str(), dumpSize / 1024);
    } else {
        printf("  [-] Failed to write %s\n", outFile.c_str());
    }

    return true;
}

// ── Process listing ────────────────────────────────────────────────────────────

static void ListProcesses() {
    ULONG64 count = 0;
    if (!pVMMDLL_PidList(g_hVmmHandle, nullptr, &count) || count == 0) {
        printf("[-] No processes found\n");
        return;
    }

    std::vector<DWORD> pids((size_t)count);
    pVMMDLL_PidList(g_hVmmHandle, pids.data(), &count);

    printf("[+] %llu processes on target:\n\n", count);
    printf("  %-8s  %s\n", "PID", "NAME");
    printf("  %-8s  %s\n", "---", "----");

    for (DWORD i = 0; i < (DWORD)count; i++) {
        LPSTR name = nullptr;
        // VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE = 2
        if (pVMMDLL_ProcessGetInformationString &&
            pVMMDLL_ProcessGetInformationString(g_hVmmHandle, pids[i], 2, &name) && name) {
            printf("  %-8lu  %s\n", pids[i], name);
            pVMMDLL_MemFree(name);
        } else {
            // Try to get just the name
            LPSTR shortName = nullptr;
            // VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL = 3
            if (pVMMDLL_ProcessGetInformationString &&
                pVMMDLL_ProcessGetInformationString(g_hVmmHandle, pids[i], 1, &shortName) && shortName) {
                printf("  %-8lu  %s\n", pids[i], shortName);
                pVMMDLL_MemFree(shortName);
            } else {
                printf("  %-8lu  (unknown)\n", pids[i]);
            }
        }
    }
}

// ── Game name aliases ──────────────────────────────────────────────────────────

static const char* ResolveGameProcess(const char* input) {
    struct Alias { const char* alias; const char* proc; };
    static const Alias aliases[] = {
        {"apex",        "r5apex_dx12.exe"},
        {"r6",          "RainbowSix.exe"},
        {"siege",       "RainbowSix.exe"},
        {"rainbow",     "RainbowSix.exe"},
        {"unturned",    "Unturned.exe"},
        {"rust",        "RustClient.exe"},
        {"delta",       "DeltaForceClient-Win64-Shipping.exe"},
        {"df",          "DeltaForceClient-Win64-Shipping.exe"},
        {"stalcraft",   "stalzone.exe"},
        {"stalzone",    "STALZONE.exe"},
        {"cs2",         "cs2.exe"},
        {nullptr, nullptr}
    };

    std::string q = input;
    for (auto& c : q) c = (char)tolower((unsigned char)c);

    for (int i = 0; aliases[i].alias; i++) {
        if (q == aliases[i].alias) return aliases[i].proc;
    }

    return input; // assume it's already a process name
}

// ── Usage ──────────────────────────────────────────────────────────────────────

static void PrintUsage(const char* exe) {
    printf("Usage: %s <game|process> [options]\n\n", exe);
    printf("Dumps game memory via DMA (FPGA card). Completely invisible to anti-cheat.\n");
    printf("Runs on PC2 (radar), reads PC1 (target) memory over hardware DMA.\n\n");
    printf("Games:\n");
    printf("  apex, r6/siege, unturned, rust, delta/df, stalcraft, cs2\n");
    printf("  Or pass any process name: dumper_dma.exe SomeGame.exe\n\n");
    printf("Options:\n");
    printf("  --device <str>   LeechCore device string (default: fpga)\n");
    printf("  --remote <ip>    Connect to remote LeechAgent (fpga://ip:port)\n");
    printf("  --outdir <dir>   Output directory (default: current dir)\n");
    printf("  --list           List all processes on target\n");
    printf("  --all            Dump ALL modules (not just main exe)\n");
    printf("  --help           Show this help\n\n");
    printf("Requirements:\n");
    printf("  vmm.dll + leechcore.dll must be in the same directory (from MemProcFS)\n");
    printf("  FPGA DMA card connected via USB\n\n");
    printf("Examples:\n");
    printf("  %s r6                          Dump Rainbow Six Siege\n", exe);
    printf("  %s apex --all                  Dump Apex with all modules\n", exe);
    printf("  %s RainbowSix.exe --outdir dumps\n", exe);
    printf("  %s --list                      Show all processes on target PC\n", exe);
}

// ── Main ───────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== DMA Dumper — Hardware Memory Reader ===\n");
    printf("=== Invisible to all anti-cheat (BattlEye/EAC/ACE/Vanguard) ===\n\n");

    std::string gameName;
    std::string deviceStr = "fpga";
    std::string outDir = ".";
    bool listOnly = false;
    bool dumpAll = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i+1 < argc) deviceStr = argv[++i];
        else if (strcmp(argv[i], "--remote") == 0 && i+1 < argc) {
            deviceStr = std::string("fpga://") + argv[++i];
        }
        else if (strcmp(argv[i], "--outdir") == 0 && i+1 < argc) outDir = argv[++i];
        else if (strcmp(argv[i], "--list") == 0) listOnly = true;
        else if (strcmp(argv[i], "--all") == 0) dumpAll = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]); return 0;
        }
        else if (gameName.empty()) gameName = argv[i];
    }

    if (!listOnly && gameName.empty()) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Load VMM
    printf("[*] Loading MemProcFS (vmm.dll)...\n");
    if (!LoadVMM()) return 1;
    printf("[+] VMM loaded\n");

    // Initialize DMA connection
    printf("[*] Connecting to DMA device: %s\n", deviceStr.c_str());
    LPCSTR initArgs[] = {"", "-device", deviceStr.c_str(), "-v"};
    g_hVmmHandle = pVMMDLL_Initialize(4, initArgs);
    if (!g_hVmmHandle) {
        printf("[-] Failed to initialize DMA connection.\n");
        printf("    Check: FPGA card connected? USB cable plugged in? FTD3XX driver installed?\n");
        return 1;
    }
    printf("[+] DMA connection established!\n\n");

    // List mode
    if (listOnly) {
        ListProcesses();
        pVMMDLL_Close(g_hVmmHandle);
        return 0;
    }

    // Resolve game name
    const char* procName = ResolveGameProcess(gameName.c_str());
    printf("[*] Looking for: %s\n", procName);

    // Find process
    DWORD pid = 0;
    if (!pVMMDLL_PidGetFromName(g_hVmmHandle, procName, &pid) || pid == 0) {
        printf("[-] Process '%s' not found on target PC.\n", procName);
        printf("[*] Use --list to see all processes.\n");
        pVMMDLL_Close(g_hVmmHandle);
        return 1;
    }
    printf("[+] Found %s — PID %lu\n\n", procName, pid);

    // Create output directory
    CreateDirectoryA(outDir.c_str(), nullptr);

    // Enumerate modules
    printf("[*] Enumerating modules via DMA...\n");
    auto modules = EnumerateModulesDirect(pid);

    if (modules.empty()) {
        printf("[-] No modules found. Trying main exe only...\n");
        // Try to at least get the main module
        if (pVMMDLL_ProcessGetModuleBaseU) {
            uint64_t mainBase = pVMMDLL_ProcessGetModuleBaseU(g_hVmmHandle, pid, procName);
            if (mainBase) {
                IMAGE_DOS_HEADER dos{};
                IMAGE_NT_HEADERS64 nt{};
                if (ReadPEHeaders(pid, mainBase, dos, nt)) {
                    ModuleInfo mi;
                    mi.name = procName;
                    mi.base = mainBase;
                    mi.size = nt.OptionalHeader.SizeOfImage;
                    modules.push_back(mi);
                }
            }
        }
    }

    if (modules.empty()) {
        printf("[-] Could not find any modules.\n");
        pVMMDLL_Close(g_hVmmHandle);
        return 1;
    }

    printf("[+] Found %zu module(s)\n", modules.size());
    for (auto& m : modules) {
        printf("    %-40s  0x%llX  (%u KB)\n", m.name.c_str(), (unsigned long long)m.base, m.size / 1024);
    }

    // Dump modules
    if (dumpAll) {
        for (auto& m : modules)
            DumpModule(pid, m, outDir);
    } else {
        // Just dump the main exe
        for (auto& m : modules) {
            std::string lower = m.name;
            for (auto& c : lower) c = (char)tolower((unsigned char)c);
            std::string target = procName;
            for (auto& c : target) c = (char)tolower((unsigned char)c);
            if (lower == target || lower.find(target) != std::string::npos) {
                DumpModule(pid, m, outDir);
                break;
            }
        }
    }

    // Write report
    std::string reportFile = outDir + "\\dma_dump.report.txt";
    FILE* rep = fopen(reportFile.c_str(), "w");
    if (rep) {
        fprintf(rep, "DMA Dump Report\n");
        fprintf(rep, "Target process: %s (PID %lu)\n", procName, pid);
        fprintf(rep, "Modules found: %zu\n\n", modules.size());
        for (auto& m : modules) {
            fprintf(rep, "%-40s  Base: 0x%llX  Size: %u KB\n",
                    m.name.c_str(), (unsigned long long)m.base, m.size / 1024);
        }
        fclose(rep);
        printf("\n[+] Report: %s\n", reportFile.c_str());
    }

    printf("\n[+] DMA dump complete.\n");
    pVMMDLL_Close(g_hVmmHandle);
    return 0;
}
