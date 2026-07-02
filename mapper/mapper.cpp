#include "mapper.hpp"
#include <winternl.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <cstring>
#include <algorithm>
#include <cstdio>

// ── PE helpers ────────────────────────────────────────────────────────────────

static IMAGE_NT_HEADERS64* GetNtHeaders(const uint8_t* base) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                   const_cast<uint8_t*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)               return nullptr;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return nullptr;
    return nt;
}

// ── Step 1 – lay out a flat local copy (sections at their VAs) ────────────────

static std::vector<uint8_t> BuildMappedImage(const uint8_t*      raw,
                                              size_t               rawSize,
                                              IMAGE_NT_HEADERS64* nt) {
    size_t imageSize = nt->OptionalHeader.SizeOfImage;
    std::vector<uint8_t> mapped(imageSize, 0);

    // Copy headers
    size_t headerBytes = std::min<size_t>(nt->OptionalHeader.SizeOfHeaders, rawSize);
    std::memcpy(mapped.data(), raw, headerBytes);

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto& s = sections[i];
        if (s.SizeOfRawData == 0) continue;

        // Bounds-check against the raw file, not the image size
        if (static_cast<size_t>(s.PointerToRawData) + s.SizeOfRawData > rawSize) continue;
        if (static_cast<size_t>(s.VirtualAddress)   + s.SizeOfRawData > imageSize) continue;

        std::memcpy(mapped.data() + s.VirtualAddress,
                    raw           + s.PointerToRawData,
                    s.SizeOfRawData);
    }
    return mapped;
}

// ── Step 2 – apply base relocations ──────────────────────────────────────────

static bool ApplyRelocations(std::vector<uint8_t>& image,
                              IMAGE_NT_HEADERS64*   nt,
                              uint64_t              newBase) {
    int64_t delta = static_cast<int64_t>(newBase)
                  - static_cast<int64_t>(nt->OptionalHeader.ImageBase);
    if (delta == 0) return true;

    auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) return true;

    if (relocDir.VirtualAddress + relocDir.Size > image.size()) return false;

    auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                      image.data() + relocDir.VirtualAddress);
    auto* end   = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                      image.data() + relocDir.VirtualAddress + relocDir.Size);

    while (reloc < end && reloc->VirtualAddress != 0 && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto*    entries = reinterpret_cast<WORD*>(reloc + 1);

        for (uint32_t i = 0; i < count; ++i) {
            int type   = entries[i] >> 12;
            int offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                size_t pos = reloc->VirtualAddress + offset;
                if (pos + sizeof(uint64_t) > image.size()) return false;
                uint64_t* target = reinterpret_cast<uint64_t*>(image.data() + pos);
                *target += static_cast<uint64_t>(delta);
            }
            // IMAGE_REL_BASED_ABSOLUTE (0) = padding, skip
        }

        reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }
    return true;
}

// ── Step 3 – resolve imports ──────────────────────────────────────────────────
//
// For each import DLL, we:
//   1. Load the DLL as a data file from System32 to parse its EAT.
//   2. Compute each exported function's offset from the DLL's load base.
//   3. Find that DLL's kernel load address (ntoskrnl, hal, etc.) via
//      NtQuerySystemInformation(SystemModuleInformation).
//   4. Add the offset to get the running kernel VA.

// RTL_PROCESS_MODULES from NtQuerySystemInformation(0x0B)
struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    char   FullPathName[256];
};
struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

using NtQuerySystemInformation_t =
    NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

static std::vector<RTL_PROCESS_MODULE_INFORMATION> GetKernelModules() {
    auto NtQSI = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
    if (!NtQSI) return {};

    ULONG needed = 0;
    NtQSI(0x0B, nullptr, 0, &needed);
    needed += 0x2000;

    std::vector<uint8_t> buf(needed);
    if (!NT_SUCCESS(NtQSI(0x0B, buf.data(), needed, &needed))) return {};

    auto* mods = reinterpret_cast<RTL_PROCESS_MODULES*>(buf.data());
    std::vector<RTL_PROCESS_MODULE_INFORMATION> result(
        mods->Modules, mods->Modules + mods->NumberOfModules);
    return result;
}

// Returns the kernel base address for a given DLL base name (case-insensitive).
static uint64_t FindKernelModuleBase(
    const std::vector<RTL_PROCESS_MODULE_INFORMATION>& mods,
    const std::string& dllName)
{
    for (auto& m : mods) {
        const char* fname = m.FullPathName + m.OffsetToFileName;
        if (_stricmp(fname, dllName.c_str()) == 0)
            return reinterpret_cast<uint64_t>(m.ImageBase);
    }
    return 0;
}

// Cache: DLL name → {loaded HMODULE, kernel base VA}
struct DllEntry { HMODULE hMod; uint64_t kernelBase; };

static HMODULE LoadDllAsData(const std::string& name) {
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    std::string path = std::string(sysPath) + "\\" + name;
    return LoadLibraryExA(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
}

// Check if an address falls within a loaded module's image range
static bool AddrInModule(HMODULE hMod, FARPROC proc) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                   reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
    uint64_t base = reinterpret_cast<uint64_t>(hMod);
    uint64_t addr = reinterpret_cast<uint64_t>(proc);
    return addr >= base && addr < base + nt->OptionalHeader.SizeOfImage;
}

// Ensure a DLL is in the cache; returns pointer to its entry or nullptr
static DllEntry* EnsureCached(
    std::unordered_map<std::string, DllEntry>& cache,
    const std::string& dllName,
    const std::vector<RTL_PROCESS_MODULE_INFORMATION>& kmods)
{
    std::string key(dllName);
    for (auto& c : key) c = static_cast<char>(tolower(c));
    if (cache.find(key) != cache.end()) return &cache[key];

    HMODULE hMod = LoadDllAsData(dllName);
    if (!hMod) return nullptr;
    uint64_t kbase = FindKernelModuleBase(kmods, dllName);
    if (!kbase) { FreeLibrary(hMod); return nullptr; }
    cache[key] = { hMod, kbase };
    return &cache[key];
}

static bool ResolveImports(std::vector<uint8_t>&  image,
                            IMAGE_NT_HEADERS64*    nt,
                            const std::vector<RTL_PROCESS_MODULE_INFORMATION>& kmods,
                            std::string&           err) {
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) return true;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                     image.data() + importDir.VirtualAddress);

    std::unordered_map<std::string, DllEntry> cache;

    // Common kernel modules that may be forwarder targets
    static const char* kForwarderModules[] = {
        "ntoskrnl.exe", "hal.dll", "ndis.sys", "fltmgr.sys", "wdf01000.sys"
    };

    for (; desc->Name; ++desc) {
        const char* dllName = reinterpret_cast<const char*>(image.data() + desc->Name);

        auto* entry = EnsureCached(cache, dllName, kmods);
        if (!entry) {
            err = std::string("Kernel module not found: ") + dllName;
            return false;
        }

        auto* thunk     = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                              image.data() + desc->FirstThunk);
        auto* origThunk = desc->OriginalFirstThunk
                        ? reinterpret_cast<IMAGE_THUNK_DATA64*>(
                              image.data() + desc->OriginalFirstThunk)
                        : thunk;

        for (; origThunk->u1.AddressOfData; ++origThunk, ++thunk) {
            if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                err = "Ordinal imports not supported";
                return false;
            }

            auto* ibn  = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                             image.data() + origThunk->u1.AddressOfData);
            const char* name = ibn->Name;

            FARPROC proc = GetProcAddress(entry->hMod, name);
            DllEntry* resolvedIn = entry;

            // If GetProcAddress returned an address outside our module,
            // the export was forwarded. Find which module owns it.
            if (proc && !AddrInModule(entry->hMod, proc)) {
                resolvedIn = nullptr;
                for (auto& [k, e] : cache) {
                    if (AddrInModule(e.hMod, proc)) { resolvedIn = &e; break; }
                }
                if (!resolvedIn) {
                    for (auto* mod : kForwarderModules) {
                        auto* candidate = EnsureCached(cache, mod, kmods);
                        if (candidate && AddrInModule(candidate->hMod, proc)) {
                            resolvedIn = candidate; break;
                        }
                    }
                }
                if (!resolvedIn) {
                    fprintf(stderr, "  IAT WARN: %s forwarded outside known modules\n", name);
                    resolvedIn = entry;
                }
            }

            // If proc is NULL, try all cached modules as fallback
            if (!proc) {
                for (auto* mod : kForwarderModules) {
                    auto* candidate = EnsureCached(cache, mod, kmods);
                    if (!candidate) continue;
                    proc = GetProcAddress(candidate->hMod, name);
                    if (proc) {
                        resolvedIn = candidate;
                        if (!AddrInModule(candidate->hMod, proc)) {
                            for (auto& [k, e] : cache) {
                                if (AddrInModule(e.hMod, proc)) { resolvedIn = &e; break; }
                            }
                        }
                        break;
                    }
                }
            }

            if (!proc) {
                err = std::string("Export not found: ") + name + " in " + dllName;
                return false;
            }

            uint64_t offset = reinterpret_cast<uint64_t>(proc)
                            - reinterpret_cast<uint64_t>(resolvedIn->hMod);
            thunk->u1.Function = resolvedIn->kernelBase + offset;
            fprintf(stderr, "  IAT: %-40s -> 0x%llx (off=0x%llx)\n",
                    name, (unsigned long long)thunk->u1.Function,
                    (unsigned long long)offset);
        }
    }

    for (auto& [k, e] : cache)
        FreeLibrary(e.hMod);

    return true;
}

// ── Public entry point ────────────────────────────────────────────────────────

MapResult ManualMap(const std::vector<uint8_t>& driverImage,
                    const KernelPrimitives&     prim) {
    MapResult result;

    if (driverImage.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.error = "Image too small"; return result;
    }

    auto* nt = GetNtHeaders(driverImage.data());
    if (!nt) { result.error = "Invalid PE headers"; return result; }

    // ── Allocate kernel memory ──
    size_t imageSize = nt->OptionalHeader.SizeOfImage;
    uint64_t kernelImageBase = prim.AllocateKernelMemory(imageSize);
    if (!kernelImageBase) { result.error = "Kernel alloc failed"; return result; }

    // ── Build flat mapped image locally ──
    auto mapped = BuildMappedImage(driverImage.data(), driverImage.size(), nt);

    // Re-parse NT headers from our local mapped copy
    auto* mappedNt = GetNtHeaders(mapped.data());
    if (!mappedNt) { result.error = "Mapped image has bad headers"; return result; }

    // ── Apply relocations ──
    if (!ApplyRelocations(mapped, mappedNt, kernelImageBase)) {
        result.error = "Relocation failed"; return result;
    }

    // ── Resolve imports ──
    auto kmods = GetKernelModules();
    if (kmods.empty()) { result.error = "Failed to enumerate kernel modules"; return result; }

    if (!ResolveImports(mapped, mappedNt, kmods, result.error))
        return result;

    // ── Write final image into kernel ──
    if (!prim.WriteKernelMemory(kernelImageBase, mapped.data(), imageSize)) {
        result.error = "Kernel write failed"; return result;
    }

    result.success    = true;
    result.imageBase  = kernelImageBase;
    result.entryPoint = kernelImageBase + mappedNt->OptionalHeader.AddressOfEntryPoint;
    return result;
}
