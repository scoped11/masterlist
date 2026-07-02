// Static Game Binary Dumper — reads PE files from disk, no driver/AC bypass needed
// Usage: static_dumper.exe --game apex|r6|rust [--path "game_dir"] [--output dump.txt]
// Parses PE headers, exports, imports, sections, and runs pattern scans for known offsets

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <algorithm>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// ============================================================
// PE file mapped into memory
// ============================================================
struct MappedPE {
    std::vector<uint8_t> raw;
    IMAGE_DOS_HEADER*    dos  = nullptr;
    IMAGE_NT_HEADERS64*  nt64 = nullptr;
    IMAGE_SECTION_HEADER* sections = nullptr;
    int numSections = 0;
    uint64_t imageBase = 0;
    bool valid = false;

    bool Load(const char* path) {
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER sz;
        GetFileSizeEx(hFile, &sz);
        raw.resize((size_t)sz.QuadPart);
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hFile, raw.data(), (DWORD)raw.size(), &bytesRead, nullptr);
        CloseHandle(hFile);
        if (!ok || bytesRead != raw.size()) return false;

        dos = (IMAGE_DOS_HEADER*)raw.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto* ntBase = (IMAGE_NT_HEADERS64*)(raw.data() + dos->e_lfanew);
        if (ntBase->Signature != IMAGE_NT_SIGNATURE) return false;

        if (ntBase->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            nt64 = ntBase;
            imageBase = nt64->OptionalHeader.ImageBase;
        } else {
            printf("  [!] 32-bit PE not supported\n");
            return false;
        }

        sections = IMAGE_FIRST_SECTION(nt64);
        numSections = nt64->FileHeader.NumberOfSections;
        valid = true;
        return true;
    }

    uint8_t* RvaToPtr(uint32_t rva) {
        for (int i = 0; i < numSections; i++) {
            auto& s = sections[i];
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData)
                return raw.data() + s.PointerToRawData + (rva - s.VirtualAddress);
        }
        return nullptr;
    }

    const IMAGE_SECTION_HEADER* FindSection(const char* name) {
        for (int i = 0; i < numSections; i++) {
            char secName[9] = {};
            memcpy(secName, sections[i].Name, 8);
            if (_stricmp(secName, name) == 0) return &sections[i];
        }
        return nullptr;
    }
};

// ============================================================
// Pattern scanner — "48 8B 05 ?? ?? ?? ??" style
// ============================================================
struct PatternEntry {
    const char* name;
    const char* pattern;
    int ripOffset;      // offset within match to read RIP-relative disp (0 = no RIP)
    int ripSize;        // bytes of displacement (usually 4)
    int instrLen;       // full instruction length for RIP calc
};

static bool ParsePattern(const char* patStr, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
    bytes.clear(); mask.clear();
    const char* p = patStr;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            bytes.push_back(0);
            mask.push_back(false);
            while (*p == '?') p++;
        } else {
            char hex[3] = { p[0], p[1], 0 };
            bytes.push_back((uint8_t)strtoul(hex, nullptr, 16));
            mask.push_back(true);
            p += 2;
        }
    }
    return !bytes.empty();
}

static int64_t ScanPattern(const uint8_t* data, size_t dataSize,
                           const std::vector<uint8_t>& bytes, const std::vector<bool>& mask) {
    if (bytes.size() > dataSize) return -1;
    size_t limit = dataSize - bytes.size();
    for (size_t i = 0; i <= limit; i++) {
        bool found = true;
        for (size_t j = 0; j < bytes.size(); j++) {
            if (mask[j] && data[i + j] != bytes[j]) { found = false; break; }
        }
        if (found) return (int64_t)i;
    }
    return -1;
}

static uint64_t ResolveRIP(uint64_t matchVA, int ripOff, int instrLen, const uint8_t* matchPtr) {
    int32_t disp = *(int32_t*)(matchPtr + ripOff);
    return matchVA + instrLen + disp;
}

// ============================================================
// Known patterns per game
// ============================================================

// Apex Legends (r5apex_dx12.exe) — common community patterns
static PatternEntry g_apexPatterns[] = {
    { "EntityList",       "4C 8D 35 ?? ?? ?? ?? 49 63 C6", 3, 4, 7 },
    { "LocalPlayer",      "48 8D 05 ?? ?? ?? ?? 44 89 65 ?? 48 89 45", 3, 4, 7 },
    { "ViewRender",       "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ?? 48 8B F8 48 85 C0", 3, 4, 7 },
    { "ViewMatrix",       "48 8D 0D ?? ?? ?? ?? 48 C1 E0 06", 3, 4, 7 },
    { "GlowEnable",       "80 3D ?? ?? ?? ?? 00 74 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0", 2, 4, 7 },
    { "NameList",         "48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 4C 89 74 24 ?? 89 5C 24", 3, 4, 7 },
    { "NetworkVar_table", "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B 08", 3, 4, 7 },
    { "LevelName",        "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 ?? 80 78 ?? 6D", 3, 4, 7 },
    { nullptr, nullptr, 0, 0, 0 }
};

// R6 Siege (RainbowSix.exe) — common patterns
static PatternEntry g_r6Patterns[] = {
    { "GameManager",       "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B 40", 3, 4, 7 },
    { "ProfileManager",    "48 89 05 ?? ?? ?? ?? 48 8D 4F ?? E8 ?? ?? ?? ?? 48 8B CF", 3, 4, 7 },
    { "NetworkManager",    "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 84 C0 74 ?? B0 01", 3, 4, 7 },
    { "RoundManager",      "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? E8", 3, 4, 7 },
    { "Camera",            "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 50", 3, 4, 7 },
    { "FovManager",        "F3 0F 10 05 ?? ?? ?? ?? 0F 2F C6 76 ?? F3 0F 10 0D", 4, 4, 8 },
    { nullptr, nullptr, 0, 0, 0 }
};

// ============================================================
// IL2CPP metadata parser (for Rust / Unity games)
// ============================================================
#pragma pack(push, 1)
struct Il2CppGlobalMetadataHeader {
    uint32_t sanity;           // 0xFAB11BAF
    int32_t  version;
    int32_t  stringLiteralOffset;
    int32_t  stringLiteralCount;
    int32_t  stringLiteralDataOffset;
    int32_t  stringLiteralDataCount;
    int32_t  stringOffset;
    int32_t  stringCount;
    int32_t  eventsOffset;
    int32_t  eventsCount;
    int32_t  propertiesOffset;
    int32_t  propertiesCount;
    int32_t  methodsOffset;
    int32_t  methodsCount;
    int32_t  parameterDefaultValuesOffset;
    int32_t  parameterDefaultValuesCount;
    int32_t  fieldDefaultValuesOffset;
    int32_t  fieldDefaultValuesCount;
    int32_t  fieldAndParameterDefaultValueDataOffset;
    int32_t  fieldAndParameterDefaultValueDataCount;
    int32_t  fieldMarshaledSizesOffset;
    int32_t  fieldMarshaledSizesCount;
    int32_t  parametersOffset;
    int32_t  parametersCount;
    int32_t  fieldsOffset;
    int32_t  fieldsCount;
    int32_t  genericParametersOffset;
    int32_t  genericParametersCount;
    int32_t  genericParameterConstraintsOffset;
    int32_t  genericParameterConstraintsCount;
    int32_t  genericContainersOffset;
    int32_t  genericContainersCount;
    int32_t  nestedTypesOffset;
    int32_t  nestedTypesCount;
    int32_t  interfacesOffset;
    int32_t  interfacesCount;
    int32_t  vtableMethodsOffset;
    int32_t  vtableMethodsCount;
    int32_t  interfaceOffsetsOffset;
    int32_t  interfaceOffsetsCount;
    int32_t  typeDefinitionsOffset;
    int32_t  typeDefinitionsCount;
    int32_t  imagesOffset;
    int32_t  imagesCount;
    int32_t  assembliesOffset;
    int32_t  assembliesCount;
};

struct Il2CppTypeDefinition {
    int32_t nameIndex;
    int32_t namespaceIndex;
    int32_t byvalTypeIndex;
    int32_t byrefTypeIndex;
    int32_t declaringTypeIndex;
    int32_t parentIndex;
    int32_t elementTypeIndex;
    int32_t genericContainerIndex;
    uint32_t flags;
    int32_t fieldStart;
    int32_t methodStart;
    int32_t eventStart;
    int32_t propertyStart;
    int32_t nestedTypesStart;
    int32_t interfacesStart;
    int32_t vtableStart;
    int32_t interfaceOffsetsStart;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint32_t bitfield;
    uint32_t token;
};

struct Il2CppFieldDefinition {
    int32_t nameIndex;
    int32_t typeIndex;
    uint32_t token;
};

struct Il2CppImageDefinition {
    int32_t nameIndex;
    int32_t assemblyIndex;
    int32_t typeStart;
    uint32_t typeCount;
    int32_t exportedTypeStart;
    uint32_t exportedTypeCount;
    int32_t entryPointIndex;
    uint32_t token;
    int32_t customAttributeStart;
    uint32_t customAttributeCount;
};
#pragma pack(pop)

struct Il2CppMeta {
    std::vector<uint8_t> raw;
    Il2CppGlobalMetadataHeader* hdr = nullptr;
    bool valid = false;

    bool Load(const char* path) {
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        GetFileSizeEx(hFile, &sz);
        raw.resize((size_t)sz.QuadPart);
        DWORD br = 0;
        ReadFile(hFile, raw.data(), (DWORD)raw.size(), &br, nullptr);
        CloseHandle(hFile);

        hdr = (Il2CppGlobalMetadataHeader*)raw.data();
        if (hdr->sanity != 0xFAB11BAF) {
            printf("  [!] Bad metadata magic: 0x%08X\n", hdr->sanity);
            return false;
        }
        valid = true;
        return true;
    }

    const char* GetString(int32_t idx) {
        if (idx < 0 || idx >= hdr->stringCount) return "<invalid>";
        return (const char*)(raw.data() + hdr->stringOffset + idx);
    }

    Il2CppTypeDefinition* GetTypeDefs(int* count) {
        *count = hdr->typeDefinitionsCount / (int)sizeof(Il2CppTypeDefinition);
        return (Il2CppTypeDefinition*)(raw.data() + hdr->typeDefinitionsOffset);
    }

    Il2CppFieldDefinition* GetFields() {
        return (Il2CppFieldDefinition*)(raw.data() + hdr->fieldsOffset);
    }

    Il2CppImageDefinition* GetImages(int* count) {
        *count = hdr->imagesCount / (int)sizeof(Il2CppImageDefinition);
        return (Il2CppImageDefinition*)(raw.data() + hdr->imagesOffset);
    }
};

// ============================================================
// Game installation auto-detect
// ============================================================
static std::string FindSteamGame(const char* folder) {
    const char* libs[] = {
        "C:\\Program Files (x86)\\Steam\\steamapps\\common",
        "C:\\Program Files\\Steam\\steamapps\\common",
        "D:\\SteamLibrary\\steamapps\\common",
        "E:\\SteamLibrary\\steamapps\\common",
        "F:\\SteamLibrary\\steamapps\\common",
    };
    for (auto& lib : libs) {
        std::string path = std::string(lib) + "\\" + folder;
        if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES)
            return path;
    }
    return "";
}

// ============================================================
// Dump routines
// ============================================================
static void DumpPEInfo(MappedPE& pe, FILE* out, const char* filename) {
    fprintf(out, "=== PE Analysis: %s ===\n", filename);
    fprintf(out, "  Image Base:     0x%llX\n", pe.imageBase);
    fprintf(out, "  Entry Point:    0x%llX (RVA 0x%X)\n",
            pe.imageBase + pe.nt64->OptionalHeader.AddressOfEntryPoint,
            pe.nt64->OptionalHeader.AddressOfEntryPoint);
    fprintf(out, "  Size of Image:  0x%X (%u KB)\n",
            pe.nt64->OptionalHeader.SizeOfImage,
            pe.nt64->OptionalHeader.SizeOfImage / 1024);
    fprintf(out, "  File Size:      %zu bytes (%.1f MB)\n",
            pe.raw.size(), pe.raw.size() / 1048576.0);
    fprintf(out, "  Sections:       %d\n", pe.numSections);
    fprintf(out, "  TimeDateStamp:  0x%X\n", pe.nt64->FileHeader.TimeDateStamp);
    fprintf(out, "  Characteristics: 0x%X%s%s\n",
            pe.nt64->FileHeader.Characteristics,
            (pe.nt64->FileHeader.Characteristics & IMAGE_FILE_DLL) ? " [DLL]" : "",
            (pe.nt64->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ? " [EXE]" : "");
    fprintf(out, "  Subsystem:      %s\n",
            pe.nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ? "Windows GUI" :
            pe.nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI ? "Windows Console" : "Other");
    fprintf(out, "\n");

    fprintf(out, "  Sections:\n");
    fprintf(out, "  %-10s %-12s %-12s %-12s %-10s Flags\n",
            "Name", "VirtAddr", "VirtSize", "RawSize", "RawPtr");
    for (int i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        fprintf(out, "  %-10s 0x%08X   0x%08X   0x%08X   0x%08X 0x%08X",
                name,
                pe.sections[i].VirtualAddress,
                pe.sections[i].Misc.VirtualSize,
                pe.sections[i].SizeOfRawData,
                pe.sections[i].PointerToRawData,
                pe.sections[i].Characteristics);
        if (pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) fprintf(out, " X");
        if (pe.sections[i].Characteristics & IMAGE_SCN_MEM_READ) fprintf(out, " R");
        if (pe.sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) fprintf(out, " W");
        fprintf(out, "\n");
    }
    fprintf(out, "\n");
}

static void DumpExports(MappedPE& pe, FILE* out) {
    auto& dir = pe.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        fprintf(out, "  Exports: none\n\n");
        return;
    }
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)pe.RvaToPtr(dir.VirtualAddress);
    if (!exp) return;

    const char* dllName = exp->Name ? (const char*)pe.RvaToPtr(exp->Name) : "?";
    fprintf(out, "  Exports (%s) — %u functions, %u names:\n", dllName, exp->NumberOfFunctions, exp->NumberOfNames);

    auto* names    = (uint32_t*)pe.RvaToPtr(exp->AddressOfNames);
    auto* ordinals = (uint16_t*)pe.RvaToPtr(exp->AddressOfNameOrdinals);
    auto* funcs    = (uint32_t*)pe.RvaToPtr(exp->AddressOfFunctions);

    int printed = 0;
    int limit = min((int)exp->NumberOfNames, 200);
    for (int i = 0; i < limit; i++) {
        const char* name = (const char*)pe.RvaToPtr(names[i]);
        uint32_t rva = funcs[ordinals[i]];
        if (name) {
            fprintf(out, "    [%4d] 0x%08X  %s\n", ordinals[i] + exp->Base, rva, name);
            printed++;
        }
    }
    if ((int)exp->NumberOfNames > limit)
        fprintf(out, "    ... and %d more\n", exp->NumberOfNames - limit);
    fprintf(out, "\n");
}

static void DumpImportDlls(MappedPE& pe, FILE* out) {
    auto& dir = pe.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        fprintf(out, "  Imports: none\n\n");
        return;
    }
    auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)pe.RvaToPtr(dir.VirtualAddress);
    if (!imp) return;

    fprintf(out, "  Imported DLLs:\n");
    int count = 0;
    for (; imp->Name; imp++) {
        const char* name = (const char*)pe.RvaToPtr(imp->Name);
        if (!name) break;

        int funcCount = 0;
        if (imp->OriginalFirstThunk) {
            auto* thunk = (IMAGE_THUNK_DATA64*)pe.RvaToPtr(imp->OriginalFirstThunk);
            while (thunk && thunk->u1.AddressOfData) { funcCount++; thunk++; }
        }
        fprintf(out, "    %s (%d functions)\n", name, funcCount);
        count++;
    }
    fprintf(out, "  Total: %d DLLs\n\n", count);
}

static void RunPatternScan(MappedPE& pe, PatternEntry* patterns, FILE* out) {
    // Collect ALL executable sections with raw data
    std::vector<const IMAGE_SECTION_HEADER*> execSecs;
    for (int i = 0; i < pe.numSections; i++) {
        if ((pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            pe.sections[i].SizeOfRawData > 0) {
            execSecs.push_back(&pe.sections[i]);
        }
    }
    if (execSecs.empty()) {
        fprintf(out, "  [!] No executable sections with raw data found\n");
        fprintf(out, "  [!] Binary is likely PACKED — needs runtime dump or DMA memory read\n\n");
        return;
    }

    fprintf(out, "  Scanning %zu executable section(s):\n", execSecs.size());
    for (auto* s : execSecs) {
        char n[9] = {}; memcpy(n, s->Name, 8);
        fprintf(out, "    %s: VA 0x%08X, raw size 0x%X (%.1f MB)\n",
                n, s->VirtualAddress, s->SizeOfRawData, s->SizeOfRawData / 1048576.0);
    }

    int found = 0, total = 0;
    for (int i = 0; patterns[i].name; i++) {
        total++;
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;
        ParsePattern(patterns[i].pattern, bytes, mask);

        bool matched = false;
        for (auto* sec : execSecs) {
            const uint8_t* secData = pe.raw.data() + sec->PointerToRawData;
            size_t secSize = sec->SizeOfRawData;
            uint64_t secVA = pe.imageBase + sec->VirtualAddress;

            int64_t off = ScanPattern(secData, secSize, bytes, mask);
            if (off >= 0) {
                uint64_t matchVA = secVA + off;
                char sn[9] = {}; memcpy(sn, sec->Name, 8);
                if (patterns[i].ripOffset > 0) {
                    uint64_t resolved = ResolveRIP(matchVA, patterns[i].ripOffset,
                                                   patterns[i].instrLen, secData + off);
                    fprintf(out, "    %-25s FOUND at 0x%llX (%s) -> 0x%llX\n",
                            patterns[i].name, matchVA, sn, resolved);
                } else {
                    fprintf(out, "    %-25s FOUND at 0x%llX (%s)\n",
                            patterns[i].name, matchVA, sn);
                }
                found++;
                matched = true;
                break;
            }
        }
        if (!matched) {
            fprintf(out, "    %-25s NOT FOUND (pattern may be outdated)\n", patterns[i].name);
        }
    }
    fprintf(out, "  Result: %d/%d patterns matched\n\n", found, total);
}

// ============================================================
// IL2CPP dump for Unity/Rust
// ============================================================
static void DumpIL2CPP(Il2CppMeta& meta, MappedPE& gameAssembly, FILE* out,
                       const char* classFilter) {
    fprintf(out, "=== IL2CPP Metadata Dump ===\n");
    fprintf(out, "  Version:       %d\n", meta.hdr->version);
    fprintf(out, "  String table:  offset=0x%X size=0x%X\n",
            meta.hdr->stringOffset, meta.hdr->stringCount);

    int typeCount = 0;
    auto* types = meta.GetTypeDefs(&typeCount);
    auto* fields = meta.GetFields();

    int imgCount = 0;
    auto* images = meta.GetImages(&imgCount);

    fprintf(out, "  Images:        %d\n", imgCount);
    fprintf(out, "  Types:         %d\n", typeCount);
    fprintf(out, "  Fields total:  %d\n", meta.hdr->fieldsCount / (int)sizeof(Il2CppFieldDefinition));
    fprintf(out, "  Methods total: %d\n\n", meta.hdr->methodsCount);

    fprintf(out, "  Assemblies:\n");
    for (int i = 0; i < imgCount; i++) {
        const char* imgName = meta.GetString(images[i].nameIndex);
        fprintf(out, "    [%3d] %-40s types: %u\n", i, imgName, images[i].typeCount);
    }
    fprintf(out, "\n");

    // Interesting game classes for Rust
    const char* rustClasses[] = {
        "BasePlayer", "BaseEntity", "BaseNetworkable", "PlayerInventory",
        "ItemContainer", "Item", "BaseProjectile", "PlayerEyes",
        "PlayerModel", "Model", "BuildingBlock", "ResourceEntity",
        "OreResourceEntity", "TreeEntity", "StorageContainer",
        "AutoTurret", "BaseHelicopter", "BradleyAPC", "HeldEntity",
        "BaseMovement", "PlayerWalkMovement", "Projectile",
        "RecoilProperties", "ViewmodelSway", "PlayerTick",
        "BaseCombatEntity", "LootContainer", "DroppedItem",
        "Supply", "SupplyDrop", "BaseVehicle", "MiniCopter",
        "RidableHorse", "SamSite", "Stash", "PlayerCorpse",
        nullptr
    };

    fprintf(out, "  === Game Classes (fields) ===\n\n");

    int dumpedClasses = 0;
    for (int t = 0; t < typeCount; t++) {
        const char* typeName = meta.GetString(types[t].nameIndex);
        const char* ns = meta.GetString(types[t].namespaceIndex);
        if (!typeName) continue;

        bool shouldDump = false;
        if (classFilter && *classFilter) {
            shouldDump = (strstr(typeName, classFilter) != nullptr);
        } else {
            for (int c = 0; rustClasses[c]; c++) {
                if (strcmp(typeName, rustClasses[c]) == 0) { shouldDump = true; break; }
            }
        }

        if (!shouldDump) continue;

        fprintf(out, "  class %s%s%s  (fields: %d, methods: %d)\n",
                (ns && *ns) ? ns : "", (ns && *ns) ? "." : "",
                typeName, types[t].field_count, types[t].method_count);

        for (int f = 0; f < types[t].field_count; f++) {
            int fi = types[t].fieldStart + f;
            const char* fieldName = meta.GetString(fields[fi].nameIndex);
            fprintf(out, "    +0x????  %s  (token: 0x%08X)\n",
                    fieldName ? fieldName : "?", fields[fi].token);
        }
        fprintf(out, "\n");
        dumpedClasses++;
    }
    fprintf(out, "  Dumped %d classes\n\n", dumpedClasses);
}

// ============================================================
// GameAssembly.dll export scan — find il2cpp API functions
// ============================================================
static void DumpIL2CppExports(MappedPE& ga, FILE* out) {
    auto& dir = ga.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return;
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)ga.RvaToPtr(dir.VirtualAddress);
    if (!exp || !exp->NumberOfNames) return;

    auto* names    = (uint32_t*)ga.RvaToPtr(exp->AddressOfNames);
    auto* ordinals = (uint16_t*)ga.RvaToPtr(exp->AddressOfNameOrdinals);
    auto* funcs    = (uint32_t*)ga.RvaToPtr(exp->AddressOfFunctions);

    fprintf(out, "  === IL2CPP API Exports ===\n");
    const char* il2cppApis[] = {
        "il2cpp_domain_get", "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
        "il2cpp_image_get_class", "il2cpp_class_get_name",
        "il2cpp_class_get_namespace", "il2cpp_class_get_fields",
        "il2cpp_class_get_methods", "il2cpp_class_get_parent",
        "il2cpp_class_from_name", "il2cpp_field_get_name",
        "il2cpp_field_get_offset", "il2cpp_field_get_type",
        "il2cpp_method_get_name", "il2cpp_method_get_param_count",
        "il2cpp_type_get_name", "il2cpp_string_chars",
        "il2cpp_object_get_class", "il2cpp_resolve_icall",
        nullptr
    };

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)ga.RvaToPtr(names[i]);
        if (!name) continue;
        for (int a = 0; il2cppApis[a]; a++) {
            if (strcmp(name, il2cppApis[a]) == 0) {
                uint32_t rva = funcs[ordinals[i]];
                fprintf(out, "    0x%08X  %s\n", rva, name);
                break;
            }
        }
    }
    fprintf(out, "\n");
}

// ============================================================
// Main
// ============================================================
static void PrintUsage() {
    printf("Static Game Binary Dumper\n");
    printf("Usage: static_dumper.exe --game <apex|r6|rust> [options]\n");
    printf("Options:\n");
    printf("  --path <dir>     Override game directory\n");
    printf("  --output <file>  Output file (default: <game>_dump.txt)\n");
    printf("  --class <name>   Filter IL2CPP classes by name substring\n");
    printf("  --all-classes    Dump ALL IL2CPP classes (large output)\n");
    printf("\nReads game binaries from disk. No driver, no AC bypass needed.\n");
}

int main(int argc, char* argv[]) {
    const char* game = nullptr;
    const char* gamePath = nullptr;
    const char* outputFile = nullptr;
    const char* classFilter = nullptr;
    bool allClasses = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--game") == 0 && i + 1 < argc) game = argv[++i];
        else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) gamePath = argv[++i];
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) outputFile = argv[++i];
        else if (strcmp(argv[i], "--class") == 0 && i + 1 < argc) classFilter = argv[++i];
        else if (strcmp(argv[i], "--all-classes") == 0) allClasses = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(); return 0;
        }
    }

    if (!game) { PrintUsage(); return 1; }

    // Auto-detect game path
    std::string autoPath;
    std::string defaultOutput;

    if (_stricmp(game, "apex") == 0) {
        if (!gamePath) {
            autoPath = FindSteamGame("Apex Legends");
            gamePath = autoPath.c_str();
        }
        defaultOutput = "apex_dump.txt";
    } else if (_stricmp(game, "r6") == 0) {
        if (!gamePath) {
            autoPath = FindSteamGame("Tom Clancy's Rainbow Six Siege");
            gamePath = autoPath.c_str();
        }
        defaultOutput = "r6_dump.txt";
    } else if (_stricmp(game, "rust") == 0) {
        if (!gamePath) {
            autoPath = FindSteamGame("Rust");
            gamePath = autoPath.c_str();
        }
        defaultOutput = "rust_dump.txt";
    } else {
        printf("[!] Unknown game: %s\n", game);
        return 1;
    }

    if (!gamePath || !*gamePath) {
        printf("[!] Could not find game installation. Use --path to specify.\n");
        return 1;
    }

    if (!outputFile) outputFile = defaultOutput.c_str();

    printf("[*] Game: %s\n", game);
    printf("[*] Path: %s\n", gamePath);
    printf("[*] Output: %s\n\n", outputFile);

    FILE* out = fopen(outputFile, "w");
    if (!out) {
        printf("[!] Cannot open output file: %s\n", outputFile);
        return 1;
    }

    fprintf(out, "Static Game Binary Dump\n");
    fprintf(out, "Game: %s\n", game);
    fprintf(out, "Path: %s\n", gamePath);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(out, "Date: %04d-%02d-%02d %02d:%02d:%02d\n\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // ---- APEX ----
    if (_stricmp(game, "apex") == 0) {
        std::string exePath = std::string(gamePath) + "\\r5apex_dx12.exe";
        std::string dllPath = std::string(gamePath) + "\\r5apex_dx12runtime.dll";

        MappedPE pe;
        printf("[*] Loading %s...\n", exePath.c_str());
        if (!pe.Load(exePath.c_str())) {
            // Try non-dx12 variant
            exePath = std::string(gamePath) + "\\r5apex.exe";
            printf("[*] Trying %s...\n", exePath.c_str());
            if (!pe.Load(exePath.c_str())) {
                printf("[!] Cannot load Apex executable\n");
                fclose(out);
                return 1;
            }
        }

        printf("[+] Loaded (%.1f MB)\n", pe.raw.size() / 1048576.0);
        DumpPEInfo(pe, out, exePath.c_str());
        DumpImportDlls(pe, out);
        DumpExports(pe, out);

        printf("[*] Running pattern scan...\n");
        RunPatternScan(pe, g_apexPatterns, out);

        // Also scan the runtime DLL
        MappedPE runtimePe;
        if (runtimePe.Load(dllPath.c_str())) {
            printf("[*] Loaded runtime DLL (%.1f MB)\n", runtimePe.raw.size() / 1048576.0);
            DumpPEInfo(runtimePe, out, dllPath.c_str());
            DumpExports(runtimePe, out);
            RunPatternScan(runtimePe, g_apexPatterns, out);
        }
    }

    // ---- R6 SIEGE ----
    else if (_stricmp(game, "r6") == 0) {
        std::string exePath = std::string(gamePath) + "\\RainbowSix.exe";

        MappedPE pe;
        printf("[*] Loading %s...\n", exePath.c_str());
        if (!pe.Load(exePath.c_str())) {
            printf("[!] Cannot load R6 executable\n");
            fclose(out);
            return 1;
        }

        printf("[+] Loaded (%.1f MB)\n", pe.raw.size() / 1048576.0);
        DumpPEInfo(pe, out, exePath.c_str());
        DumpImportDlls(pe, out);
        DumpExports(pe, out);

        printf("[*] Running pattern scan...\n");
        RunPatternScan(pe, g_r6Patterns, out);
    }

    // ---- RUST (Unity IL2CPP) ----
    else if (_stricmp(game, "rust") == 0) {
        std::string gaPath = std::string(gamePath) + "\\GameAssembly.dll";
        std::string metaPath = std::string(gamePath) +
            "\\RustClient_Data\\il2cpp_data\\Metadata\\global-metadata.dat";

        // GameAssembly.dll
        MappedPE ga;
        printf("[*] Loading %s...\n", gaPath.c_str());
        if (!ga.Load(gaPath.c_str())) {
            printf("[!] Cannot load GameAssembly.dll\n");
            fclose(out);
            return 1;
        }

        printf("[+] Loaded GameAssembly.dll (%.1f MB)\n", ga.raw.size() / 1048576.0);
        DumpPEInfo(ga, out, gaPath.c_str());
        DumpImportDlls(ga, out);
        DumpIL2CppExports(ga, out);

        // global-metadata.dat
        Il2CppMeta meta;
        printf("[*] Loading %s...\n", metaPath.c_str());
        if (!meta.Load(metaPath.c_str())) {
            printf("[!] Cannot load global-metadata.dat\n");
            fprintf(out, "  [!] global-metadata.dat failed to load\n");
        } else {
            printf("[+] Loaded metadata (%.1f MB, version %d)\n",
                   meta.raw.size() / 1048576.0, meta.hdr->version);

            if (allClasses) {
                DumpIL2CPP(meta, ga, out, "");
            } else {
                DumpIL2CPP(meta, ga, out, classFilter ? classFilter : "");
            }
        }
    }

    fclose(out);
    printf("\n[+] Dump written to: %s\n", outputFile);
    return 0;
}
