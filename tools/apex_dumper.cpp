// Apex Legends offset dumper — signature scan live process via Betest driver
// Finds global pointers (EntityList, LocalPlayer, ViewMatrix, etc.) by pattern matching
// Validates struct member offsets by reading known fields from live entities

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <fstream>

#pragma comment(lib, "ntdll.lib")

#define IOCTL_READ_PROC  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_SESSION_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
struct ReadReq { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; };
#pragma pack(pop)

static HANDLE g_hDev = INVALID_HANDLE_VALUE;
static DWORD  g_pid  = 0;
static uint8_t* g_ioBuf = nullptr;

static bool SessionAuth(HANDLE h) {
    ULONG64 challenge = GetTickCount64();
    ULONG64 token = 0;
    DWORD ret = 0;
    return DeviceIoControl(h, IOCTL_SESSION_AUTH,
                           &challenge, sizeof(challenge),
                           &token, sizeof(token), &ret, nullptr) && ret == sizeof(token);
}

static bool VerifyBetestDevice(HANDLE h, DWORD pid) {
    ReadReq req{};
    req.ProcessId = pid;
    req.Address   = 0x7FFE0000;
    req.Size      = 8;
    uint8_t buf[256]{};
    memcpy(buf, &req, sizeof(req));
    DWORD ret = 0;
    return DeviceIoControl(h, IOCTL_READ_PROC, buf, sizeof(req), buf, 256, &ret, nullptr);
}

static bool DriverInit(DWORD pid) {
    static const char* dynPrefixes[] = {
        "MsFlt", "WdFlt", "FltMgr", "NdPxy", "TdiFlt",
        "MsSecF", "WfpDr", "NtFlt", "ClfsF", "VhdFlt",
        "SrFlt", "FsDep", "PcwDrv", "MsIScsi", "VolSnap", "WmiLib",
    };

    auto tryOpen = [&](const char* path) -> bool {
        HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        // Try with SessionAuth first, then without
        bool authed = SessionAuth(h);
        if (VerifyBetestDevice(h, pid)) {
            g_hDev = h;
            g_pid  = pid;
            printf("[+] Connected via %s (auth=%d)\n", path, authed);
            return true;
        }
        CloseHandle(h);
        return false;
    };

    int opened = 0;
    for (int p = 0; p < 16; p++)
        for (int d = 0; d < 10; d++) {
            char path[64];
            snprintf(path, sizeof(path), "\\\\.\\%s%d", dynPrefixes[p], d);
            HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                printf("[*] Device exists: %s\n", path);
                CloseHandle(h);
                opened++;
            }
        }
    printf("[*] Found %d accessible devices, now probing with verify...\n", opened);

    for (int p = 0; p < 16; p++)
        for (int d = 0; d < 10; d++) {
            char path[64];
            snprintf(path, sizeof(path), "\\\\.\\%s%d", dynPrefixes[p], d);
            if (tryOpen(path)) return true;
        }
    return false;
}

static bool DriverRead(uint64_t addr, void* buf, uint32_t size) {
    if (!g_ioBuf) {
        g_ioBuf = (uint8_t*)VirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_ioBuf) return false;
    }
    if (size > 65536 - 256) return false;
    auto* req = (ReadReq*)g_ioBuf;
    req->ProcessId = g_pid;
    req->Address   = addr;
    req->Size      = size;
    DWORD ret = 0;
    if (!DeviceIoControl(g_hDev, IOCTL_READ_PROC,
                         g_ioBuf, sizeof(ReadReq), g_ioBuf, 65536,
                         &ret, nullptr))
        return false;
    memcpy(buf, g_ioBuf, size);
    return true;
}

template<typename T>
static T rpm(uint64_t addr) {
    T val{};
    DriverRead(addr, &val, sizeof(T));
    return val;
}

// ── Process discovery ─────────────────────────────────────────────────────

static DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(name, pe.szExeFile) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static uint64_t GetImageBase(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;
    typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    uint64_t base = 0;
    if (NtQIP) {
        PROCESS_BASIC_INFORMATION pbi{};
        ULONG retLen = 0;
        if (NT_SUCCESS(NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen))) {
            uint64_t pebAddr = (uint64_t)pbi.PebBaseAddress;
            DriverRead(pebAddr + 0x10, &base, 8);
        }
    }
    CloseHandle(hProc);
    return base;
}

// ── PE parsing ────────────────────────────────────────────────────────────

struct Section {
    char name[9];
    uint32_t rva;
    uint32_t vsize;
};

static std::vector<Section> GetSections(uint64_t base) {
    std::vector<Section> secs;
    uint8_t hdr[0x1000]{};
    if (!DriverRead(base, hdr, 0x1000)) return secs;

    uint32_t peOff = *(uint32_t*)(hdr + 0x3C);
    if (peOff + 0x18 > 0x1000) return secs;

    uint16_t numSec = *(uint16_t*)(hdr + peOff + 6);
    uint16_t optHdrSz = *(uint16_t*)(hdr + peOff + 20);
    uint32_t secOff = peOff + 24 + optHdrSz;

    for (int i = 0; i < numSec && secOff + 40 <= 0x1000; i++, secOff += 40) {
        Section s{};
        memcpy(s.name, hdr + secOff, 8);
        s.name[8] = 0;
        s.vsize = *(uint32_t*)(hdr + secOff + 8);
        s.rva   = *(uint32_t*)(hdr + secOff + 12);
        secs.push_back(s);
    }
    return secs;
}

static uint64_t GetImageSize(uint64_t base) {
    uint8_t hdr[0x200]{};
    if (!DriverRead(base, hdr, 0x200)) return 0;
    uint32_t peOff = *(uint32_t*)(hdr + 0x3C);
    return *(uint32_t*)(hdr + peOff + 0x50); // SizeOfImage
}

// ── Signature scanner ─────────────────────────────────────────────────────

struct SigPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask; // true = must match, false = wildcard
};

static SigPattern ParseSig(const char* sig) {
    SigPattern pat;
    const char* p = sig;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            pat.bytes.push_back(0);
            pat.mask.push_back(false);
            while (*p == '?') p++;
        } else {
            pat.bytes.push_back((uint8_t)strtoul(p, nullptr, 16));
            pat.mask.push_back(true);
            while (*p && *p != ' ') p++;
        }
    }
    return pat;
}

static int64_t ScanBuffer(const uint8_t* buf, size_t bufLen, const SigPattern& pat) {
    if (pat.bytes.size() > bufLen) return -1;
    size_t end = bufLen - pat.bytes.size();
    for (size_t i = 0; i <= end; i++) {
        bool match = true;
        for (size_t j = 0; j < pat.bytes.size(); j++) {
            if (pat.mask[j] && buf[i + j] != pat.bytes[j]) { match = false; break; }
        }
        if (match) return (int64_t)i;
    }
    return -1;
}

// ── Offset resolution ─────────────────────────────────────────────────────

struct SigDef {
    const char* name;
    const char* sig;
    int ripOffset;  // offset within pattern to the 4-byte RIP-relative displacement
    int ripBase;    // instruction length from the start of the displacement (usually ripOffset + 4)
};

// Multiple candidate signatures per offset — we try all and report hits
static SigDef g_sigs[] = {
    // EntityList — referenced in GetEntityByIndex-style functions
    {"EntityList", "4C 8B 05 ?? ?? ?? ?? 4D 85 C0 74", 3, 7},
    {"EntityList", "48 8B 05 ?? ?? ?? ?? 48 8D 14 C0", 3, 7},
    {"EntityList", "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 44 8B C0", 3, 7},

    // LocalPlayer
    {"LocalPlayer", "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 88", 3, 7},
    {"LocalPlayer", "48 8B 3D ?? ?? ?? ?? 48 85 FF 74", 3, 7},
    {"LocalPlayer", "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 90", 3, 7},

    // ViewMatrix — typically near matrix copy or setup code
    {"ViewMatrix", "48 8D 0D ?? ?? ?? ?? 48 C1 E0 06", 3, 7},
    {"ViewMatrix", "48 8D 05 ?? ?? ?? ?? 48 69 C9 ?? ?? 00 00 48 03 C8", 3, 7},

    // GlobalVars — cgame globals pointer
    {"GlobalVars", "48 8B 05 ?? ?? ?? ?? F3 0F 10 48 10", 3, 7},
    {"GlobalVars", "48 8B 0D ?? ?? ?? ?? F3 0F 10 41 10", 3, 7},
    {"GlobalVars", "48 8B 05 ?? ?? ?? ?? 8B 48 24", 3, 7},

    // NameList
    {"NameList", "48 89 05 ?? ?? ?? ?? 48 83 C4 28 C3 48 C7 05", 3, 7},
    {"NameList", "48 8B 05 ?? ?? ?? ?? 48 03 C0 48 8B 04 C1", 3, 7},

    // ViewRender
    {"ViewRender", "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ?? 48 8D 0D", 3, 7},
    {"ViewRender", "48 89 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B 0D", 3, 7},

    // LevelName — string reference near level transitions
    {"LevelName", "48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53", 3, 7},
};

// ── Struct member validation ──────────────────────────────────────────────

struct MemberCheck {
    const char* name;
    uint64_t offset;
    const char* type; // "int", "float", "vec3", "ptr"
    int expectMin;
    int expectMax;
};

static MemberCheck g_memberChecks[] = {
    {"Health",      0x0438, "int",   0, 200},
    {"MaxHealth",   0x0578, "int",   1, 200},
    {"Shield",      0x0170, "int",   0, 200},
    {"MaxShield",   0x0174, "int",   0, 200},
    {"TeamNum",     0x044C, "int",   0, 100},
    {"LifeState",   0x0798, "int",   0, 3},
    {"VecOrigin.x", 0x014C, "float", -50000, 50000},
    {"VecOrigin.y", 0x0150, "float", -50000, 50000},
    {"VecOrigin.z", 0x0154, "float", -50000, 50000},
    {"ViewAngles.x",0x2564, "float", -360, 360},
    {"ViewAngles.y",0x2568, "float", -360, 360},
    {"BoneMatrix",  0x0E98, "ptr",   0, 0},
    {"CameraPos.x", 0x1F48, "float", -50000, 50000},
    {"WeaponIndex", 0x1A2C, "int",   -1, 50000},
};

// ── Main ──────────────────────────────────────────────────────────────────

int main() {
    printf("=== Apex Legends Offset Dumper ===\n\n");

    DWORD pid = FindProcess("r5apex.exe");
    if (!pid) pid = FindProcess("r5apex_dx12.exe");
    if (!pid) {
        printf("[-] r5apex.exe / r5apex_dx12.exe not found\n");
        return 1;
    }
    printf("[+] Apex PID: %u\n", pid);

    if (!DriverInit(pid)) {
        printf("[-] Betest driver not found. Map it first.\n");
        return 1;
    }
    printf("[+] Driver connected\n");

    uint64_t base = GetImageBase(pid);
    if (!base) {
        printf("[-] Failed to get image base\n");
        return 1;
    }
    printf("[+] Image base: 0x%llX\n", (unsigned long long)base);

    uint64_t imgSize = GetImageSize(base);
    printf("[+] Image size: 0x%llX (%.1f MB)\n", (unsigned long long)imgSize, imgSize / (1024.0 * 1024.0));

    auto sections = GetSections(base);
    printf("[+] Sections: %zu\n", sections.size());
    for (auto& s : sections)
        printf("    %-8s  RVA=0x%08X  Size=0x%08X\n", s.name, s.rva, s.vsize);

    // Find .text section for signature scanning
    uint32_t textRva = 0, textSize = 0;
    for (auto& s : sections) {
        if (strcmp(s.name, ".text") == 0) {
            textRva = s.rva;
            textSize = s.vsize;
            break;
        }
    }
    if (!textRva) {
        // Fall back to first executable section
        if (!sections.empty()) {
            textRva = sections[0].rva;
            textSize = sections[0].vsize;
        }
    }

    // Also scan .rdata for some patterns
    uint32_t rdataRva = 0, rdataSize = 0;
    for (auto& s : sections) {
        if (strcmp(s.name, ".rdata") == 0) {
            rdataRva = s.rva;
            rdataSize = s.vsize;
            break;
        }
    }

    if (!textSize) {
        printf("[-] No .text section found\n");
        return 1;
    }

    printf("\n[*] Reading .text section (0x%X bytes = %.1f MB)...\n", textSize, textSize / (1024.0 * 1024.0));

    // Read in chunks (driver buffer is limited)
    const uint32_t CHUNK = 0x10000; // 64KB chunks
    std::vector<uint8_t> textBuf(textSize);
    uint32_t read = 0;
    uint32_t failedChunks = 0;
    for (uint32_t off = 0; off < textSize; off += CHUNK) {
        uint32_t sz = (off + CHUNK > textSize) ? (textSize - off) : CHUNK;
        if (!DriverRead(base + textRva + off, textBuf.data() + off, sz)) {
            failedChunks++;
            memset(textBuf.data() + off, 0xCC, sz);
        }
        read += sz;
        if ((off & 0xFFFFF) == 0) // progress every 1MB
            printf("\r    Read %.1f / %.1f MB...", read / (1024.0 * 1024.0), textSize / (1024.0 * 1024.0));
    }
    printf("\r    Read complete (%.1f MB, %u failed chunks)          \n", read / (1024.0 * 1024.0), failedChunks);

    // ── Scan for signatures ───────────────────────────────────────────────
    printf("\n=== Signature Scan Results ===\n\n");

    struct FoundOffset {
        std::string name;
        uint64_t rva;
        const char* sig;
    };
    std::vector<FoundOffset> found;
    std::map<std::string, uint64_t> bestOffsets;

    int numSigs = sizeof(g_sigs) / sizeof(g_sigs[0]);
    for (int i = 0; i < numSigs; i++) {
        auto& sd = g_sigs[i];
        auto pat = ParseSig(sd.sig);
        int64_t pos = ScanBuffer(textBuf.data(), textSize, pat);
        if (pos < 0) continue;

        // Resolve RIP-relative address
        uint64_t matchRva = textRva + (uint64_t)pos;
        int32_t disp = *(int32_t*)(textBuf.data() + pos + sd.ripOffset);
        uint64_t targetRva = matchRva + sd.ripBase + disp;

        printf("  [+] %-14s = 0x%llX  (sig hit at .text+0x%llX)\n",
               sd.name, (unsigned long long)targetRva, (unsigned long long)pos);

        found.push_back({sd.name, targetRva, sd.sig});
        if (bestOffsets.find(sd.name) == bestOffsets.end())
            bestOffsets[sd.name] = targetRva;

        // Check for additional matches
        int64_t pos2 = pos + 1;
        while (pos2 < (int64_t)(textSize - pat.bytes.size())) {
            int64_t next = ScanBuffer(textBuf.data() + pos2, textSize - pos2, pat);
            if (next < 0) break;
            pos2 += next;
            uint64_t matchRva2 = textRva + (uint64_t)pos2;
            int32_t disp2 = *(int32_t*)(textBuf.data() + pos2 + sd.ripOffset);
            uint64_t targetRva2 = matchRva2 + sd.ripBase + disp2;
            if (targetRva2 != targetRva) {
                printf("        alt hit  = 0x%llX  (sig hit at .text+0x%llX)\n",
                       (unsigned long long)targetRva2, (unsigned long long)pos2);
            }
            pos2++;
        }
    }

    // ── Validate found offsets by reading memory ──────────────────────────
    printf("\n=== Offset Validation ===\n\n");

    uint64_t entityListRva = 0, localPlayerRva = 0;
    if (bestOffsets.count("EntityList")) entityListRva = bestOffsets["EntityList"];
    if (bestOffsets.count("LocalPlayer")) localPlayerRva = bestOffsets["LocalPlayer"];

    // Try reading EntityList
    if (entityListRva) {
        uint64_t entListPtr = rpm<uint64_t>(base + entityListRva);
        printf("  EntityList @ 0x%llX -> ptr = 0x%llX %s\n",
               (unsigned long long)(base + entityListRva),
               (unsigned long long)entListPtr,
               (entListPtr > 0x10000) ? "[VALID]" : "[NULL/INVALID]");

        if (entListPtr > 0x10000) {
            // Try reading first few entities
            for (int i = 0; i < 3; i++) {
                uint64_t chunk = rpm<uint64_t>(entListPtr + i * 8);
                if (chunk) {
                    uint64_t ent = rpm<uint64_t>(chunk + 0x20);
                    printf("    Entity[%d] chunk=0x%llX  ent=0x%llX\n", i,
                           (unsigned long long)chunk, (unsigned long long)ent);
                }
            }
        }
    }

    // Try reading LocalPlayer
    uint64_t localEnt = 0;
    if (localPlayerRva) {
        localEnt = rpm<uint64_t>(base + localPlayerRva);
        printf("  LocalPlayer @ 0x%llX -> ptr = 0x%llX %s\n",
               (unsigned long long)(base + localPlayerRva),
               (unsigned long long)localEnt,
               (localEnt > 0x10000) ? "[VALID - in game]" : "[NULL - in menu?]");
    }

    // Validate struct member offsets against the local player
    if (localEnt > 0x10000) {
        printf("\n=== Struct Member Validation (LocalPlayer=0x%llX) ===\n\n",
               (unsigned long long)localEnt);

        int valid = 0, invalid = 0;
        for (auto& mc : g_memberChecks) {
            if (strcmp(mc.type, "int") == 0) {
                int val = rpm<int>(localEnt + mc.offset);
                bool ok = (val >= mc.expectMin && val <= mc.expectMax);
                printf("  %-16s [0x%04llX] = %-10d  %s\n",
                       mc.name, (unsigned long long)mc.offset, val, ok ? "[OK]" : "[BAD]");
                if (ok) valid++; else invalid++;
            } else if (strcmp(mc.type, "float") == 0) {
                float val = rpm<float>(localEnt + mc.offset);
                bool ok = (val >= (float)mc.expectMin && val <= (float)mc.expectMax && val == val); // NaN check
                printf("  %-16s [0x%04llX] = %-10.2f  %s\n",
                       mc.name, (unsigned long long)mc.offset, val, ok ? "[OK]" : "[BAD]");
                if (ok) valid++; else invalid++;
            } else if (strcmp(mc.type, "ptr") == 0) {
                uint64_t val = rpm<uint64_t>(localEnt + mc.offset);
                bool ok = (val > 0x10000 && val < 0x7FFFFFFFFFFF);
                printf("  %-16s [0x%04llX] = 0x%llX  %s\n",
                       mc.name, (unsigned long long)mc.offset, (unsigned long long)val, ok ? "[OK]" : "[BAD]");
                if (ok) valid++; else invalid++;
            }
        }
        printf("\n  Result: %d/%d valid\n", valid, valid + invalid);

        if (invalid > valid) {
            printf("\n[!] Most struct offsets are BAD — game likely patched, need new offsets.\n");
            printf("[*] Try scanning for struct members with known value patterns.\n");
        } else if (invalid > 0) {
            printf("\n[!] Some struct offsets may be stale — review the [BAD] ones.\n");
        } else {
            printf("\n[+] All struct member offsets look valid!\n");
        }
    }

    // ── Also try validating with the OLD hardcoded offsets if scan didn't find them ──
    if (!entityListRva || !localPlayerRva) {
        printf("\n=== Fallback: Testing hardcoded offsets from source ===\n\n");
        struct { const char* name; uint64_t rva; } oldOffsets[] = {
            {"EntityList",  0x1F3A258},
            {"LocalPlayer", 0x2282078},
            {"ViewMatrix",  0x11A350},
            {"ViewRender",  0x7540598},
            {"GlobalVars",  0x16B0B80},
            {"NameList",    0xD319E58},
            {"LevelName",   0x16B0E60},
        };
        for (auto& o : oldOffsets) {
            uint64_t val = rpm<uint64_t>(base + o.rva);
            bool looksValid = (val > 0x10000 && val < 0x7FFFFFFFFFFF) ||
                              (strcmp(o.name, "ViewMatrix") == 0 && *(float*)&val != 0.0f);
            printf("  %-14s [0x%llX] -> 0x%llX  %s\n",
                   o.name, (unsigned long long)o.rva,
                   (unsigned long long)val,
                   looksValid ? "[LOOKS OK]" : "[INVALID]");

            if (looksValid && bestOffsets.find(o.name) == bestOffsets.end())
                bestOffsets[o.name] = o.rva;
        }
    }

    // ── Write output ──────────────────────────────────────────────────────
    printf("\n=== Final Offsets ===\n\n");

    // Merge: use scanned values where available, keep old struct members
    struct { const char* name; uint64_t defaultVal; } allOffsets[] = {
        {"EntityList",    0x1F3A258},
        {"LocalPlayer",   0x2282078},
        {"ViewMatrix",    0x11A350},
        {"ViewRender",    0x7540598},
        {"GlobalVars",    0x16B0B80},
        {"NameList",      0xD319E58},
        {"LevelName",     0x16B0E60},
        {"Health",        0x0438},
        {"MaxHealth",     0x0578},
        {"Shield",        0x0170},
        {"MaxShield",     0x0174},
        {"TeamNum",       0x044C},
        {"LifeState",     0x0798},
        {"BleedoutState", 0x2790},
        {"LastVisTime",   0x19C0},
        {"VecOrigin",     0x014C},
        {"ViewAngles",    0x2564},
        {"BoneMatrix",    0x0E98},
        {"CameraPos",     0x1F48},
        {"SignifierName", 0x0589},
        {"AimPunchAngle", 0x2468},
        {"GlowEnable",    0x03C8},
        {"GlowColor",     0x01D0},
        {"GlowMode",      0x02C4},
        {"WeaponIndex",   0x1A2C},
    };

    FILE* f = nullptr;
    fopen_s(&f, "apex_offsets.ini", "w");
    if (f) fprintf(f, "# Apex Legends offsets — auto-dumped %s\n", __DATE__);

    for (auto& o : allOffsets) {
        uint64_t val = o.defaultVal;
        bool fromScan = false;
        if (bestOffsets.count(o.name)) {
            val = bestOffsets[o.name];
            fromScan = (val != o.defaultVal);
        }
        printf("  %-16s = %llx%s\n", o.name, (unsigned long long)val,
               fromScan ? "  [UPDATED by scan]" : "");
        if (f) fprintf(f, "%-16s = %llx\n", o.name, (unsigned long long)val);
    }

    if (f) {
        fclose(f);
        printf("\n[+] Written to apex_offsets.ini\n");
    }

    printf("\n[+] Done\n");
    CloseHandle(g_hDev);
    return 0;
}
