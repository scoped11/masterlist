// CTF Task 45: Stealth Process Dumper via Betest kernel driver
// Target: Apex Legends (r5apex.exe) — EAC protected
// Uses IOCTL_READ_PROCESS_MEM (0x805) for stealthy memory reads

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// ── Driver IOCTL interface ──────────────────────────────────────────────────

#define IOCTL_READ_KMEM    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_READ_PROC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_SESSION_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
struct KReadReq {
    uint64_t Address;
    uint32_t Size;
    uint32_t Pad;
};
struct ReadReq {
    uint64_t ProcessId;
    uint64_t Address;
    uint32_t Size;
    uint32_t Pad;
};
#pragma pack(pop)

static HANDLE g_hDev = INVALID_HANDLE_VALUE;
static DWORD  g_pid  = 0;

// Verify the opened device is actually Betest by reading our own PEB via
// the process read IOCTL. If the device is a real system device, it won't
// understand our IOCTL and will return an error (no BSOD — METHOD_BUFFERED
// IOCTLs to unknown devices just fail with STATUS_INVALID_DEVICE_REQUEST).
static bool VerifyBetestDevice(HANDLE hDev, DWORD pid) {
    ReadReq req{};
    req.ProcessId = GetCurrentProcessId();
    req.Address   = (uint64_t)GetModuleHandleA(nullptr); // our own EXE base
    req.Size      = 2; // read the MZ signature
    uint16_t val  = 0;
    DWORD ret     = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_READ_PROC,
                              &req, sizeof(req), &val, sizeof(val), &ret, nullptr);
    return ok && ret == 2 && val == IMAGE_DOS_SIGNATURE; // 'MZ' = 0x5A4D
}

static bool SessionAuth(HANDLE h) {
    ULONG64 challenge = GetTickCount64();
    ULONG64 token = 0;
    DWORD ret = 0;
    return DeviceIoControl(h, IOCTL_SESSION_AUTH,
                           &challenge, sizeof(challenge),
                           &token, sizeof(token), &ret, nullptr) && ret == sizeof(token);
}

static bool DriverInit(DWORD pid) {
    static const char* dynPrefixes[] = {
        "MsFlt", "WdFlt", "FltMgr", "NdPxy", "TdiFlt",
        "MsSecF", "WfpDr", "NtFlt", "ClfsF", "VhdFlt",
        "SrFlt", "FsDep", "PcwDrv", "MsIScsi", "VolSnap", "WmiLib",
    };
    static const char* staticNames[] = {
        "\\\\.\\MsFlt0",   "\\\\.\\WdFilter1", "\\\\.\\FltMgr2",
        "\\\\.\\NdProxy0", "\\\\.\\TdiFilter",  "\\\\.\\MsSecFlt",
        "\\\\.\\WfpDrv0",  "\\\\.\\NtFilter1",
    };

    auto tryOpen = [&](const char* path) -> bool {
        HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        if (!SessionAuth(h)) { CloseHandle(h); return false; }
        if (VerifyBetestDevice(h, pid)) {
            g_hDev = h;
            g_pid  = pid;
            printf("[+] Verified Betest device on %s\n", path);
            return true;
        }
        CloseHandle(h);
        return false;
    };

    // Dynamic names: 16 prefixes × 10 digits
    for (int p = 0; p < 16; p++) {
        for (int d = 0; d < 10; d++) {
            char path[64];
            snprintf(path, sizeof(path), "\\\\.\\%s%d", dynPrefixes[p], d);
            if (tryOpen(path)) return true;
        }
    }
    // Fallback: static names
    for (int i = 0; i < 8; i++) {
        if (tryOpen(staticNames[i])) return true;
    }
    return false;
}

// The driver's IOCTL_READ_PROCESS_MEM copies data into the METHOD_BUFFERED system
// buffer (which also holds the request struct). For reads >= sizeof(ReadReq), this
// overwrites req->Size, making IoStatus.Information garbage. The I/O manager then
// copies that many bytes back to user space. We absorb this by using a 64KB output
// buffer allocated once, so even an oversized copy stays within bounds.
static uint8_t* g_ioBuf = nullptr;
static const DWORD IO_BUF_SIZE = 65536;

static bool DriverRead(uint64_t addr, void* buf, uint32_t size) {
    if (!g_ioBuf) {
        g_ioBuf = (uint8_t*)VirtualAlloc(nullptr, IO_BUF_SIZE,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_ioBuf) return false;
    }
    if (size > IO_BUF_SIZE - 256) return false;
    auto* req = (ReadReq*)g_ioBuf;
    req->ProcessId = g_pid;
    req->Address   = addr;
    req->Size      = size;
    DWORD ret = 0;
    if (!DeviceIoControl(g_hDev, IOCTL_READ_PROC,
                         g_ioBuf, sizeof(ReadReq), g_ioBuf, IO_BUF_SIZE,
                         &ret, nullptr))
        return false;
    memcpy(buf, g_ioBuf, size);
    return true;
}

// Chunked read — large reads in 4KB pages
static bool DriverReadChunked(uint64_t addr, void* buf, size_t totalSize) {
    const uint32_t CHUNK = 0x1000;
    uint8_t* dst = (uint8_t*)buf;
    size_t remaining = totalSize;
    size_t offset = 0;

    while (remaining > 0) {
        uint32_t toRead = (remaining > CHUNK) ? CHUNK : (uint32_t)remaining;
        if (!DriverRead(addr + offset, dst + offset, toRead)) {
            memset(dst + offset, 0, toRead);
        }
        remaining -= toRead;
        offset    += toRead;
    }
    return true;
}

// ── Process discovery ───────────────────────────────────────────────────────

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

// ── PEB module walker via driver reads ──────────────────────────────────────

struct ModuleInfo {
    uint64_t base;
    uint32_t size;
    char     name[256];
};

static std::vector<ModuleInfo> GetModulesViaPEB() {
    std::vector<ModuleInfo> mods;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pid);
    if (!hProc) {
        printf("[-] OpenProcess(%u) failed: %u\n", g_pid, GetLastError());
        return mods;
    }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG ret = 0;
    NTSTATUS st = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &ret);
    CloseHandle(hProc);
    if (st != 0) {
        printf("[-] NtQueryInformationProcess failed: 0x%08X\n", (unsigned)st);
        return mods;
    }

    uint64_t pebAddr = (uint64_t)pbi.PebBaseAddress;

    uint64_t ldr = 0;
    if (!DriverRead(pebAddr + 0x18, &ldr, 8) || !ldr) {
        printf("[-] Failed to read PEB->Ldr\n");
        return mods;
    }

    uint64_t head = ldr + 0x10;
    uint64_t cur = 0;
    if (!DriverRead(head, &cur, 8)) {
        printf("[-] Failed to read InLoadOrderModuleList\n");
        return mods;
    }

    int limit = 1024;
    while (cur && cur != head && --limit > 0) {
        uint64_t base = 0;
        if (!DriverRead(cur + 0x30, &base, 8)) break;
        uint32_t imgSize = 0;
        if (!DriverRead(cur + 0x40, &imgSize, 4)) break;
        uint16_t nameLen = 0;
        if (!DriverRead(cur + 0x58, &nameLen, 2)) break;
        uint64_t nameBufAddr = 0;
        if (!DriverRead(cur + 0x60, &nameBufAddr, 8)) break;

        ModuleInfo mi{};
        mi.base = base;
        mi.size = imgSize;
        if (nameLen > 0 && nameLen < 512 && nameBufAddr) {
            wchar_t wname[256]{};
            uint32_t readBytes = min((uint32_t)nameLen, (uint32_t)(sizeof(wname) - 2));
            DriverRead(nameBufAddr, wname, readBytes);
            wname[readBytes / 2] = L'\0';
            WideCharToMultiByte(CP_ACP, 0, wname, -1, mi.name, sizeof(mi.name) - 1, nullptr, nullptr);
        }

        if (mi.base && mi.name[0])
            mods.push_back(mi);

        if (!DriverRead(cur, &cur, 8)) break;
    }
    return mods;
}

// ── PE parsing helpers ──────────────────────────────────────────────────────

static bool DriverReadSafe(uint64_t addr, void* buf, uint32_t size) {
    uint8_t* dst = (uint8_t*)buf;
    uint32_t off = 0;
    while (off < size) {
        uint32_t chunk = (size - off > 8) ? 8 : (size - off);
        if (!DriverRead(addr + off, dst + off, chunk)) return false;
        off += chunk;
    }
    return true;
}

static bool ReadPEHeaders(uint64_t base, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt) {
    if (!DriverReadSafe(base, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!DriverReadSafe(base + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    return true;
}

static std::vector<IMAGE_SECTION_HEADER> ReadSections(uint64_t base, const IMAGE_DOS_HEADER& dos,
                                                       const IMAGE_NT_HEADERS64& nt) {
    uint32_t secOff = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                    + nt.FileHeader.SizeOfOptionalHeader;
    uint16_t numSec = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> secs(numSec);
    DriverReadSafe(base + secOff, secs.data(), numSec * sizeof(IMAGE_SECTION_HEADER));
    return secs;
}

// ── Dump modes ──────────────────────────────────────────────────────────────

struct DumpConfig {
    bool fullDump;
    bool sectionsOnly;
    std::vector<std::string> targetSections;
    bool extractOffsets;
    std::string outputPath;
    std::string moduleName;
};

static bool DumpFull(uint64_t base, const IMAGE_DOS_HEADER& dos,
                     const IMAGE_NT_HEADERS64& nt,
                     const std::vector<IMAGE_SECTION_HEADER>& secs,
                     const DumpConfig& cfg) {
    uint32_t imageSize = nt.OptionalHeader.SizeOfImage;
    printf("[*] Full dump: 0x%llX, size=0x%X (%u MB)\n",
           (unsigned long long)base, imageSize, imageSize / (1024 * 1024));

    // Allocate full image buffer
    std::vector<uint8_t> image(imageSize, 0);

    // Read headers using safe 8-byte chunks (driver bug corrupts reads >= 16 bytes)
    uint32_t headerSize = nt.OptionalHeader.SizeOfHeaders;
    printf("[*] Reading headers (0x%X bytes)...\n", headerSize);
    DriverReadSafe(base, image.data(), headerSize);

    // Read each section
    for (size_t i = 0; i < secs.size(); i++) {
        auto& s = secs[i];
        char name[9]{};
        memcpy(name, s.Name, 8);

        uint32_t va   = s.VirtualAddress;
        uint32_t vSz  = s.Misc.VirtualSize;
        if (!va || !vSz) continue;
        if (va + vSz > imageSize) vSz = imageSize - va;

        printf("[*] Reading %-8s  VA=0x%08X  Size=0x%08X", name, va, vSz);

        auto t0 = std::chrono::steady_clock::now();
        DriverReadChunked(base + va, image.data() + va, vSz);
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // Check if section has content (not all zeros)
        bool hasContent = false;
        for (uint32_t j = 0; j < min(vSz, (uint32_t)0x100); j++) {
            if (image[va + j] != 0) { hasContent = true; break; }
        }
        printf("  [%.0fms]%s\n", ms, hasContent ? "" : "  (empty/zeroed)");
    }

    // Fix PE for IDA: set PointerToRawData = VirtualAddress, SizeOfRawData = VirtualSize
    // so IDA loads the dump as a memory-mapped image
    auto* fixedNt = (IMAGE_NT_HEADERS64*)(image.data() + dos.e_lfanew);
    fixedNt->OptionalHeader.ImageBase = base;

    uint32_t secFixOff = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                       + fixedNt->FileHeader.SizeOfOptionalHeader;
    auto* fixedSecs = (IMAGE_SECTION_HEADER*)(image.data() + secFixOff);

    for (uint16_t i = 0; i < fixedNt->FileHeader.NumberOfSections; i++) {
        fixedSecs[i].PointerToRawData = fixedSecs[i].VirtualAddress;
        fixedSecs[i].SizeOfRawData    = fixedSecs[i].Misc.VirtualSize;
    }

    // Write dump
    FILE* f = fopen(cfg.outputPath.c_str(), "wb");
    if (!f) { printf("[-] Cannot open %s for writing\n", cfg.outputPath.c_str()); return false; }
    fwrite(image.data(), 1, imageSize, f);
    fclose(f);
    printf("[+] Dump written: %s (%u MB)\n", cfg.outputPath.c_str(), imageSize / (1024 * 1024));
    return true;
}

static bool DumpSections(uint64_t base, const IMAGE_DOS_HEADER& dos,
                         const IMAGE_NT_HEADERS64& nt,
                         const std::vector<IMAGE_SECTION_HEADER>& secs,
                         const DumpConfig& cfg) {
    printf("[*] Targeted section dump from 0x%llX\n", (unsigned long long)base);

    for (auto& s : secs) {
        char name[9]{};
        memcpy(name, s.Name, 8);

        bool wanted = cfg.targetSections.empty();
        for (auto& t : cfg.targetSections) {
            if (_stricmp(t.c_str(), name) == 0) { wanted = true; break; }
        }
        if (!wanted) continue;

        uint32_t va  = s.VirtualAddress;
        uint32_t vSz = s.Misc.VirtualSize;
        if (!va || !vSz) continue;

        std::string outFile = cfg.outputPath + "." + name;
        // Remove leading dot from section name in filename
        for (auto& c : outFile) if (c == '.') c = '_';
        outFile += ".bin";

        printf("[*] Dumping %-8s  VA=0x%08X  Size=0x%08X -> %s\n", name, va, vSz, outFile.c_str());

        std::vector<uint8_t> buf(vSz, 0);
        DriverReadChunked(base + va, buf.data(), vSz);

        FILE* f = fopen(outFile.c_str(), "wb");
        if (f) { fwrite(buf.data(), 1, vSz, f); fclose(f); }
        else   { printf("[-] Cannot write %s\n", outFile.c_str()); }
    }
    return true;
}

// ── Offset extraction ───────────────────────────────────────────────────────

struct FoundOffset {
    std::string name;
    uint64_t    rva;
};

static std::vector<FoundOffset> ExtractOffsets(const std::vector<uint8_t>& image,
                                                uint64_t imageBase,
                                                const IMAGE_NT_HEADERS64& nt) {
    std::vector<FoundOffset> offsets;

    // Export directory
    auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress && expDir.Size &&
        expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) <= image.size()) {
        auto* exp = (IMAGE_EXPORT_DIRECTORY*)(image.data() + expDir.VirtualAddress);
        uint32_t numNames = exp->NumberOfNames;
        uint32_t nameRva  = exp->AddressOfNames;
        uint32_t funcRva  = exp->AddressOfFunctions;
        uint32_t ordRva   = exp->AddressOfNameOrdinals;

        if (numNames > 0 && numNames < 100000 &&
            nameRva + numNames * 4 <= image.size() &&
            ordRva + numNames * 2 <= image.size()) {
            auto* names = (uint32_t*)(image.data() + nameRva);
            auto* ords  = (uint16_t*)(image.data() + ordRva);
            auto* funcs = (uint32_t*)(image.data() + funcRva);

            for (uint32_t i = 0; i < min(numNames, (uint32_t)5000); i++) {
                if (names[i] < image.size()) {
                    const char* n = (const char*)(image.data() + names[i]);
                    uint16_t ord = ords[i];
                    if (ord < exp->NumberOfFunctions) {
                        offsets.push_back({n, funcs[ord]});
                    }
                }
            }
        }
    }

    // Import directory — list imported DLLs
    auto& impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress && impDir.Size &&
        impDir.VirtualAddress < image.size()) {
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(image.data() + impDir.VirtualAddress);
        int count = 0;
        while (desc->Name && desc->Name < image.size() && count < 200) {
            const char* dll = (const char*)(image.data() + desc->Name);
            offsets.push_back({"[import] " + std::string(dll), desc->Name});
            desc++;
            count++;
        }
    }

    return offsets;
}

// Pattern scanner for common game structures
static void ScanPatterns(const std::vector<uint8_t>& image, uint64_t imageBase,
                         const std::vector<IMAGE_SECTION_HEADER>& secs) {
    printf("\n[*] --- Pattern Scan Results ---\n");

    // Find .text section
    const IMAGE_SECTION_HEADER* textSec = nullptr;
    for (auto& s : secs) {
        char name[9]{};
        memcpy(name, s.Name, 8);
        if (strcmp(name, ".text") == 0) { textSec = &s; break; }
    }
    if (!textSec) { printf("[-] No .text section found\n"); return; }

    uint32_t textVA   = textSec->VirtualAddress;
    uint32_t textSize = textSec->Misc.VirtualSize;
    if (textVA + textSize > image.size()) return;

    const uint8_t* text = image.data() + textVA;

    // Scan for LEA RCX, [rip+disp32] patterns (common for global string refs)
    // 48 8D 0D xx xx xx xx = lea rcx, [rip+disp32]
    int leaCount = 0;
    std::vector<uint64_t> stringRefs;
    for (uint32_t i = 0; i + 7 < textSize && leaCount < 20; i++) {
        if (text[i] == 0x48 && text[i+1] == 0x8D && text[i+2] == 0x0D) {
            int32_t disp = *(int32_t*)(text + i + 3);
            uint64_t target = imageBase + textVA + i + 7 + disp;
            uint64_t targetRva = textVA + i + 7 + disp;
            if (targetRva < image.size()) {
                const char* str = (const char*)(image.data() + targetRva);
                // Check if it looks like a readable string
                bool readable = true;
                int len = 0;
                for (int j = 0; j < 64 && str[j]; j++) {
                    if (str[j] < 0x20 || str[j] > 0x7E) { readable = false; break; }
                    len++;
                }
                if (readable && len >= 8 && len < 64) {
                    printf("[*]   String ref @ RVA 0x%08X -> \"%.*s\"\n",
                           textVA + i, len, str);
                    leaCount++;
                }
            }
        }
    }
    printf("[*] Found %d string references (showing first 20)\n", leaCount);
}

// ── Usage / help ────────────────────────────────────────────────────────────

static void PrintUsage(const char* exe) {
    printf("Usage: %s [options]\n", exe);
    printf("\nOptions:\n");
    printf("  --proc <name>       Process name (default: r5apex.exe)\n");
    printf("  --module <name>     Module to dump (default: main exe)\n");
    printf("  --out <path>        Output file path (default: dump.bin)\n");
    printf("  --full              Full process dump (default)\n");
    printf("  --sections <list>   Dump specific sections (comma-separated, e.g. .text,.rdata)\n");
    printf("  --offsets           Extract offsets after dumping\n");
    printf("  --list-modules      List all loaded modules and exit\n");
    printf("  --no-fix            Don't fix PE headers for IDA\n");
    printf("\nExamples:\n");
    printf("  %s --full --offsets\n", exe);
    printf("  %s --sections .text,.rdata --out apex_sections\n", exe);
    printf("  %s --module EasyAntiCheat.dll --full --out eac_dump.bin\n", exe);
    printf("  %s --list-modules\n", exe);
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== CTF Task 45: Stealth Dumper (Betest driver) [v6] ===\n\n");

    DumpConfig cfg{};
    cfg.fullDump   = true;
    cfg.outputPath = "dump.bin";
    cfg.moduleName = "";
    cfg.extractOffsets = false;

    std::string procName = "r5apex.exe";
    bool listModules = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--proc") == 0 && i + 1 < argc)       procName = argv[++i];
        else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc) cfg.moduleName = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)    cfg.outputPath = argv[++i];
        else if (strcmp(argv[i], "--full") == 0)                    { cfg.fullDump = true; cfg.sectionsOnly = false; }
        else if (strcmp(argv[i], "--sections") == 0 && i + 1 < argc) {
            cfg.sectionsOnly = true;
            cfg.fullDump = false;
            char* tok = strtok(argv[++i], ",");
            while (tok) { cfg.targetSections.push_back(tok); tok = strtok(nullptr, ","); }
        }
        else if (strcmp(argv[i], "--offsets") == 0)    cfg.extractOffsets = true;
        else if (strcmp(argv[i], "--list-modules") == 0) listModules = true;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]); return 0;
        }
        else { printf("[-] Unknown option: %s\n", argv[i]); PrintUsage(argv[0]); return 1; }
    }

    // Find target process
    printf("[*] Looking for %s...\n", procName.c_str());
    DWORD pid = FindProcess(procName.c_str());
    if (!pid) { printf("[-] Process not found: %s\n", procName.c_str()); return 1; }
    printf("[+] Found PID: %u\n", pid);

    // Connect to driver
    printf("[*] Connecting to Betest driver...\n");
    if (!DriverInit(pid)) {
        printf("[!] Driver not loaded — launching mapper...\n");

        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir(exePath);
        exeDir = exeDir.substr(0, exeDir.find_last_of("\\/") + 1);

        std::string mapperPath = exeDir + "mapper_nal.exe";
        std::string driverPath = exeDir + "Betest.sys";

        if (GetFileAttributesA(mapperPath.c_str()) == INVALID_FILE_ATTRIBUTES ||
            GetFileAttributesA(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] mapper_nal.exe or Betest.sys not found in: %s\n", exeDir.c_str());
            return 1;
        }

        std::string cmd = "\"" + mapperPath + "\" \"" + driverPath +
            "\" --driver trixx --stealth 3f --hwid 3f --tpm-spoof 7 --no-auth";
        printf("[*] Running: %s\n", cmd.c_str());

        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                             0, nullptr, exeDir.c_str(), &si, &pi)) {
            printf("[-] Failed to launch mapper: %lu\n", GetLastError());
            return 1;
        }
        printf("[*] Mapper running (PID %lu), waiting...\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 120000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        {
            SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (scm) {
                const char* svcNames[] = { "TrixxSvc", "SivSvc", "WdBroker", "NalDrv", "NalDrvIntel", "iqvw64e", "TsSvc" };
                for (auto sn : svcNames) {
                    SC_HANDLE svc = OpenServiceA(scm, sn, SERVICE_ALL_ACCESS);
                    if (svc) {
                        SERVICE_STATUS ss;
                        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                    }
                }
                CloseServiceHandle(scm);
                printf("[+] BYOVD service entries cleaned\n");
            }
        }

        Sleep(1000);
        if (!DriverInit(pid)) {
            printf("[-] Driver still not available after mapper ran.\n");
            return 1;
        }
        printf("[+] Driver loaded and connected\n");
    } else {
        printf("[+] Driver already loaded — connected\n");
    }

    // Enumerate modules via PEB walk
    printf("[*] Walking PEB module list...\n");
    auto modules = GetModulesViaPEB();
    if (modules.empty()) {
        printf("[-] No modules found (PEB walk failed)\n");
        return 1;
    }
    printf("[+] Found %zu modules\n", modules.size());

    if (listModules) {
        printf("\n%-16s  %-10s  %s\n", "BASE", "SIZE", "NAME");
        printf("%-16s  %-10s  %s\n", "----", "----", "----");
        for (auto& m : modules) {
            printf("0x%014llX  0x%08X  %s\n",
                   (unsigned long long)m.base, m.size, m.name);
        }
        return 0;
    }

    // Find target module
    uint64_t targetBase = 0;
    uint32_t targetSize = 0;
    const char* targetName = nullptr;

    if (cfg.moduleName.empty()) {
        // Use first module (main exe)
        targetBase = modules[0].base;
        targetSize = modules[0].size;
        targetName = modules[0].name;
    } else {
        for (auto& m : modules) {
            if (_stricmp(m.name, cfg.moduleName.c_str()) == 0) {
                targetBase = m.base;
                targetSize = m.size;
                targetName = m.name;
                break;
            }
        }
    }

    if (!targetBase) {
        printf("[-] Module not found: %s\n", cfg.moduleName.c_str());
        printf("[*] Available modules:\n");
        for (auto& m : modules)
            printf("    %s (0x%llX)\n", m.name, (unsigned long long)m.base);
        return 1;
    }

    printf("[+] Target: %s @ 0x%llX (size=0x%X)\n",
           targetName, (unsigned long long)targetBase, targetSize);

    // Read PE headers
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPEHeaders(targetBase, dos, nt)) {
        printf("[-] Failed to read PE headers at 0x%llX\n", (unsigned long long)targetBase);
        return 1;
    }

    printf("[+] PE: Machine=0x%X  Sections=%u  ImageSize=0x%X  EntryPoint=0x%X\n",
           nt.FileHeader.Machine, nt.FileHeader.NumberOfSections,
           nt.OptionalHeader.SizeOfImage, nt.OptionalHeader.AddressOfEntryPoint);

    auto secs = ReadSections(targetBase, dos, nt);
    printf("[*] Sections:\n");
    for (auto& s : secs) {
        char name[9]{};
        memcpy(name, s.Name, 8);
        printf("    %-8s  VA=0x%08X  VSize=0x%08X  Chars=0x%08X\n",
               name, s.VirtualAddress, s.Misc.VirtualSize, s.Characteristics);
    }

    // Perform dump
    auto t0 = std::chrono::steady_clock::now();

    if (cfg.sectionsOnly) {
        DumpSections(targetBase, dos, nt, secs, cfg);
    } else {
        DumpFull(targetBase, dos, nt, secs, cfg);
    }

    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();
    printf("[+] Dump completed in %.1f seconds\n", elapsed);

    // Offset extraction
    if (cfg.extractOffsets && cfg.fullDump) {
        printf("\n[*] Extracting offsets from dump...\n");

        FILE* f = fopen(cfg.outputPath.c_str(), "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            std::vector<uint8_t> image(fsize);
            fread(image.data(), 1, fsize, f);
            fclose(f);

            auto offsets = ExtractOffsets(image, targetBase, nt);

            // Write offsets to file
            std::string ofsFile = cfg.outputPath + ".offsets.txt";
            FILE* of = fopen(ofsFile.c_str(), "w");
            if (of) {
                fprintf(of, "// Offsets extracted from %s @ 0x%llX\n",
                        targetName, (unsigned long long)targetBase);
                fprintf(of, "// Dump date: auto-generated\n\n");

                // Separate exports and imports
                fprintf(of, "// === Exports ===\n");
                for (auto& o : offsets) {
                    if (o.name.find("[import]") == std::string::npos)
                        fprintf(of, "0x%08llX  %s\n", (unsigned long long)o.rva, o.name.c_str());
                }
                fprintf(of, "\n// === Imports ===\n");
                for (auto& o : offsets) {
                    if (o.name.find("[import]") != std::string::npos)
                        fprintf(of, "0x%08llX  %s\n", (unsigned long long)o.rva, o.name.c_str());
                }
                fclose(of);
                printf("[+] Offsets written: %s (%zu entries)\n", ofsFile.c_str(), offsets.size());
            }

            // Pattern scan
            ScanPatterns(image, targetBase, secs);
        }
    }

    printf("\n[+] Done. Load %s in IDA Pro (PE64, rebase to 0x%llX)\n",
           cfg.outputPath.c_str(), (unsigned long long)targetBase);

    CloseHandle(g_hDev);
    return 0;
}
