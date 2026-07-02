// CTF Task 96: Offset Manager — live memory reader using dumped offsets
// Reads offset files from dumper2, resolves them at runtime via driver reads

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
#include <sstream>
#include <chrono>
#include <thread>

#pragma comment(lib, "ntdll.lib")

#define IOCTL_READ_PROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)
struct ReadReq { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; };
#pragma pack(pop)

static HANDLE g_hDev = INVALID_HANDLE_VALUE;
static DWORD  g_pid  = 0;

// ── Driver connection (same as dumper) ─────────────────────────────────────

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
    const char* names[] = {
        "\\\\.\\MsFlt0",   "\\\\.\\WdFilter1", "\\\\.\\FltMgr2",
        "\\\\.\\NdProxy0", "\\\\.\\TdiFilter",  "\\\\.\\MsSecFlt",
        "\\\\.\\WfpDrv0",  "\\\\.\\NtFilter1",
    };
    for (int i = 0; i < 8; i++) {
        HANDLE h = CreateFileA(names[i], GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        if (VerifyBetestDevice(h, pid)) {
            g_hDev = h;
            g_pid  = pid;
            return true;
        }
        CloseHandle(h);
    }
    return false;
}

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

template<typename T>
static bool Read(uint64_t addr, T& out) {
    return DriverRead(addr, &out, sizeof(T));
}

// ── Process discovery ──────────────────────────────────────────────────────

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

// ── Offset database ────────────────────────────────────────────────────────

struct Offset {
    std::string name;
    uint64_t rva;
    uint64_t resolved;
};

static std::vector<Offset> LoadOffsets(const char* path) {
    std::vector<Offset> offsets;
    std::ifstream f(path);
    if (!f.is_open()) return offsets;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '/' || line[0] == '#') continue;

        // Format: 0xRVA  name  [-> 0xResolved]
        uint64_t rva = 0;
        char name[256]{};
        uint64_t resolved = 0;

        if (sscanf(line.c_str(), "0x%llX %255s", (unsigned long long*)&rva, name) >= 2) {
            Offset o;
            o.name = name;
            o.rva = rva;
            o.resolved = 0;

            auto arrow = line.find("->");
            if (arrow != std::string::npos) {
                sscanf(line.c_str() + arrow + 2, " 0x%llX", (unsigned long long*)&o.resolved);
            }
            offsets.push_back(o);
        }
    }
    return offsets;
}

// ── Live monitor mode ──────────────────────────────────────────────────────

static void MonitorOffsets(uint64_t imageBase, const std::vector<Offset>& offsets) {
    printf("\n=== Live Offset Monitor (Ctrl+C to stop) ===\n\n");
    printf("%-30s  %-18s  %-18s  %s\n", "NAME", "ADDRESS", "VALUE (u64)", "VALUE (float)");
    printf("%-30s  %-18s  %-18s  %s\n", "----", "-------", "-----------", "-------------");

    while (true) {
        // Move cursor up to overwrite
        printf("\033[%dA", (int)offsets.size());

        for (auto& o : offsets) {
            uint64_t addr = imageBase + o.rva;
            if (o.resolved) addr = o.resolved;

            // Read the pointer at offset, then dereference
            uint64_t ptrVal = 0;
            float fltVal = 0.0f;
            bool ok = Read(addr, ptrVal);
            if (ok) Read(addr, fltVal);

            printf("%-30s  0x%016llX  0x%016llX  %.4f          \n",
                   o.name.c_str(),
                   (unsigned long long)addr,
                   (unsigned long long)ptrVal,
                   fltVal);
        }
        Sleep(500);
    }
}

// ── Single-read mode ───────────────────────────────────────────────────────

static void ReadAllOffsets(uint64_t imageBase, const std::vector<Offset>& offsets) {
    printf("\n%-30s  %-18s  %-18s  %-12s  %s\n",
           "NAME", "ADDRESS", "PTR_VALUE", "INT32", "FLOAT");
    printf("%-30s  %-18s  %-18s  %-12s  %s\n",
           "----", "-------", "---------", "-----", "-----");

    for (auto& o : offsets) {
        uint64_t addr = imageBase + o.rva;
        if (o.resolved) addr = o.resolved;

        uint64_t ptrVal = 0;
        int32_t intVal = 0;
        float fltVal = 0.0f;

        Read(addr, ptrVal);
        Read(addr, intVal);
        Read(addr, fltVal);

        printf("%-30s  0x%016llX  0x%016llX  %-12d  %.4f\n",
               o.name.c_str(),
               (unsigned long long)addr,
               (unsigned long long)ptrVal,
               intVal, fltVal);
    }
}

// ── Pointer chain walker ───────────────────────────────────────────────────

static void WalkPointerChain(uint64_t baseAddr, int depth) {
    printf("\n[*] Walking pointer chain from 0x%llX (depth=%d)\n",
           (unsigned long long)baseAddr, depth);

    uint64_t addr = baseAddr;
    for (int i = 0; i < depth; i++) {
        uint64_t val = 0;
        if (!Read(addr, val)) {
            printf("    [%d] 0x%016llX -> READ FAILED\n", i, (unsigned long long)addr);
            break;
        }
        printf("    [%d] 0x%016llX -> 0x%016llX", i, (unsigned long long)addr, (unsigned long long)val);

        // Check if value looks like a pointer
        if (val > 0x10000 && val < 0x7FFFFFFFFFFF) {
            // Try reading as string
            char strBuf[64]{};
            if (Read(val, *(uint64_t*)strBuf) && strBuf[0] >= 0x20 && strBuf[0] <= 0x7E) {
                DriverRead(val, strBuf, 63);
                strBuf[63] = 0;
                bool readable = true;
                int len = 0;
                for (int j = 0; j < 63 && strBuf[j]; j++) {
                    if (strBuf[j] < 0x20 || strBuf[j] > 0x7E) { readable = false; break; }
                    len++;
                }
                if (readable && len >= 4)
                    printf("  (\"%.*s\")", len, strBuf);
            }
            printf("\n");
            addr = val;
        } else {
            printf("  (not a pointer)\n");
            break;
        }
    }
}

// ── Main ───────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== CTF Task 96: Offset Manager ===\n\n");

    std::string procName = "r5apex.exe";
    std::string offsetFile;
    uint64_t imageBase = 0;
    bool monitor = false;
    bool walkChain = false;
    uint64_t walkAddr = 0;
    int walkDepth = 8;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--proc") == 0 && i+1 < argc)    procName = argv[++i];
        else if (strcmp(argv[i], "--offsets") == 0 && i+1 < argc) offsetFile = argv[++i];
        else if (strcmp(argv[i], "--base") == 0 && i+1 < argc)
            imageBase = (uint64_t)_strtoui64(argv[++i], nullptr, 16);
        else if (strcmp(argv[i], "--monitor") == 0)            monitor = true;
        else if (strcmp(argv[i], "--walk") == 0 && i+1 < argc) {
            walkChain = true;
            walkAddr = (uint64_t)_strtoui64(argv[++i], nullptr, 16);
        }
        else if (strcmp(argv[i], "--depth") == 0 && i+1 < argc) walkDepth = atoi(argv[++i]);
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("  --proc <name>       Process name (default: r5apex.exe)\n");
            printf("  --offsets <file>     Offset file from dumper2 (e.g. r5apex.exe.dump.bin.offsets.txt)\n");
            printf("  --base <hex>        Image base address (from dump report)\n");
            printf("  --monitor           Continuously monitor offset values\n");
            printf("  --walk <hex>        Walk pointer chain from address\n");
            printf("  --depth <n>         Pointer chain walk depth (default: 8)\n");
            return 0;
        }
        else { printf("[-] Unknown: %s\n", argv[i]); return 1; }
    }

    // Find process
    printf("[*] Looking for %s...\n", procName.c_str());
    DWORD pid = FindProcess(procName.c_str());
    if (!pid) { printf("[-] Process not found: %s\n", procName.c_str()); return 1; }
    printf("[+] Found PID: %u\n", pid);

    // Connect to driver
    printf("[*] Connecting to Betest driver...\n");
    if (!DriverInit(pid)) {
        printf("[-] Driver not found. Load with mapper_nal.exe first.\n");
        return 1;
    }
    printf("[+] Driver connected\n");

    // Get image base from PEB if not specified
    if (imageBase == 0) {
        // Read PEB to get image base
        PROCESS_BASIC_INFORMATION pbi{};
        ULONG retLen = 0;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            typedef NTSTATUS(NTAPI* NtQueryInfoProc)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
            auto NtQIP = (NtQueryInfoProc)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                          "NtQueryInformationProcess");
            if (NtQIP && NT_SUCCESS(NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen))) {
                uint64_t pebAddr = (uint64_t)pbi.PebBaseAddress;
                Read(pebAddr + 0x10, imageBase);
            }
            CloseHandle(hProc);
        }
        if (imageBase)
            printf("[+] Image base from PEB: 0x%llX\n", (unsigned long long)imageBase);
    }

    // Pointer chain walk mode
    if (walkChain) {
        WalkPointerChain(walkAddr, walkDepth);
        CloseHandle(g_hDev);
        return 0;
    }

    // Load offsets
    if (offsetFile.empty()) {
        printf("[-] No offset file specified. Use --offsets <file>\n");
        printf("[*] Generate offsets with: dumper2.exe --proc %s --auto --offsets\n", procName.c_str());
        CloseHandle(g_hDev);
        return 1;
    }

    printf("[*] Loading offsets from %s...\n", offsetFile.c_str());
    auto offsets = LoadOffsets(offsetFile.c_str());
    if (offsets.empty()) {
        printf("[-] No offsets loaded from %s\n", offsetFile.c_str());
        CloseHandle(g_hDev);
        return 1;
    }
    printf("[+] Loaded %zu offsets\n", offsets.size());

    // Read or monitor
    if (monitor) {
        MonitorOffsets(imageBase, offsets);
    } else {
        ReadAllOffsets(imageBase, offsets);
    }

    printf("\n[+] Done\n");
    CloseHandle(g_hDev);
    return 0;
}
