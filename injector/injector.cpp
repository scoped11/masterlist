// DLL Injector — Kernel-assisted DLL injection via Betest driver
// Uses BYOVD stack (mapper -> Betest driver) for stealth memory writes
//
// Injection methods:
//   1. LoadLibrary    — Classic: alloc+write path, remote thread calls LoadLibraryA
//   2. Manual map     — No LoadLibrary: maps PE sections, resolves imports, runs DllMain
//   3. Shellcode      — Raw shellcode injection + execute
//
// All memory writes go through the Betest kernel driver (IOCTL 0x806),
// bypassing usermode hooks on WriteProcessMemory/NtWriteVirtualMemory.
//
// Build: bld_inject.cmd
// Run:   injector.exe <target.exe> <payload.dll> [options]

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

// ═══════════════════════════════════════════════════════════════════════════════
// Betest driver interface
// ═══════════════════════════════════════════════════════════════════════════════

#define IOCTL_READ_PROC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WRITE_PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_SESSION_AUTH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_WRITE_DATA)

#pragma pack(push, 1)
struct ProcReadReq  { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; };
struct ProcWriteReq { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; uint8_t Data[1]; };
#pragma pack(pop)

static HANDLE g_hDev = INVALID_HANDLE_VALUE;
static DWORD  g_targetPid = 0;
static uint8_t* g_ioBuf = nullptr;
static const DWORD IO_BUF_SIZE = 1 << 20; // 1MB for large DLLs

static bool SessionAuth(HANDLE h) {
    ULONG64 challenge = GetTickCount64();
    ULONG64 token = 0;
    DWORD ret = 0;
    return DeviceIoControl(h, IOCTL_SESSION_AUTH,
                           &challenge, sizeof(challenge),
                           &token, sizeof(token), &ret, nullptr) && ret == sizeof(token);
}

static bool VerifyBetestDevice(HANDLE h) {
    ProcReadReq req{};
    req.ProcessId = GetCurrentProcessId();
    req.Address   = (uint64_t)GetModuleHandleA(nullptr);
    req.Size      = 2;
    uint16_t val  = 0;
    DWORD ret     = 0;
    return DeviceIoControl(h, IOCTL_READ_PROC,
                           &req, sizeof(req), &val, sizeof(val), &ret, nullptr)
           && ret == 2 && val == 0x5A4D;
}

static bool DriverInit() {
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
        if (VerifyBetestDevice(h)) {
            g_hDev = h;
            return true;
        }
        CloseHandle(h);
        return false;
    };

    for (int p = 0; p < 16; p++)
        for (int d = 0; d < 10; d++) {
            char path[64];
            snprintf(path, sizeof(path), "\\\\.\\%s%d", dynPrefixes[p], d);
            if (tryOpen(path)) return true;
        }
    for (int i = 0; i < 8; i++)
        if (tryOpen(staticNames[i])) return true;
    return false;
}

static bool DriverRead(DWORD pid, uint64_t addr, void* buf, uint32_t size) {
    if (!g_ioBuf) {
        g_ioBuf = (uint8_t*)VirtualAlloc(nullptr, IO_BUF_SIZE,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_ioBuf) return false;
    }
    if (size > IO_BUF_SIZE - 256) return false;
    auto* req = (ProcReadReq*)g_ioBuf;
    req->ProcessId = pid;
    req->Address   = addr;
    req->Size      = size;
    DWORD ret = 0;
    if (!DeviceIoControl(g_hDev, IOCTL_READ_PROC,
                         g_ioBuf, sizeof(ProcReadReq), g_ioBuf, IO_BUF_SIZE,
                         &ret, nullptr))
        return false;
    memcpy(buf, g_ioBuf, size);
    return true;
}

static bool DriverWrite(DWORD pid, uint64_t addr, const void* data, uint32_t size) {
    size_t reqSize = offsetof(ProcWriteReq, Data) + size;
    std::vector<uint8_t> buf(reqSize);
    auto* req = (ProcWriteReq*)buf.data();
    req->ProcessId = pid;
    req->Address   = addr;
    req->Size      = size;
    memcpy(req->Data, data, size);
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, IOCTL_WRITE_PROC,
                           buf.data(), (DWORD)reqSize,
                           nullptr, 0, &ret, nullptr) != FALSE;
}

static bool DriverWriteChunked(DWORD pid, uint64_t addr, const void* data, uint32_t totalSize) {
    const uint32_t CHUNK = 0x10000; // 64KB chunks
    const uint8_t* src = (const uint8_t*)data;
    for (uint32_t off = 0; off < totalSize; off += CHUNK) {
        uint32_t sz = (totalSize - off < CHUNK) ? (totalSize - off) : CHUNK;
        if (!DriverWrite(pid, addr + off, src + off, sz))
            return false;
    }
    return true;
}

template<class T> T rpm(DWORD pid, uint64_t addr) {
    T v{};
    DriverRead(pid, addr, &v, sizeof(T));
    return v;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Process utilities
// ═══════════════════════════════════════════════════════════════════════════════

static DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(name, pe.szExeFile) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static uint64_t GetModuleBase(DWORD pid, const char* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    uint64_t base = 0;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(modName, me.szModule) == 0) {
                base = (uint64_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

static HANDLE OpenTarget(DWORD pid) {
    return OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Method 1: LoadLibrary injection
// Allocates memory in target, writes DLL path via driver, creates remote thread
// calling LoadLibraryA. Simple but leaves DLL visible in module list.
// ═══════════════════════════════════════════════════════════════════════════════

static bool InjectLoadLibrary(DWORD pid, const char* dllPath) {
    printf("[*] Method: LoadLibrary\n");

    char fullPath[MAX_PATH];
    if (!GetFullPathNameA(dllPath, MAX_PATH, fullPath, nullptr)) {
        printf("[-] GetFullPathName failed: %lu\n", GetLastError());
        return false;
    }

    if (GetFileAttributesA(fullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL not found: %s\n", fullPath);
        return false;
    }

    HANDLE hProc = OpenTarget(pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    size_t pathLen = strlen(fullPath) + 1;
    void* remoteStr = VirtualAllocEx(hProc, nullptr, pathLen,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStr) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }
    printf("[+] Allocated %zu bytes at 0x%llX in target\n",
           pathLen, (unsigned long long)remoteStr);

    if (!DriverWrite(pid, (uint64_t)remoteStr, fullPath, (uint32_t)pathLen)) {
        printf("[-] Driver write failed\n");
        VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    printf("[+] Wrote DLL path via driver (bypassed WriteProcessMemory hooks)\n");

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(hK32, "LoadLibraryA");
    if (!pLoadLib) {
        printf("[-] Cannot resolve LoadLibraryA\n");
        VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLib,
                                         remoteStr, 0, nullptr);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        // Try NtCreateThreadEx as fallback
        typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
            PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if (NtCreateThreadEx) {
            NTSTATUS st = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
                                            pLoadLib, remoteStr, 0, 0, 0, 0, nullptr);
            if (st < 0) {
                printf("[-] NtCreateThreadEx failed: 0x%lX\n", st);
                VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
                CloseHandle(hProc);
                return false;
            }
            printf("[+] NtCreateThreadEx succeeded (CRT blocked, NtCreate fallback)\n");
        } else {
            VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }
    }

    printf("[+] Remote thread created, waiting for DLL load...\n");
    WaitForSingleObject(hThread, 10000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (exitCode == 0) {
        printf("[-] LoadLibraryA returned NULL (DLL load failed in target)\n");
        return false;
    }

    printf("[+] DLL loaded at 0x%lX in target process\n", exitCode);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Method 2: Manual map injection
// Maps DLL into target without LoadLibrary — invisible to module enumeration.
// Resolves imports, applies relocations, executes TLS callbacks, calls DllMain.
// All writes go through the Betest driver.
// ═══════════════════════════════════════════════════════════════════════════════

struct ManualMapData {
    uint64_t pLoadLibraryA;
    uint64_t pGetProcAddress;
    uint64_t pRtlAddFunctionTable;
    uint64_t pBaseAddress;
    uint32_t fdwReason;
    uint32_t bSuccess;
};

// Shellcode that runs inside target process to:
//   1. Process import table (LoadLibraryA + GetProcAddress)
//   2. Execute TLS callbacks
//   3. Call DllMain(hinstDLL, DLL_PROCESS_ATTACH, nullptr)
// This shellcode is position-independent; ManualMapData is passed as arg
#pragma code_seg(push, ".shell")
static void __stdcall ShellcodeMapper(ManualMapData* pData) {
    if (!pData) return;

    auto pLLA = (decltype(&LoadLibraryA))pData->pLoadLibraryA;
    auto pGPA = (decltype(&GetProcAddress))pData->pGetProcAddress;
    auto base = (uint8_t*)pData->pBaseAddress;

    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    auto* opt = &nt->OptionalHeader;

    // Relocations
    uint64_t delta = (uint64_t)base - opt->ImageBase;
    if (delta && opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc = (IMAGE_BASE_RELOCATION*)(base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress) {
            uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (uint32_t i = 0; i < count; i++) {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t* patch = (uint64_t*)(base + reloc->VirtualAddress + offset);
                    *patch += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* patch = (uint32_t*)(base + reloc->VirtualAddress + offset);
                    *patch += (uint32_t)delta;
                }
            }
            reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }

    // Imports
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (imp->Name) {
            char* modName = (char*)(base + imp->Name);
            HMODULE hMod = pLLA(modName);
            if (!hMod) { imp++; continue; }

            auto* thunk = (IMAGE_THUNK_DATA64*)(base + (imp->OriginalFirstThunk
                ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto* func  = (IMAGE_THUNK_DATA64*)(base + imp->FirstThunk);

            while (thunk->u1.AddressOfData) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    func->u1.Function = (uint64_t)pGPA(hMod,
                        (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                } else {
                    auto* name = (IMAGE_IMPORT_BY_NAME*)(base + thunk->u1.AddressOfData);
                    func->u1.Function = (uint64_t)pGPA(hMod, name->Name);
                }
                thunk++;
                func++;
            }
            imp++;
        }
    }

    // TLS callbacks
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY64*)(base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callbacks) {
            while (*callbacks) {
                (*callbacks)((PVOID)base, DLL_PROCESS_ATTACH, nullptr);
                callbacks++;
            }
        }
    }

    // Exception handling (x64 SEH)
    if (pData->pRtlAddFunctionTable &&
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        auto pAddFunc = (decltype(&RtlAddFunctionTable))pData->pRtlAddFunctionTable;
        auto* rfuncs = (RUNTIME_FUNCTION*)(base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        uint32_t count = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
                         / sizeof(RUNTIME_FUNCTION);
        pAddFunc(rfuncs, count, (DWORD64)base);
    }

    // Call DllMain
    typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
    if (opt->AddressOfEntryPoint) {
        auto DllMain = (DllMain_t)(base + opt->AddressOfEntryPoint);
        pData->bSuccess = DllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, nullptr) ? 1 : 0;
    } else {
        pData->bSuccess = 1; // no entry point = success
    }
}
static void ShellcodeMapper_End() {} // marker
#pragma code_seg(pop)

static bool InjectManualMap(DWORD pid, const char* dllPath) {
    printf("[*] Method: Manual Map (stealth)\n");

    // Read DLL from disk
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open DLL: %s (err %lu)\n", dllPath, GetLastError());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        printf("[-] DLL too small: %lu bytes\n", fileSize);
        CloseHandle(hFile);
        return false;
    }

    std::vector<uint8_t> rawDll(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, rawDll.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        printf("[-] ReadFile failed\n");
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);

    auto* dos = (IMAGE_DOS_HEADER*)rawDll.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid MZ signature\n");
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(rawDll.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid PE signature\n");
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[-] Not an x64 DLL (machine: 0x%X)\n", nt->FileHeader.Machine);
        return false;
    }
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        printf("[-] PE is not a DLL\n");
        return false;
    }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    printf("[+] DLL: %s (%lu bytes on disk, 0x%llX mapped)\n",
           dllPath, fileSize, (unsigned long long)imageSize);

    // Open target for VirtualAllocEx
    HANDLE hProc = OpenTarget(pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    // Allocate in target
    void* remoteBase = VirtualAllocEx(hProc, nullptr, imageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        printf("[-] VirtualAllocEx for DLL failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }
    printf("[+] Allocated 0x%llX bytes at 0x%llX\n",
           (unsigned long long)imageSize, (unsigned long long)remoteBase);

    // Build mapped image in local buffer
    std::vector<uint8_t> mappedImage(imageSize, 0);
    memcpy(mappedImage.data(), rawDll.data(),
           nt->OptionalHeader.SizeOfHeaders);

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        memcpy(mappedImage.data() + sections[i].VirtualAddress,
               rawDll.data() + sections[i].PointerToRawData,
               sections[i].SizeOfRawData);
    }

    // Write mapped image via driver
    printf("[*] Writing PE image via driver...\n");
    if (!DriverWriteChunked(pid, (uint64_t)remoteBase,
                             mappedImage.data(), (uint32_t)imageSize)) {
        printf("[-] Driver write of PE image failed\n");
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Prepare shellcode data
    ManualMapData mapData{};
    mapData.pLoadLibraryA    = (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    mapData.pGetProcAddress  = (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    mapData.pRtlAddFunctionTable = (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlAddFunctionTable");
    mapData.pBaseAddress     = (uint64_t)remoteBase;
    mapData.fdwReason        = DLL_PROCESS_ATTACH;
    mapData.bSuccess         = 0;

    // Calculate shellcode size
    size_t shellSize = (size_t)((uint8_t*)&ShellcodeMapper_End - (uint8_t*)&ShellcodeMapper);
    if (shellSize > 0x10000) shellSize = 0x4000; // safety cap

    // Allocate space for shellcode + data
    size_t totalAlloc = shellSize + sizeof(ManualMapData) + 0x100;
    void* remoteShell = VirtualAllocEx(hProc, nullptr, totalAlloc,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShell) {
        printf("[-] VirtualAllocEx for shellcode failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    uint64_t dataAddr = (uint64_t)remoteShell + shellSize + 0x10;
    // Align to 16
    dataAddr = (dataAddr + 15) & ~15ULL;

    // Write shellcode via driver
    if (!DriverWrite(pid, (uint64_t)remoteShell, (void*)&ShellcodeMapper, (uint32_t)shellSize)) {
        printf("[-] Driver write of shellcode failed\n");
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Write map data via driver
    if (!DriverWrite(pid, dataAddr, &mapData, sizeof(mapData))) {
        printf("[-] Driver write of map data failed\n");
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    printf("[+] Shellcode written at 0x%llX, data at 0x%llX\n",
           (unsigned long long)remoteShell, (unsigned long long)dataAddr);

    // Execute shellcode
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
                                         (LPTHREAD_START_ROUTINE)remoteShell,
                                         (LPVOID)dataAddr, 0, nullptr);
    if (!hThread) {
        typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
            PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if (NtCreateThreadEx) {
            NTSTATUS st = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
                                            remoteShell, (LPVOID)dataAddr,
                                            0, 0, 0, 0, nullptr);
            if (st < 0) {
                printf("[-] NtCreateThreadEx failed: 0x%lX\n", st);
                VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
                VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
                CloseHandle(hProc);
                return false;
            }
            printf("[+] NtCreateThreadEx succeeded\n");
        } else {
            printf("[-] CreateRemoteThread failed and NtCreateThreadEx unavailable\n");
            VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }
    }

    printf("[+] Shellcode executing in target...\n");
    WaitForSingleObject(hThread, 15000);
    CloseHandle(hThread);

    // Read back result
    ManualMapData result{};
    DriverRead(pid, dataAddr, &result, sizeof(result));

    // Clean up shellcode (leave DLL mapped)
    VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);

    // Zero PE headers in target to reduce forensic footprint
    std::vector<uint8_t> zeros(0x1000, 0);
    DriverWrite(pid, (uint64_t)remoteBase, zeros.data(), (uint32_t)zeros.size());
    printf("[+] PE headers zeroed in target\n");

    CloseHandle(hProc);

    if (result.bSuccess) {
        printf("[+] DllMain returned TRUE — injection successful\n");
        printf("[+] DLL mapped at 0x%llX (hidden from module list)\n",
               (unsigned long long)remoteBase);
        return true;
    } else {
        printf("[-] DllMain returned FALSE or shellcode did not complete\n");
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Method 3: Raw shellcode injection
// Reads a .bin file, writes it to target, executes it.
// ═══════════════════════════════════════════════════════════════════════════════

static bool InjectShellcode(DWORD pid, const char* binPath) {
    printf("[*] Method: Raw Shellcode\n");

    HANDLE hFile = CreateFileA(binPath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open shellcode file: %s\n", binPath);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<uint8_t> shellcode(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, shellcode.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    printf("[+] Shellcode: %lu bytes\n", fileSize);

    HANDLE hProc = OpenTarget(pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    void* remoteMem = VirtualAllocEx(hProc, nullptr, fileSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    if (!DriverWrite(pid, (uint64_t)remoteMem, shellcode.data(), fileSize)) {
        printf("[-] Driver write failed\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
                                         (LPTHREAD_START_ROUTINE)remoteMem,
                                         nullptr, 0, nullptr);
    if (!hThread) {
        typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
            PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if (NtCreateThreadEx) {
            NTSTATUS st = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
                                            remoteMem, nullptr, 0, 0, 0, 0, nullptr);
            if (st < 0) {
                printf("[-] NtCreateThreadEx failed: 0x%lX\n", st);
                VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
                CloseHandle(hProc);
                return false;
            }
        } else {
            printf("[-] Thread creation failed\n");
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }
    }

    printf("[+] Shellcode executing at 0x%llX\n", (unsigned long long)remoteMem);
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

enum InjMethod { INJ_LOADLIB = 0, INJ_MANUALMAP = 1, INJ_SHELLCODE = 2 };

static void PrintUsage() {
    printf(
        "PenisFinger DLL Injector — Kernel-assisted injection via Betest driver\n\n"
        "Usage:\n"
        "  injector.exe <process> <payload> [options]\n\n"
        "  <process>   Target process name (e.g. game.exe) or PID\n"
        "  <payload>   Path to DLL or .bin shellcode file\n\n"
        "Options:\n"
        "  --loadlib     LoadLibrary injection (default)\n"
        "  --manualmap   Manual map injection (stealth, no module list entry)\n"
        "  --shellcode   Raw shellcode injection (.bin file)\n"
        "  --hide        Hide injector process via DKOM after injection\n"
        "  --wait        Wait for target process if not running\n"
        "  --pid <N>     Target by PID instead of process name\n\n"
        "Examples:\n"
        "  injector.exe game.exe myhack.dll                   LoadLibrary inject\n"
        "  injector.exe game.exe internal.dll --manualmap     Manual map (stealth)\n"
        "  injector.exe game.exe payload.bin --shellcode      Shellcode inject\n"
        "  injector.exe game.exe hack.dll --manualmap --hide  Full stealth\n\n"
        "Requires: Betest kernel driver mapped via mapper_nal.exe first.\n"
    );
}

int main(int argc, char* argv[]) {
    printf("=== PenisFinger Injector v1.0 ===\n\n");

    if (argc < 3) {
        PrintUsage();
        return 1;
    }

    const char* target  = argv[1];
    const char* payload = argv[2];
    InjMethod method    = INJ_LOADLIB;
    bool hideProc       = false;
    bool waitTarget     = false;
    bool usePid         = false;
    DWORD directPid     = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--loadlib") == 0)     method = INJ_LOADLIB;
        else if (strcmp(argv[i], "--manualmap") == 0)  method = INJ_MANUALMAP;
        else if (strcmp(argv[i], "--shellcode") == 0)  method = INJ_SHELLCODE;
        else if (strcmp(argv[i], "--hide") == 0)       hideProc = true;
        else if (strcmp(argv[i], "--wait") == 0)       waitTarget = true;
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            usePid = true;
            directPid = (DWORD)atoi(argv[++i]);
        }
        else {
            printf("[-] Unknown option: %s\n", argv[i]);
            PrintUsage();
            return 1;
        }
    }

    // Connect to Betest driver
    printf("[*] Connecting to Betest driver...\n");
    if (!DriverInit()) {
        printf("[!] Driver not loaded — launching mapper with HWID spoofer...\n");

        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir(exePath);
        exeDir = exeDir.substr(0, exeDir.find_last_of("\\/") + 1);

        std::string mapperPath = exeDir + "mapper_nal.exe";
        std::string driverPath = exeDir + "Betest.sys";

        if (GetFileAttributesA(mapperPath.c_str()) == INVALID_FILE_ATTRIBUTES ||
            GetFileAttributesA(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] mapper_nal.exe or Betest.sys not found in: %s\n", exeDir.c_str());
            printf("    Place them next to this exe.\n");
            return 1;
        }

        std::string cmd = "\"" + mapperPath + "\" \"" + driverPath +
            "\" --driver trixx --stealth 3f --eac 7f --hwid 3f --tpm-spoof 7 --no-auth";
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
        if (!DriverInit()) {
            printf("[-] Driver still not available after mapper ran.\n");
            return 1;
        }
        printf("[+] Driver loaded and connected (HWID spoofer active)\n");
    } else {
        printf("[+] Driver already loaded — connected\n");
    }

    // Find target process
    if (usePid) {
        g_targetPid = directPid;
    } else {
        g_targetPid = FindProcess(target);
        if (!g_targetPid && waitTarget) {
            printf("[*] Waiting for %s...\n", target);
            while (!g_targetPid) {
                Sleep(1000);
                g_targetPid = FindProcess(target);
            }
        }
    }

    if (!g_targetPid) {
        printf("[-] Target process not found: %s\n", target);
        return 1;
    }
    printf("[+] Target: %s (PID %lu)\n", target, g_targetPid);

    // Inject
    bool ok = false;
    switch (method) {
        case INJ_LOADLIB:   ok = InjectLoadLibrary(g_targetPid, payload); break;
        case INJ_MANUALMAP: ok = InjectManualMap(g_targetPid, payload); break;
        case INJ_SHELLCODE: ok = InjectShellcode(g_targetPid, payload); break;
    }

    if (!ok) {
        printf("\n[-] Injection failed.\n");
        return 1;
    }

    // Hide injector process
    if (hideProc) {
        uint64_t selfPid = GetCurrentProcessId();
        DWORD ret = 0;
        if (DeviceIoControl(g_hDev, IOCTL_HIDE_PROCESS,
                             &selfPid, sizeof(selfPid), nullptr, 0, &ret, nullptr)) {
            printf("[+] Injector process hidden via DKOM\n");
        }
    }

    printf("\n[+] Injection complete.\n");
    CloseHandle(g_hDev);
    return 0;
}
