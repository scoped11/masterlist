#include "mono.h"
#include "xstr.h"
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

static DWORD64 getModuleViaPEB(const char* moduleName)
{
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG ret = 0;
    HANDLE hLimited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pID);
    if (!hLimited)
    {
        Log("NtQueryInformationProcess: failed to open limited handle");
        return 0;
    }
    NTSTATUS status = NtQueryInformationProcess(hLimited, ProcessBasicInformation, &pbi, sizeof(pbi), &ret);
    CloseHandle(hLimited);

    if (status != 0)
    {
        Log("NtQueryInformationProcess failed (0x%X)", status);
        return 0;
    }

    uintptr_t pebBase = (uintptr_t)pbi.PebBaseAddress;
    Log("PEB base: 0x%llX", (unsigned long long)pebBase);

    uintptr_t ldr = GmrMem::Read<uintptr_t>(pebBase + 0x18);
    if (!ldr) { Log("PEB.Ldr is zero"); return 0; }

    uintptr_t head = ldr + 0x10;
    uintptr_t cur  = GmrMem::Read<uintptr_t>(head);

    int limit = 512;
    while (cur && cur != head && --limit > 0)
    {
        uintptr_t dllBase = GmrMem::Read<uintptr_t>(cur + 0x30);
        uint16_t  nameLen = GmrMem::Read<uint16_t>(cur + 0x58);
        uintptr_t nameBuf = GmrMem::Read<uintptr_t>(cur + 0x58 + 8);

        if (nameLen > 0 && nameLen < 512 && nameBuf)
        {
            wchar_t wname[256] = {};
            GmrMem::Read(nameBuf, wname, min((size_t)nameLen, sizeof(wname) - 2));

            char aname[256] = {};
            WideCharToMultiByte(CP_ACP, 0, wname, -1, aname, sizeof(aname), nullptr, nullptr);

            if (_stricmp(aname, moduleName) == 0)
            {
                Log("%s -> 0x%llX (PEB walk)", moduleName, (unsigned long long)dllBase);
                return dllBase;
            }
        }
        cur = GmrMem::Read<uintptr_t>(cur);
    }
    Log("%s not found in PEB module list", moduleName);
    return 0;
}

DWORD64 baseAddress = NULL;
HANDLE  hProcSnap   = NULL;
PROCESSENTRY32 procEntry32;
HANDLE  hModuleSnap = NULL;
MODULEENTRY32  modEntry32;
DWORD   pID  = NULL;
HANDLE  hProc = NULL;

// Convert TCHAR (may be wchar_t in Unicode builds) process name to narrow char for comparison.
static void tchar_to_narrow(const TCHAR* src, char* dst, int dstLen)
{
#ifdef UNICODE
    WideCharToMultiByte(CP_ACP, 0, src, -1, dst, dstLen, nullptr, nullptr);
#else
    strncpy_s(dst, dstLen, src, _TRUNCATE);
#endif
}

bool attatchProc(const char* procName)
{
    procEntry32.dwSize = sizeof(PROCESSENTRY32);
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE)
    {
        Log("Failed to get process snapshot");
        return false;
    }

    if (!Process32First(hProcSnap, &procEntry32))
    {
        Log("Process32First failed");
        CloseHandle(hProcSnap);
        return false;
    }

    do
    {
        char narrow[MAX_PATH] = {};
        tchar_to_narrow(procEntry32.szExeFile, narrow, MAX_PATH);
        if (_stricmp(procName, narrow) == 0)
        {
            Log("%s found (PID %u)", narrow, procEntry32.th32ProcessID);
            pID = procEntry32.th32ProcessID;
            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pID);
            CloseHandle(hProcSnap);
            return true;
        }
    } while (Process32Next(hProcSnap, &procEntry32));

    Log("%s not found", procName);
    CloseHandle(hProcSnap);
    return false;
}

DWORD64 getModule(const char* moduleName)
{
    DWORD64 pebResult = getModuleViaPEB(moduleName);
    if (pebResult) return pebResult;
    Log("%s not found via PEB walk", moduleName);
    return 0;
}

std::uint32_t getProcessId(const char* proc)
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snapshot, &pe))
    {
        do
        {
            char narrow[MAX_PATH] = {};
            tchar_to_narrow(pe.szExeFile, narrow, MAX_PATH);
            if (_stricmp(proc, narrow) == 0)
            {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

namespace Memory
{
    // Resolve mono DLL base + root domain offset. Called from init() and
    // retried from the class-resolution loop if the DLL wasn't in the PEB yet.
    bool resolve_mono()
    {
        if (!pID) return false;
        if (!baseAddress)
        {
            baseAddress = getModule(XS(0x37,0x35,0x34,0x35,0x77,0x68,0x74,0x6A,0x77,0x38,0x3E,0x2D,0x3D,0x39,0x74,0x3E,0x36,0x36).c_str());
            if (baseAddress)
                Log("Mono base: 0x%llX", (unsigned long long)baseAddress);
            else
                Log("Mono DLL not in PEB yet, will retry...");
        }
        if (baseAddress && !GET_ROOT_DOMAIN_OFFSET)
        {
            GET_ROOT_DOMAIN_OFFSET = find_root_domain_offset();
            if (GET_ROOT_DOMAIN_OFFSET)
                Log("Root domain offset: 0x%llX", (unsigned long long)GET_ROOT_DOMAIN_OFFSET);
            else
                Log("CRITICAL: Could not find root domain offset!");
        }
        return baseAddress != 0 && GET_ROOT_DOMAIN_OFFSET != 0;
    }

    void init()
    {
        std::string procName = XS(0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x3F,0x22,0x3F);
        while (!attatchProc(procName.c_str()))
        {
            Log("Waiting for game... (press END to quit)");
            for (int i = 0; i < 20; i++) {
                if (GetAsyncKeyState(VK_END) & 1) return;
                Sleep(500);
            }
        }
        if (pID)
        {
            if (!GmrMem::Init(pID))
                Log("CRITICAL: Failed to open Betest device (is the driver loaded?)");
            else
                Log("Betest driver opened OK (pid=%u)", (unsigned)pID);

            resolve_mono();
        }
    }
}
