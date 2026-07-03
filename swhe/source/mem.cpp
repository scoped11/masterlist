/*
 * mem.cpp - Process attachment, module resolution, and SWHE initialization
 *
 * Brings together three steps:
 *   1. Find Unturned.exe via toolhelp snapshot  (attatchProc)
 *   2. Initialize the SWHE exploit against its window  (Memory::init)
 *   3. Walk the target PEB to locate mono-2.0-bdwgc.dll and its root domain
 *      offset so the Mono introspection layer can begin  (Memory::resolve_mono)
 *
 * Note: XS() calls throughout are compile-time encrypted string literals
 * (from xstr.h) that decrypt at runtime to avoid static string signatures.
 */

#include "mono.h"
#include "xstr.h"
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

/*
 * getModuleViaPEB - Resolve a DLL base address by walking the target's PEB.
 *
 * Instead of calling EnumProcessModules / CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)
 * (which requires PROCESS_VM_READ or equivalent), this function:
 *   1. Opens a limited handle (PROCESS_QUERY_LIMITED_INFORMATION) to get the
 *      PEB address via NtQueryInformationProcess.
 *   2. Uses SWHE reads (read<T> / read_buffer) to walk
 *      PEB -> Ldr -> InLoadOrderModuleList, reading each LDR_DATA_TABLE_ENTRY's
 *      DllBase and BaseDllName.
 *
 * This works because SWHE reads bypass the normal access-rights check —
 * we only need enough privilege to query the PEB pointer, not to call
 * ReadProcessMemory. The loop is capped at 512 entries as a safety limit.
 *
 * Struct offsets (x64):
 *   PEB + 0x18          = Ldr (PEB_LDR_DATA*)
 *   Ldr + 0x10          = InLoadOrderModuleList (LIST_ENTRY)
 *   Entry + 0x30        = DllBase
 *   Entry + 0x58        = BaseDllName (UNICODE_STRING: Length, MaxLength, Buffer)
 */
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

    // PEB.Ldr -> PEB_LDR_DATA
    uintptr_t ldr = read<uintptr_t>(pebBase + 0x18);
    if (!ldr) { Log("PEB.Ldr is zero"); return 0; }

    // InLoadOrderModuleList head (doubly-linked list of LDR_DATA_TABLE_ENTRY)
    uintptr_t head = ldr + 0x10;
    uintptr_t cur  = read<uintptr_t>(head);

    int limit = 512;
    while (cur && cur != head && --limit > 0)
    {
        uintptr_t dllBase = read<uintptr_t>(cur + 0x30);   // LDR_DATA_TABLE_ENTRY.DllBase
        uint16_t  nameLen = read<uint16_t>(cur + 0x58);     // BaseDllName.Length (bytes)
        uintptr_t nameBuf = read<uintptr_t>(cur + 0x58 + 8);  // BaseDllName.Buffer

        if (nameLen > 0 && nameLen < 512 && nameBuf)
        {
            wchar_t wname[256] = {};
            read_buffer(nameBuf, wname, min((size_t)nameLen, sizeof(wname) - 2));

            char aname[256] = {};
            WideCharToMultiByte(CP_ACP, 0, wname, -1, aname, sizeof(aname), nullptr, nullptr);

            if (_stricmp(aname, moduleName) == 0)
            {
                Log("%s -> 0x%llX (PEB walk)", moduleName, (unsigned long long)dllBase);
                return dllBase;
            }
        }
        // Follow Flink to next entry
        cur = read<uintptr_t>(cur);
    }
    Log("%s not found in PEB module list", moduleName);
    return 0;
}

// ---------------------------------------------------------------------------
// Global process state (definitions for the extern declarations in mem.h)
// ---------------------------------------------------------------------------
DWORD64 baseAddress = NULL;
HANDLE  hProcSnap   = NULL;
PROCESSENTRY32 procEntry32;
HANDLE  hModuleSnap = NULL;
MODULEENTRY32  modEntry32;
DWORD   pID  = NULL;
HANDLE  hProc = NULL;

// Helper: convert TCHAR (wide or narrow depending on build config) to char.
static void tchar_to_narrow(const TCHAR* src, char* dst, int dstLen)
{
#ifdef UNICODE
    WideCharToMultiByte(CP_ACP, 0, src, -1, dst, dstLen, nullptr, nullptr);
#else
    strncpy_s(dst, dstLen, src, _TRUNCATE);
#endif
}

/*
 * attatchProc - Find a running process by name using a toolhelp snapshot.
 *
 * Enumerates all processes, compares names case-insensitively, and stashes
 * the PID and a limited handle in the globals (pID, hProc). Only requests
 * PROCESS_QUERY_LIMITED_INFORMATION — SWHE handles the actual memory access.
 */
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

// getModule - Public wrapper that resolves a module via PEB walk.
DWORD64 getModule(const char* moduleName)
{
    DWORD64 pebResult = getModuleViaPEB(moduleName);
    if (pebResult) return pebResult;
    Log("%s not found via PEB walk", moduleName);
    return 0;
}

// getProcessId - Standalone PID lookup (used by callers that only need the PID,
// not the full attatchProc setup).
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
    /*
     * resolve_mono - Locate the Mono runtime DLL and its root domain offset.
     *
     * Called during init() and can be retried later if the DLL hasn't loaded yet
     * (Unturned's Mono runtime may not be mapped immediately at process start).
     *
     * Steps:
     *   1. Walk the PEB to find "mono-2.0-bdwgc.dll" (the string is XS()-encrypted).
     *   2. Scan the DLL's export/data sections for the root domain singleton offset
     *      via find_root_domain_offset() (defined in mono.h).
     *
     * Returns true only when both the base address and root domain offset are resolved.
     */
    bool resolve_mono()
    {
        if (!pID) return false;
        if (!baseAddress)
        {
            // XS() decrypts to "mono-2.0-bdwgc.dll" at runtime
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

    /*
     * Memory::init - Entry point for the memory subsystem.
     *
     * 1. Polls for Unturned.exe (retries every 10s, abortable with END key).
     * 2. Initializes CProcess (finds the game's window by class/title).
     * 3. Initializes CExploit (installs the SWHE hook on that window).
     * 4. Sets g_swhe_ready = true so all read/write helpers become active.
     * 5. Calls resolve_mono() to locate the Mono runtime for class/field
     *    introspection used by the cheat features.
     */
    void init()
    {
        const char* procName = "Unturned.exe";
        while (!attatchProc(procName))
        {
            Log("Waiting for Unturned... (press END to quit)");
            for (int i = 0; i < 20; i++) {
                if (GetAsyncKeyState(VK_END) & 1) return;
                Sleep(500);
            }
        }
        if (pID)
        {
            // CProcess::Initialize finds the game window (needed for the shatter attack)
            if (!g_proc.Initialize(L"Unturned", nullptr, (char*)"Unturned.exe"))
            {
                Log("CRITICAL: Failed to find Unturned window");
                return;
            }
            Log("Found Unturned window (PID %u, HWND %p)", g_proc.ProcessID, g_proc.ProcessHwnd);

            // CExploit::Initialize sets up the hook (SetWindowsHookExA) on the target window
            if (!g_exploit.Initialize(&g_proc))
            {
                Log("CRITICAL: SWHE exploit init failed");
                return;
            }
            g_swhe_ready = true;
            Log("SWHE exploit initialized OK");

            resolve_mono();
        }
    }
}
