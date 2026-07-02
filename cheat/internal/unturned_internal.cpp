// Unturned Internal DLL — injected into Unturned.exe
// Uses direct memory access (in-process), streamproof GDI overlay with full menu
// Same features as external, but no kernel driver needed for reads/writes

#ifndef INTERNAL_MODE
#define INTERNAL_MODE
#endif
#include <Windows.h>
#include <cstdio>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "msimg32.lib")

// In-process memory — replaces kernel driver IOCTLs with direct pointer dereference
#include "mem_internal.hpp"

#include "../external/log.h"
#include "../external/xstr.h"

// Globals that mem.h declares as extern
DWORD64 baseAddress = 0;
HANDLE  hProcSnap   = NULL;
PROCESSENTRY32 procEntry32;
HANDLE  hModuleSnap = NULL;
MODULEENTRY32  modEntry32;
DWORD   pID  = 0;
HANDLE  hProc = NULL;

// read/write/read_buffer using in-process GmrMem
template <class dataType>
inline void write(dataType valToWrite, DWORD64 addressToWrite)
{
    GmrMem::Write<dataType>(addressToWrite, valToWrite);
}

template <class dataType>
inline dataType read(DWORD64 addressToRead)
{
    return GmrMem::Read<dataType>(addressToRead);
}

inline void read_buffer(DWORD64 addressToRead, void* buffer, size_t size)
{
    GmrMem::Read(addressToRead, buffer, (ULONG)size);
}

// Include game logic headers (INTERNAL_MODE makes mem.h skip gmr_mem.hpp and its own read/write)
#include "../external/math.h"
#include "../external/mono.h"
#include "../external/config.h"
#include "../external/types/unity.h"
#include "../external/types/game.h"
#include "../external/unturned.h"
#include "../external/overlay.h"
#include "../external/features.h"

// Include .cpp files for variable definitions and member function implementations
#include "../external/types/unity.cpp"
#include "../external/types/game.cpp"
#include "../external/unturned.cpp"

// In-process module resolution — replaces PEB walk (we're already injected)
static DWORD64 getModuleInternal(const char* moduleName)
{
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (hMod) {
        Log("%s -> 0x%llX (in-process)", moduleName, (unsigned long long)hMod);
        return (DWORD64)hMod;
    }
    return 0;
}

static bool resolveMonoInternal()
{
    if (!baseAddress) {
        baseAddress = getModuleInternal("mono-2.0-bdwgc.dll");
        if (!baseAddress) baseAddress = getModuleInternal("mono.dll");
        if (baseAddress) Log("Mono base: 0x%llX", (unsigned long long)baseAddress);
    }
    if (baseAddress && !GET_ROOT_DOMAIN_OFFSET) {
        GET_ROOT_DOMAIN_OFFSET = find_root_domain_offset();
        if (GET_ROOT_DOMAIN_OFFSET)
            Log("Root domain offset: 0x%llX", (unsigned long long)GET_ROOT_DOMAIN_OFFSET);
    }
    return baseAddress != 0 && GET_ROOT_DOMAIN_OFFSET != 0;
}

static DWORD WINAPI InternalThread(LPVOID hModule)
{
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);

    Log("=== Unturned INTERNAL Cheat ===");
    Log("[*] DLL injected at 0x%llX", (unsigned long long)hModule);

    pID = GetCurrentProcessId();
    hProc = GetCurrentProcess();
    GmrMem::Init(pID);

    Log("[*] Resolving Mono runtime...");
    for (int retry = 0; retry < 30 && !resolveMonoInternal(); retry++) {
        Log("Mono not ready, retrying in 2s...");
        Sleep(2000);
    }
    if (!baseAddress || !GET_ROOT_DOMAIN_OFFSET) {
        Log("[!] Failed to resolve Mono runtime");
        FreeLibraryAndExitThread((HMODULE)hModule, 1);
        return 1;
    }

    Log("[*] Resolving classes...");
    for (;;) {
        Classes::init();
        if (Classes::Player && Classes::Provider) break;
        if (GetAsyncKeyState(VK_END) & 1) {
            FreeLibraryAndExitThread((HMODULE)hModule, 0);
            return 0;
        }
        Log("Mono classes not ready yet, retrying in 2s...");
        Sleep(2000);
    }

    Log("[*] Resolving offsets...");
    Offsets::init();

    if (Offsets::_isConnected) {
        Log("[*] Waiting for server connection...");
        while (!SDG::Provider::isConnected()) {
            if (GetAsyncKeyState(VK_END) & 1) {
                FreeLibraryAndExitThread((HMODULE)hModule, 0);
                return 0;
            }
            Sleep(1000);
        }
    } else {
        Sleep(3000);
    }

    Log("[*] Waiting for local player...");
    SDG::Player* localPlayer = nullptr;
    while (!(localPlayer = Features::GetLocalPlayer())) {
        if (GetAsyncKeyState(VK_END) & 1) {
            FreeLibraryAndExitThread((HMODULE)hModule, 0);
            return 0;
        }
        Sleep(500);
    }
    Log("[+] Local player: %p", localPlayer);

    std::thread overlayThread(Overlay::Run);
    overlayThread.detach();

    Log("[+] Cheat active — press END to unload, F1 for menu");

    while (true) {
        if (GetAsyncKeyState(VK_END) & 1) break;

        if (Offsets::_isConnected && !SDG::Provider::isConnected()) {
            Sleep(1000);
            continue;
        }

        localPlayer = Features::GetLocalPlayer();
        if (!localPlayer) { Sleep(500); continue; }

        Config::ProcessHotkeys();
        Features::Update(localPlayer);

        Sleep(3 + (GetTickCount() % 7));
    }

    Log("[*] Unloading...");
    Overlay::Shutdown();
    Sleep(200);

    auto lp = Features::GetLocalPlayer();
    if (lp && Offsets::_movement) {
        auto mv = lp->movement();
        if (mv && (uintptr_t)mv > 0x10000) {
            if (Offsets::pluginSpeedMultiplier) mv->pluginSpeedMultiplier_set(1.0f);
            if (Offsets::pluginJumpMultiplier) mv->pluginJumpMultiplier_set(1.0f);
            if (Offsets::pluginGravityMultiplier) mv->pluginGravityMultiplier_set(1.0f);
        }
    }
    Config::fullbright = false;
    Features::UpdateFullbright();
    Config::fovChanger = false;
    Features::UpdateFOVChanger();

    if (f) fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread((HMODULE)hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, InternalThread, hModule, 0, nullptr);
    }
    return TRUE;
}
