/*
 * mem.h - Memory interface layer
 *
 * All game memory reads and writes funnel through the templates in this file.
 * The rest of the cheat never touches SWHE directly — it calls read<T>(),
 * write<T>(), or read_buffer(), which forward to the SWHE primitives in
 * mem_swhe.h.
 *
 * This replaces the old kernel-driver backend (GmrMem / Betest.sys).
 * Swapping the backend only requires changing what these wrappers call;
 * the cheat's feature code stays the same.
 */

#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <iostream>
#include <string>
#include <memory>

#include "log.h"
#include "mem_swhe.h"

// Process state — shared across the codebase.
// baseAddress:   Base of the Mono runtime DLL in the target process.
// pID / hProc:   Target process ID and a limited-info handle to it.
// hProcSnap, procEntry32, hModuleSnap, modEntry32:
//   Scratch variables used during toolhelp snapshot enumeration.
extern DWORD64 baseAddress;
extern HANDLE hProcSnap;
extern PROCESSENTRY32 procEntry32;
extern HANDLE hModuleSnap;
extern MODULEENTRY32 modEntry32;
extern DWORD pID;
extern HANDLE hProc;

// read<T> - Read a value of any type from the target process.
// Delegates to SwheRead::ReadBuffer so the SWHE chunking is transparent.
template <class dataType>
inline dataType read(DWORD64 addressToRead)
{
    dataType val{};
    SwheRead::ReadBuffer(addressToRead, &val, sizeof(dataType));
    return val;
}

// write<T> - Write a value of any type into the target process.
template <class dataType>
inline void write(dataType valToWrite, DWORD64 addressToWrite)
{
    SwheRead::WriteBuffer(addressToWrite, &valToWrite, sizeof(dataType));
}

// read_buffer - Raw buffer read for variable-length data (strings, arrays, structs).
inline void read_buffer(DWORD64 addressToRead, void* buffer, size_t size)
{
    SwheRead::ReadBuffer(addressToRead, buffer, size);
}

// Process discovery and module resolution.
extern bool attatchProc(const char* procName);
extern DWORD64 getModule(const char* moduleName);
extern std::uint32_t getProcessId(const char* proc);

namespace Memory
{
    // init()         - Waits for Unturned.exe, initializes the SWHE exploit,
    //                  then resolves the Mono runtime.
    // resolve_mono() - Finds mono-2.0-bdwgc.dll via PEB walk and locates
    //                  the root domain offset needed for Mono introspection.
    extern void init();
    extern bool resolve_mono();
}
