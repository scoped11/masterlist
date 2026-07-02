#pragma  once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <iostream>
#include <string>
#include <memory>

#include "log.h"

// change me to use your driver and stuff

//Vars to use
extern DWORD64 baseAddress;

//Vars for process snapshot
extern HANDLE hProcSnap;
extern PROCESSENTRY32 procEntry32;

//Vars for module snapshot
extern HANDLE hModuleSnap;
extern MODULEENTRY32 modEntry32;

//Process ID of attached proc
extern DWORD pID;

//Handle to process
extern HANDLE hProc;

#ifndef INTERNAL_MODE
// Kernel driver read/write via Betest.sys (dynamic device name)
// Loaded by mapper_nal.exe before launching the cheat.
#include "gmr_mem.hpp"

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

//Attaches to process and gives ALL_ACCESS so you can rpm/wpm for your hack
extern bool attatchProc(const char* procName);

extern DWORD64 getModule(const char* moduleName);
extern std::uint32_t getProcessId(const char* proc);

namespace Memory
{
	extern void init();
	extern bool resolve_mono();
}
#endif


// idk what substances i was on thinking this was smart
//template <class dataType>
//class Field
//{
//	uintptr_t instance;
//	uintptr_t offset;
//public:
//	Field(uintptr_t ins, uintptr_t ofs) : instance{ ins }, offset { ofs }
//	{
//
//	}
//	dataType Read()
//	{
//		return read<dataType>(instance + offset);
//	}
//	void Write(dataType value)
//	{
//		write<dataType>(value, instance + offset);
//	}
//};
