#pragma once
#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>
#include "pz_log.h"

namespace PzMem
{
	inline HANDLE process = nullptr;
	inline DWORD pid = 0;
	inline uint64_t moduleBase = 0;

	template<typename T>
	inline bool Read(uint64_t addr, T& out)
	{
		if (!process || !addr) return false;
		SIZE_T read = 0;
		return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &read) && read == sizeof(T);
	}

	inline bool ReadBuffer(uint64_t addr, void* buf, size_t size)
	{
		if (!process || !addr || !buf) return false;
		SIZE_T read = 0;
		return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), buf, size, &read) && read == size;
	}

	inline DWORD FindProcessId(const char* exeName)
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) return 0;
		PROCESSENTRY32 pe = { sizeof(pe) };
		DWORD found = 0;
		if (Process32First(snap, &pe))
		{
			do
			{
				if (_stricmp(pe.szExeFile, exeName) == 0) { found = pe.th32ProcessID; break; }
			} while (Process32Next(snap, &pe));
		}
		CloseHandle(snap);
		return found;
	}

	inline uint64_t GetModuleBase(DWORD procId, const char* modName)
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
		if (snap == INVALID_HANDLE_VALUE) return 0;
		MODULEENTRY32 me = { sizeof(me) };
		uint64_t base = 0;
		if (Module32First(snap, &me))
		{
			do
			{
				if (_stricmp(me.szModule, modName) == 0) { base = reinterpret_cast<uint64_t>(me.modBaseAddr); break; }
			} while (Module32Next(snap, &me));
		}
		CloseHandle(snap);
		return base;
	}

	inline bool Attach(const char* exeName, const char* moduleName)
	{
		pid = FindProcessId(exeName);
		if (!pid) return false;
		process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!process) return false;
		moduleBase = GetModuleBase(pid, moduleName);
		PZ_LOG("attached pid=%lu module %s=0x%llX", pid, moduleName, (unsigned long long)moduleBase);
		return true;
	}

	inline void Detach()
	{
		if (process) { CloseHandle(process); process = nullptr; }
		pid = 0;
		moduleBase = 0;
	}
}