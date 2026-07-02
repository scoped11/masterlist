#pragma once
#ifndef DMA_BUILD
#define DMA_BUILD
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <vector>
#include "log.h"

#include "vmmdll.h"

inline VMM_HANDLE hVMM = NULL;
inline DWORD dwPID = 0;
inline DWORD64 baseAddress = 0;

template <class dataType>
inline dataType read(DWORD64 addressToRead)
{
	dataType rpmBuffer{};
	if (!hVMM || !dwPID || !addressToRead || addressToRead < 0x10000) return rpmBuffer;
	VMMDLL_MemReadEx(hVMM, dwPID, addressToRead, (PBYTE)&rpmBuffer, sizeof(dataType), NULL,
		VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
	return rpmBuffer;
}

template <class dataType>
inline void write(dataType valToWrite, DWORD64 addressToWrite)
{
	if (!hVMM || !dwPID || !addressToWrite || addressToWrite < 0x10000) return;
	VMMDLL_MemWrite(hVMM, dwPID, addressToWrite, (PBYTE)&valToWrite, sizeof(dataType));
}

inline void read_buffer(DWORD64 addressToRead, void* buffer, size_t size)
{
	if (!hVMM || !dwPID || !addressToRead || addressToRead < 0x10000 || !buffer) {
		if (buffer) memset(buffer, 0, size);
		return;
	}
	DWORD cbRead = 0;
	VMMDLL_MemReadEx(hVMM, dwPID, addressToRead, (PBYTE)buffer, (DWORD)size, &cbRead,
		VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
}

inline std::string ReadManagedStringA(uintptr_t strPtr)
{
	if (!strPtr || strPtr < 0x10000) return "";
	int len = read<int>(strPtr + 0x10);
	if (len <= 0 || len > 256) return "";

	std::vector<wchar_t> wbuf(len + 1, 0);
	read_buffer(strPtr + 0x14, wbuf.data(), len * sizeof(wchar_t));

	std::string result;
	result.reserve(len);
	for (int i = 0; i < len; i++)
	{
		wchar_t wc = wbuf[i];
		if (wc >= 32 && wc < 127)
			result += (char)wc;
		else if (wc)
			result += '?';
	}
	return result;
}

namespace DMA
{
	inline bool Init()
	{
		LPCSTR args[] = { "", "-device", "fpga" };
		hVMM = VMMDLL_Initialize(3, args);
		if (!hVMM)
		{
			Log("[-] VMMDLL_Initialize failed. Is the DMA card connected via Data port?");
			return false;
		}
		Log("[+] MemProcFS initialized");
		return true;
	}

	inline bool FindProcess(const char* processName)
	{
		if (!VMMDLL_PidGetFromName(hVMM, (LPSTR)processName, &dwPID))
		{
			Log("[-] Process '%s' not found on target PC", processName);
			return false;
		}
		Log("[+] Found %s @ PID %d", processName, dwPID);
		return true;
	}

	inline DWORD64 GetModuleBase(const char* moduleName)
	{
		PVMMDLL_MAP_MODULEENTRY pModuleEntry = NULL;
		wchar_t wModName[256] = {};
		MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wModName, 256);

		if (!VMMDLL_Map_GetModuleFromNameW(hVMM, dwPID, wModName, &pModuleEntry, 0))
			return 0;

		DWORD64 base = pModuleEntry->vaBase;
		VMMDLL_MemFree(pModuleEntry);
		return base;
	}

	inline void ListProcesses()
	{
		if (!hVMM) return;
		PVMMDLL_PROCESS_INFORMATION pAll = NULL;
		DWORD cProcs = 0;
		if (!VMMDLL_ProcessGetInformationAll(hVMM, &pAll, &cProcs) || !pAll)
		{
			Log("[-] Failed to enumerate processes");
			return;
		}

		printf("\n=== Processes on Target PC (%u) ===\n", cProcs);
		printf("  %-8s  %-40s  %s\n", "PID", "Name", "State");
		printf("  %-8s  %-40s  %s\n", "---", "----", "-----");

		for (DWORD i = 0; i < cProcs; i++)
		{
			auto& p = pAll[i];
			if (p.dwState != 0) continue;
			if (p.szNameLong[0])
				printf("  %-8u  %-40s  Active\n", p.dwPID, p.szNameLong);
			else if (p.szName[0])
				printf("  %-8u  %-40s  Active\n", p.dwPID, p.szName);
		}
		printf("===================================\n\n");
		VMMDLL_MemFree(pAll);
	}

	inline bool FindProcessInteractive()
	{
		if (!hVMM) return false;
		PVMMDLL_PROCESS_INFORMATION pAll = NULL;
		DWORD cProcs = 0;
		if (!VMMDLL_ProcessGetInformationAll(hVMM, &pAll, &cProcs) || !pAll)
		{
			Log("[-] Failed to enumerate processes");
			return false;
		}

		struct ProcEntry { DWORD pid; char name[64]; };
		std::vector<ProcEntry> active;
		for (DWORD i = 0; i < cProcs; i++)
		{
			auto& p = pAll[i];
			if (p.dwState != 0) continue;
			if (!p.szName[0]) continue;
			bool isSystem = (strcmp(p.szName, "System") == 0 || strcmp(p.szName, "[System Proc") == 0
				|| strcmp(p.szName, "Registry") == 0 || strcmp(p.szName, "smss.exe") == 0
				|| strcmp(p.szName, "csrss.exe") == 0 || strcmp(p.szName, "wininit.exe") == 0
				|| strcmp(p.szName, "services.exe") == 0 || strcmp(p.szName, "lsass.exe") == 0
				|| strcmp(p.szName, "svchost.exe") == 0 || strcmp(p.szName, "fontdrvhost.ex") == 0
				|| strcmp(p.szName, "winlogon.exe") == 0 || strcmp(p.szName, "dwm.exe") == 0
				|| strcmp(p.szName, "MemCompression") == 0 || strcmp(p.szName, "spoolsv.exe") == 0
				|| strcmp(p.szName, "conhost.exe") == 0 || strcmp(p.szName, "dllhost.exe") == 0
				|| strcmp(p.szName, "WmiPrvSE.exe") == 0 || strcmp(p.szName, "RuntimeBroker.") == 0
				|| strcmp(p.szName, "SearchHost.exe") == 0 || strcmp(p.szName, "sihost.exe") == 0
				|| strcmp(p.szName, "taskhostw.exe") == 0 || strcmp(p.szName, "ctfmon.exe") == 0
				|| strcmp(p.szName, "SecurityHealth") == 0 || p.dwPID <= 4);
			if (isSystem) continue;

			ProcEntry e;
			e.pid = p.dwPID;
			if (p.szNameLong[0])
				strncpy_s(e.name, p.szNameLong, 63);
			else
				strncpy_s(e.name, p.szName, 63);
			active.push_back(e);
		}
		VMMDLL_MemFree(pAll);

		if (active.empty())
		{
			Log("[-] No user processes found on target PC");
			return false;
		}

		printf("\n=== User Processes on Target PC ===\n");
		for (int i = 0; i < (int)active.size(); i++)
			printf("  [%2d]  PID %-8u  %s\n", i + 1, active[i].pid, active[i].name);
		printf("===================================\n");
		printf("Enter number to select (or 0 to cancel): ");

		int choice = 0;
		if (scanf_s("%d", &choice) != 1 || choice < 1 || choice > (int)active.size())
		{
			Log("[-] Cancelled");
			return false;
		}

		dwPID = active[choice - 1].pid;
		Log("[+] Selected: %s (PID %u)", active[choice - 1].name, dwPID);
		return true;
	}

	inline void Close()
	{
		if (hVMM)
		{
			VMMDLL_Close(hVMM);
			hVMM = NULL;
		}
	}
}

namespace Memory
{
	inline void init()
	{
		baseAddress = DMA::GetModuleBase("mono-2.0-bdwgc.dll");
		if (!baseAddress)
		{
			Log("[-] Failed to find mono-2.0-bdwgc.dll in target process");
			return;
		}
		Log("[+] mono-2.0-bdwgc.dll -> 0x%llX", baseAddress);
	}
}
