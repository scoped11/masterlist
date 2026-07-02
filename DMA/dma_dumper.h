#pragma once
#include "dma_mem.h"
#include <vector>
#include <string>
#include <conio.h>
#include <direct.h>
#include <ctime>
#include <shlobj.h>

namespace Dumper
{
	struct ModuleInfo
	{
		std::string name;
		DWORD64 base;
		DWORD size;
	};

	inline std::vector<ModuleInfo> EnumerateModules()
	{
		std::vector<ModuleInfo> modules;
		PVMMDLL_MAP_MODULE pModuleMap = NULL;

		if (!VMMDLL_Map_GetModuleU(hVMM, dwPID, &pModuleMap, VMMDLL_MODULE_FLAG_NORMAL))
		{
			Log("[-] Failed to enumerate modules");
			return modules;
		}

		for (DWORD i = 0; i < pModuleMap->cMap; i++)
		{
			auto& entry = pModuleMap->pMap[i];
			ModuleInfo mi;
			mi.name = entry.uszText;
			mi.base = entry.vaBase;
			mi.size = (DWORD)entry.cbImageSize;
			modules.push_back(mi);
		}

		VMMDLL_MemFree(pModuleMap);
		return modules;
	}

	inline bool DumpModule(const ModuleInfo& mod, const char* outputDir)
	{
		Log("[*] Dumping %s (0x%llX, %d KB)...", mod.name.c_str(), mod.base, mod.size / 1024);

		IMAGE_DOS_HEADER dosHeader = {};
		read_buffer(mod.base, &dosHeader, sizeof(dosHeader));
		if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			Log("[-] Invalid DOS header for %s (MZ check failed)", mod.name.c_str());
			return false;
		}

		IMAGE_NT_HEADERS64 ntHeaders = {};
		read_buffer(mod.base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders));
		if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
		{
			Log("[-] Invalid NT header for %s", mod.name.c_str());
			return false;
		}

		DWORD imageSize = ntHeaders.OptionalHeader.SizeOfImage;
		if (imageSize == 0 || imageSize > 512 * 1024 * 1024)
		{
			Log("[-] Invalid image size: %u", imageSize);
			return false;
		}

		std::vector<BYTE> image(imageSize, 0);

		DWORD headerSize = ntHeaders.OptionalHeader.SizeOfHeaders;
		read_buffer(mod.base, image.data(), headerSize);

		WORD numSections = ntHeaders.FileHeader.NumberOfSections;
		DWORD64 sectionBase = mod.base + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

		for (WORD i = 0; i < numSections; i++)
		{
			IMAGE_SECTION_HEADER section = {};
			read_buffer(sectionBase + i * sizeof(IMAGE_SECTION_HEADER), &section, sizeof(section));

			if (section.VirtualAddress == 0 || section.Misc.VirtualSize == 0)
				continue;

			DWORD readSize = min(section.Misc.VirtualSize, imageSize - section.VirtualAddress);
			if (section.VirtualAddress + readSize > imageSize)
				continue;

			DWORD chunkSize = 0x1000;
			for (DWORD offset = 0; offset < readSize; offset += chunkSize)
			{
				DWORD toRead = min(chunkSize, readSize - offset);
				read_buffer(mod.base + section.VirtualAddress + offset,
					image.data() + section.VirtualAddress + offset, toRead);
			}
		}

		// Fix section headers for raw dumped format
		IMAGE_NT_HEADERS64* pNt = (IMAGE_NT_HEADERS64*)(image.data() + dosHeader.e_lfanew);
		IMAGE_SECTION_HEADER* pSections = (IMAGE_SECTION_HEADER*)((BYTE*)pNt + sizeof(IMAGE_NT_HEADERS64));

		for (WORD i = 0; i < numSections; i++)
		{
			pSections[i].PointerToRawData = pSections[i].VirtualAddress;
			pSections[i].SizeOfRawData = pSections[i].Misc.VirtualSize;
		}

		char filepath[MAX_PATH];
		sprintf_s(filepath, "%s\\%s", outputDir, mod.name.c_str());

		FILE* f = nullptr;
		fopen_s(&f, filepath, "wb");
		if (!f)
		{
			Log("[-] Failed to create file: %s", filepath);
			return false;
		}

		fwrite(image.data(), 1, imageSize, f);
		fclose(f);

		Log("[+] Dumped %s (%u KB) -> %s", mod.name.c_str(), imageSize / 1024, filepath);
		return true;
	}

	inline std::string GetGameDumpsDir()
	{
		char desktop[MAX_PATH] = {};
		if (SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop) == S_OK)
		{
			std::string dumps = std::string(desktop) + "\\Dumps";
			_mkdir(dumps.c_str());
			return dumps;
		}
		_mkdir("Dumps");
		return "Dumps";
	}

	inline std::string dumpProcessName = "Unknown";

	inline void DumpAllModules()
	{
		auto modules = EnumerateModules();
		if (modules.empty())
		{
			Log("[-] No modules found");
			return;
		}

		time_t now = time(nullptr);
		struct tm t = {};
		localtime_s(&t, &now);
		char dateSuffix[32];
		sprintf_s(dateSuffix, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

		std::string gameName = dumpProcessName;
		auto dot = gameName.find('.');
		if (dot != std::string::npos) gameName = gameName.substr(0, dot);

		std::string baseDir = GetGameDumpsDir();
		char dumpDir[MAX_PATH];
		sprintf_s(dumpDir, "%s\\%s_%s", baseDir.c_str(), gameName.c_str(), dateSuffix);
		_mkdir(dumpDir);

		Log("[+] Found %zu modules. Dumping to %s/", modules.size(), dumpDir);
		printf("\n");

		int success = 0, failed = 0;
		for (auto& mod : modules)
		{
			if (DumpModule(mod, dumpDir))
				success++;
			else
				failed++;
		}

		printf("\n=== Dump Complete ===\n");
		printf("Success: %d | Failed: %d | Total: %zu\n", success, failed, modules.size());
		printf("Output: %s\\\n", dumpDir);
	}

	inline void DumpSingleModule(const char* moduleName)
	{
		auto modules = EnumerateModules();
		for (auto& mod : modules)
		{
			if (_stricmp(mod.name.c_str(), moduleName) == 0)
			{
				time_t now = time(nullptr);
				struct tm t = {};
				localtime_s(&t, &now);
				char dateSuffix[32];
				sprintf_s(dateSuffix, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

				std::string gameName = dumpProcessName;
				auto dot = gameName.find('.');
				if (dot != std::string::npos) gameName = gameName.substr(0, dot);

				std::string baseDir = GetGameDumpsDir();
				char dumpDir[MAX_PATH];
				sprintf_s(dumpDir, "%s\\%s_%s", baseDir.c_str(), gameName.c_str(), dateSuffix);
				_mkdir(dumpDir);
				DumpModule(mod, dumpDir);
				return;
			}
		}
		Log("[-] Module '%s' not found", moduleName);
	}

	inline void ListModules()
	{
		auto modules = EnumerateModules();
		printf("\n=== Loaded Modules (%zu) ===\n", modules.size());
		for (auto& mod : modules)
		{
			printf("  0x%012llX  %8u KB  %s\n", mod.base, mod.size / 1024, mod.name.c_str());
		}
		printf("===========================\n");
	}
}
