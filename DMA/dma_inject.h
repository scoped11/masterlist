#pragma once
#include "dma_mem.h"
#include <vector>
#include <string>

namespace DMAInject
{
	// x64 PEB offsets
	constexpr uint64_t PEB_LDR_OFFSET = 0x18;
	constexpr uint64_t LDR_INLOADORDER_OFFSET = 0x10;
	constexpr uint64_t LDR_ENTRY_DLLBASE = 0x30;
	constexpr uint64_t LDR_ENTRY_DLLNAME = 0x58;
	constexpr uint64_t LDR_ENTRY_FULLNAME = 0x48;

	inline uintptr_t getPEB()
	{
		VMMDLL_PROCESS_INFORMATION info = {};
		info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
		info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
		SIZE_T cb = sizeof(info);
		if (!VMMDLL_ProcessGetInformation(hVMM, dwPID, &info, &cb))
			return 0;
		return info.win.vaPEB;
	}

	inline std::wstring readRemoteWideString(uintptr_t addr, int maxChars = 128)
	{
		if (!addr || addr < 0x10000) return L"";
		std::vector<wchar_t> buf(maxChars + 1, 0);
		read_buffer(addr, buf.data(), maxChars * sizeof(wchar_t));
		return std::wstring(buf.data());
	}

	// walk PEB->Ldr->InLoadOrderModuleList to find a loaded module by name
	inline uintptr_t findRemoteModule(const char* moduleName)
	{
		uintptr_t peb = getPEB();
		if (!peb) return 0;

		uintptr_t ldr = read<uintptr_t>(peb + PEB_LDR_OFFSET);
		if (!ldr) return 0;

		uintptr_t listHead = ldr + LDR_INLOADORDER_OFFSET;
		uintptr_t entry = read<uintptr_t>(listHead);

		wchar_t wTarget[128] = {};
		MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wTarget, 128);
		_wcslwr_s(wTarget, 128);

		for (int i = 0; i < 256 && entry && entry != listHead; i++)
		{
			uint16_t nameLen = read<uint16_t>(entry + LDR_ENTRY_DLLNAME);
			uintptr_t namePtr = read<uintptr_t>(entry + LDR_ENTRY_DLLNAME + 8);

			if (nameLen > 0 && nameLen < 512 && namePtr)
			{
				auto name = readRemoteWideString(namePtr, nameLen / 2);
				std::wstring lower = name;
				for (auto& c : lower) c = towlower(c);

				if (lower.find(wTarget) != std::wstring::npos)
					return read<uintptr_t>(entry + LDR_ENTRY_DLLBASE);
			}
			entry = read<uintptr_t>(entry);
		}
		return 0;
	}

	// resolve an export from a remote module by walking PE export table via DMA
	inline uintptr_t resolveRemoteExport(uintptr_t moduleBase, const char* funcName)
	{
		if (!moduleBase) return 0;

		uint16_t magic = read<uint16_t>(moduleBase);
		if (magic != 0x5A4D) return 0;

		uint32_t peOff = read<uint32_t>(moduleBase + 0x3C);
		uintptr_t ntHeaders = moduleBase + peOff;

		uint32_t expRVA = read<uint32_t>(ntHeaders + 0x88);
		uint32_t expSize = read<uint32_t>(ntHeaders + 0x8C);
		if (!expRVA) return 0;

		uintptr_t expDir = moduleBase + expRVA;
		uint32_t numNames = read<uint32_t>(expDir + 0x18);
		uint32_t namesRVA = read<uint32_t>(expDir + 0x20);
		uint32_t ordinalsRVA = read<uint32_t>(expDir + 0x24);
		uint32_t funcsRVA = read<uint32_t>(expDir + 0x1C);

		for (uint32_t i = 0; i < numNames && i < 4096; i++)
		{
			uint32_t nameRVA = read<uint32_t>(moduleBase + namesRVA + i * 4);
			char name[128] = {};
			read_buffer(moduleBase + nameRVA, name, 127);

			if (strcmp(name, funcName) == 0)
			{
				uint16_t ordinal = read<uint16_t>(moduleBase + ordinalsRVA + i * 2);
				uint32_t funcRVA = read<uint32_t>(moduleBase + funcsRVA + ordinal * 4);
				uintptr_t funcAddr = moduleBase + funcRVA;
				if (funcRVA >= expRVA && funcRVA < expRVA + expSize)
					return 0; // forwarded export
				return funcAddr;
			}
		}
		return 0;
	}

	// scan for RWX memory regions — Mono JIT allocates large RWX pages for compiled code
	// we look for gaps of zeroed memory inside these regions
	struct CodeCave
	{
		uintptr_t addr;
		size_t size;
	};

	inline CodeCave findCodeCave(size_t needed, uintptr_t monoBase = 0)
	{
		CodeCave result = { 0, 0 };

		PVMMDLL_MAP_VAD pVadMap = NULL;
		if (!VMMDLL_Map_GetVadW(hVMM, dwPID, TRUE, &pVadMap) || !pVadMap)
			return result;

		for (DWORD i = 0; i < pVadMap->cMap; i++)
		{
			auto& e = pVadMap->pMap[i];

			bool isRWX = (e.Protection == 6 || e.Protection == 7);
			if (!isRWX) continue;

			uint64_t regionSize = e.vaEnd - e.vaStart + 1;
			if (regionSize < needed + 0x1000) continue;

			// scan from the end of the region backwards for zeroed memory
			size_t scanSize = (size_t)(regionSize < 0x10000 ? regionSize : 0x10000);
			uintptr_t scanStart = (uintptr_t)(e.vaEnd - scanSize + 1);

			std::vector<uint8_t> buf(scanSize, 0xFF);
			read_buffer(scanStart, buf.data(), scanSize);

			size_t zeroRun = 0;
			size_t bestRunStart = 0;
			size_t bestRunLen = 0;

			for (size_t j = 0; j < scanSize; j++)
			{
				if (buf[j] == 0x00)
				{
					if (zeroRun == 0) bestRunStart = j;
					zeroRun++;
					if (zeroRun > bestRunLen)
						bestRunLen = zeroRun;
				}
				else
				{
					if (zeroRun >= needed && zeroRun > bestRunLen)
					{
						bestRunLen = zeroRun;
						bestRunStart = j - zeroRun;
					}
					zeroRun = 0;
				}
			}
			if (zeroRun >= needed && zeroRun > bestRunLen)
			{
				bestRunLen = zeroRun;
				bestRunStart = scanSize - zeroRun;
			}

			if (bestRunLen >= needed)
			{
				result.addr = scanStart + bestRunStart;
				result.size = bestRunLen;
				VMMDLL_MemFree(pVadMap);

				// align to 16 bytes
				result.addr = (result.addr + 0xF) & ~0xFULL;
				result.size -= (result.addr - (scanStart + bestRunStart));
				return result;
			}
		}

		VMMDLL_MemFree(pVadMap);
		return result;
	}

	// write bytes to target process via DMA
	inline bool writeBytes(uintptr_t addr, const void* data, size_t size)
	{
		if (!hVMM || !dwPID || !addr) return false;
		return VMMDLL_MemWrite(hVMM, dwPID, addr, (PBYTE)data, (DWORD)size);
	}

	// read bytes from target process via DMA
	inline bool readBytes(uintptr_t addr, void* data, size_t size)
	{
		read_buffer(addr, data, size);
		return true;
	}

	// hook a COM vtable entry — swaps the pointer at vtable[index] and returns the original
	inline uintptr_t hookVTableEntry(uintptr_t objectAddr, int vtableIndex, uintptr_t newFunc)
	{
		uintptr_t vtable = read<uintptr_t>(objectAddr);
		if (!vtable) return 0;

		uintptr_t entryAddr = vtable + vtableIndex * 8;
		uintptr_t original = read<uintptr_t>(entryAddr);

		write<uintptr_t>(newFunc, entryAddr);
		return original;
	}

	// find DXGI swap chain by scanning for vtable pattern
	// Unity creates IDXGISwapChain during D3D11 device init
	// we find dxgi.dll's .rdata for the vtable, then scan heap for pointers to it
	inline uintptr_t findSwapChain()
	{
		uintptr_t dxgiBase = findRemoteModule("dxgi.dll");
		if (!dxgiBase)
		{
			Log("[-] dxgi.dll not found in target");
			return 0;
		}
		Log("[+] dxgi.dll @ 0x%llX", dxgiBase);

		uintptr_t d3d11Base = findRemoteModule("d3d11.dll");
		Log("[+] d3d11.dll @ 0x%llX", d3d11Base);

		// read PE headers to find .rdata section
		uint32_t peOff = read<uint32_t>(dxgiBase + 0x3C);
		uint16_t numSections = read<uint16_t>(dxgiBase + peOff + 0x6);
		uintptr_t sectionTable = dxgiBase + peOff + 0x18 + read<uint16_t>(dxgiBase + peOff + 0x14);

		uintptr_t rdataStart = 0, rdataEnd = 0;
		for (int i = 0; i < numSections && i < 32; i++)
		{
			char secName[9] = {};
			read_buffer(sectionTable + i * 40, secName, 8);
			if (strcmp(secName, ".rdata") == 0)
			{
				uint32_t virtSize = read<uint32_t>(sectionTable + i * 40 + 0x8);
				uint32_t virtAddr = read<uint32_t>(sectionTable + i * 40 + 0xC);
				rdataStart = dxgiBase + virtAddr;
				rdataEnd = rdataStart + virtSize;
				break;
			}
		}

		if (!rdataStart)
		{
			Log("[-] dxgi.dll .rdata not found");
			return 0;
		}

		// scan .rdata for CDXGISwapChain vtable candidates
		// a vtable is a contiguous array of pointers into the dxgi.dll code section
		std::vector<uintptr_t> vtableCandidates;

		size_t rdataSize = (size_t)(rdataEnd - rdataStart);
		if (rdataSize > 0x100000) rdataSize = 0x100000;

		std::vector<uint8_t> rdataBuf(rdataSize);
		read_buffer(rdataStart, rdataBuf.data(), rdataSize);

		for (size_t off = 0; off + 128 <= rdataSize; off += 8)
		{
			uintptr_t* ptrs = (uintptr_t*)(rdataBuf.data() + off);
			int validCount = 0;
			for (int j = 0; j < 16; j++)
			{
				if (ptrs[j] >= dxgiBase && ptrs[j] < dxgiBase + 0x200000)
					validCount++;
			}
			// a real vtable has most entries pointing into the module
			if (validCount >= 12)
				vtableCandidates.push_back(rdataStart + off);
		}

		Log("[*] Found %zu vtable candidates in dxgi.dll", vtableCandidates.size());

		// scan the process heap for objects whose first qword points to one of these vtables
		// the swap chain object is on the heap
		PVMMDLL_MAP_VAD pVadMap = NULL;
		if (!VMMDLL_Map_GetVadW(hVMM, dwPID, TRUE, &pVadMap) || !pVadMap)
			return 0;

		for (DWORD i = 0; i < pVadMap->cMap; i++)
		{
			auto& e = pVadMap->pMap[i];
			bool isRW = (e.Protection == 4 || e.Protection == 6);
			if (!isRW) continue;

			uint64_t regionSize = e.vaEnd - e.vaStart + 1;
			if (regionSize < 0x1000 || regionSize > 0x1000000) continue;

			size_t scanLen = (size_t)(regionSize < 0x100000 ? regionSize : 0x100000);
			std::vector<uint8_t> heapBuf(scanLen);
			read_buffer((uintptr_t)e.vaStart, heapBuf.data(), scanLen);

			for (size_t off = 0; off + 8 <= scanLen; off += 8)
			{
				uintptr_t val = *(uintptr_t*)(heapBuf.data() + off);
				for (auto& vt : vtableCandidates)
				{
					if (val == vt)
					{
						uintptr_t candidate = (uintptr_t)e.vaStart + off;
						// verify: Present should be vtable[8], which should point into dxgi.dll
						uintptr_t presentAddr = read<uintptr_t>(vt + 8 * 8);
						if (presentAddr >= dxgiBase && presentAddr < dxgiBase + 0x200000)
						{
							Log("[+] SwapChain @ 0x%llX (vtable: 0x%llX, Present: 0x%llX)",
								candidate, vt, presentAddr);
							VMMDLL_MemFree(pVadMap);
							return candidate;
						}
					}
				}
			}
		}

		VMMDLL_MemFree(pVadMap);
		Log("[-] SwapChain not found");
		return 0;
	}

	// find the game window HWND by reading swap chain's description
	// DXGI_SWAP_CHAIN_DESC.OutputWindow is at offset 0x28 in the struct
	// but the desc is internal — we use a different approach:
	// scan for the window by class name via the game process
	inline uintptr_t findGameHWND()
	{
		// for Unity games, window class is "UnityWndClass"
		// we resolve this from PC2 since we can call Win32 APIs locally
		// BUT the HWND belongs to PC1's desktop — we can't use FindWindow
		// instead, we read it from the swap chain's internal structures

		// CDXGISwapChain stores the HWND at a known offset
		// this varies by Windows version, so we use MemProcFS module info
		return 0; // populated by caller
	}
}
