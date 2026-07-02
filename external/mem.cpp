#include "mono.h"

DWORD64 baseAddress = NULL;

namespace Memory
{
	void init()
	{
		HMODULE hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
		if (!hMono)
		{
			Log("Failed to find mono-2.0-bdwgc.dll");
			return;
		}

		baseAddress = (DWORD64)hMono;
		Log("mono-2.0-bdwgc.dll -> 0x%p", (void*)baseAddress);

		GET_ROOT_DOMAIN_OFFSET = find_root_domain_offset();
		if (!GET_ROOT_DOMAIN_OFFSET)
			Log("CRITICAL: Could not find root domain offset!");
	}
}
