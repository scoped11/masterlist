#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#include "dma_mem.h"
#include "dma_features.h"
#include "dma_dumper.h"
#include "dma_webserver.h"
#include "dma_offsetdump.h"
#include "dma_internal.h"
#include <thread>

#include "../external/unturned.cpp"
#include "../external/types/game.cpp"
#include "../external/types/unity.cpp"

int main(int argc, char* argv[])
{
	SetConsoleTitleA("Coopyy DMA - RADAR PC");
	printf("=== Coopyy DMA (Streamproof) ===\n");
	printf("Run this on your RADAR PC (PC2)\n\n");

	if (argc > 1 && strcmp(argv[1], "--offsets") == 0)
	{
		setvbuf(stdout, NULL, _IONBF, 0);
		printf("=== DMA Offset Dumper (Multi-Game, Multi-Engine) ===\n");
		printf("Engines: Mono, IL2CPP, UE4, UE5, Source 2, Source(Respawn), Enfusion, AnvilNext\n");
		printf("Games:   Unturned, Rust, Squad, Sea of Thieves, Delta Force, Arena Breakout,\n");
		printf("         CS2, Apex Legends, Arma Reforger, DayZ, R6 Siege\n");
		printf("Also auto-detects engine type for unknown games.\n\n");
		printf("Initializing DMA...\n");
		if (!DMA::Init()) { printf("DMA init failed.\n"); return 1; }
		printf("DMA connected. Scanning for games...\n");
		OffsetDump::AutoDump();
		DMA::Close();
		printf("\nDone.\n");
		return 0;
	}

	bool internalMode = false;
	uint64_t internalHwnd = 0;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--internal") == 0)
			internalMode = true;
		if (strcmp(argv[i], "--hwnd") == 0 && i + 1 < argc)
			internalHwnd = strtoull(argv[++i], NULL, 16);
	}

	if (argc > 1 && strcmp(argv[1], "--list") == 0)
	{
		printf("=== DMA Process List ===\n");
		if (!DMA::Init()) { printf("DMA init failed.\n"); _getch(); return 1; }
		DMA::ListProcesses();
		DMA::Close();
		printf("Press any key to exit.\n");
		_getch();
		return 0;
	}

	if (argc > 1 && strcmp(argv[1], "--dump") == 0)
	{
		printf("=== DMA PE Dumper Mode ===\n");
		if (!DMA::Init()) { printf("DMA init failed.\n"); _getch(); return 1; }

		bool found = false;
		const char* targetName = (argc > 2) ? argv[2] : nullptr;
		if (targetName)
		{
			found = DMA::FindProcess(targetName);
			Dumper::dumpProcessName = targetName;
		}

		if (!found)
		{
			if (targetName)
				Log("[!] '%s' not found. Showing all processes on target PC...", targetName);
			else
				Log("[*] No target specified. Showing all processes on target PC...");

			if (!DMA::FindProcessInteractive())
			{
				DMA::Close();
				goto idle;
			}

			VMMDLL_PROCESS_INFORMATION info = {};
			info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
			info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
			SIZE_T cbInfo = sizeof(info);
			if (VMMDLL_ProcessGetInformation(hVMM, dwPID, &info, &cbInfo))
				Dumper::dumpProcessName = info.szNameLong[0] ? info.szNameLong : info.szName;
			else
				Dumper::dumpProcessName = "Unknown";
		}

		Dumper::DumpAllModules();
		DMA::Close();
		printf("\nDone. Press any key to exit.\n");
		_getch();
		return 0;
	}

	WebServer::Start(9222);
	Log("[+] Web menu live on port 9222");
	Log("    Open http://localhost:9222 or http://<this-pc-ip>:9222\n");

	if (!DMA::Init()) {
		Log("[-] DMA init failed. Web menu still running.");
		goto idle;
	}

	Log("Searching for Unturned.exe on target PC...");
	{
		int retries = 0;
		while (!DMA::FindProcess("Unturned.exe"))
		{
			if (GetAsyncKeyState(VK_END) & 1) goto cleanup;
			if (++retries > 120)
			{
				Log("[-] Gave up after 120 attempts. Is Unturned running on PC1?");
				Log("    Web menu still running. Press END to exit.");
				goto idle;
			}
			Log("[*] Retrying in 3s... (%d/120)", retries);
			Sleep(3000);
		}
	}

	Log("Initializing mono...");
	Memory::init();

	if (!baseAddress)
	{
		Log("[-] Failed to find mono-2.0-bdwgc.dll");
		Log("    Web menu still running. Press END to exit.");
		goto idle;
	}

	Log("[+] mono base: 0x%llX", baseAddress);
	Log("Resolving classes...");

	GET_ROOT_DOMAIN_OFFSET = find_root_domain_offset();
	if (!GET_ROOT_DOMAIN_OFFSET)
	{
		Log("[-] CRITICAL: Could not find root domain offset!");
		Log("    Web menu still running. Press END to exit.");
		goto idle;
	}

	Classes::init();

	printf("\n=== Class Debug ===\n");
	printf("Provider       : %p\n", Classes::Provider);
	printf("Player         : %p\n", Classes::Player);
	printf("SteamChannel   : %p\n", Classes::SteamChannel);
	printf("SteamPlayer    : %p\n", Classes::SteamPlayer);
	printf("PlayerEquipment: %p\n", Classes::PlayerEquipment);
	printf("ItemGunAsset   : %p\n", Classes::ItemGunAsset);
	printf("PlayerLife     : %p\n", Classes::PlayerLife);
	printf("PlayerMovement : %p\n", Classes::PlayerMovement);
	printf("PlayerLook     : %p\n", Classes::PlayerLook);
	printf("ZombieManager  : %p\n", Classes::ZombieManager);
	printf("===================\n\n");

	Log("Resolving offsets...");
	Offsets::init();

	printf("\n=== Offset Status ===\n");
	printf("_localPlayer  : %s (0x%X)\n", Offsets::_localPlayer ? "OK" : "--", (uint32_t)Offsets::_localPlayer);
	printf("_player       : %s (0x%X)\n", Offsets::_player ? "OK" : "--", (uint32_t)Offsets::_player);
	printf("_life         : %s (0x%X)\n", Offsets::_life ? "OK" : "--", (uint32_t)Offsets::_life);
	printf("_health       : %s (0x%X)\n", Offsets::_health ? "OK" : "--", (uint32_t)Offsets::_health);
	printf("_movement     : %s (0x%X)\n", Offsets::_movement ? "OK" : "--", (uint32_t)Offsets::_movement);
	printf("_look         : %s (0x%X)\n", Offsets::_look ? "OK" : "--", (uint32_t)Offsets::_look);
	printf("_yaw          : %s (0x%X)\n", Offsets::_yaw ? "OK" : "--", (uint32_t)Offsets::_yaw);
	printf("_pitch        : %s (0x%X)\n", Offsets::_pitch ? "OK" : "--", (uint32_t)Offsets::_pitch);
	printf("=====================\n\n");

	Log("Waiting for server connection...");
	while (!SDG::Provider::isConnected())
	{
		if (GetAsyncKeyState(VK_END) & 1) goto cleanup;
		Sleep(1000);
		printf(".");
	}
	printf("\n");

	{
		auto localPlayer = Features::GetLocalPlayer();
		if (!localPlayer)
		{
			Log("[-] Couldn't find local player");
			goto idle;
		}

		Log("[+] Local player: 0x%llX", (uintptr_t)localPlayer);

		if (internalMode)
		{
			Log("\n=== INTERNAL ESP MODE ===");
			Log("Injecting rendering hook into game process...\n");

			if (!internalHwnd)
			{
				Log("[!] No HWND specified. Run with --hwnd <hex> to provide the game window handle.");
				Log("    Find it on PC1: powershell -c \"(Get-Process Unturned).MainWindowHandle.ToString('X')\"");
				Log("    Example: CoopyyDMA.exe --internal --hwnd 1A0B2C");
				goto idle;
			}

			if (!InternalESP::inject())
			{
				Log("[-] Internal ESP injection failed");
				goto idle;
			}

			Log("[+] Internal ESP active — drawing inside game on PC1");
			Log("    HWND: 0x%llX", internalHwnd);
			Log("    Control via web menu: http://localhost:9222");
			Log("    Press END to unhook and exit\n");

			while (true)
			{
				if (GetAsyncKeyState(VK_END) & 1)
					break;

				if (!SDG::Provider::isConnected())
				{
					Sleep(1000);
					continue;
				}

				localPlayer = Features::GetLocalPlayer();
				if (!localPlayer) { Sleep(500); continue; }

				Features::Update(localPlayer);
				InternalESP::updateSharedData(internalHwnd);
				Sleep(10);
			}

			InternalESP::unhook();
			Log("[+] Internal ESP unhooked");
		}
		else
		{
		Log("DMA cheat active. ESP renders on PC1 via esp_client.exe.");
		Log("Control via web menu: http://localhost:9222");
		Log("ESP data API: http://<this-pc-ip>:9222/api/gamedata\n");

		while (true)
		{
			if (GetAsyncKeyState(VK_END) & 1)
				break;

			if (!SDG::Provider::isConnected())
			{
				Sleep(1000);
				continue;
			}

			localPlayer = Features::GetLocalPlayer();
			if (!localPlayer)
			{
				Sleep(500);
				continue;
			}

			Features::Update(localPlayer);
			Sleep(10);
		}
		}

		Sleep(200);
	}
	goto cleanup;

idle:
	Log("Press END to exit. Web menu remains active.");
	while (!(GetAsyncKeyState(VK_END) & 1))
		Sleep(200);

cleanup:
	Log("Shutting down...");
	WebServer::Stop();
	DMA::Close();
	printf("\nPress any key to exit.\n");
	_getch();
	return 0;
}
